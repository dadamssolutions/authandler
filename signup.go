package authandler

import (
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/dadamssolutions/adaptd"
)

// SignUpAdapter handles the sign up GET and POST requests.
// If it is determine that the sign up page should be shown, then the handler passed to the Adapter is called.
// If the user sign up POST request fails, the handler passed to the adapter is called again,
// this time with an error on the Request's context.
//
// The form for the POST request should point back to this handler.
// The form should have six inputs: firstname, lastname, username, email, password, repeatedPassword
func (a *HTTPAuth) SignUpAdapter() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		return !a.userIsAuthenticated(w, r)
	}

	logOnError := "CSRF token not valid for password reset request"

	adapters := []adaptd.Adapter{adaptd.CheckAndRedirect(f, a.RedirectHandler(a.RedirectAfterLogin, http.StatusSeeOther), "User requesting login page is logged in")}

	return a.StandardPostAndGetAdapter(http.HandlerFunc(a.signUp), a.RedirectAfterSignUp, a.SignUpURL, logOnError, adapters...)
}

// SignUpVerificationAdapter handles verification of sign ups.
// The user is sent an email with a verification link. When the user clicks that link they are sent to
// this handler that verifies the token they were given and marks them as verified.
func (a *HTTPAuth) SignUpVerificationAdapter() adaptd.Adapter {
	// A check function that returns err == nil if the user is logged in or the password reset token is valid.
	f := func(w http.ResponseWriter, r *http.Request) error {
		username, err := a.passResetHandler.ValidToken(r)
		u := getUserFromDB(a.db, a.UsersTableName, "username", username)
		*r = *r.WithContext(NewUserContext(r.Context(), u))
		if err != nil {
			return NewError(TokenError)
		}
		return nil
	}

	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			RedirectOnError(f, a.RedirectHandler(a.SignUpURL, http.StatusUnauthorized), "Invalid sign up validation query"),
			RedirectOnError(a.verifySignUp, a.RedirectHandler(a.SignUpURL, http.StatusUnauthorized), "Invalid sign up validation query"),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

func (a *HTTPAuth) signUp(w http.ResponseWriter, r *http.Request) {
	// If the user is authenticated already, then we just redirect
	if a.userIsAuthenticated(w, r) {
		log.Printf("User requesting sign up page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
		return
	}
	// If the user is not logged in, we get the information and validate it
	password, repeatedPassword := url.QueryEscape(r.PostFormValue("password")), url.QueryEscape(r.PostFormValue("repeatedPassword"))
	if password == "" || password != repeatedPassword {
		log.Println("Sign up passwords did not match, redirecting back to sign up page")
		*r = *r.WithContext(NewErrorContext(r.Context(), NewError(PasswordConfirmationError)))
		return
	}
	username := url.QueryEscape(r.PostFormValue("username"))
	addr, err := mail.ParseAddress(r.PostFormValue("email"))
	if err != nil {
		log.Printf("Sign up included a bad email address: %v\n", r.PostFormValue("email"))
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	firstName, lastName := url.QueryEscape(r.PostFormValue("firstName")), url.QueryEscape(r.PostFormValue("lastName"))
	hashedPassword, err := a.GenerateHashFromPassword([]byte(password))
	if err != nil {
		log.Println("Unable to has password")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	user := &User{FirstName: firstName, LastName: lastName, Username: strings.ToLower(username), Email: strings.ToLower(addr.Address), passHash: hashedPassword, validated: false}

	if usernameExists, emailExists := usernameOrEmailExists(a.db, a.UsersTableName, user); usernameExists {
		log.Printf("Username %v exists\n", user.Username)
		*r = *r.WithContext(NewErrorContext(r.Context(), NewError(UsernameExists)))
		return
	} else if emailExists {
		log.Printf("Email %v exists\n", user.GetEmail())
		*r = *r.WithContext(NewErrorContext(r.Context(), NewError(EmailExists)))
		return
	}

	// Get the reset token and send the message.
	token := a.passResetHandler.GenerateNewToken(user.Username)
	data := make(map[string]interface{})
	data["Link"] = "https://" + a.domainName + a.SignUpVerificationURL + "?" + token.Query()
	err = a.emailHandler.SendMessage(a.SignUpEmailTemplate, "Welcome!", data, user)
	if err != nil || !user.isValid() {
		log.Println("User sign up failed, redirecting back to sign up page")
		err = NewError(PasswordConfirmationError)
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	err = addUserToDatabase(a.db, a.UsersTableName, user)
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
	}
}

func (a *HTTPAuth) verifySignUp(w http.ResponseWriter, r *http.Request) error {
	user := UserFromContext(r.Context())
	if user == nil {
		return NewError(TokenError)
	}

	err := validateUser(a.db, a.UsersTableName, user)
	if err != nil {
		err = NewError(TokenError)
	}
	return err
}
