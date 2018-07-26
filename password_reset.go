package authandler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"net/url"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authandler/handlers/passreset"
)

// PasswordResetRequestAdapter handles the GET and POST requests for requesting password reset.
// If the request is GET, the getHandler passed to the Adapter.
//
// The form shown to the user in a GET request should have an input with name 'email'
// The POST request should be pointed to the same handler, and the user is sent a link to reset their password.
//
// When a POST request is received, the database is checked for the existing user. If the user exists,
// and email is send to the user. You can include {{.link}} in the template to include the password reset link.
//
// If a user with the supplied email does not exists, then the handler passed to the Adapter is called
// with the appropriate error on the Request's context.
//
// After successful password reset, the user is redirected to redirectOnSuccess.
// If their is an error, the user is redirected to redirectOnError.
func (a *HTTPAuth) PasswordResetRequestAdapter() adaptd.Adapter {

	postHandler := a.CSRFPostAdapter(a.PasswordResetURL, "CSRF token not valid for password reset request")(http.HandlerFunc(a.passwordResetRequest))

	return a.standardPostAndGetAdapter(postHandler, a.RedirectAfterResetRequest)
}

// PasswordResetAdapter handles the GET and POST requests for reseting the password.
// If the request is GET with the correct query string, the getHandler passed to the Adapter.
//
// If the request is GET with invalid query string, the user is redirected to redirectOnError
// unless the user is logged in. An authenticated user is allow to reset their password.
//
// The form shown to the user in a GET request should have inputs with names 'password' and 'repeatedPassword'
// The POST request should be pointed to the same handler, and the user's password is updated.
//
// After successful password reset, the user is redirected to redirectOnSuccess.
// If their is an error, the user is redirected to redirectOnError.
func (a *HTTPAuth) PasswordResetAdapter() adaptd.Adapter {
	// A check function that returns err == nil if the user is logged in or the password reset token is valid.
	f := func(w http.ResponseWriter, r *http.Request) error {
		username, err := a.passResetHandler.ValidToken(r)
		u := getUserFromDB(a.db, a.UsersTableName, "username", username)
		*r = *r.WithContext(NewUserContext(r.Context(), u))
		if !(a.userIsAuthenticated(w, r) || err == nil) {
			return NewError(TokenError)
		}
		return nil
	}

	// A check function that attaches a password reset token to the header.
	g := func(w http.ResponseWriter, r *http.Request) error {
		token := ""
		u := UserFromContext(r.Context())
		if u != nil {
			token = a.passResetHandler.GenerateNewToken(u.Username)
		}
		if token == "" {
			return errors.New("Cannot attach token")
		}
		w.Header().Add(passreset.HeaderName, token)
		return nil
	}

	postHandler := a.CSRFPostAdapter(a.PasswordResetURL, "CSRF token not valid for password reset request")(http.HandlerFunc(a.passwordReset))

	adapters := []adaptd.Adapter{
		RedirectOnError(f, http.RedirectHandler(a.PasswordResetURL, http.StatusUnauthorized), "Invalid password reset query"),
		RedirectOnError(g, http.RedirectHandler(a.PasswordResetURL, http.StatusInternalServerError), "Error attaching password reset token"),
	}

	return a.standardPostAndGetAdapter(postHandler, a.LoginURL, adapters...)
}

func (a *HTTPAuth) passwordReset(w http.ResponseWriter, r *http.Request) {
	password, repeatedPassword := url.QueryEscape(r.PostFormValue("password")), url.QueryEscape(r.PostFormValue("repeatedPassword"))

	username, err := a.passResetHandler.ValidHeaderToken(r)
	if password != repeatedPassword {
		err = NewError(PasswordError)
	}
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	passHash, err := a.GenerateHashFromPassword([]byte(password))
	if err != nil {
		err = NewError(PasswordError)
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	err = updateUserPassword(a.db, a.UsersTableName, username, base64.RawURLEncoding.EncodeToString(passHash))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
	}
}

func (a *HTTPAuth) passwordResetRequest(w http.ResponseWriter, r *http.Request) {
	addr, err := mail.ParseAddress(r.PostFormValue("email"))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), NewError(EmailDoesNotExist)))
		return
	}

	user := getUserFromDB(a.db, a.UsersTableName, "email", addr.Address)
	if user == nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), NewError(EmailDoesNotExist)))
		return
	}
	pwResetLink := a.passResetHandler.GenerateNewToken(user.Username)

	data := make(map[string]interface{})
	data["Link"] = a.domainName + a.PasswordResetURL + pwResetLink
	err = a.emailHandler.SendMessage(a.PasswordResetEmailTemplate, "Password Reset Request", data, user)
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
	}
}
