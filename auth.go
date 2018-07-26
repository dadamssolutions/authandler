package authandler

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authandler/handlers/csrf"
	"github.com/dadamssolutions/authandler/handlers/email"
	"github.com/dadamssolutions/authandler/handlers/passreset"
	"github.com/dadamssolutions/authandler/handlers/session"
	"github.com/dadamssolutions/authandler/handlers/session/sessions"
	_ "github.com/lib/pq" // Database driver
	"golang.org/x/crypto/bcrypt"
)

func createUsersTable(db *sql.DB, tableName string) error {
	tx, err := db.Begin()
	if err != nil {
		return nil
	}
	_, err = tx.Exec(fmt.Sprintf(createUsersTableSQL, tableName))
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func deleteUsersTestTable(db *sql.DB, tableName string) error {
	tx, err := db.Begin()
	if err != nil {
		return nil
	}
	_, err = tx.Exec(fmt.Sprintf(deleteUsersTestTableSQL, tableName))
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// HTTPAuth is a general handler that authenticates a user for http requests.
// It also handles csrf token generation and validation.
type HTTPAuth struct {
	db                         *sql.DB
	sesHandler                 *session.Handler
	csrfHandler                *csrf.Handler
	passResetHandler           *passreset.Handler
	emailHandler               *email.Sender
	secret                     []byte
	domainName                 string
	UsersTableName             string
	LoginURL                   string
	RedirectAfterLogin         string
	LogOutURL                  string
	SignUpURL                  string
	RedirectAfterSignUp        string
	SignUpVerificationURL      string
	PasswordResetRequestURL    string
	PasswordResetURL           string
	RedirectAfterResetRequest  string
	PasswordResetEmailTemplate *template.Template
	SignUpEmailTemplate        *template.Template
	GenerateHashFromPassword   func([]byte) ([]byte, error)
	CompareHashAndPassword     func([]byte, []byte) error
}

// DefaultHTTPAuth uses the standard bcyrpt functions for
// generating and comparing password hashes.
// cost parameter is the desired cost for bycrypt generated hashes.
// The parameters listed are the ones necessary for setting up the handler.
// All other fields are customizable after creating the handler.
func DefaultHTTPAuth(db *sql.DB, tableName, domainName string, emailSender *email.Sender, sessionTimeout, persistantSessionTimeout time.Duration, cost int, secret []byte) (*HTTPAuth, error) {
	var err error
	g := func(pass []byte) ([]byte, error) {
		return bcrypt.GenerateFromPassword(pass, cost)
	}
	ah := &HTTPAuth{db: db, emailHandler: emailSender, UsersTableName: tableName, secret: secret}
	// Password hashing functions
	ah.GenerateHashFromPassword = g
	ah.CompareHashAndPassword = bcrypt.CompareHashAndPassword
	// Sessions handler
	ah.sesHandler, err = session.NewHandlerWithDB(db, "sessions", sessionTimeout, persistantSessionTimeout, secret)
	if err != nil {
		// Session handler could not be created, likely a database problem.
		return nil, errors.New("Session handler could not be created")
	}
	// Cross-site request forgery handler
	ah.csrfHandler = csrf.NewHandler(db, sessionTimeout, secret)
	if ah.csrfHandler == nil {
		// CSRF handler could not be created, likely a database problem.
		return nil, errors.New("CSRF handler could not be created")
	}
	// Password reset token handler.
	ah.passResetHandler = passreset.NewHandler(db, sessionTimeout, secret)
	if ah.passResetHandler == nil {
		// Password reset handler could not be created, likely a database problem.
		return nil, errors.New("Password reset handler could not be created")
	}
	// Create the user database
	err = createUsersTable(db, tableName)
	if err != nil {
		return nil, errors.New("Users database table could not be created")
	}

	// Add https:// to domain name, if necessary
	if strings.HasPrefix(domainName, "https://") {
		domainName = "https://" + domainName
	}
	// Important redirecting URLs
	ah.domainName = domainName
	ah.LoginURL = "/login"
	ah.LogOutURL = "/logout"
	ah.RedirectAfterLogin = "/users"
	ah.SignUpURL = "/sign_up"
	ah.RedirectAfterSignUp = "/signed_up"
	ah.SignUpVerificationURL = "/verify_sign_up"
	ah.PasswordResetRequestURL = "/pass_reset_request"
	ah.PasswordResetURL = "/pass_reset"
	ah.RedirectAfterResetRequest = "/pass_reset_sent"
	// Email templates
	ah.PasswordResetEmailTemplate = template.Must(template.ParseFiles("templates/passwordreset.tmpl.html"))
	ah.SignUpEmailTemplate = template.Must(template.ParseFiles("templates/signup.tmpl.html"))
	return ah, nil
}

// AddDefaultHandlers adds the standard handlers needed for the auth handler.
func (a *HTTPAuth) AddDefaultHandlers(signUp, afterSignUp, verifySignUp, logIn, afterLogIn, logOut, passResetRequest, passResetSent, passReset http.Handler) {
	http.Handle(a.SignUpURL, a.SignUpAdapter()(signUp))
	http.Handle(a.RedirectAfterSignUp, adaptd.EnsureHTTPS(false)(afterSignUp))
	http.Handle(a.SignUpVerificationURL, a.SignUpVerificationAdapter()(verifySignUp))
	http.Handle(a.LoginURL, a.LoginAdapter()(logIn))
	http.Handle(a.RedirectAfterLogin, adaptd.EnsureHTTPS(false)(afterLogIn))
	http.Handle(a.LogOutURL, a.LogoutAdapter("/")(logOut))
	http.Handle(a.PasswordResetURL, a.PasswordResetAdapter()(passReset))
	http.Handle(a.RedirectAfterResetRequest, adaptd.EnsureHTTPS(false)(passResetSent))
	http.Handle(a.PasswordResetRequestURL, a.PasswordResetAdapter()(passResetRequest))
}

// AddDefaultHandlersWithMux adds the standard handlers needed for the auth handler to the ServeMux.
func (a *HTTPAuth) AddDefaultHandlersWithMux(mux *http.ServeMux, signUp, afterSignUp, verifySignUp, logIn, afterLogIn, logOut, passResetRequest, passResetSent, passReset http.Handler) {
	mux.Handle(a.SignUpURL, a.SignUpAdapter()(signUp))
	mux.Handle(a.RedirectAfterSignUp, adaptd.EnsureHTTPS(false)(afterSignUp))
	mux.Handle(a.SignUpVerificationURL, a.SignUpVerificationAdapter()(verifySignUp))
	mux.Handle(a.LoginURL, a.LoginAdapter()(logIn))
	mux.Handle(a.RedirectAfterLogin, adaptd.EnsureHTTPS(false)(afterLogIn))
	mux.Handle(a.LogOutURL, a.LogoutAdapter("/")(logOut))
	mux.Handle(a.PasswordResetURL, a.PasswordResetAdapter()(passReset))
	mux.Handle(a.RedirectAfterResetRequest, adaptd.EnsureHTTPS(false)(passResetSent))
	mux.Handle(a.PasswordResetRequestURL, a.PasswordResetAdapter()(passResetRequest))
}

// RedirectIfUserNotAuthenticated is like http.HandleFunc except it is verified the user is logged in.
// It automatically applies the adaptd.EnsureHTTPS adapter.
func (a *HTTPAuth) RedirectIfUserNotAuthenticated() adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			adaptd.CheckAndRedirect(a.userIsAuthenticated, a.LoginURL, "User not authenticated", http.StatusFound),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

// CSRFPostAdapter handles the CSRF token verification for POST requests.
func (a *HTTPAuth) CSRFPostAdapter(redirectOnError, logOnError string) adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) error {
		return a.csrfHandler.ValidToken(r)
	}
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			RedirectOnError(f, http.RedirectHandler(redirectOnError, http.StatusUnauthorized), logOnError),
		}

		return adaptd.Adapt(h, adapters...)
	}
}

// CSRFGetAdapter attaches a new CSRF token to the header of the response.
func (a *HTTPAuth) CSRFGetAdapter() adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			adaptd.AddHeaderWithFunc(csrf.HeaderName, a.csrfHandler.GenerateNewToken),
		}

		return adaptd.Adapt(h, adapters...)
	}
}
func (a *HTTPAuth) standardPostAndGetAdapter(postHandler http.Handler, redirectOnSuccess string, extraAdapters ...adaptd.Adapter) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			PostAndOtherOnError(postHandler, redirectOnSuccess),
			a.CSRFGetAdapter(),
		}

		return adaptAndAbsorbError(h, append(adapters, extraAdapters...)...)
	}
}

// SignUpAdapter handles the sign up GET and POST requests.
// If it is determine that the sign up page should be shown, then the handler passed to the Adapter is called.
// If the user sign up POST request fails, the handler passed to the adapter is called again,
// this time with an error on the Request's context.
//
// The form for the POST request should point back to this handler.
// The form should have six inputs: firstname, lastname, username, email, password, repeatedPassword
func (a *HTTPAuth) SignUpAdapter() adaptd.Adapter {
	postHandler := a.CSRFPostAdapter(a.SignUpURL, "CSRF token not valid for password reset request")(http.HandlerFunc(a.signUp))

	return a.standardPostAndGetAdapter(postHandler, a.RedirectAfterSignUp)
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
			RedirectOnError(f, http.RedirectHandler(a.SignUpURL, http.StatusUnauthorized), "Invalid sign up validation query"),
			RedirectOnError(a.verifySignUp, http.RedirectHandler(a.SignUpURL, http.StatusUnauthorized), "Invalid sign up validation query"),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

// LoginAdapter handles the login GET and POST requests
// If it is determined that the login page should be shown, then the handler passed to the Adapter is called.
// If the user login POST request fails, the handler passed to the adapter is called again,
// this time with an error on the Request's context.
//
// The form for the POST request should point back to this handler.
// The form should have three inputs: username, password, and remember.
func (a *HTTPAuth) LoginAdapter() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		return !a.userIsAuthenticated(w, r)
	}

	postHandler := adaptd.Adapt(http.HandlerFunc(a.logUserIn),
		adaptd.OnCheck(f, http.RedirectHandler(a.RedirectAfterLogin, http.StatusAccepted), "User already logged in"),
		a.CSRFPostAdapter(a.LoginURL, "CSRF token not valid for log in request"),
	)

	return a.standardPostAndGetAdapter(postHandler, a.RedirectAfterLogin, adaptd.CheckAndRedirect(f, a.RedirectAfterLogin, "User requesting login page is logged in", http.StatusAccepted))
}

// LogoutAdapter handles the logout requests
// The handler passed to the Adapter is only called is when the logout fails.
// In this case, the error and the session are put on the Request's context.
func (a *HTTPAuth) LogoutAdapter(redirectOnSuccess string) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		g := func(w http.ResponseWriter, r *http.Request) bool {
			return !a.logUserOut(w, r)
		}

		adapters := []adaptd.Adapter{
			adaptd.CheckAndRedirect(a.userIsAuthenticated, "Requesting logout page, but no user is logged in", redirectOnSuccess, http.StatusFound),
			adaptd.CheckAndRedirect(g, "User was logged out", redirectOnSuccess, http.StatusFound),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

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

// CurrentUser returns the username of the current user
func (a *HTTPAuth) CurrentUser(r *http.Request) *User {
	// If there is a current user, then we must have a cooke for them.
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	user := UserFromContext(r.Context())
	if err != nil {
		if user != nil {
			*r = *r.WithContext(NewUserContext(r.Context(), nil))
		}
		return nil
	}

	if user != nil {
		return user
	}
	// If there is a cookie, then for simplicity, we add the user to the Request's context.
	user = getUserFromDB(a.db, a.UsersTableName, "username", ses.Username())
	if user != nil {
		*r = *r.WithContext(NewUserContext(r.Context(), user))
	}
	return user
}

// IsCurrentUser returns true if the username corresponds to the user logged in with a cookie in the request.
func (a *HTTPAuth) IsCurrentUser(r *http.Request, username string) bool {
	currentUser := a.CurrentUser(r)
	return username != "" && currentUser != nil && currentUser.Username == username
}

func (a *HTTPAuth) logUserIn(w http.ResponseWriter, r *http.Request) {
	var ses *sessions.Session
	// If the user is authenticated already, then we just redirect
	if a.userIsAuthenticated(w, r) {
		log.Printf("User requesting login page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
		return
	}
	// If the user is not logged in, we check the credentials
	username, password := url.QueryEscape(r.PostFormValue("username")), url.QueryEscape(r.PostFormValue("password"))
	remember := url.QueryEscape(r.PostFormValue("remember"))
	rememberMe, _ := strconv.ParseBool(remember)
	user := getUserFromDB(a.db, a.UsersTableName, "username", username)
	// If the user has provided correct credentials, then we log them in by creating a session.
	if user != nil && user.IsValidated() && a.CompareHashAndPassword(user.passHash, []byte(password)) == nil {
		ses, _ = a.sesHandler.CreateSession(username, rememberMe)
	}
	// If the session was created, then the user is logged in
	if ses != nil {
		log.Printf("User %v logged in successfully. Redirecting to %v\n", username, a.RedirectAfterLogin)
		a.sesHandler.AttachCookie(w, ses)
		return
	}
	log.Println("User login failed, redirecting back to login page")
	err := NewError(BadLogin)
	*r = *r.WithContext(NewErrorContext(r.Context(), err))
}

func (a *HTTPAuth) logUserOut(w http.ResponseWriter, r *http.Request) bool {
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	if ses != nil {
		err = a.sesHandler.DestroySession(ses)
		if err != nil {
			log.Printf("Could not log user out so creating a new session context\n")
			a.sesHandler.AttachCookie(w, ses)
			*r = *r.WithContext(NewErrorContext(r.Context(), err))
		}
	}
	return err == nil
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

func (a *HTTPAuth) signUp(w http.ResponseWriter, r *http.Request) {
	// If the user is authenticated already, then we just redirect
	if a.userIsAuthenticated(w, r) {
		log.Printf("User requesting login page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
		return
	}
	// If the user is not logged in, we get the information and validate it
	password, repeatedPassword := url.QueryEscape(r.PostFormValue("password")), url.QueryEscape(r.PostFormValue("repeatedPassword"))
	username := url.QueryEscape(r.PostFormValue("username"))
	addr, err := mail.ParseAddress(r.PostFormValue("email"))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	firstName, lastName := url.QueryEscape(r.PostFormValue("firstName")), url.QueryEscape(r.PostFormValue("lastName"))
	hashedPassword, err := a.GenerateHashFromPassword([]byte(password))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	user := &User{FirstName: firstName, LastName: lastName, Username: username, email: addr.Address, passHash: hashedPassword, validated: false}
	signUpLink := a.passResetHandler.GenerateNewToken(user.Username)
	data := make(map[string]interface{})
	data["Link"] = a.domainName + a.SignUpURL + signUpLink
	err = a.emailHandler.SendMessage(a.SignUpEmailTemplate, "Welcome!", data, user)
	if password == "" || password != repeatedPassword || err != nil || !user.isValid() {
		log.Println("User sign up failed, redirecting back to sign up page")
		err = NewError(BadLogin)
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

func (a *HTTPAuth) userIsAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	// Check that the user is logged in by looking for a session cookie
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	if err != nil {
		return false
	}
	user := getUserFromDB(a.db, a.UsersTableName, "username", ses.Username())
	a.sesHandler.AttachCookie(w, ses)
	*r = *r.WithContext(NewUserContext(r.Context(), user))
	return true
}
