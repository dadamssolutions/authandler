package authandler

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authandler/handlers/csrf"
	"github.com/dadamssolutions/authandler/handlers/passreset"
	"github.com/dadamssolutions/authandler/handlers/session"
	"github.com/dadamssolutions/authandler/handlers/session/sessions"
	_ "github.com/lib/pq" // Database driver
	"golang.org/x/crypto/bcrypt"
)

const (
	updateUserPasswordSQL = "UPDATE %v SET pass_hash = '%v' WHERE username = '%v';"
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
	db                       *sql.DB
	sesHandler               *session.Handler
	csrfHandler              *csrf.Handler
	passResetHandler         *passreset.Handler
	secret                   []byte
	UsersTableName           string
	LoginURL                 string
	LogoutURL                string
	RedirectAfterLogin       string
	GenerateHashFromPassword func([]byte) ([]byte, error)
	CompareHashAndPassword   func([]byte, []byte) error
}

// NewHTTPAuth takes database information and hash generation and comparative functions
// and returns a HTTPAuth handler with those specifications.
// Most callers should user DefaultHTTPAuth instead.
func NewHTTPAuth(driverName, dbURL, tableName string, sessionTimeout, persistantSessionTimeout time.Duration, g func([]byte) ([]byte, error), c func([]byte, []byte) error, secret []byte) (*HTTPAuth, error) {
	db, err := sql.Open(driverName, dbURL)
	if err != nil {
		// Database connections failed.
		return nil, errors.New("Database connection failed")
	}
	ses, err := session.NewHandlerWithDB(db, "sessions", sessionTimeout, persistantSessionTimeout, secret)
	if err != nil {
		// Session handler could not be created, likely a database problem.
		return nil, errors.New("Session handler could not be created")
	}
	csrf := csrf.NewHandler(db, sessionTimeout, secret)
	if csrf == nil {
		// CSRF handler could not be created, likely a database problem.
		return nil, errors.New("CSRF handler could not be created")
	}
	prh := passreset.NewHandler(db, sessionTimeout, secret)
	if prh == nil {
		// Password reset handler could not be created, likely a database problem.
		return nil, errors.New("Password reset handler could not be created")
	}
	err = createUsersTable(db, tableName)
	if err != nil {
		return nil, errors.New("Users database table could not be created")
	}
	return &HTTPAuth{db: db, sesHandler: ses, csrfHandler: csrf, passResetHandler: prh, UsersTableName: tableName, GenerateHashFromPassword: g, CompareHashAndPassword: c, LoginURL: "/login", LogoutURL: "/logout", RedirectAfterLogin: "/user"}, nil
}

// DefaultHTTPAuth uses the standard bcyrpt functions for
// generating and comparing password hashes.
// cost parameter is the desired cost for bycrypt generated hashes.
func DefaultHTTPAuth(driverName, dbURL string, sessionTimeout, persistantSessionTimeout time.Duration, cost int, secret []byte) (*HTTPAuth, error) {
	g := func(pass []byte) ([]byte, error) {
		return bcrypt.GenerateFromPassword(pass, cost)
	}
	return NewHTTPAuth(driverName, dbURL, "users", sessionTimeout, persistantSessionTimeout, g, bcrypt.CompareHashAndPassword, secret)
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

// LoginAdapter handles the login GET and POST requests
// If it is determined that the login page should be shown, then the handler function is called.
// If the user login POST request fails, the handler passed to the adapter is called again,
// this time with an error on the Request's context.
//
// The form for the post request should point back to this handler.
// The form should have three inputs: username, password, and remember.
func (a *HTTPAuth) LoginAdapter() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		return !a.userIsAuthenticated(w, r)
	}

	postHandler := adaptd.Adapt(http.HandlerFunc(a.logUserIn),
		adaptd.OnCheck(f, http.RedirectHandler(a.RedirectAfterLogin, http.StatusAccepted), "User already logged in"),
		a.CSRFPostAdapter(a.LoginURL, "CSRF token not valid for log in request"),
	)

	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			PostAndOtherOnError(postHandler, a.RedirectAfterLogin),
			a.CSRFGetAdapter(),
			adaptd.CheckAndRedirect(f, a.RedirectAfterLogin, "User requesting login page is logged in", http.StatusAccepted),
		}

		return adaptAndAbsorbError(h, adapters...)
	}
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
// If the user is logged in, they are allowed to change their password straight away.
//
// The form shown to the user in a GET request should have input with name 'email'
// The POST request should be pointed to the same handler, and the user is sent a link to reset their password.
//
// After successful password reset, the user is redirected to redirectOnSuccess.
// If their is an error, the user is redirected to redirectOnError.
// TODO: Implement this based on the comments above.
// TEST
func (a *HTTPAuth) PasswordResetRequestAdapter(redirectOnSuccess, redirectOnError string) adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		_, err := a.passResetHandler.ValidToken(r)
		return a.userIsAuthenticated(w, r) || err == nil
	}

	g := func(w http.ResponseWriter, r *http.Request) bool {
		_, err := a.passResetHandler.ValidHeaderToken(r)
		return a.userIsAuthenticated(w, r) || err != nil
	}

	postHandler := adaptd.Adapt(http.HandlerFunc(a.passwordResetRequest),
		adaptd.CheckAndRedirect(g, redirectOnError, "Password reset token is invalid", http.StatusBadRequest),
		a.CSRFPostAdapter(redirectOnError, "CSRF token not valid for password reset request"),
	)

	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			PostAndOtherOnError(postHandler, redirectOnSuccess),
			adaptd.CheckAndRedirect(f, redirectOnError, "Invalid password reset query", http.StatusBadRequest),
		}

		return adaptAndAbsorbError(h, adapters...)
	}
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
func (a *HTTPAuth) PasswordResetAdapter(redirectOnSuccess, redirectOnError string) adaptd.Adapter {
	// A check function that returns true if the user is logged in or the password reset token is valid.
	f := func(w http.ResponseWriter, r *http.Request) error {
		username, err := a.passResetHandler.ValidToken(r)
		u := getUserFromDB(a.db, a.UsersTableName, username)
		*r = *r.WithContext(NewUserContext(r.Context(), u))
		if !(a.userIsAuthenticated(w, r) || err == nil) {
			return errors.New("Password reset not authorized")
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

	postHandler := a.CSRFPostAdapter(redirectOnError, "CSRF token not valid for password reset request")(http.HandlerFunc(a.passwordReset))

	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			PostAndOtherOnError(postHandler, redirectOnSuccess),
			RedirectOnError(f, http.RedirectHandler(redirectOnError, http.StatusUnauthorized), "Invalid password reset query"),
			RedirectOnError(g, http.RedirectHandler(redirectOnError, http.StatusInternalServerError), "Error attaching password reset token"),
		}

		return adaptAndAbsorbError(h, adapters...)
	}
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
	user = getUserFromDB(a.db, a.UsersTableName, ses.Username())
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
	hashedPassword, err := a.getUserPasswordHash(username)
	// If the user has provided correct credentials, then we log them in by creating a session.
	if err == nil && a.CompareHashAndPassword(hashedPassword, []byte(password)) == nil {
		ses, _ = a.sesHandler.CreateSession(username, rememberMe)
	}
	// If the session was created, then the user is logged in
	if ses != nil {
		log.Printf("User %v logged in successfully. Redirecting to %v\n", username, a.RedirectAfterLogin)
		a.sesHandler.AttachCookie(w, ses)
		return
	}
	log.Println("User login failed, redirecting back to login page")
	err = errors.New("Login failed")
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
		err = errors.New("Passwords for reset do not match")
	}
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	passHash, err := a.GenerateHashFromPassword([]byte(password))
	if err != nil {
		err = errors.New("Error hashing password for database")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	err = a.updateUserPassword(username, base64.RawURLEncoding.EncodeToString(passHash))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
	}
}

// TODO: impletement this to send an email to the user when they request a password reset
func (a *HTTPAuth) passwordResetRequest(w http.ResponseWriter, r *http.Request) {
	password, repeatedPassword := url.QueryEscape(r.PostFormValue("password")), url.QueryEscape(r.PostFormValue("repeatedPassword"))

	username, err := a.passResetHandler.ValidHeaderToken(r)
	if password != repeatedPassword {
		err = errors.New("Passwords for reset do not match")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	if err != nil {
		err = errors.New("Password reset token not valid")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	passHash, err := a.GenerateHashFromPassword([]byte(password))
	if err != nil {
		err = errors.New("Error hashing password for database")
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
		return
	}
	err = a.updateUserPassword(username, base64.RawURLEncoding.EncodeToString(passHash))
	if err != nil {
		*r = *r.WithContext(NewErrorContext(r.Context(), err))
	}
}

func (a *HTTPAuth) signUp(w http.ResponseWriter, r *http.Request) {

}

func (a *HTTPAuth) getUserPasswordHash(username string) ([]byte, error) {
	tx, err := a.db.Begin()
	if err != nil {
		log.Println(err)
		return nil, errors.New("Failed to get password from database")
	}
	var pwHash string
	err = tx.QueryRow(fmt.Sprintf(getUserPasswordHash, a.UsersTableName, username)).Scan(&pwHash)
	if err != nil {
		tx.Rollback()
		log.Printf("User %v not found in the database\n", username)
		return nil, fmt.Errorf("User %v not found in database", username)
	}
	pwDecoded, err := base64.RawURLEncoding.DecodeString(pwHash)
	if err != nil {
		tx.Rollback()
		log.Println(err)
		log.Println("Error decoding password from database. Database might be corrupted!")
		return nil, errors.New("Failed to get password from database")
	}
	return pwDecoded, tx.Commit()
}

func (a *HTTPAuth) updateUserPassword(username, passHash string) error {
	tx, err := a.db.Begin()
	if err != nil {
		return errors.New("Failed to connect to database")
	}
	_, err = tx.Exec(fmt.Sprintf(updateUserPasswordSQL, a.UsersTableName, passHash, username))
	if err != nil {
		tx.Rollback()
		return errors.New("Failed to update user's password")
	}
	tx.Commit()
	log.Printf("%v's password was updated successfully\n", username)
	return nil
}

func (a *HTTPAuth) userIsAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	// Check that the user is logged in by looking for a session cookie
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	if err != nil {
		return false
	}
	user := getUserFromDB(a.db, a.UsersTableName, ses.Username())
	a.sesHandler.AttachCookie(w, ses)
	*r = *r.WithContext(NewUserContext(r.Context(), user))
	return true
}
