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
	err = createUsersTable(db, tableName)
	if err != nil {
		return nil, errors.New("Users database table could not be created")
	}
	return &HTTPAuth{db: db, sesHandler: ses, csrfHandler: csrf, UsersTableName: tableName, GenerateHashFromPassword: g, CompareHashAndPassword: c, LoginURL: "/login", LogoutURL: "/logout", RedirectAfterLogin: "/user"}, nil
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
			adaptd.CheckAndRedirect(a.userIsAuthenticated, a.LoginURL, http.StatusFound),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

// CSRFAdapter handles both GET and POST requests.
// If the request is GET, then we generate a CSRF token to be included
// If the request is POST, then we validate the CSRF token before continuing
func (a *HTTPAuth) CSRFAdapter(postHandler http.Handler) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			TryPostErrorContext(a.csrfHandler.ValidToken, postHandler),
			adaptd.AddHeaderWithFunc(csrf.HeaderName, a.csrfHandler.GenerateNewToken),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

// CSRFAdapterCSRFWithAuth is a simple helper that combines the functionality of Auth
// and CSRF checks, in that order
func (a *HTTPAuth) CSRFAdapterCSRFWithAuth(postHandler http.Handler) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			a.RedirectIfUserNotAuthenticated(),
			a.CSRFAdapter(postHandler),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

// LoginAdapter handles the login GET and POST requests
// If it is determined that the login page should be shown, then the handler function is called.
// If the user login POST request fails, the handler passed to the adapter is called again,
// this time with a redirect with http.StatusUnauthorized.
//
// The form for the post request should point back to this handler.
// The form should have three imputs: username, password, and remember.
func (a *HTTPAuth) LoginAdapter() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		if a.userIsAuthenticated(w, r) {
			ses := SessionFromContext(r.Context())
			a.sesHandler.AttachCookie(w, ses)
			return false
		}
		return true
	}

	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.CheckAndRedirect(f, a.RedirectAfterLogin, http.StatusAccepted),
			a.CSRFAdapter(RedirectOnError(a.logUserIn, http.RedirectHandler(a.LoginURL, http.StatusUnauthorized))(http.RedirectHandler(a.RedirectAfterLogin, http.StatusAccepted))),
		}

		return adaptd.Adapt(h, adapters...)
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
			adaptd.CheckAndRedirect(a.userIsAuthenticated, redirectOnSuccess, http.StatusFound),
			adaptd.CheckAndRedirect(g, redirectOnSuccess, http.StatusFound),
		}
		return adaptd.Adapt(h, adapters...)
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
		// http.Redirect(w, r, a.RedirectAfterLogin, http.StatusFound)
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
		// http.Redirect(w, r, a.RedirectAfterLogin, http.StatusAccepted)
		return
	}
	log.Println("User login failed, redirecting back to login page")
	err = errors.New("Login failed")
	*r = *r.WithContext(NewErrorContext(r.Context(), err))
	// http.Redirect(w, r, a.LoginURL, http.StatusUnauthorized)
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

func (a *HTTPAuth) userIsAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	// Check that the user is logged in by looking for a session cookie
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	if err != nil {
		return false
	}
	a.sesHandler.AttachCookie(w, ses)
	user := getUserFromDB(a.db, a.UsersTableName, ses.Username())
	*r = *r.WithContext(NewUserContext(r.Context(), user))
	return true
}
