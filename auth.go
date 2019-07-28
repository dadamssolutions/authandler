/*
Package authandler provides a self-contained authentication handler using a Postgresql database backend.

The handler will create all the necessary tables it needs or the user can provide a tableName that exists and has the appropriate columns for the application. For example, the table where the user information is stored (by default called 'users') should have at least username (PRIMARY KEY), fname, lname, email, role (int), validated (bool), passhash (char(80)).

authandler also "handles" all session information and csrf token generation and validation. That is, this package is designed to be an automatic, all-in-one solution. The user should not have to worry about the logic of authentication and validation, but should know who is logged in, if any.
*/
package authandler

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
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
	allowXForwardedProto       bool
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
//
// In order for this to work properly, you must also set the two email templates and the error template.
// i.e. `auth.PasswordResetEmailTemplate = template.Must(template.ParseFiles("templates/passwordreset.tmpl.html"))`
func DefaultHTTPAuth(db *sql.DB, tableName, domainName string, allowXForwardedProto bool, emailSender *email.Sender, sessionTimeout, persistantSessionTimeout, csrfsTimeout, passwordResetTimeout time.Duration, cost int, secret []byte) (*HTTPAuth, error) {
	var err error
	g := func(pass []byte) ([]byte, error) {
		return bcrypt.GenerateFromPassword(pass, cost)
	}
	ah := &HTTPAuth{db: db, emailHandler: emailSender, UsersTableName: tableName, secret: secret, allowXForwardedProto: allowXForwardedProto}
	// Password hashing functions
	ah.GenerateHashFromPassword = g
	ah.CompareHashAndPassword = bcrypt.CompareHashAndPassword
	// Sessions handler
	ah.sesHandler, err = session.NewHandlerWithDB(db, "sessions", "sessionID", sessionTimeout, persistantSessionTimeout, secret)
	if err != nil {
		// Session handler could not be created, likely a database problem.
		return nil, errors.New("Session handler could not be created")
	}
	// Cross-site request forgery handler
	ah.csrfHandler = csrf.NewHandler(db, csrfsTimeout, secret)
	if ah.csrfHandler == nil {
		// CSRF handler could not be created, likely a database problem.
		return nil, errors.New("CSRF handler could not be created")
	}
	// Password reset token handler.
	ah.passResetHandler = passreset.NewHandler(db, "pass_reset_tokens", passwordResetTimeout, secret)
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
	ah.LoginURL = "/login/"
	ah.LogOutURL = "/logout/"
	ah.RedirectAfterLogin = "/user/"
	ah.SignUpURL = "/sign-up/"
	ah.RedirectAfterSignUp = "/signed-up/"
	ah.SignUpVerificationURL = "/verify-sign-up/"
	ah.PasswordResetRequestURL = "/pass-reset-request/"
	ah.PasswordResetURL = "/pass-reset/"
	ah.RedirectAfterResetRequest = "/pass-reset-sent/"
	return ah, nil
}

// AddDefaultHandlers adds the standard handlers needed for the auth handler.
func (a *HTTPAuth) AddDefaultHandlers(home, signUp, afterSignUp, verifySignUp, logIn, afterLogIn, logOut, passResetRequest, passResetSent, passReset http.Handler) {
	a.AddDefaultHandlersWithMux(http.DefaultServeMux, home, signUp, afterSignUp, verifySignUp, logIn, afterLogIn, logOut, passResetRequest, passResetSent, passReset)
}

// AddDefaultHandlersWithMux adds the standard handlers needed for the auth handler to the ServeMux.
func (a *HTTPAuth) AddDefaultHandlersWithMux(mux *http.ServeMux, home, signUp, afterSignUp, verifySignUp, logIn, afterLogIn, logOut, passResetRequest, passResetSent, passReset http.Handler) {
	mux.Handle("/", a.MustHaveAdapters()(home))
	mux.Handle(a.SignUpURL, a.MustHaveAdapters(a.SignUpAdapter())(signUp))
	mux.Handle(a.RedirectAfterSignUp, a.MustHaveAdapters()(afterSignUp))
	mux.Handle(a.SignUpVerificationURL, a.MustHaveAdapters(a.SignUpVerificationAdapter())(verifySignUp))
	mux.Handle(a.LoginURL, a.MustHaveAdapters(a.LoginAdapter())(logIn))
	mux.Handle(a.RedirectAfterLogin, a.MustHaveAdapters(a.RedirectIfUserNotAuthenticated())(afterLogIn))
	mux.Handle(a.LogOutURL, a.MustHaveAdapters(a.LogoutAdapter("/"))(logOut))
	mux.Handle(a.PasswordResetURL, a.MustHaveAdapters(a.PasswordResetAdapter())(passReset))
	mux.Handle(a.RedirectAfterResetRequest, a.MustHaveAdapters()(passResetSent))
	mux.Handle(a.PasswordResetRequestURL, a.MustHaveAdapters(a.PasswordResetRequestAdapter())(passResetRequest))
}

// RedirectHandler ensures that the authentication aspects are taken care of before the redirect is sent.
// One should use this instead of http.Redirect or a.RedirectHandler.
func (a *HTTPAuth) RedirectHandler(url string, code int) http.Handler {
	return a.AttachSessionCookie()(http.RedirectHandler(url, code))
}

// LoadOrCreateSession adapter loads a session if the request has the correct cookie.
// If the request does not have the correct cookie, we create one, attach it to the response,
// and put it on the Request's context.
func (a *HTTPAuth) LoadOrCreateSession() adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ses, err := a.sesHandler.ParseSessionFromRequest(r)
			if err != nil {
				ses, err = a.sesHandler.CreateSession("", false)
				if err != nil {
					log.Println("Error creating a session")
				}
			}
			r = r.WithContext(NewSessionContext(r.Context(), ses))
			h.ServeHTTP(w, r)
		})
	}
}

// AttachSessionCookie adapter calls the handler and then attaches the session cookie to the response.
// This should be the last adapter attached to the handler.
func (a *HTTPAuth) AttachSessionCookie() adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ses := SessionFromContext(r.Context())
			if ses != nil {
				err := ErrorFromContext(r.Context())
				if err != nil {
					ses.AddError(err.Error())
					a.sesHandler.UpdateSessionIfValid(ses)
				}
				err = a.sesHandler.AttachCookie(w, ses)
				if err == nil {
					updateUserLastAccess(a.db, a.UsersTableName, ses.Username())
				}
			}
			h.ServeHTTP(w, r)
		})
	}
}

// MustHaveAdapters are the adapters that we must have for essentially every Handler
//
// As of now, they are EnsureHHTPS. LoadOrCreateSession, and AttachSessionCookie (which is at the end)
func (a *HTTPAuth) MustHaveAdapters(otherAdapters ...adaptd.Adapter) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		firstAdapters := []adaptd.Adapter{adaptd.EnsureHTTPS(a.allowXForwardedProto), a.LoadOrCreateSession()}
		otherAdapters = append(firstAdapters, otherAdapters...)
		otherAdapters = append(otherAdapters, a.AttachSessionCookie())
		return adaptd.Adapt(h, otherAdapters...)
	}
}

// RedirectIfUserNotAuthenticated is like http.HandleFunc except it is verified the user is logged in.
// It automatically applies the MustHaveAdapters.
func (a *HTTPAuth) RedirectIfUserNotAuthenticated() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		authenticated := a.userIsAuthenticated(w, r)
		if !authenticated {
			*r = *r.WithContext(NewErrorContext(r.Context(), errors.New("You must log in to view that page")))
		}
		return authenticated
	}
	adapters := []adaptd.Adapter{
		adaptd.CheckAndRedirect(f, a.RedirectHandler(a.LoginURL, http.StatusSeeOther), "User not authenticated"),
	}
	return a.MustHaveAdapters(adapters...)
}

// RedirectIfNoPermission is like http.HandleFunc except it is verified the user is logged in and
// has permission to view the page.
func (a *HTTPAuth) RedirectIfNoPermission(minRole Role) adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		a.userIsAuthenticated(w, r)
		user := UserFromContext(r.Context())
		if user == nil {
			return false
		}
		return user.Role.HasRole(minRole)
	}
	adapters := []adaptd.Adapter{
		adaptd.CheckAndRedirect(f, a.RedirectHandler(a.RedirectAfterLogin, http.StatusSeeOther), "User does not have permission"),
	}
	return a.MustHaveAdapters(adapters...)
}

// CSRFPostAdapter handles the CSRF token verification for POST requests.
func (a *HTTPAuth) CSRFPostAdapter(redirectOnError, logOnError string) adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) error {
		err := a.csrfHandler.ValidToken(r)
		return err
	}
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			RedirectOnError(f, a.RedirectHandler(redirectOnError, http.StatusSeeOther), logOnError),
		}

		return adaptd.Adapt(h, adapters...)
	}
}

// CSRFGetAdapter attaches a new CSRF token to the header of the response.
func (a *HTTPAuth) CSRFGetAdapter() adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.AddCookieWithFunc(csrf.CookieName, a.csrfHandler.GenerateNewToken),
		}
		return adaptd.Adapt(h, adapters...)
	}
}

// StandardPostAndGetAdapter uses other adapters to do a standard type of POST/GET request.
//
// If the request is POST, then the request is checked for a CSRF token. If the token is verified
// then the postHandler is called.
//
// If the POST handler does not put an error on the Request's context, then the user is redirected
// to redirectOnSuccess
// If, at any point, there is an error on the Request's context (either put there by the postHandler
// or bad CSRF token detection), then the user is redirected to redirectOnError and logOnError
// is logged to the console.
func (a *HTTPAuth) StandardPostAndGetAdapter(postHandler http.Handler, redirectOnSuccess, redirectOnError, logOnError string, extraAdapters ...adaptd.Adapter) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		onSuccess := a.RedirectHandler(redirectOnSuccess, http.StatusSeeOther)
		onError := a.RedirectHandler(redirectOnError, http.StatusSeeOther)
		adapters := []adaptd.Adapter{
			PostAndOtherOnError(a.CSRFPostAdapter(redirectOnError, logOnError)(postHandler), onSuccess, onError),
		}
		extraAdapters = append(extraAdapters, a.CSRFGetAdapter())

		return adaptd.Adapt(h, append(adapters, extraAdapters...)...)
	}
}

// CurrentUser returns the username of the current user
func (a *HTTPAuth) CurrentUser(r *http.Request) *User {
	// If there is a current user, then we must have a cooke for them.
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	if ses != nil && !ses.IsUserLoggedIn() {
		return nil
	}
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

// Flashes returns the flashes of the session and updates the database.
func (a *HTTPAuth) Flashes(ses *sessions.Session) ([]interface{}, []interface{}) {
	return a.sesHandler.ReadFlashes(ses)
}

func (a *HTTPAuth) logUserOut(w http.ResponseWriter, r *http.Request) bool {
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	if ses.IsUserLoggedIn() {
		username := ses.Username()
		err = a.sesHandler.LogUserOut(ses)
		if err != nil {
			log.Printf("Could not log %v out\n", username)
		} else {
			log.Printf("%v was successfully logged out\n", username)
			ses.AddMessage("You have been successfully logged out")
		}
	}
	*r = *r.WithContext(NewSessionContext(r.Context(), ses))
	return err == nil
}

func (a *HTTPAuth) userIsAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	// Check that the user is logged in by looking for a session cookie
	ses := SessionFromContext(r.Context())
	if ses == nil {
		ses, _ = a.sesHandler.ParseSessionFromRequest(r)
		if ses == nil {
			return false
		}
		*r = *r.WithContext(NewSessionContext(r.Context(), ses))
	}
	if ses.IsUserLoggedIn() {
		user := getUserFromDB(a.db, a.UsersTableName, "username", ses.Username())
		*r = *r.WithContext(NewUserContext(r.Context(), user))
		return true
	}
	return false
}
