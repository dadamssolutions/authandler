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
//
// In order for this to work properly, you must also set the two email templates and the error template.
// i.e. `auth.PasswordResetEmailTemplate = template.Must(template.ParseFiles("templates/passwordreset.tmpl.html"))`
func DefaultHTTPAuth(db *sql.DB, tableName, domainName string, emailSender *email.Sender, sessionTimeout, persistantSessionTimeout, csrfsTimeout, passwordResetTimeout time.Duration, cost int, secret []byte) (*HTTPAuth, error) {
	var err error
	g := func(pass []byte) ([]byte, error) {
		return bcrypt.GenerateFromPassword(pass, cost)
	}
	ah := &HTTPAuth{db: db, emailHandler: emailSender, UsersTableName: tableName, secret: secret}
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
	ah.passResetHandler = passreset.NewHandler(db, passwordResetTimeout, secret)
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
			RedirectOnError(f, http.RedirectHandler(redirectOnError, http.StatusSeeOther), logOnError),
		}

		return adaptd.Adapt(h, adapters...)
	}
}

// CSRFGetAdapter attaches a new CSRF token to the header of the response.
func (a *HTTPAuth) CSRFGetAdapter() adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			adaptd.AddCookieWithFunc(csrf.CookieName, a.csrfHandler.GenerateNewToken),
		}

		return adaptd.Adapt(h, adapters...)
	}
}
func (a *HTTPAuth) standardPostAndGetAdapter(postHandler http.Handler, redirectOnSuccess, redirectOnError string, extraAdapters ...adaptd.Adapter) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		adapters := []adaptd.Adapter{
			adaptd.EnsureHTTPS(false),
			PostAndOtherOnError(postHandler, redirectOnSuccess, redirectOnError),
			a.CSRFGetAdapter(),
		}

		return adaptAndAbsorbError(h, append(adapters, extraAdapters...)...)
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
