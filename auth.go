package httpauth

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

	"github.com/dadamssolutions/authandler/csrfhandler"
	"github.com/dadamssolutions/authandler/seshandler"
	"github.com/dadamssolutions/authandler/seshandler/session"
	_ "github.com/lib/pq" // Database driver
	"golang.org/x/crypto/bcrypt"
)

const (
	createUsersTableSQL = "CREATE TABLE IF NOT EXISTS %v (username varchar, fname varchar, lname varchar, email varchar NOT NULL UNIQUE, valid_code char(64), pass_hash char(80), PRIMARY KEY (username));"
	getUserPasswordHash = "SELECT pass_hash FROM %v WHERE username = '%v';"
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

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil && r.TLS.HandshakeComplete
}

// HTTPAuth is a general handler that authenticates a user for http requests.
// It also handles csrf token generation and validation.
type HTTPAuth struct {
	db                       *sql.DB
	sesHandler               *seshandler.SesHandler
	csrfHandler              *csrfhandler.CSRFHandler
	csrfUsername             string
	UsersTableName           string
	LoginURL                 string
	LogoutURL                string
	RedirectAfterLogin       string
	GenerateHashFromPassword func([]byte) ([]byte, error)
	CompareHashAndPassword   func([]byte, []byte) error
}

// NewHTTPAuth takes database information and hash generation and comparative functions
// and returns a HTTPAuth handler with those specifications.
func NewHTTPAuth(driverName, dbURL, tableName string, sessionTimeout, persistantSessionTimeout time.Duration, g func([]byte) ([]byte, error), c func([]byte, []byte) error) (*HTTPAuth, error) {
	db, err := sql.Open(driverName, dbURL)
	if err != nil {
		// Database connections failed.
		return nil, errors.New("Database connection failed")
	}
	ses, err := seshandler.NewSesHandlerWithDB(db, "sessions", sessionTimeout, persistantSessionTimeout)
	if err != nil {
		// Session handler could not be created, likely a database problem.
		return nil, errors.New("Session handler could not be created")
	}
	csrf := csrfhandler.NewCSRFHandler(db, sessionTimeout)
	if csrf == nil {
		// CSRF handler could not be created, likely a database problem.
		return nil, errors.New("CSRF handler could not be created")
	}
	err = createUsersTable(db, tableName)
	if err != nil {
		return nil, errors.New("Users database table could not be created")
	}
	return &HTTPAuth{db: db, sesHandler: ses, csrfHandler: csrf, UsersTableName: tableName, GenerateHashFromPassword: g, CompareHashAndPassword: c, LoginURL: "/login", LogoutURL: "/logout", RedirectAfterLogin: "/user", csrfUsername: "csrf"}, nil
}

// DefaultHTTPAuth uses the standard bcyrpt functions for
// generating and comparing password hashes.
// cost parameter is the desired cost for bycrypt generated hashes.
func DefaultHTTPAuth(driverName, dbURL string, sessionTimeout, persistantSessionTimeout time.Duration, cost int) (*HTTPAuth, error) {
	g := func(pass []byte) ([]byte, error) {
		return bcrypt.GenerateFromPassword(pass, cost)
	}
	return NewHTTPAuth(driverName, dbURL, "users", sessionTimeout, persistantSessionTimeout, g, bcrypt.CompareHashAndPassword)
}

// HandleFuncHTTPSRedirect is like http.HandleFunc except it is verified the request was via https protocol.
func (a *HTTPAuth) HandleFuncHTTPSRedirect(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isHTTPS(r) {
			httpsURL := "https://" + r.Host + r.RequestURI
			log.Printf("Non-HTTPS request redirected to %v\n", httpsURL)
			http.Redirect(w, r, httpsURL, http.StatusTemporaryRedirect)
		} else {
			handler(w, r)
		}
	}
}

// HandleFuncAuth is like http.HandleFunc except it is verified the user is logged in.
func (a *HTTPAuth) HandleFuncAuth(handler http.HandlerFunc) http.HandlerFunc {
	return a.HandleFuncHTTPSRedirect(func(w http.ResponseWriter, r *http.Request) {
		ses, err := a.userIsAuthenticated(r)
		if err != nil {
			log.Printf("User requesting %v but is not logged in. Redirecting to login page\n", r.URL)
			http.Redirect(w, r, a.LoginURL, http.StatusFound)
		} else {
			log.Printf("User %v is logged in, handling request %v", ses.Username(), r.URL)
			a.sesHandler.AttachCookie(w, ses)
			handler(w, r)
		}
	})
}

// HandleFuncCSRF handles both GET and POST requests.
// If the request is GET, then we generate a CSRF token to be included
// If the request is POST, then we validate the CSRF token before continuing
func (a *HTTPAuth) HandleFuncCSRF(getHandler CSRFHandler, postHandler http.HandlerFunc) http.HandlerFunc {
	return a.HandleFuncHTTPSRedirect(func(w http.ResponseWriter, r *http.Request) {
		var err error
		if r.Method == "POST" {
			if a.csrfHandler.ValidToken(r.PostFormValue("csrf")) {
				postHandler(w, r)
				return
			}
			err = errors.New("Invalid CSRF token")
		}
		token := a.csrfHandler.GenerateNewToken()
		if token == "" {
			err = errors.New("Error generating a new CSRF token")
		}
		getHandler(w, r, token, err)
	})
}

// HandleFuncCSRFWithAuth is a simple helper that combines the functionality of Auth
// and CSRF checks, in that order
func (a *HTTPAuth) HandleFuncCSRFWithAuth(getHandler CSRFHandler, postHandler http.HandlerFunc) http.HandlerFunc {
	return a.HandleFuncAuth(a.HandleFuncCSRF(getHandler, postHandler))
}

// LoginHandler handles the login GET and POST requests
// If it is determined that the login page should be shown, then the handler function is called.
// The string parameter of the handler represents the csrf token that should be used with the login request.
// The error parament of the handler represents any errors that occurred when logging the user in.
func (a *HTTPAuth) LoginHandler(handler CSRFHandler) http.HandlerFunc {
	h := func(w http.ResponseWriter, r *http.Request, token string, err error) {
		ses, e := a.userIsAuthenticated(r)
		if e == nil {
			log.Printf("User requesting login page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
			a.sesHandler.AttachCookie(w, ses)
			http.Redirect(w, r, a.RedirectAfterLogin, http.StatusFound)
			return
		}
		handler(w, r, token, err)
	}
	return a.HandleFuncCSRF(h, a.logUserIn)
}

// LogoutHandler handles the logout GET and POST requests
// If it is determined that the logout page should be shown, then the handler function is called.
func (a *HTTPAuth) LogoutHandler(redirectOnSuccess string) http.HandlerFunc {
	return a.HandleFuncHTTPSRedirect(func(w http.ResponseWriter, r *http.Request) {
		ses, err := a.userIsAuthenticated(r)
		if err != nil {
			log.Printf("User requesting logout page, but is already logged out. Redirecting to %v\n", redirectOnSuccess)
		} else {
			err = a.sesHandler.DestroySession(ses)
			if err != nil {
				log.Printf("Error logging a user out: %v\n", err)
			}
			log.Printf("User %v logged out, redirecting to %v\n", ses.Username(), redirectOnSuccess)
		}
		http.Redirect(w, r, redirectOnSuccess, http.StatusFound)
	})
}

// CurrentUser returns the username of the current user
func (a *HTTPAuth) CurrentUser(r *http.Request) string {
	ses, err := a.sesHandler.ParseSessionFromRequest(r)
	if err != nil || ses == nil {
		return ""
	}
	return ses.Username()
}

// IsCurrentUser returns true if the username corresponds to the user logged in with a cookie in the request.
func (a *HTTPAuth) IsCurrentUser(r *http.Request, username string) bool {
	return username != "" && a.CurrentUser(r) == username
}

func (a *HTTPAuth) logUserIn(w http.ResponseWriter, r *http.Request) {
	var ses *session.Session
	// If the user is authenticated already, then we just redirect
	ses, err := a.userIsAuthenticated(r)
	if err == nil {
		log.Printf("User requesting login page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
		a.sesHandler.AttachCookie(w, ses)
		http.Redirect(w, r, a.RedirectAfterLogin, http.StatusFound)
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
		http.Redirect(w, r, a.RedirectAfterLogin, http.StatusAccepted)
		return
	}
	log.Println("User login failed, redirecting back to login page")
	err = errors.New("Login failed")
	http.Redirect(w, r, a.LoginURL, http.StatusUnauthorized)
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

func (a *HTTPAuth) userIsAuthenticated(r *http.Request) (*session.Session, error) {
	// Check that the user is logged in by looking for a session cookie
	return a.sesHandler.ParseSessionFromRequest(r)
}
