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
type HTTPAuth struct {
	db                       *sql.DB
	sesHandler               *seshandler.SesHandler
	UsersTableName           string
	LoginURL                 string
	LogoutURL                string
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
	ses, err := seshandler.NewSesHandlerWithDB(db, sessionTimeout, persistantSessionTimeout)
	if err != nil {
		// Session handler could not be created, likely a database problem.
		return nil, errors.New("Session handler could not be created")
	}
	err = createUsersTable(db, tableName)
	if err != nil {
		return nil, errors.New("Users database table could not be created")
	}
	return &HTTPAuth{db: db, sesHandler: ses, UsersTableName: tableName, GenerateHashFromPassword: g, CompareHashAndPassword: c, LoginURL: "/login", LogoutURL: "/logout"}, nil
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
func (a *HTTPAuth) HandleFuncHTTPSRedirect(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
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
func (a *HTTPAuth) HandleFuncAuth(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
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

// LoginHandler handles the login GET and POST requests
// If it is determined that the login page should be shown, then the handler function is called.
func (a *HTTPAuth) LoginHandler(handler func(http.ResponseWriter, *http.Request, error), redirectOnSuccess string) func(http.ResponseWriter, *http.Request) {
	return a.HandleFuncHTTPSRedirect(func(w http.ResponseWriter, r *http.Request) {
		ses, err := a.userIsAuthenticated(r)
		if err == nil {
			log.Printf("User requesting login page, but is already logged in. Redirecting to %v\n", redirectOnSuccess)
			a.sesHandler.AttachCookie(w, ses)
			http.Redirect(w, r, redirectOnSuccess, http.StatusFound)
			return
		}
		err = nil
		if r.Method == "POST" {
			username, password := url.QueryEscape(r.PostFormValue("username")), url.QueryEscape(r.PostFormValue("password"))
			remember := url.QueryEscape(r.PostFormValue("remember"))
			rememberMe, _ := strconv.ParseBool(remember)
			ses = a.logUserIn(username, password, rememberMe)
			if ses != nil {
				log.Printf("User %v logged in successfully. Redirecting to %v\n", username, redirectOnSuccess)
				a.sesHandler.AttachCookie(w, ses)
				http.Redirect(w, r, redirectOnSuccess, http.StatusAccepted)
				return
			}
			log.Println("User login failed, redirecting back to login page")
			err = errors.New("Login failed")
		}
		log.Printf("User requesting login page\n")
		handler(w, r, err)
	})
}

// LogoutHandler handles the logout GET and POST requests
// If it is determined that the logout page should be shown, then the handler function is called.
func (a *HTTPAuth) LogoutHandler(redirectOnSuccess string) func(http.ResponseWriter, *http.Request) {
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

func (a *HTTPAuth) logUserIn(username, password string, persistant bool) *session.Session {
	hashedPassword, err := a.getUserPasswordHash(username)
	if err == nil && a.CompareHashAndPassword(hashedPassword, []byte(password)) == nil {
		ses, err := a.sesHandler.CreateSession(username, persistant)
		if err == nil {
			return ses
		}
	}
	return nil
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
