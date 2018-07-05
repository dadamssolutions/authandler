package httpauth

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dadamssolutions/authandler/seshandler"
	"github.com/dadamssolutions/authandler/seshandler/session"
	_ "github.com/lib/pq" // Database driver
	"golang.org/x/crypto/bcrypt"
)

// HTTPAuth is a general handler that authenticates a user for http requests.
type HTTPAuth struct {
	db                       *sql.DB
	sesHandler               *seshandler.SesHandler
	LoginURL                 string
	LogoutURL                string
	GenerateHashFromPassword func([]byte) ([]byte, error)
	CompareHashAndPassword   func([]byte, []byte) error
}

// NewHTTPAuth takes database information and hash generation and comparative functions
// and returns a HTTPAuth handler with those specifications.
func NewHTTPAuth(driverName, dbURL string, sessionTimeout, persistantSessionTimeout time.Duration, g func([]byte) ([]byte, error), c func([]byte, []byte) error) (*HTTPAuth, error) {
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
	return &HTTPAuth{db: db, sesHandler: ses, GenerateHashFromPassword: g, CompareHashAndPassword: c, LoginURL: "/login", LogoutURL: "/logout"}, nil
}

// DefaultHTTPAuth uses the standard bcyrpt functions for
// generating and comparing password hashes.
// cost parameter is the desired cost for bycrypt generated hashes.
func DefaultHTTPAuth(driverName, dbURL string, sessionTimeout, persistantSessionTimeout time.Duration, cost int) (*HTTPAuth, error) {
	g := func(pass []byte) ([]byte, error) {
		return bcrypt.GenerateFromPassword(pass, cost)
	}
	return NewHTTPAuth(driverName, dbURL, sessionTimeout, persistantSessionTimeout, g, bcrypt.CompareHashAndPassword)
}

// HandleFuncHTTPSRedirect is like http.HandleFunc except it is verified the request was via https protocol.
func (a *HTTPAuth) HandleFuncHTTPSRedirect(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if isHTTPS(r) {
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

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil && r.TLS.HandshakeComplete
}

func (a *HTTPAuth) userIsAuthenticated(r *http.Request) (*session.Session, error) {
	// Check that the user is logged in by looking for a session cookie
	return a.sesHandler.ParseSessionFromRequest(r)
}
