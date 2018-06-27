package httpauth

import (
	"database/sql"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// HTTPAuth is a general handler that authenticates a user for http requests.
type HTTPAuth struct {
	db                       *sql.DB
	GenerateHashFromPassword func([]byte) ([]byte, error)
	CompareHashAndPassword   func([]byte, []byte) error
}

// NewHTTPAuth takes database information and hash generation and comparative functions
// and returns a HTTPAuth handler with those specifications.
func NewHTTPAuth(dbURL, driverName string, g func([]byte) ([]byte, error), c func([]byte, []byte) error) (*HTTPAuth, error) {
	db, err := sql.Open(driverName, dbURL)
	if err != nil {
		// Database connections failed.
		return nil, DatabaseConnectionFailedError{err}
	}

	return &HTTPAuth{db: db, GenerateHashFromPassword: g, CompareHashAndPassword: c}, nil
}

// DefaultHTTPAuth uses the standard bcyrpt functions for
// generating and comparing password hashes.
// cost parameter is the desired cost for bycrypt generated hashes.
func DefaultHTTPAuth(dbURL, driverName string, cost int) (*HTTPAuth, error) {
	g := func(pass []byte) ([]byte, error) {
		return bcrypt.GenerateFromPassword(pass, cost)
	}
	return NewHTTPAuth(dbURL, driverName, g, bcrypt.CompareHashAndPassword)
}

// HandleFunc is like http.HandleFunc expect it is verified that the user has been
// authenticated and has permission to view this page.
func (a *HTTPAuth) HandleFunc(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	// TODO: Lookup the proper way to do this.
	// If the user is logged in, then display the page.
	// If the user is not logged in, send them to the log in page.
	return func(w http.ResponseWriter, r *http.Request) {
		if a.userIsAuthenticated() {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			handler(w, r)
		}
	}
}

func (a *HTTPAuth) userIsAuthenticated() bool {
	// TODO: If user is authenticated, return true. Else, return false.
	return false
}
