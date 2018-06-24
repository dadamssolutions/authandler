package seshandler

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"log"
	"time"
)

const (
	sessionCookieName = "sessionID"
	selectorIDLength  = 16
	sessionIDLength   = 64
)

func hashString(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hashBytes[:])
}

func generateRandomString(length int) string {
	if length <= 0 {
		log.Panicln("Cannot generate a random string of negative length")
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		log.Panicf("ERROR: %v\n", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

func generateSelectorID() string {
	return generateRandomString(selectorIDLength)
}

func generateSessionID() string {
	return generateRandomString(sessionIDLength)
}

// SesHandler creates and maintains session in a database.
type SesHandler struct {
	dataAccess  dataAccessLayer
	maxLifetime time.Duration
}

// NewSesHandlerWithDB creates a new session handler.
// The database connection should be a pointer to the database connection
// used in the rest of the app for concurrency purposes.
// If timeout < 0, then it is set to 0 (session cookie).
func NewSesHandlerWithDB(db *sql.DB, timeout time.Duration) (*SesHandler, error) {
	return newSesHandler(sesAccess{db}, timeout)
}

func newSesHandler(da dataAccessLayer, timeout time.Duration) (*SesHandler, error) {
	if timeout < 0 {
		timeout = 0
	}
	ses := &SesHandler{dataAccess: da, maxLifetime: timeout}
	return ses, ses.dataAccess.createTable()
}

// CreateSession generates a new session for the given user ID.
func (sh *SesHandler) CreateSession(username string, sessionOnly bool) (*Session, error) {
	return sh.dataAccess.createSession(username, sh.maxLifetime, sessionOnly)
}

// DestroySession gets rid of a session, if it exists in the database.
// If destroy is successful, the session pointer is set to nil.
func (sh *SesHandler) DestroySession(session *Session) error {
	return sh.dataAccess.destroySession(session)
}

// IsValidSession determines if the given session is valid.
func (sh *SesHandler) IsValidSession(session *Session) bool {
	if err := sh.dataAccess.validateSession(session); err != nil {
		return false
	}
	return true
}

// UpdateSession sets the expiration of the session to time.Now.
func (sh *SesHandler) UpdateSession(session *Session) error {
	return sh.dataAccess.updateSession(session, sh.maxLifetime)
}
