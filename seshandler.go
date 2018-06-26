package seshandler

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "sessionID"
	selectorIDLength  = 16
	sessionIDLength   = 64
)

func hashString(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return url.QueryEscape(base64.RawURLEncoding.EncodeToString(hashBytes[:]))
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
	dataAccess  sesDataAccess
	maxLifetime time.Duration
}

// NewSesHandlerWithDB creates a new session handler.
// The database connection should be a pointer to the database connection
// used in the rest of the app for concurrency purposes.
// If timeout < 0, then it is set to 0 (session cookie).
func NewSesHandlerWithDB(db *sql.DB, sessionTimeout time.Duration, persistantSessionTimeout time.Duration) (*SesHandler, error) {
	da, err := newDataAccess(db, sessionTimeout, persistantSessionTimeout)
	return newSesHandler(da, persistantSessionTimeout), err
}

func newSesHandler(da sesDataAccess, timeout time.Duration) *SesHandler {
	if timeout < 0 {
		timeout = 0
	}
	ses := &SesHandler{dataAccess: da, maxLifetime: timeout}
	return ses
}

// CreateSession generates a new session for the given user ID.
func (sh *SesHandler) CreateSession(username string, persistant bool) (*Session, error) {
	session, err := sh.dataAccess.createSession(username, sh.maxLifetime, persistant)
	if err != nil {
		log.Println(err)
	}
	return session, err
}

// DestroySession gets rid of a session, if it exists in the database.
// If destroy is successful, the session pointer is set to nil.
func (sh *SesHandler) DestroySession(session *Session) error {
	err := sh.dataAccess.destroySession(session)
	if err != nil {
		log.Println(err)
	}
	return err
}

// isValidSession determines if the given session is valid.
func (sh *SesHandler) isValidSession(session *Session) bool {
	if !sh.validateUserInputs(session) {
		return false
	}
	if err := sh.dataAccess.validateSession(session); err != nil {
		log.Println(err)
		return false
	}
	return true
}

// UpdateSessionIfValid sets the expiration of the session to time.Now.
// Should also be used to verify that a session is valid.
// If the session is invalid, then an error will be returned.
func (sh *SesHandler) UpdateSessionIfValid(session *Session) error {
	if ok := sh.isValidSession(session); !ok {
		log.Println("Session with selector ID " + session.getSelectorID() + " is not a valid session, so we can't update it")
		return invalidSessionError(session.getSelectorID())
	}
	err := sh.dataAccess.updateSession(session, sh.maxLifetime)
	if err != nil {
		log.Println(err)
	}
	return err
}

// ParseSessionFromRequest takes a request, determines if there is a valid session cookie,
// and returns the session, if it exists.
func (sh *SesHandler) ParseSessionFromRequest(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	// No session cookie available
	if err != nil {
		log.Println(err)
		return nil, noSessionCookieFoundInRequest()
	}
	session, err := sh.ParseSessionCookie(cookie)
	if err != nil {
		log.Println(err)
	}
	return session, err
}

// ParseSessionCookie takes a cookie, determines if there is a valid session cookie,
// and returns the session, if it exists.
func (sh *SesHandler) ParseSessionCookie(cookie *http.Cookie) (*Session, error) {
	unescapedCookie, err := url.QueryUnescape(cookie.Value)
	cookieStrings := strings.Split(unescapedCookie, "|")
	if err != nil || cookie.Name != sessionCookieName || len(cookieStrings) != 3 {
		log.Println("Cookie string does not have the required parts")
		return nil, invalidSessionCookie()
	}

	selectorID, username, sessionID := cookieStrings[0], cookieStrings[1], cookieStrings[2]
	session := &Session{cookie: cookie, selectorID: selectorID, username: username, sessionID: sessionID, lock: &sync.RWMutex{}}
	if !sh.isValidSession(session) {
		return nil, invalidSessionCookie()
	}
	return session, nil
}

func (sh *SesHandler) validateUserInputs(session *Session) bool {
	s1 := url.QueryEscape(session.getSelectorID())
	s2 := url.QueryEscape(session.getUsername())
	s3 := url.QueryEscape(session.getSessionID())
	if s1 != session.getSelectorID() || s2 != session.getUsername() || s3 != session.getSessionID() {
		log.Println("The session has invalid pieces. The user must have altered them:")
		log.Println(session.getSelectorID())
		log.Println(session.getUsername())
		log.Println(session.getSessionID())
		return false
	}
	return true
}
