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
func NewSesHandlerWithDB(db *sql.DB, timeout time.Duration) (*SesHandler, error) {
	return newSesHandler(sesDataAccess{db}, timeout)
}

func newSesHandler(da sesDataAccess, timeout time.Duration) (*SesHandler, error) {
	if timeout < 0 {
		timeout = 0
	}
	if da.DB == nil {
		log.Println("Cannot connect to the database")
		return nil, badDatabaseConnectionError()
	}
	ses := &SesHandler{dataAccess: da, maxLifetime: timeout}
	err := ses.dataAccess.createTable()
	if err != nil {
		log.Println(err)
	}
	return ses, err
}

// CreateSession generates a new session for the given user ID.
func (sh *SesHandler) CreateSession(username string, sessionOnly bool) (*Session, error) {
	session, err := sh.dataAccess.createSession(username, sh.maxLifetime, sessionOnly)
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

// IsValidSession determines if the given session is valid.
func (sh *SesHandler) IsValidSession(session *Session) bool {
	if !sh.validateUserInputs(session) {
		return false
	}
	if err := sh.dataAccess.validateSession(session); err != nil {
		log.Println(err)
		return false
	}
	return true
}

// UpdateSession sets the expiration of the session to time.Now.
func (sh *SesHandler) UpdateSession(session *Session) error {
	if ok := sh.IsValidSession(session); !ok {
		log.Println("Session with ID " + session.getID() + " is not a valid session, so we can't update it")
		return invalidSessionError(session.getID())
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
	if err != nil || strings.Compare(cookie.Name, sessionCookieName) != 0 || len(cookieStrings) != 3 {
		log.Println("Cookie string does not have the required parts")
		return nil, invalidSessionCookie()
	}

	id, username, sessionID := cookieStrings[0], cookieStrings[1], cookieStrings[2]
	session := &Session{cookie: cookie, id: id, username: username, sessionID: sessionID, lock: &sync.RWMutex{}}
	if !sh.IsValidSession(session) {
		return nil, invalidSessionCookie()
	}
	if session.isExpired() {
		log.Println("Parsed session " + session.getID() + ", but it is expired at " + session.cookie.Expires.String())
		return nil, sessionExpiredError(id)
	}
	return session, nil
}

func (sh *SesHandler) validateUserInputs(session *Session) bool {
	s1 := url.QueryEscape(session.getID())
	s2 := url.QueryEscape(session.getUsername())
	s3 := url.QueryEscape(session.sessionID)
	if strings.Compare(s1, session.getID()) != 0 || strings.Compare(s2, session.getUsername()) != 0 || strings.Compare(s3, session.sessionID) != 0 {
		log.Println("The session has invalid pieces. The user must have altered them:")
		log.Println(session.getID())
		log.Println(session.getUsername())
		log.Println(session.sessionID)
		return false
	}
	return true
}
