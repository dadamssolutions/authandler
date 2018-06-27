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
	"time"

	"github.com/dadamssolutions/authandler/seshandler/session"
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
func (sh *SesHandler) CreateSession(username string, persistant bool) (*session.Session, error) {
	ses, err := sh.dataAccess.createSession(username, sh.maxLifetime, persistant)
	if err != nil {
		log.Println(err)
	}
	return ses, err
}

// DestroySession gets rid of a session, if it exists in the database.
// If destroy is successful, the session pointer is set to nil.
func (sh *SesHandler) DestroySession(ses *session.Session) error {
	err := sh.dataAccess.destroySession(ses)
	if err != nil {
		log.Println(err)
	}
	return err
}

// isValidSession determines if the given session is valid.
func (sh *SesHandler) isValidSession(ses *session.Session) bool {
	validInputs := sh.validateUserInputs(ses)
	if validInputs {
		if err := sh.dataAccess.validateSession(ses, sh.maxLifetime); err == nil {
			return true
		}
	}
	return false
}

// UpdateSessionIfValid sets the expiration of the session to time.Now.
// Should also be used to verify that a session is valid.
// If the session is invalid, then an error will be returned.
func (sh *SesHandler) UpdateSessionIfValid(ses *session.Session) (*session.Session, error) {
	if ok := sh.isValidSession(ses); !ok {
		log.Println("Session with selector ID " + ses.SelectorID() + " is not a valid session, so we can't update it")
		return nil, invalidSessionError(ses.SelectorID())
	}
	if ses.IsPersistant() {
		err := sh.dataAccess.updateSession(ses, sh.maxLifetime)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	} else {
		err := sh.DestroySession(ses)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		newerSession, err := sh.CreateSession(ses.Username(), false)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		ses = newerSession
	}
	return ses, nil
}

// ParseSessionFromRequest takes a request, determines if there is a valid session cookie,
// and returns the session, if it exists.
func (sh *SesHandler) ParseSessionFromRequest(r *http.Request) (*session.Session, error) {
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
func (sh *SesHandler) ParseSessionCookie(cookie *http.Cookie) (*session.Session, error) {
	var ses *session.Session
	unescapedCookie, err := url.QueryUnescape(cookie.Value)
	cookieStrings := strings.Split(unescapedCookie, "|")
	if err != nil || cookie.Name != sessionCookieName || len(cookieStrings) != 3 {
		log.Println("Cookie string does not have the required parts")
		return nil, invalidSessionCookie()
	}

	selectorID, username, sessionID := cookieStrings[0], cookieStrings[1], cookieStrings[2]
	// Get the info on the session from the database
	dbSession, err := sh.dataAccess.getSessionInfo(selectorID, sessionID, sh.maxLifetime)
	if err != nil {
		return nil, invalidSessionCookie()
	}
	// The only thing we really need from this right now is whether the session is persistant.
	if dbSession.IsPersistant() {
		ses = session.NewSession(selectorID, sessionID, username, sessionCookieName, sh.maxLifetime)
	} else {
		ses = session.NewSession(selectorID, sessionID, username, sessionCookieName, 0)
	}
	if !sh.isValidSession(ses) {
		return nil, invalidSessionCookie()
	}
	return ses, nil
}

// AttachCookie returns a cookie to attach to a ResponseRequest
func (sh *SesHandler) AttachCookie(w http.ResponseWriter, ses *session.Session) error {
	// Need this incase the call to UpdateSessionIfValid returns an error
	selectorID := ses.SelectorID()
	ses, err := sh.UpdateSessionIfValid(ses)
	if err != nil {
		log.Println("Invalid session: no cookie returned")
		return invalidSessionError(selectorID)
	}
	http.SetCookie(w, ses.SessionCookie())
	return nil
}

func (sh *SesHandler) validateUserInputs(ses *session.Session) bool {
	s1 := url.QueryEscape(ses.SelectorID())
	s2 := url.QueryEscape(ses.Username())
	s3 := url.QueryEscape(ses.SessionID())
	if s1 != ses.SelectorID() || s2 != ses.Username() || s3 != ses.SessionID() {
		log.Println("The session has invalid pieces. The user must have altered them:")
		log.Println(ses.SelectorID())
		return false
	}
	return true
}
