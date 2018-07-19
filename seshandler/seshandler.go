/*
Package seshandler uses a database backend to manage session cookies for a server. A seshandler can manage persistant and session only cookies simultaneously.

Once a database connection is established, one can create a seshandler with something like:
	sh, err := seshandler.NewSesHandlerWithDB(db, time.Minute * 20, time.Day)

One can create a new (persistant) session with:
	session, err := sh.CreateSession("username", true)

The session structs themselves should not be acted upon independently. Instead the sessions should be passed to the handler:
	err = sh.DestroySession(session)
This will "destroy" the session struct itself and in the database. Once the struct is destroyed, it can be passed to the handler which will detected its destroyed-ness. For security reasons, a destroyed session cannot be un-destoyed.

A selectorID and a sessionID is generated for each session. The selectorID and a hash of the sessionID is stored in the database. The selectorID and sessionID are sent with the response. This is an idea take from https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence#title.2

This package is best used with an authentication handler.
*/
package seshandler

import (
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dadamssolutions/authandler/seshandler/session"
)

// These are made constants because the database should be cleared and updated if they change.
const (
	SessionCookieName = "sessionID"
	selectorIDLength  = 16
	sessionIDLength   = 64
)

// SesHandler creates and maintains session in a database.
type SesHandler struct {
	dataAccess  sesDataAccess
	maxLifetime time.Duration
}

// NewSesHandlerWithDB creates a new session handler.
// The database connection should be a pointer to the database connection
// used in the rest of the app for concurrency purposes.
// If either timeout <= 0, then it is set to 0 (session only cookies).
func NewSesHandlerWithDB(db *sql.DB, tableName string, sessionTimeout time.Duration, persistantSessionTimeout time.Duration) (*SesHandler, error) {
	da, err := newDataAccess(db, tableName, sessionTimeout, persistantSessionTimeout)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return newSesHandler(da, persistantSessionTimeout), nil
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
		// An error here likely means a problem with the database
		log.Println(err)
	}
	return ses, err
}

// DestroySession gets rid of a session, if it exists in the database.
// If destroy is successful, the session pointer is set to nil.
func (sh *SesHandler) DestroySession(ses *session.Session) error {
	err := sh.dataAccess.destroySession(ses)
	if err != nil {
		// An error here likely means a problem with the database
		log.Println(err)
	}
	return err
}

// isValidSession determines if the given session is valid.
func (sh *SesHandler) isValidSession(ses *session.Session) bool {
	// First we check that the inputs have not been tampered with
	if ses != nil && sh.validateUserInputs(ses) {
		// The we check the session against the session in the database
		if err := sh.dataAccess.validateSession(ses, sh.maxLifetime); err != nil {
			log.Println(err)
		} else {
			return true
		}
	}
	return false
}

// UpdateSessionIfValid resets the expiration of the session from time.Now.
// Should also be used to verify that a session is valid.
// If the session is invalid, then a non-nil error will be returned.
func (sh *SesHandler) UpdateSessionIfValid(ses *session.Session) (*session.Session, error) {
	if ok := sh.isValidSession(ses); !ok {
		log.Println("We were provided an invalid session so we can't update it")
		return nil, invalidSessionError(sh.dataAccess.tableName)
	}
	// If the session is persistant, then we reset the expiration from time.Now
	if ses.IsPersistant() {
		err := sh.dataAccess.updateSession(ses, sh.maxLifetime)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	} else {
		// If the session is not persistant, then it should be destroyed
		// and another one created in its place.
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
	cookie, err := r.Cookie(SessionCookieName)
	// No session cookie available
	if err != nil {
		log.Println(err)
		return nil, noSessionCookieFoundInRequest(sh.dataAccess.tableName)
	}
	session, err := sh.ParseSessionCookie(cookie)
	if err != nil {
		log.Println(err)
	}
	return session, err
}

// ParseSessionCookie takes a cookie, determines if it is a valid session cookie,
// and returns the session, if it exists.
func (sh *SesHandler) ParseSessionCookie(cookie *http.Cookie) (*session.Session, error) {
	// Break the cookie into its parts.
	unescapedCookie, err := url.QueryUnescape(cookie.Value)
	cookieStrings := strings.Split(unescapedCookie, "|")
	if err != nil || cookie.Name != SessionCookieName || len(cookieStrings) != 3 {
		log.Printf("Not a valid %v cookie\n", sh.dataAccess.tableName)
		return nil, invalidSessionCookie(sh.dataAccess.tableName)
	}

	selectorID, username, sessionID := cookieStrings[0], cookieStrings[1], cookieStrings[2]
	// Get the info on the session from the database
	dbSession, err := sh.dataAccess.getSessionInfo(selectorID, sessionID, sh.maxLifetime)
	if err != nil {
		log.Printf("Database returned an error for selector ID %v\n", selectorID)
		return nil, invalidSessionCookie(sh.dataAccess.tableName)
	}
	// Make sure the session is valid before returning it
	if !sh.isValidSession(dbSession) || dbSession.Username() != username {
		sh.DestroySession(dbSession)
		return nil, invalidSessionCookie(sh.dataAccess.tableName)
	}
	return dbSession, nil
}

// AttachCookie sets a cookie on a ResponseWriter
// A session is returned because the session may have changed when it is updated
func (sh *SesHandler) AttachCookie(w http.ResponseWriter, ses *session.Session) (*session.Session, error) {
	// Need to save the selector incase the call to UpdateSessionIfValid returns an error
	var err error
	var selectorID string
	if ses != nil {
		selectorID = ses.SelectorID()
	}
	ses, err = sh.UpdateSessionIfValid(ses)
	if err != nil {
		log.Printf("Invalid %v with ID %v: no cookie returned", sh.dataAccess.tableName, selectorID)
		return ses, invalidSessionError(sh.dataAccess.tableName)
	}
	// Attach the cookie to the response writer
	http.SetCookie(w, ses.SessionCookie())
	return ses, nil
}

func (sh *SesHandler) validateUserInputs(ses *session.Session) bool {
	// Escaping these should not change them.
	// If it does, then we know the session has been altered.
	s1 := url.QueryEscape(ses.SelectorID())
	s2 := url.QueryEscape(ses.Username())
	s3 := url.QueryEscape(ses.SessionID())
	if s1 != ses.SelectorID() || s2 != ses.Username() || s3 != ses.SessionID() {
		log.Printf("The %v has invalid pieces. The user must have altered them: ", sh.dataAccess.tableName)
		log.Println(ses.SelectorID())
		return false
	}
	return true
}
