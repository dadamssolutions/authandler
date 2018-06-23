package seshandler

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Session type represents an HTTP session.
type Session struct {
	id         string
	sessionID  string
	username   string
	expireTime time.Time

	lock *sync.RWMutex
}

// NewSession creates a new session with the given information
func newSession(id, sessionID, username string, maxLifetime time.Duration) *Session {
	return &Session{id: id, sessionID: sessionID, username: username, expireTime: time.Now().Add(maxLifetime), lock: &sync.RWMutex{}}
}

// ParseSession parses string that would come from a cookie into a Session struct.
func parseSession(r *http.Request, maxLifetime time.Duration) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	// No session cookie available
	if err != nil {
		return nil, err
	}
	return parseSessionFromCookie(cookie)
}

// SessionCookie builds a cookie from the Session struct
func (s *Session) sessionCookie(maxLifetime time.Duration) *http.Cookie {
	s.lock.RLock()
	defer s.lock.RUnlock()
	cookie := http.Cookie{Name: sessionCookieName, Value: s.cookieValue(), Path: "/", HttpOnly: true, Secure: true, Expires: s.expireTime, MaxAge: int(maxLifetime)}
	return &cookie
}

func parseSessionFromCookie(cookie *http.Cookie) (*Session, error) {
	unescapedCookie, err := url.QueryUnescape(cookie.Value)
	cookieStrings := strings.Split(unescapedCookie, "|")
	if err != nil || strings.Compare(cookie.Name, sessionCookieName) != 0 || cookie.Expires.IsZero() || len(cookieStrings) != 3 {
		return nil, invalidSessionCookie()
	}
	id, username, sessionID := cookieStrings[0], cookieStrings[1], cookieStrings[2]
	if cookie.Expires.Before(time.Now()) {
		return nil, sessionExpiredError(id)
	}
	session := &Session{id: id, username: username, sessionID: sessionID, expireTime: cookie.Expires, lock: &sync.RWMutex{}}
	if len(id) < selectorIDLength || len(sessionID) < sessionIDLength {
		return nil, invalidSessionCookie()
	}
	return session, nil
}

func (s *Session) cookieValue() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return url.QueryEscape(s.id + "|" + s.username + "|" + s.sessionID)
}

func (s *Session) hashPayload() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.username + s.id
}

// GetID returns the session's ID
func (s *Session) getID() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.id
}

// GetUsername returns the username of the account to which the session is associated.
func (s *Session) getUsername() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.username
}

// GetExpireTime returns the time that the session will expire.
func (s *Session) getExpireTime() time.Time {
	return s.expireTime
}

// IsExpired returns whether the session is expired.
func (s *Session) isExpired() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return !time.Now().Before(s.expireTime)
}

// UpdateExpireTime updates the time that the session expires
func (s *Session) updateExpireTime(maxLifetime time.Duration) time.Time {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.expireTime = time.Now().Add(maxLifetime)
	return s.expireTime
}
