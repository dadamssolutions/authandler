package seshandler

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TODO: Make session a cookie and get rid of some of the parsing.

// Session type represents an HTTP session.
type Session struct {
	cookie    *http.Cookie
	id        string
	sessionID string
	username  string
	destroyed bool

	lock *sync.RWMutex
}

// NewSession creates a new session with the given information
func newSession(id, sessionID, username string, maxLifetime time.Duration) *Session {
	s := &Session{id: id, sessionID: sessionID, username: username, lock: &sync.RWMutex{}}
	c := &http.Cookie{Name: sessionCookieName, Value: s.cookieValue(), Path: "/", HttpOnly: true, Secure: true}
	s.cookie = c
	if maxLifetime != 0 {
		c.Expires = time.Now().Add(maxLifetime)
		c.MaxAge = int(maxLifetime / time.Second)
	}
	return s
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
func (s *Session) sessionCookie(maxLifetime time.Duration) (*http.Cookie, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if !s.isValid() {
		return nil, invalidSessionCookie()
	}
	return s.cookie, nil
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
	if len(id) < selectorIDLength || len(sessionID) < sessionIDLength {
		return nil, invalidSessionCookie()
	}
	session := &Session{cookie: cookie, id: id, username: username, sessionID: sessionID, lock: &sync.RWMutex{}}
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
	return s.cookie.Expires
}

// IsExpired returns whether the session is expired.
func (s *Session) isExpired() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return !time.Now().Before(s.cookie.Expires) && !s.cookie.Expires.IsZero()
}

func (s *Session) markSessionExpired() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cookie.Expires = time.Now().Add(-1 * time.Second)
}

// UpdateExpireTime updates the time that the session expires
func (s *Session) updateExpireTime(maxLifetime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cookie.Expires = time.Now().Add(maxLifetime)
}

func (s *Session) destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.destroyed = true
}

func (s *Session) isDestroyed() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.destroyed
}

func (s *Session) isValid() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return !s.isDestroyed() && !s.isExpired()
}
