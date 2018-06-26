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
	c := &http.Cookie{Name: sessionCookieName, Value: s.cookieValue(), Path: "/", HttpOnly: true, Secure: true, MaxAge: int(maxLifetime.Seconds())}
	s.cookie = c
	if maxLifetime != 0 {
		c.Expires = time.Now().Add(maxLifetime)
		c.MaxAge = int(maxLifetime.Seconds())
	}
	return s
}

// SessionCookie builds a cookie from the Session struct
func (s *Session) sessionCookie() (*http.Cookie, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if !s.isValid() {
		return nil, invalidSessionCookie()
	}
	return s.cookie, nil
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
	return s.cookie.Expires.Before(time.Now()) && !s.isSessionOnly()
}

func (s *Session) isSessionOnly() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.cookie.Expires.IsZero()
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

// Equals returns whether other session is equal to this session
func (s *Session) Equals(other *Session) bool {
	s.lock.RLock()
	other.lock.RLock()
	defer s.lock.RUnlock()
	defer other.lock.RUnlock()
	return strings.Compare(s.getID(), other.getID()) == 0 && strings.Compare(s.getUsername(), other.getUsername()) == 0 && strings.Compare(s.sessionID, other.sessionID) == 0 && s.destroyed == other.destroyed
}
