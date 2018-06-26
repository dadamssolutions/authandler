package session

import (
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Session type represents an HTTP session.
type Session struct {
	cookie     *http.Cookie
	selectorID string
	sessionID  string
	username   string
	persistant bool
	destroyed  bool

	lock *sync.RWMutex
}

// NewSession creates a new session with the given information
func NewSession(selectorID, sessionID, username, sessionCookieName string, maxLifetime time.Duration) *Session {
	s := &Session{selectorID: selectorID, sessionID: sessionID, username: username, lock: &sync.RWMutex{}}
	c := &http.Cookie{Name: sessionCookieName, Value: s.CookieValue(), Path: "/", HttpOnly: true, Secure: true, MaxAge: int(maxLifetime.Seconds())}
	s.cookie = c
	if maxLifetime != 0 {
		c.Expires = time.Now().Add(maxLifetime)
		s.persistant = true
	}
	return s
}

// SessionCookie builds a cookie from the Session struct
func (s *Session) SessionCookie() *http.Cookie {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if !s.IsValid() {
		return nil
	}
	return s.cookie
}

// CookieValue returns the value of the cookie sent with the response
func (s *Session) CookieValue() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return url.QueryEscape(s.selectorID + "|" + s.username + "|" + s.sessionID)
}

// HashPayload returns the string related to the session to be hashed.
func (s *Session) HashPayload() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.username + s.selectorID
}

// SelectorID returns the session's selector ID
func (s *Session) SelectorID() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.selectorID
}

// SessionID returns the session's session ID
func (s *Session) SessionID() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.sessionID
}

// Username returns the username of the account to which the session is associated.
func (s *Session) Username() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.username
}

// ExpireTime returns the time that the session will expire.
func (s *Session) ExpireTime() time.Time {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.cookie.Expires
}

// IsExpired returns whether the session is expired.
func (s *Session) IsExpired() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.IsPersistant() && s.cookie.Expires.Before(time.Now())
}

// IsPersistant returns whether the session is a persistant one.
func (s *Session) IsPersistant() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.persistant
}

// MarkSessionExpired marks the session expired.
func (s *Session) MarkSessionExpired() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cookie.Expires = time.Now().Add(-1 * time.Second)
}

// UpdateExpireTime updates the time that the session expires
func (s *Session) UpdateExpireTime(maxLifetime time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cookie.Expires = time.Now().Add(maxLifetime)
}

// Destroy destroys a session.
func (s *Session) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.destroyed = true
}

// IsDestroyed returns whether the session has been destroyed
func (s *Session) IsDestroyed() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.destroyed
}

// IsValid returns whether the session is valid
// A session is valid if it is neither destroyed nor expired.
func (s *Session) IsValid() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return !s.IsDestroyed() && !s.IsExpired()
}

// Equals returns whether other session is equal to this session
func (s *Session) Equals(other *Session) bool {
	s.lock.RLock()
	other.lock.RLock()
	defer s.lock.RUnlock()
	defer other.lock.RUnlock()
	return s.SelectorID() == other.SelectorID() && s.Username() == other.Username() && s.SessionID() == other.SessionID() && s.IsDestroyed() == other.IsDestroyed()
}
