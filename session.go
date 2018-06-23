package seshandler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "sessionID"
	sessionIDLength   = 64
	maxLifetime       = time.Hour * 2
)

// Session type represents an HTTP session.
type Session struct {
	id          string
	ip          string
	username    string
	expireTime  time.Time
	maxLifetime time.Duration

	lock *sync.RWMutex
}

func hashString(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hashBytes[:])
}

// NewSession creates a new session with the given information
func NewSession(id, ip, username string) *Session {
	return &Session{id: id, ip: ip, username: username, expireTime: time.Now().Add(maxLifetime), maxLifetime: maxLifetime, lock: &sync.RWMutex{}}
}

// ParseSession parses string that would come from a cookie into a Session struct.
func ParseSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	// No session cookie available
	if err != nil {
		return nil, err
	}
	return parseSessionFromCookie(cookie)
}

// SessionCookie builds a cookie from the Session struct
func (s *Session) SessionCookie() *http.Cookie {
	s.lock.RLock()
	defer s.lock.RUnlock()
	cookie := http.Cookie{Name: sessionCookieName, Value: s.String(), Path: "/", HttpOnly: true, Secure: true, Expires: s.expireTime, MaxAge: int(maxLifetime)}
	return &cookie
}

func parseSessionFromCookie(cookie *http.Cookie) (*Session, error) {
	unescapedCookie, err := url.QueryUnescape(cookie.Value)
	cookieStrings := strings.Split(unescapedCookie, "|")
	if err != nil || strings.Compare(cookie.Name, sessionCookieName) != 0 || cookie.Expires.IsZero() || len(cookieStrings) != 4 {
		return nil, invalidSessionCookie()
	}
	id, username, ip, hash := cookieStrings[0], cookieStrings[1], cookieStrings[2], cookieStrings[3]
	if cookie.Expires.Before(time.Now()) {
		return nil, sessionExpiredError(id)
	}
	session := &Session{id: id, ip: ip, username: username, expireTime: cookie.Expires, maxLifetime: maxLifetime, lock: &sync.RWMutex{}}
	hashCheck := hashString(session.dataPayload())
	if len(id) < sessionIDLength || strings.Compare(hash, hashCheck) != 0 {
		return nil, invalidSessionCookie()
	}
	return session, nil
}

func (s *Session) String() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	hash := hashString(s.dataPayload())
	return url.QueryEscape(s.id + "|" + s.username + "|" + s.ip + "|" + hash)
}

func (s *Session) dataPayload() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.username + s.id + s.ip
}

// GetID returns the session's ID
func (s *Session) GetID() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.id
}

// GetIP returns the IP address associated with the session.
func (s *Session) GetIP() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.ip
}

// GetUsername returns the username of the account to which the session is associated.
func (s *Session) GetUsername() string {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.username
}

// IsExpired returns whether the session is expired.
func (s *Session) IsExpired() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return !time.Now().Before(s.expireTime)
}

// UpdateExpireTime updates the time that the session expires
func (s *Session) updateExpireTime() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.expireTime = time.Now().Add(maxLifetime)
}
