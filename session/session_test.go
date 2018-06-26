package session

import (
	"log"
	"strings"
	"testing"
	"time"
)

var timeout = time.Minute
var sessionCookieName = "sessionID"
var selectorIDLength = 16
var sessionIDLength = 64

func TestSessionOnlyCookieCreate(t *testing.T) {
	ses := NewSession("", "", "", sessionCookieName, 0)
	cookie := ses.SessionCookie()

	if cookie == nil || cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		log.Fatal("Cookie will not expire after session terminated")
	}
}

func TestExpiredSession(t *testing.T) {
	ses := NewSession("", "", "", sessionCookieName, timeout)
	if ses.IsExpired() {
		t.Fatal("Session should not be expired")
	}
	ses.MarkSessionExpired()
	if !ses.IsExpired() {
		t.Fatal("Session should be expired")
	}
}

func TestUpdateSessionExpiredTime(t *testing.T) {
	ses := NewSession("", "", "", sessionCookieName, timeout)
	firstTime := time.Now().Add(timeout)
	time.Sleep(time.Microsecond)
	ses.UpdateExpireTime(timeout)

	if ses.ExpireTime().Before(firstTime) {
		t.Fatal("Expired time not updated properly")
	}
}

func TestSessionCookie(t *testing.T) {
	ses := NewSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), "thedadams", sessionCookieName, timeout)
	cookie := ses.SessionCookie()
	// Should have a valid cookie
	if cookie == nil || cookie.Name != sessionCookieName || cookie.Value != ses.CookieValue() || !ses.ExpireTime().Equal(cookie.Expires) || cookie.MaxAge != int(timeout.Seconds()) {
		log.Fatal("Session cookie not created properly")
	}

	ses.Destroy()
	cookie = ses.SessionCookie()
	if cookie != nil {
		log.Fatal("Cookie created for a destroyed session.")
	}

	ses.destroyed = false
	ses.cookie.Expires = time.Now()
	time.Sleep(time.Microsecond)
	cookie = ses.SessionCookie()
	if cookie != nil {
		log.Fatal("Cookie created for an expired session")
	}
}
