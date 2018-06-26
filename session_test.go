package seshandler

import (
	"log"
	"strings"
	"testing"
	"time"
)

func TestSessionOnlyCookieCreate(t *testing.T) {
	ses := newSession("", "", "", 0)
	cookie := ses.sessionCookie()

	if cookie == nil || cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		log.Fatal("Cookie will not expire after session terminated")
	}
}

func TestExpiredSession(t *testing.T) {
	ses := newSession("", "", "", timeout)
	if ses.isExpired() {
		t.Fatal("Session should not be expired")
	}
	ses.markSessionExpired()
	if !ses.isExpired() {
		t.Fatal("Session should be expired")
	}
}

func TestUpdateSessionExpiredTime(t *testing.T) {
	ses := newSession("", "", "", timeout)
	firstTime := time.Now().Add(timeout)
	time.Sleep(time.Microsecond)
	ses.updateExpireTime(timeout)

	if ses.getExpireTime().Before(firstTime) {
		t.Fatal("Expired time not updated properly")
	}
}

func TestSessionCookie(t *testing.T) {
	ses := newSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), "thedadams", timeout)
	cookie := ses.sessionCookie()
	// Should have a valid cookie
	if cookie == nil || cookie.Name != sessionCookieName || cookie.Value != ses.cookieValue() || !ses.getExpireTime().Equal(cookie.Expires) || cookie.MaxAge != int(timeout.Seconds()) {
		log.Fatal("Session cookie not created properly")
	}

	ses.destroy()
	cookie = ses.sessionCookie()
	if cookie != nil {
		log.Fatal("Cookie created for a destroyed session.")
	}

	ses.destroyed = false
	ses.cookie.Expires = time.Now()
	time.Sleep(time.Microsecond)
	cookie = ses.sessionCookie()
	if cookie != nil {
		log.Fatal("Cookie created for an expired session")
	}
}
