package seshandler

import (
	"log"
	"strings"
	"testing"
	"time"
)

func TestExpiredSession(t *testing.T) {
	ses := newSession("", "", "", timeout)
	if ses.isExpired() {
		t.Fatal("Session should not be expired")
	}
	ses.updateExpireTime(0) // Set expire time to now
	time.Sleep(time.Microsecond)
	if !ses.isExpired() {
		t.Fatal("Session should be expired")
	}
}

func TestUpdateSessionExpiredTime(t *testing.T) {
	ses := newSession("", "", "", timeout)
	firstTime := time.Now().Add(timeout)
	time.Sleep(time.Microsecond * 2)
	ses.updateExpireTime(timeout)

	if ses.getExpireTime().Before(firstTime) {
		t.Fatal("Expired time not updated properly")
	}
}

func TestSessionCookie(t *testing.T) {
	ses := newSession(strings.Repeat("d", 64), "127.0.0.1", "thedadams", timeout)
	cookie := ses.sessionCookie(timeout)

	if strings.Compare(cookie.Name, sessionCookieName) != 0 || strings.Compare(cookie.Value, ses.string()) != 0 || !ses.getExpireTime().Equal(cookie.Expires) || cookie.MaxAge != int(timeout) {
		log.Fatal("Session cookie not created properly")
	}
}

func TestSessionParsing(t *testing.T) {
	ses := newSession(strings.Repeat("d", 64), "127.0.0.1", "thedadams", timeout)
	sesTest, err := parseSessionFromCookie(ses.sessionCookie(timeout))

	if err != nil || strings.Compare(ses.id, sesTest.id) != 0 || strings.Compare(ses.ip, sesTest.ip) != 0 || strings.Compare(ses.username, sesTest.username) != 0 {
		t.Fatal("Session cookie not parsed properly")
	}
}
