package seshandler

import (
	"log"
	"strings"
	"testing"
	"time"
)

func TestExpiredSession(t *testing.T) {
	ses := NewSession("", "", "")
	if ses.IsExpired() {
		t.Fatal("Session should not be expired")
	}
	ses.expireTime = time.Now()
	time.Sleep(time.Microsecond)
	if !ses.IsExpired() {
		t.Fatal("Session should be expired")
	}
}

func TestUpdateExpiredTime(t *testing.T) {
	ses := NewSession("", "", "")
	firstTime := ses.expireTime.Add(time.Duration(0))
	time.Sleep(time.Microsecond * 2)
	ses.updateExpireTime()

	if ses.expireTime.Equal(firstTime) {
		t.Fatal("Expired time not updated properly")
	}
}

func TestSessionCookie(t *testing.T) {
	ses := NewSession(strings.Repeat("d", 64), "127.0.0.1", "thedadams")
	cookie := ses.SessionCookie()

	if strings.Compare(cookie.Name, sessionCookieName) != 0 || strings.Compare(cookie.Value, ses.String()) != 0 || !ses.expireTime.Equal(cookie.Expires) || cookie.MaxAge != int(maxLifetime) {
		log.Fatal("Session cookie not created properly")
	}
}

func TestSessionParsing(t *testing.T) {
	ses := NewSession(strings.Repeat("d", 64), "127.0.0.1", "thedadams")
	sesTest, err := parseSessionFromCookie(ses.SessionCookie())

	if err != nil || strings.Compare(ses.id, sesTest.id) != 0 || strings.Compare(ses.ip, sesTest.ip) != 0 || strings.Compare(ses.username, sesTest.username) != 0 {
		t.Fatal("Session cookie not parsed properly")
	}
}
