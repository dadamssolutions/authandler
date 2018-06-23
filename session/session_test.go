package session

import (
	"log"
	"strings"
	"testing"
	"time"
)

var timeout = time.Second

func TestExpiredSession(t *testing.T) {
	ses := NewSession("", "", "", timeout)
	if ses.IsExpired() {
		t.Fatal("Session should not be expired")
	}
	ses.expireTime = time.Now()
	time.Sleep(time.Microsecond)
	if !ses.IsExpired() {
		t.Fatal("Session should be expired")
	}
}

func TestUpdateSessionExpiredTime(t *testing.T) {
	ses := NewSession("", "", "", timeout)
	firstTime := time.Now().Add(timeout)
	time.Sleep(time.Microsecond * 2)
	ses.UpdateExpireTime(timeout)

	if ses.expireTime.Before(firstTime) {
		t.Fatal("Expired time not updated properly")
	}
}

func TestSessionCookie(t *testing.T) {
	ses := NewSession(strings.Repeat("d", 64), "127.0.0.1", "thedadams", timeout)
	cookie := ses.SessionCookie(timeout)

	if strings.Compare(cookie.Name, sessionCookieName) != 0 || strings.Compare(cookie.Value, ses.String()) != 0 || !ses.expireTime.Equal(cookie.Expires) || cookie.MaxAge != int(timeout) {
		log.Fatal("Session cookie not created properly")
	}
}

func TestSessionParsing(t *testing.T) {
	ses := NewSession(strings.Repeat("d", 64), "127.0.0.1", "thedadams", timeout)
	sesTest, err := parseSessionFromCookie(ses.SessionCookie(timeout))

	if err != nil || strings.Compare(ses.id, sesTest.id) != 0 || strings.Compare(ses.ip, sesTest.ip) != 0 || strings.Compare(ses.username, sesTest.username) != 0 {
		t.Fatal("Session cookie not parsed properly")
	}
}
