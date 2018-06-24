package seshandler

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSessionOnlyCookieCreate(t *testing.T) {
	ses := newSession("", "", "", 0)
	cookie, err := ses.sessionCookie()

	if err != nil || cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		fmt.Println(err)
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
	cookie, err := ses.sessionCookie()
	// Should have a valid cookie
	if err != nil || strings.Compare(cookie.Name, sessionCookieName) != 0 || strings.Compare(cookie.Value, ses.cookieValue()) != 0 || !ses.getExpireTime().Equal(cookie.Expires) || cookie.MaxAge != int(timeout/time.Second) {
		log.Fatal("Session cookie not created properly")
	}

	ses.destroy()
	cookie, err = ses.sessionCookie()
	if err == nil || cookie != nil {
		log.Fatal("Cookie created for a destroyed session.")
	}

	ses.destroyed = false
	ses.cookie.Expires = time.Now()
	time.Sleep(time.Microsecond)
	cookie, err = ses.sessionCookie()
	if err == nil || cookie != nil {
		log.Fatal("Cookie created for an expired session")
	}
}

func TestSessionParsing(t *testing.T) {
	ses := newSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), "thedadams", timeout)
	cookie, _ := ses.sessionCookie()
	sesTest, err := parseSessionFromCookie(cookie)

	if err != nil || strings.Compare(ses.id, sesTest.id) != 0 || strings.Compare(ses.sessionID, sesTest.sessionID) != 0 || strings.Compare(ses.username, sesTest.username) != 0 {
		t.Fatal("Session cookie not parsed properly")
	}
}

func TestParseSessionFromRequest(t *testing.T) {
	ses := newSession(strings.Repeat("l", selectorIDLength), strings.Repeat("m", sessionIDLength), "any", 0)
	r, _ := http.NewRequest("GET", "/", nil)
	parsedSes, err := parseSession(r)
	if err == nil {
		log.Fatal("Cookie was parse where none exists")
	}

	r.AddCookie(ses.cookie)
	parsedSes, err = parseSession(r)
	if err != nil || !ses.Equals(parsedSes) {
		log.Println(err)
		log.Fatal("Cookie not parsed from request")
	}
}
