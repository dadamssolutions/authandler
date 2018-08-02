package authandler

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserLogOutHandler(t *testing.T) {
	ts := httptest.NewTLSServer(a.MustHaveAdapters(a.LogoutAdapter("/"))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	ses, _ := a.sesHandler.CreateSession("dadams", true)

	// No cookie present so should just redirect
	resp, err := client.Do(req)
	if err == nil {
		t.Error("Request not redirected")
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Error("Logout with no user logged in should just redirect to \"/\"")
	}

	// Cookie present. User should be logged out.
	req.AddCookie(ses.SessionCookie())
	resp, err = client.Do(req)
	if err == nil || len(resp.Cookies()) != 1 {
		t.Error("Request not redirected")
	}
	newSession, _ := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if resp.StatusCode != http.StatusSeeOther || newSession.IsUserLoggedIn() {
		log.Println(ses.IsUserLoggedIn())
		t.Error("User not logged out properly")
	}

	// Cookie present, but already logged out. User should be redirected
	resp, err = client.Do(req)
	if err == nil {
		t.Error("Request not redirected")
	}
	newSession, _ = a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if resp.StatusCode != http.StatusSeeOther || newSession.IsUserLoggedIn() {
		log.Println(ses.IsUserLoggedIn())
		t.Error("User not logged out properly")
	}
}
