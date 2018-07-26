package authandler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserLogOutHandler(t *testing.T) {
	ts := httptest.NewTLSServer(a.LogoutAdapter("/")(testHand))
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
	if resp.StatusCode != http.StatusFound {
		t.Error("Logout with no user logged in should just redirect to \"/\"")
	}

	// Cookie present. User should be logged out and session destroyed.
	req.AddCookie(ses.SessionCookie())
	resp, err = client.Do(req)
	if err == nil {
		t.Error("Request not redirected")
	}
	sesTest, err := a.sesHandler.UpdateSessionIfValid(ses)
	if resp.StatusCode != http.StatusFound || sesTest != nil || err == nil {
		t.Error("User not logged out properly")
	}

	// Cookie present, but already destroyed. User should be redirected
	resp, err = client.Do(req)
	if err == nil {
		t.Error("Request not redirected")
	}
	sesTest, err = a.sesHandler.UpdateSessionIfValid(ses)
	if resp.StatusCode != http.StatusFound || sesTest != nil || err == nil {
		t.Error("User not logged out properly")
	}
}
