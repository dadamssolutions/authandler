package httpauth

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var a *HTTPAuth
var num int

func TestHTTPSRedirectHTTP(t *testing.T) {
	num = 0
	ts := httptest.NewServer(http.HandlerFunc(a.HandleFuncHTTPSRedirect(testHandler)))
	defer ts.Close()

	client := ts.Client()
	client.CheckRedirect = checkRedirect
	resp, err := client.Get(ts.URL)

	if err == nil || resp.StatusCode != http.StatusTemporaryRedirect || num != 0 {
		t.Error("HTTP request not redirected")
	}
}
func TestHTTPSRedirectHTTPS(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(http.HandlerFunc(a.HandleFuncHTTPSRedirect(testHandler)))
	defer ts.Close()

	client := ts.Client()
	resp, err := client.Get(ts.URL)

	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		log.Println(err)
		t.Error("HTTPS request unexpectedly redirected")
	}
}

func TestUserNotLoggedInHandler(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(http.HandlerFunc(a.HandleFuncAuth(testHandler)))
	defer ts.Close()

	client := ts.Client()
	client.CheckRedirect = checkRedirect
	resp, err := client.Get(ts.URL)
	if err == nil || resp.StatusCode != http.StatusFound || num != 0 {
		log.Printf("Status code: %v with error: %v\n", resp.StatusCode, err)
		t.Error("Not redirected when user is not logged in")
	}
}

func TestUserLoggedInHandler(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(http.HandlerFunc(a.HandleFuncAuth(testHandler)))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest("GET", ts.URL, nil)

	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		log.Printf("Status code: %v with error: %v\n", resp.Status, err)
		t.Error("Redirected, but user is logged in")
	}

	if len(resp.Cookies()) == 0 || resp.Cookies()[0].Name != ses.SessionCookie().Name || resp.Cookies()[0].Value != ses.CookieValue() {
		t.Error("Cookie attached to response does not correspond to the session")
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("Redirected to %v", req.URL)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	num++
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	var err error
	a, err = DefaultHTTPAuth("postgres", "user=test dbname=house-pts-test sslmode=disable", time.Second, 2*time.Second, 10)
	if err != nil {
		log.Panic(err)
	}
	exitCode := m.Run()
	// Wait a little bit for the sessions to be removed
	time.Sleep(time.Second)
	os.Exit(exitCode)
}
