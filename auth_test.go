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
	w := httptest.NewRecorder()

	// Create the user logged in session
	ses, _ := a.ses.CreateSession("dadams", false)

	a.ses.AttachCookie(w, ses)
	req.AddCookie(w.Result().Cookies()[0])

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		log.Printf("Status code: %v with error: %v\n", resp.Status, err)
		t.Error("Redirected, but user is logged in")
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
	time.Sleep(time.Millisecond * 200)
	os.Exit(exitCode)
}
