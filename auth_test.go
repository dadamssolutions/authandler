package httpauth

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var a *HTTPAuth

func TestHTTPSRedirectHTTP(t *testing.T) {
	num := 0
	ts := httptest.NewServer(http.HandlerFunc(a.HandleFuncHTTPSRedirect(func(w http.ResponseWriter, r *http.Request) {
		num++
	})))
	defer ts.Close()

	client := ts.Client()
	resp, err := client.Get(ts.URL)

	if err == nil || resp.StatusCode != http.StatusTemporaryRedirect || num != 0 {
		t.Error("HTTP request not redirected")
	}
}
func TestHTTPSRedirectHTTPS(t *testing.T) {
	num := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(a.HandleFuncHTTPSRedirect(func(w http.ResponseWriter, r *http.Request) {
		num++
	})))
	defer ts.Close()

	client := ts.Client()
	resp, err := client.Get(ts.URL)

	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		log.Println(err)
		t.Error("HTTPS request unexpectedly redirected")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	a, _ = DefaultHTTPAuth("postgres", "", time.Millisecond, time.Second, 10)
	exitCode := m.Run()
	os.Exit(exitCode)
}
