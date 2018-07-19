package authandler

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dadamssolutions/authandler/csrfhandler"
)

var a *HTTPAuth
var num int
var testHand testHandler

func checkRedirect(req *http.Request, via []*http.Request) error {
	log.Println(req.Method)
	return fmt.Errorf("Redirected to %v", req.URL)
}

type testHandler struct{}

func (t testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	num++
	ses := SessionFromContext(r.Context())
	if ses != nil {
		a.sesHandler.AttachCookie(w, ses)
	}
	err := ErrorFromContext(r.Context())
	if err != nil {
		log.Println(err)
		num *= 10
	}
	w.Write([]byte("Test handler"))
}

func addUserToDatabase() {
	// Add user to the database for testing
	pass := strings.Repeat("d", 64)
	passHash, _ := a.GenerateHashFromPassword([]byte(pass))
	tx, _ := a.db.Begin()
	tx.Exec("INSERT INTO users (username, email, pass_hash) VALUES ('dadams', 'test@gmail.com', '" + base64.RawURLEncoding.EncodeToString(passHash) + "');")
	tx.Commit()
}

func removeUserFromDatabase() {
	// Remove user from database
	tx, _ := a.db.Begin()
	tx.Exec("DELETE FROM sessions WHERE user_id = 'dadams';")
	tx.Exec("DELETE FROM csrfs WHERE user_id = 'dadams';")
	tx.Exec("DELETE FROM users WHERE username = 'dadams';")
	tx.Commit()
}

func TestUserNotLoggedInHandler(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(a.RedirectIfUserNotAuthenticated()(testHand))
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
	ts := httptest.NewTLSServer(a.RedirectIfUserNotAuthenticated()(testHand))
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

func TestCurrentUserBadCookie(t *testing.T) {
	addUserToDatabase()

	req, _ := http.NewRequest("GET", "/", nil)

	if a.CurrentUser(req) != nil {
		t.Error("No cookie in request should return empty string")
	}

	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())
	a.sesHandler.DestroySession(ses)

	if a.CurrentUser(req) != nil {
		t.Error("Destroyed cookie in request should return empty string")
	}

	removeUserFromDatabase()
}

func TestCurrentUserGoodCookie(t *testing.T) {
	addUserToDatabase()

	req, _ := http.NewRequest("GET", "/", nil)
	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	if a.CurrentUser(req).Username != "dadams" {
		t.Error("Valid cookie in request should return correct user")
	}

	removeUserFromDatabase()
}

func TestIsCurrentUser(t *testing.T) {
	addUserToDatabase()

	req, _ := http.NewRequest("GET", "/", nil)
	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	if !a.IsCurrentUser(req, "dadams") {
		t.Error("Current user should be dadams with valid cookie")
	}

	if a.IsCurrentUser(req, "nadams") {
		t.Error("Current user should not be nadams with valid cookie")
	}

	if a.IsCurrentUser(req, "") {
		t.Error("Current user should automatically be false if username is empty")
	}

	a.sesHandler.DestroySession(ses)
	if a.IsCurrentUser(req, "dadams") {
		t.Error("Current user should not be dadams with destroyed cookie")
	}

	removeUserFromDatabase()
}

func TestGetUserPasswordHash(t *testing.T) {
	passHash, err := a.GenerateHashFromPassword([]byte(strings.Repeat("d", 64)))
	tx, _ := a.db.Begin()
	tx.Exec("INSERT INTO users (username, email, pass_hash) VALUES ('dadams', 'test@gmail.com', '" + base64.RawURLEncoding.EncodeToString(passHash) + "');")
	tx.Commit()
	b, err := a.getUserPasswordHash("nadams")
	if b != nil || err == nil {
		t.Error("User not in database returned a valid password hash")
	}

	b, err = a.getUserPasswordHash("dadams")
	if b == nil || err != nil || !bytes.Equal(b, passHash) {
		t.Error("User in database returned an invalid password hash")
	}
	tx, _ = a.db.Begin()
	tx.Exec("DELETE FROM users WHERE username = 'dadams';")
	tx.Commit()
}

func TestUserLogInHandlerNotLoggedIn(t *testing.T) {
	num = 0
	addUserToDatabase()

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login"
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)

	// No cookie present so should just redirect
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		t.Error("Request redirected in error")
	}
	if resp.StatusCode != http.StatusOK {
		t.Error("Login GET request with no user logged in should be normal")
	}

	removeUserFromDatabase()
}

func TestUserLogInHandlerLoggingIn(t *testing.T) {
	addUserToDatabase()
	num = 0

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "false")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfhandler.HeaderName, a.csrfHandler.GenerateNewToken())

	// POST request should log user in
	resp, err := client.Do(req)
	if err != nil || len(resp.Cookies()) == 0 || resp.StatusCode != http.StatusAccepted || num != 0 {
		log.Println(err)
		log.Println(len(resp.Cookies()))
		log.Println(resp.StatusCode)
		t.Error("Should be redirected after a successful login")
	}
	ses, _ := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if ses == nil || ses.IsPersistant() || ses.Username() != "dadams" {
		t.Error("The cookie on a login response is not valid")
	}

	// Now user should be redirected when visiting login page
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)
	req.AddCookie(ses.SessionCookie())
	resp, err = client.Do(req)
	if err == nil || len(resp.Cookies()) == 0 || num != 0 {
		t.Error("Request should be redirected when user is logged in")
	}
	if resp.StatusCode != http.StatusFound {
		t.Error("Login GET request with user logged in should redirect")
	}

	// Log user out
	ses, _ = a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	cookie := ses.SessionCookie()
	a.sesHandler.DestroySession(ses)

	// Now user should be asked to login, even with expired session cookie attached
	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Error("Request redirected in error")
	}
	if resp.StatusCode != http.StatusOK || num != 1 {
		log.Println(resp.StatusCode, num)
		t.Error("Login GET request with no user logged in should not redirect")
	}

	removeUserFromDatabase()
}

func TestUserLogInHandlerBadInfo(t *testing.T) {
	addUserToDatabase()
	num = 0

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("e", 64))
	form.Set("remember", "false")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfhandler.HeaderName, a.csrfHandler.GenerateNewToken())

	// POST request should not log user in with wrong password
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Cookies()) != 0 || num != 0 {
		t.Error("Should be redirected to the login page after unsuccessful login attempt")
	}

	form.Set("username", "nadams")
	req, _ = http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfhandler.HeaderName, a.csrfHandler.GenerateNewToken())
	// POST request should not log user in
	resp, _ = client.Do(req)
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Cookies()) != 0 || num != 0 {
		t.Error("Should be redirected to the login page after unsuccessful login attempt")
	}

	removeUserFromDatabase()
}

func TestUserLogInHandlerPersistant(t *testing.T) {
	addUserToDatabase()
	num = 0

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "true")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfhandler.HeaderName, a.csrfHandler.GenerateNewToken())

	// POST request should log user in
	resp, err := client.Do(req)
	if err != nil || len(resp.Cookies()) == 0 || resp.StatusCode != http.StatusAccepted {
		t.Error("Should be redirected after a successful login")
	}

	ses, err := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if err != nil || !ses.IsPersistant() {
		t.Error("Session created should be persistant with 'Remember me'")
	}

	cookie := ses.SessionCookie()
	a.sesHandler.DestroySession(ses)

	// Now user should be asked to login, even with expired session cookie attached
	req, _ = http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Error("Request redirected in error")
	}
	if resp.StatusCode != http.StatusOK || num != 1 {
		t.Error("Login GET request with no user logged in should not redirect")
	}

	removeUserFromDatabase()
}

func TestUserLogInHandlerBadPersistant(t *testing.T) {
	addUserToDatabase()
	num = 0

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "yes")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfhandler.HeaderName, a.csrfHandler.GenerateNewToken())

	// POST request should log user in
	resp, err := client.Do(req)
	if err != nil || len(resp.Cookies()) == 0 || resp.StatusCode != http.StatusAccepted {
		t.Error("Should be redirected after a successful login")
	}

	ses, err := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if err != nil || ses.IsPersistant() {
		t.Error("Session created should not be persistant with bad remember value")
	}

	// Log the user out
	a.sesHandler.DestroySession(ses)

	removeUserFromDatabase()
}

func TestUserLogInHandlerNoCSRF(t *testing.T) {
	addUserToDatabase()
	num = 0

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login"
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "yes")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	// Don't set the CSRF header
	// req.Header.Set(csrfhandler.HeaderName, a.csrfHandler.GenerateNewToken())

	// POST request should not be valid because the CSRF token is not there
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusOK || num != 10 {
		log.Println(resp.StatusCode)
		log.Println(num)
		t.Error("Login attempt without CSRF token should redirect to login page")
	}

	removeUserFromDatabase()
}

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

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	var err error
	a, err = DefaultHTTPAuth("postgres", "user=test dbname=house-pts-test sslmode=disable", time.Second, 2*time.Second, 10)
	if err != nil {
		log.Panic(err)
	}
	testHand = testHandler{}
	exitCode := m.Run()
	// Wait a little bit for the sessions to be removed
	time.Sleep(time.Second)
	deleteUsersTestTable(a.db, a.UsersTableName)
	os.Exit(exitCode)
}
