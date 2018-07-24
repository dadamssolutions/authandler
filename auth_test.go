package authandler

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dadamssolutions/authandler/handlers/csrf"
	"github.com/dadamssolutions/authandler/handlers/email"
	"github.com/dadamssolutions/authandler/handlers/passreset"
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
		w.WriteHeader(http.StatusUnauthorized)
	}
	w.Write([]byte("Test handler"))
}

func addUserToDatabase() {
	// Add user to the database for testing
	pass := strings.Repeat("d", 64)
	passHash, _ := a.GenerateHashFromPassword([]byte(pass))
	tx, _ := a.db.Begin()
	tx.Exec("INSERT INTO users (username, email, pass_hash) VALUES ('dadams', 'test%40gmail.com', '" + base64.RawURLEncoding.EncodeToString(passHash) + "');")
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

func TestCurrentUserFromContext(t *testing.T) {
	addUserToDatabase()

	user := &User{FirstName: "Donnie", LastName: "Adams", Username: "dadams", email: "test%40gmail.com"}
	ses, _ := a.sesHandler.CreateSession(user.Username, false)
	req, _ := http.NewRequest("GET", "/", nil)
	req = req.WithContext(NewUserContext(req.Context(), user))

	userFromContext := a.CurrentUser(req)

	// If the session has not been added, then we should get no current user.
	if userFromContext != nil {
		t.Error("If no cookie is included, then no user should be found")
	}

	// Now we attach the cookie and the request should have a user.
	req.AddCookie(ses.SessionCookie())
	userFromContext = a.CurrentUser(req)

	if userFromContext == nil || userFromContext.Username != "dadams" {
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
	addUserToDatabase()

	b, err := a.getUserPasswordHash("nadams")
	if b != nil || err == nil {
		t.Error("User not in database returned a valid password hash")
	}

	b, err = a.getUserPasswordHash("dadams")
	err = a.CompareHashAndPassword(b, []byte(strings.Repeat("d", 64)))
	if b == nil || err != nil {
		log.Println(b)
		log.Println(err)
		t.Error("User in database returned an invalid password hash")
	}

	removeUserFromDatabase()
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
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

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
	redirectedURL, _ := resp.Location()
	if err != nil || redirectedURL.Path == req.URL.Path || len(resp.Cookies()) == 0 || num != 0 {
		log.Println(err)
		log.Println(len(resp.Cookies()))
		log.Println(num)
		t.Error("Request should be redirected when user is logged in")
	}
	if resp.StatusCode != http.StatusAccepted {
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
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

	// POST request should not log user in with wrong password
	resp, _ := client.Do(req)
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Cookies()) != 0 || num != 10 {
		log.Println(resp.Status)
		log.Println(num)
		log.Println(resp.Location())
		t.Error("Should be redirected to the login page after unsuccessful login attempt")
	}

	form.Set("username", "nadams")
	req, _ = http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())
	// POST request should not log user in
	resp, _ = client.Do(req)
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Cookies()) != 0 || num != 110 {
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
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

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
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

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
	loc, _ := resp.Location()
	if resp.StatusCode != http.StatusUnauthorized || loc.Path != "/login" {
		log.Println(resp.StatusCode)
		log.Println(loc.Path)
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

func TestPasswordResetNoQuery(t *testing.T) {
	ts := httptest.NewTLSServer(a.PasswordResetAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || redirectURL.Path != "/error" {
		t.Error("Get request to password reset with no query should fail")
	}
}

func TestPasswordResetLoggedIn(t *testing.T) {
	addUserToDatabase()

	ts := httptest.NewTLSServer(a.PasswordResetAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	// Fake log a user in
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error("Get request to password reset with logged in user should go through")
	}

	// Fake log user out.
	a.sesHandler.DestroySession(ses)

	resp, err = client.Do(req)
	redirectURL, _ := resp.Location()
	if len(req.Cookies()) == 0 || err != nil || resp.StatusCode != http.StatusUnauthorized || redirectURL.Path != "/error" {
		t.Error("Get request to password reset after user logged out should redirect")
	}

	removeUserFromDatabase()
}

func TestPasswordResetValidQuery(t *testing.T) {
	addUserToDatabase()

	passResetQuery := a.passResetHandler.GenerateNewToken("dadams")
	ts := httptest.NewTLSServer(a.PasswordResetAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL+"?"+passResetQuery, nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Println(err)
		log.Println(resp.StatusCode, resp.Status)
		t.Error("Get request to password reset with correct query should go through")
	}

	// Second request should be invalid
	resp, err = client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || redirectURL.Path != "/error" {
		t.Error("Get request to password reset with user query token should fail")
	}

	removeUserFromDatabase()
}

func TestPasswordResetForm(t *testing.T) {
	addUserToDatabase()

	passResetQuery := a.passResetHandler.GenerateNewToken("dadams")
	ts := httptest.NewTLSServer(a.PasswordResetAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("password", strings.Repeat("e", 64))
	form.Set("repeatedPassword", strings.Repeat("e", 64))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(passreset.HeaderName, passResetQuery)
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusAccepted || redirectURL.Path != "/login" {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request with valid token should redirect to /login")
	}

	passHash, _ := a.getUserPasswordHash("dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("e"), 64)))) != nil {
		t.Error("Password hash wasn't updated properly")
	}

	removeUserFromDatabase()
}

func TestPasswordResetNoCSRF(t *testing.T) {
	addUserToDatabase()

	passResetQuery := a.passResetHandler.GenerateNewToken("dadams")
	ts := httptest.NewTLSServer(a.PasswordResetAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("password", strings.Repeat("e", 64))
	form.Set("repeatedPassword", strings.Repeat("e", 64))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(passreset.HeaderName, passResetQuery)

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || redirectURL.Path != "/error" {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request without csrf token should redirect to /error")
	}

	passHash, _ := a.getUserPasswordHash("dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("d"), 64)))) != nil {
		t.Error("Password hash was updated when it shouldn't have")
	}

	removeUserFromDatabase()
}

func TestPasswordResetNoPasswordToken(t *testing.T) {
	addUserToDatabase()

	ts := httptest.NewTLSServer(a.PasswordResetAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("password", strings.Repeat("e", 64))
	form.Set("repeatedPassword", strings.Repeat("e", 64))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || redirectURL.Path != "/error" {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request without password reset token should redirect to /error")
	}

	passHash, _ := a.getUserPasswordHash("dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("d"), 64)))) != nil {
		t.Error("Password hash was updated when it shouldn't have")
	}

	removeUserFromDatabase()
}

func TestPasswordResetRequest(t *testing.T) {
	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get(csrf.HeaderName) == "" {
		t.Error("Valid password request returned unexpected response")
	}
}

func TestSendPasswordResetEmail(t *testing.T) {
	addUserToDatabase()

	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("email", "test@gmail.com")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusAccepted || redirectURL.Path != "/login" {
		t.Error("Password email not sent properly")
	}
}

func TestSendPasswordResetEmailWithoutCSRF(t *testing.T) {
	addUserToDatabase()

	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("email", "test@gmail.com")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || redirectURL.Path != "/error" {
		t.Error("Password reset email was sent without CSRF verification")
	}
}

func TestSendPasswordResetEmailBadEmail(t *testing.T) {
	addUserToDatabase()

	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter("/login", "/error")(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("email", "test@outlook.com")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || redirectURL != nil {
		t.Error("Password email not sent properly")
	}
}

// A Test send mail function so actual emails are not sent
func SendMail(hostname string, auth smtp.Auth, from string, to []string, msg []byte) error {
	if len(to) > 1 {
		return errors.New("Message should only be sent to one address")
	}
	message, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(message.Body)
	if err != nil {
		return err
	}
	if message.Header.Get("Content-Type") == "" || message.Header.Get("To") != to[0] || message.Header.Get("From") != from || len(body) == 0 {
		return errors.New("Message was not constructed properly")
	}
	return nil
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	db, err := sql.Open("postgres", "user=test dbname=house-pts-test sslmode=disable")
	eh := email.NewSender("House Points Test", hostname, "587", testEmail1, password)
	eh.SendMail = SendMail
	a, err = DefaultHTTPAuth(db, "users", eh, time.Second, 2*time.Second, 10, bytes.Repeat([]byte("d"), 16))
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
