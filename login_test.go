package authandler

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUserLogInHandlerNotLoggedIn(t *testing.T) {
	num = 0
	addTestUserToDatabase(true)

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	ts.URL = ts.URL + "/login"
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)

	// No cookie present so should just redirect
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Println(err)
		log.Println(resp.Status)
		t.Error("Request redirected in error")
	}

	removeTestUserFromDatabase()
}

func TestUserLogInHandlerLoggingIn(t *testing.T) {
	addTestUserToDatabase(true)
	num = 0
	w := httptest.NewRecorder()

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
	a.csrfHandler.GenerateNewToken(w)
	req.AddCookie(w.Result().Cookies()[0])

	// POST request should log user in
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	if err == nil || len(resp.Cookies()) != 1 || resp.StatusCode != http.StatusSeeOther || loc.Path != a.RedirectAfterLogin {
		log.Println(err)
		log.Println(len(resp.Cookies()))
		log.Println(resp.Status)
		t.Error("Should be redirected after a successful login")
	}
	ses, _ := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if ses == nil || ses.IsPersistant() || ses.Username() != "dadams" || !ses.IsUserLoggedIn() {
		t.Error("The cookie on a login response is not valid")
	}

	// Now user should be redirected when visiting login page
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)
	req.AddCookie(ses.SessionCookie())
	resp, err = client.Do(req)
	redirectedURL, _ := resp.Location()
	if err == nil || redirectedURL.Path != a.RedirectAfterLogin || len(resp.Cookies()) != 1 {
		log.Println(err)
		log.Println(redirectedURL.Path)
		log.Println(len(resp.Cookies()))
		t.Error("Request should be redirected when user is logged in")
	}
	if resp.StatusCode != http.StatusSeeOther {
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

	removeTestUserFromDatabase()
}

func TestUserLogInHandlerBadInfo(t *testing.T) {
	addTestUserToDatabase(true)
	num = 0
	w := httptest.NewRecorder()

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
	a.csrfHandler.GenerateNewToken(w)
	req.AddCookie(w.Result().Cookies()[0])

	// POST request should not log user in with wrong password
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	ses, _ := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	_, errs := ses.Flashes()
	if err == nil || len(resp.Cookies()) != 1 || loc.Path != a.LoginURL || ses.IsUserLoggedIn() || len(errs) != 1 {
		log.Println(resp.Status)
		log.Println(resp.Location())
		log.Println(errs)
		t.Error("Should be redirected to the login page after unsuccessful login attempt")
	}
	w = httptest.NewRecorder()
	form.Set("username", "nadams")
	req, _ = http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w)
	req.AddCookie(w.Result().Cookies()[0])
	// POST request should not log user in
	resp, _ = client.Do(req)
	loc, _ = resp.Location()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 || loc.Path != a.LoginURL {
		t.Error("Should be redirected to the login page after unsuccessful login attempt")
	}

	removeTestUserFromDatabase()
}

func TestUserLogInHandlerPersistant(t *testing.T) {
	addTestUserToDatabase(true)
	num = 0
	w := httptest.NewRecorder()
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
	a.csrfHandler.GenerateNewToken(w)
	req.AddCookie(w.Result().Cookies()[0])

	// POST request should log user in
	resp, err := client.Do(req)
	if err == nil || len(resp.Cookies()) != 1 || resp.StatusCode != http.StatusSeeOther {
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

	removeTestUserFromDatabase()
}

func TestUserLogInHandlerBadPersistant(t *testing.T) {
	addTestUserToDatabase(true)
	num = 0
	w := httptest.NewRecorder()

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
	a.csrfHandler.GenerateNewToken(w)
	req.AddCookie(w.Result().Cookies()[0])

	// POST request should log user in
	resp, err := client.Do(req)
	if err == nil || len(resp.Cookies()) == 0 || resp.StatusCode != http.StatusSeeOther {
		t.Error("Should be redirected after a successful login")
	}

	ses, err := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if err != nil || ses.IsPersistant() {
		t.Error("Session created should not be persistant with bad remember value")
	}

	// Log the user out
	a.sesHandler.DestroySession(ses)

	removeTestUserFromDatabase()
}

func TestUserLogInHandlerNoCSRF(t *testing.T) {
	addTestUserToDatabase(true)
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
	resp, err := client.Do(req)
	loc, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || loc.Path != "/login" {
		log.Println(err)
		log.Println(resp.StatusCode)
		log.Println(loc.Path)
		t.Error("Login attempt without CSRF token should redirect to login page")
	}

	removeTestUserFromDatabase()
}
func TestUserNotValidatedCannotLogIn(t *testing.T) {
	addTestUserToDatabase(false)
	w := httptest.NewRecorder()

	ts := httptest.NewTLSServer(a.LoginAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("password", strings.Repeat("d", 64))
	form.Set("remember", "true")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	a.csrfHandler.GenerateNewToken(w)
	req.AddCookie(w.Result().Cookies()[0])

	// POST request should log user in
	resp, err := client.Do(req)
	ses, _ := a.sesHandler.ParseSessionCookie(resp.Cookies()[0])
	if err == nil || ses == nil || ses.IsUserLoggedIn() || resp.StatusCode != http.StatusSeeOther {
		log.Println(err)
		log.Println(ses)
		log.Println(ses.IsUserLoggedIn())
		t.Error("User should not be able to log in if they are unverified")
	}

	removeTestUserFromDatabase()
}
