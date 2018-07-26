package authandler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dadamssolutions/authandler/handlers/csrf"
	"github.com/dadamssolutions/authandler/handlers/passreset"
)

func TestPasswordResetNoQuery(t *testing.T) {
	ts := httptest.NewTLSServer(a.PasswordResetAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(redirectURL.Path)
		t.Error("Get request to password reset with no query should fail")
	}
}

func TestPasswordResetLoggedIn(t *testing.T) {
	addTestUserToDatabase(true)

	ts := httptest.NewTLSServer(a.PasswordResetAdapter()(testHand))
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
	if len(req.Cookies()) == 0 || err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetURL {
		t.Error("Get request to password reset after user logged out should redirect")
	}

	removeTestUserFromDatabase()
}

func TestPasswordResetValidQuery(t *testing.T) {
	addTestUserToDatabase(true)

	passResetQuery := a.passResetHandler.GenerateNewToken("dadams")
	ts := httptest.NewTLSServer(a.PasswordResetAdapter()(testHand))
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
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetURL {
		t.Error("Get request to password reset with user query token should fail")
	}

	removeTestUserFromDatabase()
}

func TestPasswordResetForm(t *testing.T) {
	addTestUserToDatabase(true)

	passResetQuery := a.passResetHandler.GenerateNewToken("dadams")
	ts := httptest.NewTLSServer(a.PasswordResetAdapter()(testHand))
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
	if err != nil || resp.StatusCode != http.StatusAccepted || redirectURL.Path != a.LoginURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request with valid token should redirect to " + a.LoginURL)
	}

	passHash, _ := getUserPasswordHash(a.db, a.UsersTableName, "dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("e"), 64)))) != nil {
		t.Error("Password hash wasn't updated properly")
	}

	removeTestUserFromDatabase()
}

func TestPasswordResetNoCSRF(t *testing.T) {
	addTestUserToDatabase(true)

	passResetQuery := a.passResetHandler.GenerateNewToken("dadams")
	ts := httptest.NewTLSServer(a.PasswordResetAdapter()(testHand))
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
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request without csrf token should redirect to " + a.PasswordResetURL)
	}

	passHash, _ := getUserPasswordHash(a.db, a.UsersTableName, "dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("d"), 64)))) != nil {
		t.Error("Password hash was updated when it shouldn't have")
	}

	removeTestUserFromDatabase()
}

func TestPasswordResetNoPasswordToken(t *testing.T) {
	addTestUserToDatabase(true)

	ts := httptest.NewTLSServer(a.PasswordResetAdapter()(testHand))
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
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Location())
		t.Error("Post request without password reset token should redirect to " + a.PasswordResetURL)
	}

	passHash, _ := getUserPasswordHash(a.db, a.UsersTableName, "dadams")
	if a.CompareHashAndPassword(passHash, ([]byte(bytes.Repeat([]byte("d"), 64)))) != nil {
		t.Error("Password hash was updated when it shouldn't have")
	}

	removeTestUserFromDatabase()
}

func TestPasswordResetRequest(t *testing.T) {
	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get(csrf.HeaderName) == "" {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(resp.Header.Get(csrf.HeaderName))
		t.Error("Valid password request returned unexpected response")
	}
}

func TestSendPasswordResetEmail(t *testing.T) {
	addTestUserToDatabase(true)

	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter()(testHand))
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
	if err != nil || resp.StatusCode != http.StatusAccepted || redirectURL.Path != a.RedirectAfterResetRequest {
		t.Error("Password email not sent properly")
	}
}

func TestSendPasswordResetEmailWithoutCSRF(t *testing.T) {
	addTestUserToDatabase(true)

	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("email", "test@gmail.com")

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetURL {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(redirectURL.Path)
		t.Error("Password reset email was sent without CSRF verification")
	}
}

func TestSendPasswordResetEmailBadEmail(t *testing.T) {
	addTestUserToDatabase(true)

	ts := httptest.NewTLSServer(a.PasswordResetRequestAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	testCases := []url.Values{
		url.Values{"test": []string{"test@outlook.com"}},
		url.Values{"test": []string{"test@outlook.com"}},
		url.Values{"test": []string{"first last@outlook.com"}},
		url.Values{"test": []string{"test@google mail.com"}},
		url.Values{"test": []string{"test@outlook\n--.com"}},
		url.Values{"test": []string{"test@out -- look.com"}},
	}

	for _, f := range testCases {

		req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(f.Encode()))
		req.Header.Set("Content-type", "application/x-www-form-urlencoded")
		req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

		resp, err := client.Do(req)
		redirectURL, _ := resp.Location()
		if err == nil || resp.StatusCode != http.StatusSeeOther || redirectURL.Path != a.PasswordResetRequestURL {
			log.Println(err)
			log.Println(resp.Status)
			log.Println(redirectURL.Path)
			t.Error("Password email sent when it shouldn't have been sent")
		}
	}

	removeTestUserFromDatabase()
}
