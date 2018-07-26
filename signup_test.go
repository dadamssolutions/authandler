package authandler

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dadamssolutions/authandler/handlers/csrf"
)

func TestSignUp(t *testing.T) {
	ts := httptest.NewTLSServer(a.SignUpAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get(csrf.HeaderName) == "" {
		t.Error("Valid password request returned unexpected response")
	}
}

func TestSignUpPost(t *testing.T) {
	ts := httptest.NewTLSServer(a.SignUpAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	form := url.Values{}
	form.Set("username", "dadams")
	form.Set("firstName", "Donnie")
	form.Set("lastName", "Adams")
	form.Set("email", "test@gmail.com")
	form.Set("password", strings.Repeat("d", 32))
	form.Set("repeatedPassword", strings.Repeat("d", 32))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

	resp, err := client.Do(req)
	redirectURL, _ := resp.Location()
	if err != nil || resp.StatusCode != http.StatusAccepted || redirectURL.Path != a.RedirectAfterSignUp {
		t.Error("Sign up email not sent properly")
	}

	removeTestUserFromDatabase()
}

func TestSignUpPostErrorChecking(t *testing.T) {
	addTestUserToDatabase(true)

	ts := httptest.NewTLSServer(a.SignUpAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect
	testCases := []struct {
		firstName, lastName, username, email, password, repeatedPassword string
	}{
		{"Donnie", "Adams", "dadams", "test@gmail.com", "dddd", "dddd"},
		{"", "Adams", "dadams", "test@gmail.com", "dddd", "dddd"},
		{"Donnie", "", "dadams", "test@gmail.com", "dddd", "dddd"},
		{"Donnie", "Adams", "", "test@gmail.com", "dddd", "dddd"},
		{"Donnie", "Adams", "dadams", "", "dddd", "dddd"},
		{"Donnie", "Adams", "dadams", "test@gmail.com", "", "dddd"},
		{"Donnie", "Adams", "dadams", "test@gmail.com", "dddd", "ddd"},
	}

	for _, v := range testCases {

		f := url.Values{"firstName": []string{v.firstName}, "lastName": []string{v.lastName}, "username": []string{v.username}, "email": []string{v.email}, "password": []string{v.password}, "repeatedPassword": []string{v.repeatedPassword}}

		req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(f.Encode()))
		req.Header.Set("Content-type", "application/x-www-form-urlencoded")
		req.Header.Set(csrf.HeaderName, a.csrfHandler.GenerateNewToken())

		resp, err := client.Do(req)
		loc, _ := resp.Location()
		if err == nil || resp.StatusCode != http.StatusSeeOther || loc.Path != a.SignUpURL {
			t.Error("Password email sent when it shouldn't have been sent")
		}
	}

	removeTestUserFromDatabase()
}

func TestUserValidation(t *testing.T) {
	addTestUserToDatabase(false)
	ts := httptest.NewTLSServer(a.SignUpVerificationAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	passQuery := a.passResetHandler.GenerateNewToken("dadams")
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?"+passQuery, nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Error("User not validated correctly")
	}

	user := getUserFromDB(a.db, a.UsersTableName, "username", "dadams")
	if !user.IsValidated() {
		log.Println(user)
		t.Error("User validation request passed, but user was not validated in the database")
	}

	removeTestUserFromDatabase()
}

func TestUserValidationNoQuery(t *testing.T) {
	addTestUserToDatabase(false)
	ts := httptest.NewTLSServer(a.SignUpVerificationAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	// Don't include the reset query
	//passQuery := a.passResetHandler.GenerateNewToken("dadams")
	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		log.Println(err)
		log.Println(resp.Status)
		t.Error("User validated without reset query")
	}

	user := getUserFromDB(a.db, a.UsersTableName, "username", "dadams")
	if user.IsValidated() {
		log.Println(user)
		t.Error("User validation request passed, but user was validated in the database incorrectly")
	}

	removeTestUserFromDatabase()
}

func TestUserValidationBadQuery(t *testing.T) {
	addTestUserToDatabase(false)
	ts := httptest.NewTLSServer(a.SignUpVerificationAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	// Don't include the reset query
	passQuery := a.passResetHandler.GenerateNewToken("dadams")
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?"+passQuery[1:], nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Error("User validated without reset query")
	}

	user := getUserFromDB(a.db, a.UsersTableName, "username", "dadams")
	if user.IsValidated() {
		log.Println(user)
		t.Error("User validation request passed, but user was validated in the database incorrectly")
	}

	removeTestUserFromDatabase()
}

func TestUserCannotValidateIfLoggedIn(t *testing.T) {
	addTestUserToDatabase(false)

	ts := httptest.NewTLSServer(a.SignUpVerificationAdapter()(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	// Log user in by creating a session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(ses.SessionCookie())

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		log.Println(err)
		log.Println(resp.Status)
		t.Error("User was able to verify while logged in")
	}

	removeTestUserFromDatabase()

}
