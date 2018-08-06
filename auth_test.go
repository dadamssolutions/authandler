package authandler

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dadamssolutions/authandler/handlers/email"
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
	err := ErrorFromContext(r.Context())
	if err != nil {
		log.Println(err)
		num *= 10
	}
	w.Write([]byte("Test handler"))
}

func deleteTestTables(db *sql.DB, tableName ...string) error {
	tx, err := db.Begin()
	if err != nil {
		return nil
	}
	for i := range tableName {
		_, err = tx.Exec(fmt.Sprintf(deleteTestTableSQL, tableName[i]))
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func addTestUserToDatabase(validated bool) {
	// Add user to the database for testing
	pass := strings.Repeat("d", 64)
	passHash, _ := a.GenerateHashFromPassword([]byte(pass))
	tx, _ := a.db.Begin()
	tx.Exec(fmt.Sprintf("INSERT INTO users (username, email, pass_hash, validated) VALUES ('dadams', 'test@gmail.com', '%v', %v);", base64.RawURLEncoding.EncodeToString(passHash), validated))
	tx.Commit()
}

func removeTestUserFromDatabase() {
	// Remove user from database
	tx, _ := a.db.Begin()
	tx.Exec("DELETE FROM sessions WHERE user_id = 'dadams';")
	tx.Exec("DELETE FROM csrfs WHERE user_id = 'dadams';")
	tx.Exec("DELETE FROM users WHERE username = 'dadams';")
	tx.Commit()
}

func TestUserNotLoggedInHandler(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(a.RedirectIfUserNotAuthenticated())(testHand))
	defer ts.Close()

	client := ts.Client()
	client.CheckRedirect = checkRedirect
	resp, err := client.Get(ts.URL)
	if err == nil || resp.StatusCode != http.StatusSeeOther || num != 0 || len(resp.Cookies()) == 0 {
		log.Println(err)
		log.Println(resp.Status)
		log.Println(len(resp.Cookies()))
		t.Error("Not redirected when user is not logged in")
	}
}

func TestUserLoggedInHandler(t *testing.T) {
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(a.RedirectIfUserNotAuthenticated())(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		log.Printf("Status code: %v with error: %v\n", resp.Status, err)
		t.Error("Redirected, but user is logged in")
	}

	if len(resp.Cookies()) == 0 || resp.Cookies()[0].Name != ses.SessionCookie().Name || resp.Cookies()[0].Value != ses.CookieValue() {
		log.Println(len(resp.Cookies()))
		t.Error("Cookie attached to response does not correspond to the session")
	}
}

func TestUserHasRole(t *testing.T) {
	addTestUserToDatabase(true)
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(a.RedirectIfNoPermission(0))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())
	user := a.CurrentUser(req)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 1 {
		t.Error("Redirected, but user has permission")
	}

	user.Role = Admin
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)

	// Create the user logged in session
	ses, _ = a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	resp, err = client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK || num != 2 {
		t.Error("Redirected, but user has permission")
	}

	removeTestUserFromDatabase()
}

func TestUserDoesNotHaveRole(t *testing.T) {
	addTestUserToDatabase(true)
	num = 0
	ts := httptest.NewTLSServer(a.MustHaveAdapters(a.RedirectIfNoPermission(2))(testHand))
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = checkRedirect

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())
	user := a.CurrentUser(req)

	resp, err := client.Do(req)
	if err == nil || resp.StatusCode != http.StatusSeeOther || num != 0 {
		t.Error("Not redirected when user does not have permission")
	}

	user.Role = Manager
	req, _ = http.NewRequest(http.MethodGet, ts.URL, nil)

	// Create the user logged in session
	ses, _ = a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	resp, err = client.Do(req)
	if err == nil || resp.StatusCode != http.StatusSeeOther || num != 0 {
		t.Error("Not redirected when user does not have permission")
	}

	removeTestUserFromDatabase()
}

func TestCurrentUserBadCookie(t *testing.T) {
	addTestUserToDatabase(true)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)

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

	removeTestUserFromDatabase()
}

func TestCurrentUserGoodCookie(t *testing.T) {
	addTestUserToDatabase(true)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	// Create the user logged in session
	ses, _ := a.sesHandler.CreateSession("dadams", true)
	req.AddCookie(ses.SessionCookie())

	if a.CurrentUser(req).Username != "dadams" {
		t.Error("Valid cookie in request should return correct user")
	}

	removeTestUserFromDatabase()
}

func TestCurrentUserFromContext(t *testing.T) {
	addTestUserToDatabase(true)

	user := &User{FirstName: "Donnie", LastName: "Adams", Username: "dadams", email: "test%40gmail.com"}
	ses, _ := a.sesHandler.CreateSession(user.Username, false)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
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

	removeTestUserFromDatabase()
}

func TestIsCurrentUser(t *testing.T) {
	addTestUserToDatabase(true)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
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

	removeTestUserFromDatabase()
}

func TestGetUserPasswordHash(t *testing.T) {
	addTestUserToDatabase(true)

	b, err := getUserPasswordHash(a.db, a.UsersTableName, "nadams")
	if b != nil || err == nil {
		t.Error("User not in database returned a valid password hash")
	}

	b, err = getUserPasswordHash(a.db, a.UsersTableName, "dadams")
	err = a.CompareHashAndPassword(b, []byte(strings.Repeat("d", 64)))
	if b == nil || err != nil {
		log.Println(b)
		log.Println(err)
		t.Error("User in database returned an invalid password hash")
	}

	removeTestUserFromDatabase()
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
	db, err := sql.Open("postgres", "user=test dbname=test sslmode=disable")
	eh := email.NewSender("House Points Test", hostname, "587", testEmail1, password)
	eh.SendMail = SendMail
	a, err = DefaultHTTPAuth(db, "users", "www.test.com", eh, time.Second, 2*time.Second, time.Second, time.Second, 10, bytes.Repeat([]byte("d"), 16))
	if err != nil {
		log.Panic(err)
	}
	a.PasswordResetEmailTemplate = template.Must(template.ParseFiles("templates/passwordreset.tmpl.html"))
	a.SignUpEmailTemplate = template.Must(template.ParseFiles("templates/signup.tmpl.html"))
	testHand = testHandler{}
	exitCode := m.Run()
	// Wait a little bit for the sessions to be removed
	time.Sleep(time.Second)
	deleteTestTables(a.db, a.UsersTableName, a.sesHandler.GetTableName(), a.csrfHandler.GetTableName(), a.passResetHandler.GetTableName())
	os.Exit(exitCode)
}
