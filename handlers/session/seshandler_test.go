package session

import (
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dadamssolutions/authandler/handlers/session/sessions"
	_ "github.com/lib/pq"
)

var timeout = time.Minute
var db, err = sql.Open("postgres", "postgres://authandler:authandler@db:5432/authandler_session?sslmode=disable")
var da sesDataAccess
var sh *Handler

func TestBadDatabaseConnectionError(t *testing.T) {
	// Pass nil to get a bad database error
	_, err := newDataAccess(nil, "sessions", "sessionID", nil, timeout, timeout)
	if err == nil {
		t.Error(err)
	}

	// Open a bad database to test errors
	dbt, err := sql.Open("postgres", "user=test dbname=")

	_, err = newDataAccess(dbt, "sessions", sh.dataAccess.cookieName, nil, timeout, timeout)
	if err == nil {
		t.Error(err)
	}

	_, err = NewHandlerWithDB(dbt, "sessions", "sessionID", timeout, timeout, nil)
	if err == nil {
		t.Error(err)
	}
}

func TestIDGenerators(t *testing.T) {
	id := sh.dataAccess.generateSelectorID()
	if len(id) != selectorIDLength {
		t.Errorf("Selector ID is not of the expected length. %v != %v", len(id), selectorIDLength)
	}

	id = sh.dataAccess.generateSessionID()
	if len(id) != sessionIDLength {
		t.Errorf("Session ID is not of the expected length. %v != %v", len(id), sessionIDLength)
	}
}

func TestBadDatabaseConnection(t *testing.T) {
	sh := newHandler(sesDataAccess{}, timeout)
	if sh == nil {
		t.Error("Session handler should always be returned by unexported newSesHandler")
	}
}

func TestNegativeTimeoutSesCreation(t *testing.T) {
	sh1, err := NewHandlerWithDB(db, "sessions", "sessionID", timeout, -timeout, nil)
	if err != nil {
		log.Println(err)
		t.Error("We should not have an error with negative timeout")
	}
	if sh1.maxLifetime != 0 {
		t.Error("A negative timeout should produce a 0 maxLifetime")
	}
}

func TestUpdateExpiredTime(t *testing.T) {
	// We should get an update to expiration time.
	ses, _ := sh.CreateSession("dadams", true)
	now := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err := sh.UpdateSessionIfValid(ses)
	if err != nil || ses.ExpireTime().Before(now) {
		log.Println(err)
		t.Error("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	sesNotInDatabase := sessions.NewSession("", "", "", "", "", time.Microsecond)
	nowt := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Millisecond)
	err = sh.UpdateSessionIfValid(sesNotInDatabase)
	if err == nil || nowt.Before(sesNotInDatabase.ExpireTime()) {
		log.Println(err)
		t.Error("Session expiration update unexpected.")
	}
}

func TestUpdateToNonPersisantShouldCreateNewSession(t *testing.T) {
	ses, _ := sh.CreateSession("username", false)
	selector, session := ses.SelectorID(), ses.SessionID()
	err := sh.UpdateSessionIfValid(ses)
	if err != nil || ses.SelectorID() == selector || ses.SessionID() == session || ses.IsDestroyed() {
		t.Error("Non-persistent session should be destroyed and re-created on update")
	}
}

func TestCreateSession(t *testing.T) {
	ses, err := sh.CreateSession("thedadams", true)
	if err != nil || !ses.IsValid() || !ses.IsPersistent() {
		t.Error("Session not created properly")
	}

	ses, err = sh.CreateSession("thedadams", false)
	if err != nil || !ses.IsValid() || ses.IsPersistent() {
		t.Error("Session not created properly")
	}
}

func TestSessionNotValidForEncryptionReasons(t *testing.T) {
	ses, err := sh.CreateSession("thedadams", true)
	if err != nil || !ses.IsValid() || !ses.IsPersistent() {
		t.Error("Session not created properly")
	}

	if !sh.isValidSession(ses) {
		t.Error("Session where username and encrypted username match should be valid")
	}

	newSession := sessions.NewSession(ses.SelectorID(), ses.SessionID(), ses.Username(), ses.Username(), sh.dataAccess.cookieName, sh.maxLifetime)

	if sh.isValidSession(newSession) {
		t.Error("Session where username and encrypted username don't match should be invalid")
	}

	sh.DestroySession(ses)
}

func TestSessionValidityWithLongUsername(t *testing.T) {
	ses, err := sh.CreateSession("thedadamsthedadams", true)
	if err != nil || !ses.IsValid() || !ses.IsPersistent() {
		t.Error("Session not created properly")
	}

	if !sh.isValidSession(ses) {
		t.Error("Session where username and encrypted username match should be valid")
	}

	sh.DestroySession(ses)
}

func TestDestroySession(t *testing.T) {
	// We put the session in the database so it is destroyed
	ses, err := sh.CreateSession("anyone", true)
	err = sh.DestroySession(ses)
	if ses.IsValid() || err != nil {
		log.Println(err)
		t.Error("Session not destroyed.")
	}

	// Session is not in the database and should be destroyed
	sessionNotInDatabase := sessions.NewSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "", "nadams", sh.dataAccess.cookieName, sh.maxLifetime)
	err = sh.DestroySession(sessionNotInDatabase)
	if sessionNotInDatabase.IsValid() || err != nil {
		log.Println(err)
		t.Error("Session not destroyed.")
	}
}

func TestParseSessionFromRequest(t *testing.T) {
	ses, _ := sh.CreateSession("dadams", true)
	r, _ := http.NewRequest("GET", "/", nil)
	sesTest, err := sh.ParseSessionFromRequest(r)
	if err == nil || sesTest != nil {
		t.Error("Cookie was parsed where none exists")
	}

	r.AddCookie(ses.SessionCookie())
	sesTest, err = sh.ParseSessionFromRequest(r)
	if err != nil || !sesTest.Equals(ses, sh.dataAccess.hashString) {
		log.Println(err)
		t.Error("Cookie not parsed properly from request")
	}
}

func TestParsedSessionOfInvalidCookie(t *testing.T) {
	ses, _ := sh.CreateSession("dadams", true)
	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(ses.SessionCookie())
	sh.DestroySession(ses)
	sesTest, err := sh.ParseSessionFromRequest(r)
	if err == nil || sesTest != nil {
		t.Error("Cookie was parsed for destoyed session")
	}
}

func TestSessionParsingFromCookie(t *testing.T) {
	ses, _ := sh.CreateSession("dadams", true)
	sessionNotInDatabase := sessions.NewSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "", "nadams", sh.dataAccess.cookieName, sh.maxLifetime)
	cookie := sessionNotInDatabase.SessionCookie()
	sesTest, err := sh.ParseSessionCookie(ses.SessionCookie())

	// Should be a valid cookie
	if err != nil || !ses.Equals(sesTest, sh.dataAccess.hashString) {
		log.Println(err)
		t.Error("Session cookie not parsed properly")
	}

	// The session is not in the database so should be invalid
	sessionNotInDatabase.UpdateExpireTime(time.Second)
	cookie = sessionNotInDatabase.SessionCookie()
	sesTest, err = sh.ParseSessionCookie(cookie)
	if err == nil || sesTest != nil {
		t.Error("Session cookie should be invalid")
	}

	// The cookie name is not correct
	sessionNotInDatabase = sessions.NewSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), "", "thedadams", "something else", timeout)
	sesTest, err = sh.ParseSessionCookie(sessionNotInDatabase.SessionCookie())
	if err == nil || sesTest != nil {
		t.Error("Session cookie should be invalid")
	}
}

func TestParsingCookieDetectsPersistance(t *testing.T) {
	sesP, _ := sh.CreateSession("dadams", true)
	ses, _ := sh.CreateSession("nadams", false)

	sesPTest, _ := sh.ParseSessionCookie(sesP.SessionCookie())
	if sesPTest == nil || !sesPTest.IsPersistent() {
		t.Error("Persistent cookie parsed as non-persistent")
	}

	sesTest, _ := sh.ParseSessionCookie(ses.SessionCookie())
	if sesTest == nil || sesTest.IsPersistent() {
		t.Error("Non-persistent cookie parsed as persistent")
	}
}

func TestAttachPersistentCookieToResponseWriter(t *testing.T) {
	session, _ := sh.CreateSession("dadams", true)
	w := httptest.NewRecorder()
	err := sh.AttachCookie(w, session)
	resp := w.Result()
	attachedSession, err := sh.ParseSessionCookie(resp.Cookies()[0])
	if err != nil || !session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Cookie not attached to response writer")
	}

	sh.DestroySession(session)
	w = httptest.NewRecorder()
	err = sh.AttachCookie(w, session)
	if err == nil || session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Invalid cookie attached to response writer")
	}
}

func TestAttachSessionOnlyCookieToResponseWriter(t *testing.T) {
	session, _ := sh.CreateSession("dadams", false)
	w := httptest.NewRecorder()
	err := sh.AttachCookie(w, session)
	resp := w.Result()
	attachedSession, err := sh.ParseSessionCookie(resp.Cookies()[0])
	if err != nil || !session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Cookie not attached to response writer")
	}

	sh.DestroySession(session)
	w = httptest.NewRecorder()
	err = sh.AttachCookie(w, session)
	if err == nil || session.Equals(attachedSession, sh.dataAccess.hashString) {
		t.Error("Invalid cookie attached to response writer")
	}
}

func TestValidateUserInputs(t *testing.T) {
	for i := 0; i < 100; i++ {
		ses := sessions.NewSession(sh.dataAccess.generateSelectorID(), sh.dataAccess.generateSessionID(), sh.dataAccess.generateRandomString(12), "", sh.dataAccess.cookieName, 0)
		if !sh.validateUserInputs(ses) {
			t.Error("Session should have IDs and username")
		}
	}

	for i := 0; i < 100; i++ {
		ses := sessions.NewSession(sh.dataAccess.generateSelectorID(), sh.dataAccess.generateSessionID(), sh.dataAccess.generateRandomString(12)+" "+sh.dataAccess.generateRandomString(9), "", sh.dataAccess.cookieName, 0)
		if sh.validateUserInputs(ses) {
			log.Println(ses)
			t.Error("Session should NOT have IDs and username")
		}
	}
}

func TestTimeoutOfNonPersistentCookies(t *testing.T) {
	sh, _ := NewHandlerWithDB(db, "sessions", "sessionID", 500*time.Millisecond, time.Second, nil)
	ses1, _ := sh.CreateSession("dadams", true)
	ses2, _ := sh.CreateSession("nadams", false)

	time.Sleep(time.Millisecond * 25) // Wait for a short time

	err := sh.UpdateSessionIfValid(ses2)
	if err != nil || ses2.IsDestroyed() {
		t.Error("Non-persistent session should not be destroyed yet")
	}

	time.Sleep(time.Millisecond * 500) // Wait for clean-up to fire

	// ses2 should not be destroyed
	if !sh.isValidSession(ses2) {
		t.Error("Non-persistent session should not be destroyed")
	}

	// Update the persistent session so it stays in the database
	sh.UpdateSessionIfValid(ses1)

	time.Sleep(time.Millisecond * 500) // Wait for clean-up to fire

	// ses2 should now be destroyed
	if sh.isValidSession(ses2) {
		t.Error("Non-persistent session should now be destroyed")
	}

	// Now ses1 should be in the database.
	if !sh.isValidSession(ses1) {
		t.Error("A persistent session should be valid")
	}

	time.Sleep(time.Second)

	// Now ses1 should be destroyed
	if sh.isValidSession(ses1) {
		t.Error("A persistent session should now be invalid")
	}
}

func TestReadFlashes(t *testing.T) {
	ses, _ := sh.CreateSession("dadams", false)
	ses.AddError("Error1")
	ses.AddMessage("Message1")
	ses.AddMessage("Message2")

	msgs, errs := sh.ReadFlashes(ses)
	if len(msgs) != 2 || len(errs) != 1 {
		t.Error("Messages or errors not returned properly")
	}

	ses1, _ := sh.ParseSessionCookie(ses.SessionCookie())

	msgs, errs = ses1.Flashes()
	if len(msgs) != 0 || len(errs) != 0 {
		t.Error("Flashes should be empty after reading.")
	}
}

func TestLogUserIn(t *testing.T) {
	session, _ := sh.CreateSession("", false)
	sh.LogUserIn(session, "dadams")

	if !session.IsUserLoggedIn() || session.Username() != "dadams" {
		t.Error("User not logged into session")
	}

	sh.LogUserOut(session)

	if session.IsUserLoggedIn() || session.Username() != "" {
		t.Error("User not logged out of session")
	}
}
func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	triesLeft := 5

	// Wait for the database to be ready.
	for triesLeft > 0 {
		if tx, err := db.Begin(); err == nil {
			tx.Rollback()
			break
		}
		log.Printf("Database not ready, %d tries left", triesLeft)
		triesLeft--
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		log.Fatal(err)
	}
	sh, err = NewHandlerWithDB(db, "sessions", "sessionID", timeout, timeout, nil)
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	err = sh.dataAccess.dropTable()
	if err != nil {
		log.Fatal(err)
	}
	// The second time we drop the table, it should fail.
	err = sh.dataAccess.dropTable()
	if err == nil {
		log.Fatal("We shouldn't be able to drop the table twice.")
	}
	os.Exit(num)
}
