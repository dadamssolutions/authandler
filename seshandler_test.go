package seshandler

import (
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dadamssolutions/seshandler/session"
	_ "github.com/lib/pq"
)

var timeout = time.Minute
var db, err = sql.Open("postgres", "user=test dbname=postgres sslmode=disable")
var da sesDataAccess
var sh *SesHandler

func TestBadDatabaseConnectionError(t *testing.T) {
	// Pass nil to get a bad database error
	_, err := newDataAccess(nil, timeout, timeout)
	if err == nil {
		t.Fatal(err)
	}

	// Open a bad database to test errors
	dbt, err := sql.Open("postgres", "user=test dbname=")

	_, err = newDataAccess(dbt, timeout, timeout)
	if err == nil {
		t.Fatal(err)
	}

	_, err = NewSesHandlerWithDB(dbt, timeout, timeout)
	if err == nil {
		t.Fatal(err)
	}
}

func TestIDGenerators(t *testing.T) {
	id := generateSelectorID()
	if len(id) != selectorIDLength {
		t.Fatalf("Selector ID is not of the expected length. %v != %v", len(id), selectorIDLength)
	}

	id = generateSessionID()
	if len(generateSessionID()) != sessionIDLength {
		t.Fatalf("Session ID is not of the expected length. %v != %v", len(id), sessionIDLength)
	}
}

func TestBadDatabaseConnection(t *testing.T) {
	sh := newSesHandler(sesDataAccess{}, timeout)
	if sh == nil {
		t.Fatal("Session handler should always be returned by unexported newSesHandler")
	}
}

func TestNegativeTimeoutSesCreation(t *testing.T) {
	sh1, err := NewSesHandlerWithDB(db, timeout, -timeout)
	if err != nil {
		log.Println(err)
		t.Fatal("We should not have an error with negative timeout")
	}
	if sh1.maxLifetime != 0 {
		log.Fatal("A negative timeout should produce a 0 maxLifetime")
	}
}

func TestUpdateExpiredTime(t *testing.T) {
	// We should get an update to expiration time.
	ses, _ := sh.CreateSession("dadams", true)
	now := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	ses, err := sh.UpdateSessionIfValid(ses)
	if err != nil || ses.ExpireTime().Before(now) {
		log.Println(err)
		t.Fatal("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	sesNotInDatabase := session.NewSession("", "", "", "", time.Microsecond)
	nowt := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Millisecond)
	updatedSes, err := sh.UpdateSessionIfValid(sesNotInDatabase)
	if err == nil || updatedSes != nil || nowt.Before(sesNotInDatabase.ExpireTime()) {
		log.Println(err)
		t.Fatal("Session expiration update unexpected.")
	}
}

func TestUpdateToNonPersisantShouldCreateNewSession(t *testing.T) {
	ses, _ := sh.CreateSession("username", false)
	newerSession, err := sh.UpdateSessionIfValid(ses)
	if err != nil || newerSession.SelectorID() == ses.SelectorID() || newerSession.SessionID() == ses.SessionID() || !ses.IsDestroyed() || newerSession.IsDestroyed() {
		log.Fatal("Non-persistant session should be destroyed and re-created on update")
	}
}

func TestCreateSession(t *testing.T) {
	ses, err := sh.CreateSession("thedadams", true)
	if err != nil || !ses.IsValid() || !ses.IsPersistant() {
		t.Fatal("Session not created properly")
	}

	ses, err = sh.CreateSession("thedadams", false)
	if err != nil || !ses.IsValid() || ses.IsPersistant() {
		t.Fatal("Session not created properly")
	}
}

func TestDestroySession(t *testing.T) {
	// We put the session in the database so it is destroyed
	ses, err := sh.CreateSession("anyone", true)
	err = sh.DestroySession(ses)
	if ses.IsValid() || err != nil {
		log.Println(err)
		t.Fatal("Session not destroyed.")
	}

	// Session is not in the database and should be destroyed
	sessionNotInDatabase := session.NewSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "nadams", sessionCookieName, sh.maxLifetime)
	err = sh.DestroySession(sessionNotInDatabase)
	if sessionNotInDatabase.IsValid() || err != nil {
		log.Println(err)
		t.Fatal("Session not destroyed.")
	}
}

func TestSessionExistsForUser(t *testing.T) {
	ses, _ := sh.CreateSession("dadams", true)
	exists, _ := sh.dataAccess.sessionExistsForUser(ses.Username())
	if !exists {
		t.Fatal("The user should have a session in the database")
	}

	sessionNotInDatabase := session.NewSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "nadams", sessionCookieName, sh.maxLifetime)
	exists, _ = sh.dataAccess.sessionExistsForUser(sessionNotInDatabase.Username())
	if exists {
		t.Fatal("The user should NOT have a session in the database")
	}
}

func TestParseSessionFromRequest(t *testing.T) {
	ses, _ := sh.CreateSession("dadams", true)
	r, _ := http.NewRequest("GET", "/", nil)
	_, err := sh.ParseSessionFromRequest(r)
	if err == nil {
		t.Fatal("Cookie was parsed where none exists")
	}

	r.AddCookie(ses.SessionCookie())
	sesTest, err := sh.ParseSessionFromRequest(r)
	if err != nil || !sesTest.Equals(ses) {
		log.Println(err)
		t.Fatal("Cookie not parsed properly from request")
	}
}

func TestSessionParsingFromCookie(t *testing.T) {
	ses, _ := sh.CreateSession("dadams", true)
	sessionNotInDatabase := session.NewSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "nadams", sessionCookieName, sh.maxLifetime)
	cookie := sessionNotInDatabase.SessionCookie()
	sesTest, err := sh.ParseSessionCookie(ses.SessionCookie())

	// Should be a valid cookie
	if err != nil || !ses.Equals(sesTest) {
		log.Println(err)
		t.Fatal("Session cookie not parsed properly")
	}

	// The session is not in the database so should be invalid
	sessionNotInDatabase.UpdateExpireTime(time.Second)
	cookie = sessionNotInDatabase.SessionCookie()
	sesTest, err = sh.ParseSessionCookie(cookie)
	if err == nil || sesTest != nil {
		t.Fatal("Session cookie should be invalid")
	}

	// The cookie name is not correct
	sessionNotInDatabase = session.NewSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), "thedadams", "something else", timeout)
	sesTest, err = sh.ParseSessionCookie(sessionNotInDatabase.SessionCookie())
	if err == nil || sesTest != nil {
		t.Fatal("Session cookie should be invalid")
	}
}

func TestParsingCookieDetectsPersistance(t *testing.T) {
	sesP, _ := sh.CreateSession("dadams", true)
	ses, _ := sh.CreateSession("nadams", false)

	sesPTest, _ := sh.ParseSessionCookie(sesP.SessionCookie())
	if sesPTest == nil || !sesPTest.IsPersistant() {
		log.Fatal("Persistant cookie parsed as non-persistant")
	}

	sesTest, _ := sh.ParseSessionCookie(ses.SessionCookie())
	if sesTest == nil || sesTest.IsPersistant() {
		log.Fatal("Non-persistant cookie parsed as persistant")
	}
}

func TestAttachCookieToResponseWriter(t *testing.T) {
	session, _ := sh.CreateSession("dadams", true)
	w := httptest.NewRecorder()
	err := sh.AttachCookie(w, session)
	resp := w.Result()
	attachedSession, _ := sh.ParseSessionCookie(resp.Cookies()[0])
	if err != nil || !session.Equals(attachedSession) {
		log.Fatal("Cookie not attached to response writer")
	}

	sh.DestroySession(session)
	w = httptest.NewRecorder()
	err = sh.AttachCookie(w, session)
	if err == nil || session.Equals(attachedSession) {
		log.Fatal("Invalid cookie attached to response writer")
	}
}

func TestValidateUserInputs(t *testing.T) {
	for i := 0; i < 100; i++ {
		ses := session.NewSession(generateSelectorID(), generateSessionID(), generateRandomString(12), sessionCookieName, 0)
		if !sh.validateUserInputs(ses) {
			t.Fatal("Session should have IDs and username")
		}
	}

	for i := 0; i < 100; i++ {
		ses := session.NewSession(generateSelectorID(), generateSessionID(), generateRandomString(12)+" "+generateRandomString(9), sessionCookieName, 0)
		if sh.validateUserInputs(ses) {
			log.Println(ses)
			t.Fatal("Session should NOT have IDs and username")
		}
	}
}

func TestTimeoutOfNonPersistantCookies(t *testing.T) {
	sh, _ := NewSesHandlerWithDB(db, time.Millisecond, time.Millisecond*100)
	for i := 0; i < 5; i++ {
		ses1, _ := sh.CreateSession("dadams", true)
		ses2, _ := sh.CreateSession("nadams", false)

		time.Sleep(time.Millisecond) // Wait for a short time

		ses2, err := sh.UpdateSessionIfValid(ses2)
		if err != nil || ses2.IsDestroyed() {
			log.Fatal("Non-persistant session should not be destroyed yet")
		}

		time.Sleep(time.Millisecond * 60) // Wait for clean-up to fire

		// ses2 should not be destroyed
		if sh.isValidSession(ses2) {
			log.Fatal("Non-persistant session should now be destroyed")
		}

		// Now ses1 should be in the database.
		if !sh.isValidSession(ses1) {
			t.Fatal("A persistant session should be valid")
		}

		time.Sleep(time.Millisecond * 60)

		// Now ses1 should be destroyed
		if sh.isValidSession(ses1) {
			t.Fatal("A persistant session should now be invalid")
		}
	}
}
func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	if err != nil {
		log.Fatal(err)
	}
	sh, err = NewSesHandlerWithDB(db, timeout, timeout)
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
