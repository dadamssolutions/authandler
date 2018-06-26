package seshandler

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var timeout = time.Minute
var db, err = sql.Open("postgres", "user=test dbname=postgres sslmode=disable")
var da sesDataAccess
var sh *SesHandler
var sessionNotInDatabase = newSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "nonone", timeout)
var sessionInDatabase *Session

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
	now := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err := sh.UpdateSessionIfValid(sessionInDatabase)
	if err != nil || sessionInDatabase.getExpireTime().Before(now) {
		log.Println(err)
		t.Fatal("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	nowt := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err = sh.UpdateSessionIfValid(sessionNotInDatabase)
	if err == nil || nowt.Before(sessionNotInDatabase.getExpireTime()) {
		log.Println(err)
		t.Fatal("Session expiration update unexpected.")
	}
}

func TestUpdateToNonPersisantShouldCreateNewSession(t *testing.T) {
	session, _ := sh.CreateSession("username", false)
	selectorID, sessionID := session.getSelectorID(), session.getSessionID()
	err := sh.UpdateSessionIfValid(session)
	if err != nil || selectorID == session.getSelectorID() || sessionID == session.getSessionID() || session.isDestroyed() {
		log.Fatal("Non-persistant session should be destroyed and re-created on update")
	}
}

func TestCreateSession(t *testing.T) {
	s, err := sh.CreateSession("thedadams", true)
	if err != nil || !s.isValid() || !s.isPersistant() {
		t.Fatal("Session not created properly")
	}

	s, err = sh.CreateSession("thedadams", false)
	if err != nil || !s.isValid() || s.isPersistant() {
		t.Fatal("Session not created properly")
	}
}

func TestDestroySession(t *testing.T) {
	// We put the session in the database so it is destroyed
	s, err := sh.CreateSession("anyone", true)
	err = sh.DestroySession(s)
	if s.isValid() || err != nil {
		log.Println(err)
		t.Fatal("Session not destroyed.")
	}

	// Session is not in the database and should be destroyed
	sessionNotInDatabase.destroyed = true
	err = sh.DestroySession(sessionNotInDatabase)
	if sessionNotInDatabase.isValid() || err != nil {
		log.Println(err)
		t.Fatal("Session not destroyed.")
	}
}

func TestSessionExistsForUser(t *testing.T) {
	exists, _ := sh.dataAccess.sessionExistsForUser(sessionInDatabase.username)
	if !exists {
		t.Fatal("The user should have a session in the database")
	}

	exists, _ = sh.dataAccess.sessionExistsForUser(sessionNotInDatabase.username)
	if exists {
		t.Fatal("The user should NOT have a session in the database")
	}
}

func TestParseSessionFromRequest(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	_, err := sh.ParseSessionFromRequest(r)
	if err == nil {
		t.Fatal("Cookie was parsed where none exists")
	}

	r.AddCookie(sessionInDatabase.cookie)
	sesTest, err := sh.ParseSessionFromRequest(r)
	if err != nil || !sesTest.Equals(sessionInDatabase) {
		log.Println(err)
		t.Fatal("Cookie not parsed properly from request")
	}

	anotherSession, _ := sh.CreateSession("somone", true)
	r, _ = http.NewRequest("GET", "/", nil)
	sh.DestroySession(anotherSession)
	r.AddCookie(anotherSession.cookie)
	sesTest, err = sh.ParseSessionFromRequest(r)
	if err == nil || sesTest != nil {
		log.Println(err)
		log.Println(sesTest)
		t.Fatal("Cookie parse when none should be")
	}
}

func TestSessionParsingFromCookie(t *testing.T) {
	ses := newSession(strings.Repeat("d", selectorIDLength), strings.Repeat("d", sessionIDLength), "thedadams", timeout)
	cookie, _ := ses.sessionCookie()
	sesTest, err := sh.ParseSessionCookie(sessionInDatabase.cookie)

	// Should be a valid cookie
	if err != nil || !sessionInDatabase.Equals(sesTest) {
		log.Println(err)
		t.Fatal("Session cookie not parsed properly")
	}

	// The cookie is expired so it should not be valid
	sh.maxLifetime = -time.Second
	anotherSession, _ := sh.CreateSession("dadams", true)
	sesTest, err = sh.ParseSessionCookie(anotherSession.cookie)
	userSessionExists, _ := sh.dataAccess.sessionExistsForUser("dadams")
	if err == nil || sesTest != nil || userSessionExists {
		t.Fatal("Session cookie should be invalid because it is expired")
	}
	// Reset session handler maxlife for the rest of the tests
	sh.maxLifetime = timeout

	// The session is not in the database so should be invalid
	ses.cookie.Expires = time.Now().Add(time.Second)
	ses.cookie.Value = ses.cookieValue()
	cookie, _ = ses.sessionCookie()
	sesTest, err = sh.ParseSessionCookie(cookie)
	if err == nil || sesTest != nil {
		t.Fatal("Session cookie should be invalid")
	}

	// The cookie name is not correct
	ses.cookie.Name = "Something else"
	sesTest, err = sh.ParseSessionCookie(cookie)
	if err == nil || sesTest != nil {
		t.Fatal("Session cookie should be invalid")
	}
}

func TestValidateUserInputs(t *testing.T) {
	for i := 0; i < 100; i++ {
		ses := newSession(generateSelectorID(), generateSessionID(), generateRandomString(12), 0)
		if !sh.validateUserInputs(ses) {
			t.Fatal("Session should have IDs and username")
		}
	}

	for i := 0; i < 100; i++ {
		ses := newSession(generateSelectorID(), generateSessionID(), generateRandomString(12)+" "+generateRandomString(9), 0)
		if sh.validateUserInputs(ses) {
			log.Println(ses)
			t.Fatal("Session should NOT have IDs and username")
		}
	}
}

func TestTimeoutOfNonPersistantCookies(t *testing.T) {
	sh, _ := NewSesHandlerWithDB(db, time.Millisecond, time.Millisecond*300)
	for i := 0; i < 5; i++ {
		ses1, _ := sh.CreateSession("dadams", true)
		ses2, _ := sh.CreateSession("nadams", false)

		time.Sleep(time.Millisecond) // Wait for a short time

		err := sh.UpdateSessionIfValid(ses1)
		if err != nil || ses2.isDestroyed() {
			log.Fatal("Non-persistant session should not be destroyed yet")
		}

		time.Sleep(time.Millisecond * 100) // Wait for clean-up to fire

		// ses2 should not be destroyed
		if sh.isValidSession(ses2) {
			log.Fatal("Non-persistant session should now be destroyed")
		}

		// Now ses1 should be in the database.
		if !sh.isValidSession(ses1) {
			t.Fatal("A persistant session should be valid")
		}

		time.Sleep(time.Millisecond * 500)

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
	sessionInDatabase, err = sh.CreateSession("thedadams", true)
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
