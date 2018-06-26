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
	sh1, err := NewSesHandlerWithDB(db, -timeout, timeout)
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
	err := sh.UpdateSession(sessionInDatabase)
	if err != nil || sessionInDatabase.getExpireTime().Before(now) {
		log.Println(err)
		t.Fatal("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	nowt := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err = sh.UpdateSession(sessionNotInDatabase)
	if err == nil || nowt.Before(sessionNotInDatabase.getExpireTime()) {
		log.Println(err)
		t.Fatal("Session expiration update unexpected.")
	}
}

func TestCreateSession(t *testing.T) {
	s, err := sh.CreateSession("thedadams", false)
	if err != nil || !s.isValid() || s.isSessionOnly() {
		t.Fatal("Session not created properly")
	}

	s, err = sh.CreateSession("thedadams", true)
	if err != nil || !s.isValid() || !s.isSessionOnly() {
		t.Fatal("Session not created properly")
	}
}

func TestDestroySession(t *testing.T) {
	// We put the session in the database so it is destroyed
	s, err := sh.CreateSession("anyone", false)
	err = sh.DestroySession(s)
	if s.isValid() || err != nil {
		log.Println(err)
		t.Fatal("Session not destroyed.")
	}

	// Session is not in the database and should be destroyed
	sessionNotInDatabase.destroyed = false
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
	anotherSession, _ := sh.CreateSession("dadams", false)
	sesTest, err = sh.ParseSessionCookie(anotherSession.cookie)
	userSessionExists, _ := sh.dataAccess.sessionExistsForUser("dadams")
	log.Println(err)
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

func TestTimeoutOfSessionOnlyCookies(t *testing.T) {
	sh, _ := NewSesHandlerWithDB(db, time.Millisecond*100, time.Microsecond)
	ses, _ := sh.CreateSession("long", false)
	for i := 0; i < 10; i++ {
		ses1, _ := sh.CreateSession("dadams", false)
		ses2, _ := sh.CreateSession("nadams", true)

		time.Sleep(time.Millisecond * 30) // Wait for the clean up to fire

		// Now ses1 should be in the database.
		if !sh.IsValidSession(ses1) {
			log.Println(i)
			t.Fatal("A persistant session should be valid")
		}

		// Now ses2 should NOT be in the database.
		if sh.IsValidSession(ses2) {
			log.Println(i)
			t.Fatal("A session only cookie should be removed from the database")
		}
	}

	// The first session created should also be timed-out after all this.
	if sh.IsValidSession(ses) {
		t.Fatal("Timed-out persistant sessions should also be removed")
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
	sessionInDatabase, err = sh.CreateSession("thedadams", false)
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
