package seshandler

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

var timeout = time.Minute
var db, err = sql.Open("postgres", "user=test dbname=postgres sslmode=disable")
var da = &sesAccess{db}
var sessionNotInDatabase = newSession(strings.Repeat("a", selectorIDLength), strings.Repeat("a", sessionIDLength), "nonone", timeout)
var sessionInDatabase *Session

func TestUpdateExpiredTime(t *testing.T) {
	// We should get an update to expiration time.
	sh, _ := newSesHandler(da, timeout)
	now := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err := sh.UpdateSession(sessionInDatabase)
	if err != nil || sessionInDatabase.getExpireTime().Before(now) {
		log.Println(err)
		log.Fatal("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	nowt := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err = sh.UpdateSession(sessionNotInDatabase)
	if err == nil || nowt.Before(sessionNotInDatabase.getExpireTime()) {
		log.Fatal("Session expiration update unexpected.")
	}
}

func TestIDGenerators(t *testing.T) {
	id := generateSelectorID()
	if len(id) != selectorIDLength {
		log.Fatalf("Selector ID is not of the expected length. %v != %v", len(id), selectorIDLength)
	}

	id = generateSessionID()
	if len(generateSessionID()) != sessionIDLength {
		log.Fatalf("Session ID is not of the expected length. %v != %v", len(id), sessionIDLength)
	}
}

func TestCreateSession(t *testing.T) {
	sh, _ := newSesHandler(da, timeout)
	s, err := sh.CreateSession("thedadams", false)
	if err != nil || !s.isValid() || s.isSessionOnly() {
		log.Fatal("Session not created properly")
	}

	s, err = sh.CreateSession("thedadams", true)
	if err != nil || !s.isValid() || !s.isSessionOnly() {
		log.Fatal("Session not created properly")
	}
}

func TestDestroySession(t *testing.T) {
	sh, _ := newSesHandler(da, timeout)
	s, err := sh.CreateSession("anyone", false)
	err = sh.DestroySession(s)
	if s.isValid() || err != nil {
		log.Println(err)
		log.Fatal("Session not destroyed.")
	}
	sessionNotInDatabase.destroyed = false
	err = sh.DestroySession(sessionNotInDatabase)
	if !sessionNotInDatabase.isValid() || err == nil {
		log.Println(err)
		log.Fatal("Session destroyed unexpectedly.")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	if err != nil {
		log.Fatal(err)
	}
	da := sesAccess{db}
	err = da.createTable()
	if err != nil {
		log.Fatal(err)
	}
	sessionInDatabase, err = da.createSession("thedadams", timeout, false)
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	err = da.dropTable()
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(num)
}
