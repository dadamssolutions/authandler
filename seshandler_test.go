package seshandler

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

var timeout = time.Second

type FakeDataAccess struct {
	err bool
}

// Fake functions to satisfy data access interface.
func (f FakeDataAccess) createTable() error {
	if f.err {
		return databaseTableCreationError()
	}
	return nil
}
func (f FakeDataAccess) createSession(username string, maxLifetime time.Duration, sessionOnly bool) (*Session, error) {
	if f.err {
		return nil, databaseAccessError()
	}
	return newSession(generateSelectorID(), generateSessionID(), username, maxLifetime), nil
}
func (f FakeDataAccess) updateSession(session *Session, maxLifetime time.Duration) error {
	if f.err {
		return databaseAccessError()
	}
	session.updateExpireTime(maxLifetime)
	return nil
}
func (f FakeDataAccess) destroySession(session *Session) error {
	if f.err {
		return databaseAccessError()
	}
	session.destroy()
	return nil
}
func (f FakeDataAccess) validateSession(session *Session) error {
	if f.err {
		return sessionNotFoundError(session.getID())
	}
	return nil
}

func TestTableCreation(t *testing.T) {
	da := FakeDataAccess{true}
	_, err := newSesHandler(da, 0)
	if err == nil {
		t.Fatalf("Expected an error in creating the database table.")
	}
	da.err = false
	_, err = newSesHandler(da, 0)
	if err != nil {
		t.Fatalf("Unexpected error in creating the database table.")
	}
}

func TestUpdateExpiredTime(t *testing.T) {
	// We should get an update to expiration time.
	da := FakeDataAccess{false}
	sh, _ := newSesHandler(&da, timeout)
	session := newSession("", "", "", sh.maxLifetime)
	now := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err := sh.UpdateSession(session)
	if err != nil || session.getExpireTime().Before(now) {
		log.Fatal("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	da.err = true
	nowt := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err = sh.UpdateSession(session)
	if err == nil || nowt.Before(session.getExpireTime()) {
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
	da := FakeDataAccess{false}
	sh, _ := newSesHandler(&da, timeout)
	now := time.Now()
	s, err := sh.CreateSession("thedadams", false)
	if err != nil || s == nil || strings.Compare(s.getUsername(), "thedadams") != 0 || len(s.id) != selectorIDLength || len(s.sessionID) != sessionIDLength || s.getExpireTime().Before(now) || s.isExpired() {
		log.Fatal("Session not created properly")
	}

}

func TestDestroySession(t *testing.T) {
	da := FakeDataAccess{false}
	sh, _ := newSesHandler(&da, timeout)
	s, err := sh.CreateSession("thedadams", false)
	err = sh.DestroySession(s)
	if s.isValid() || err != nil {
		log.Fatal("Session not destroyed.")
	}

	s, _ = sh.CreateSession("thedadams", false)
	da.err = true
	err = sh.DestroySession(s)
	if !s.isValid() || err == nil {
		log.Fatal("Session destroyed unexpectedly.")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	os.Exit(m.Run())
}
