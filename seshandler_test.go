package seshandler

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/dadamssolutions/seshandler/session"
)

var timeout = time.Second

type FakeDataAccess struct {
	err bool
}

func (f FakeDataAccess) createTable() error {
	if f.err {
		return databaseTableCreationError()
	}
	return nil
}
func (f FakeDataAccess) insertSession() (*session.Session, error) {
	if f.err {
		return nil, databaseAccessError()
	}
	return nil, nil
}
func (f FakeDataAccess) updateSession(session *session.Session, maxLifetime time.Duration) error {
	if f.err {
		return databaseAccessError()
	}
	session.UpdateExpireTime(maxLifetime)
	return nil
}
func (f FakeDataAccess) destroySession(session *session.Session) error {
	if f.err {
		return databaseAccessError()
	}
	return nil
}
func (f FakeDataAccess) validateSession(session *session.Session) error {
	if f.err {
		return sessionNotFoundError(session.GetID())
	}
	return nil
}

func TestTableCreation(t *testing.T) {
	da := FakeDataAccess{true}
	_, err := newSesHandler(da, 0)
	if err == nil {
		t.Fatal("Expected an error in creating the database table.")
	}
	da.err = false
	_, err = newSesHandler(da, 0)
	if err != nil {
		t.Fatal("Unexpected error in creating the database table.")
	}
}

func TestUpdateExpiredTime(t *testing.T) {
	// We should get an update to expiration time.
	da := FakeDataAccess{false}
	sh, _ := newSesHandler(&da, timeout)
	session := session.NewSession("", "", "", sh.maxLifetime)
	now := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err := sh.UpdateSession(session)
	if err != nil || session.GetExpireTime().Before(now) {
		log.Fatal("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	da.err = true
	nowt := time.Now().Add(sh.maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err = sh.UpdateSession(session)
	if err == nil || nowt.Before(session.GetExpireTime()) {
		log.Fatal("Session expiration update unexpected.")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	os.Exit(m.Run())
}
