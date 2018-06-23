package seshandler

import (
	"fmt"
	"log"
	"testing"
	"time"
)

type FakeDataAccess struct {
	err bool
}

func (f FakeDataAccess) createTable() error {
	if f.err {
		return databaseTableCreationError()
	}
	return nil
}
func (f FakeDataAccess) insertSession() (*Session, error) {
	if f.err {
		return nil, databaseAccessError()
	}
	return nil, nil
}
func (f FakeDataAccess) updateSession(session *Session) error {
	if f.err {
		return databaseAccessError()
	}
	session.updateExpireTime()
	return nil
}
func (f FakeDataAccess) destroySession(session *Session) error {
	if f.err {
		return databaseAccessError()
	}
	return nil
}
func (f FakeDataAccess) validateSession(session *Session) error {
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
	sh, _ := newSesHandler(&da, 0)
	session := NewSession("", "", "")
	now := time.Now().Add(maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err := sh.UpdateSession(session)
	if err != nil || session.expireTime.Before(now) {
		log.Fatal("Session expiration not updated.")
	}

	// Now we should not get an update to expiration time.
	da.err = true
	nowt := time.Now().Add(maxLifetime)
	time.Sleep(time.Microsecond * 2)
	err = sh.UpdateSession(session)
	if err == nil || nowt.Before(session.expireTime) {
		fmt.Println(nowt)
		fmt.Println(session.expireTime)
		log.Fatal("Session expiration update unexpected.")
	}
}
