package seshandler

import (
	"testing"
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
func (f FakeDataAccess) createSession() (string, error) {
	if f.err {
		return "", databaseAccessError()
	}
	return "", nil
}
func (f FakeDataAccess) updateSession(sessionID string) error {
	if f.err {
		return databaseAccessError()
	}
	return nil
}
func (f FakeDataAccess) destroySession(sessionID string) error {
	if f.err {
		return databaseAccessError()
	}
	return nil
}
func (f FakeDataAccess) validateSession(sessionID string) error {
	if f.err {
		return sessionNotFoundError(sessionID)
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
