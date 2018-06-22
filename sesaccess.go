package seshandler

import "database/sql"

const (
	databaseCreation = "CREATE TABLE IF NOT EXISTS sessions (id char(64) NOT NULL, ip cidr NOT NULL, user_id NOT NULL, PRIMARY KEY (id, ip, user_id);"
)

type dataAccessLayer interface {
	createTable() error
	createSession() (string, error)
	updateSession(string) error
	destroySession(string) error
	validateSession(string) error
}

type sesAccess struct {
	*sql.DB
}

func (s sesAccess) createTable() error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError()
	}
	_, err = tx.Exec(databaseCreation)
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError()
	}
	return tx.Commit()
}

func (s sesAccess) createSession() (string, error) {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return "", err
	}
	// TODO
	return "", tx.Commit()

}

func (s sesAccess) updateSession(sessionID string) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	// TODO
	return tx.Commit()
}

func (s sesAccess) destroySession(sessionID string) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	// TODO
	return tx.Commit()
}

func (s sesAccess) validateSession(sessionID string) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	// TODO
	return tx.Commit()
}
