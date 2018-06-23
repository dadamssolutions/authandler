package seshandler

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
)

const (
	idLength         = 64
	databaseCreation = "CREATE TABLE IF NOT EXISTS sessions (id char(64) NOT NULL UNIQUE, ip cidr NOT NULL, user_id NOT NULL expiration timestamp, PRIMARY KEY (id, ip, user_id);"
	getSessionInfo   = "SELECT (id, ip, user_id) FROM sessions WHERE id = $1;"
	updateSession    = "UPDATE sessions SET expiration = $1 WHERE id = $2;"
)

type dataAccessLayer interface {
	createTable() error
	insertSession() (*Session, error)
	updateSession(*Session) error
	destroySession(*Session) error
	validateSession(*Session) error
}

type sesAccess struct {
	*sql.DB
}

func enerateID() string {
	b := make([]byte, idLength)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
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

func (s sesAccess) insertSession() (*Session, error) {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	// TODO
	return nil, tx.Commit()

}

func (s sesAccess) updateSession(session *Session) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(updateSession, session.expireTime.Add(maxLifetime), session.GetID())
	if err != nil {
		tx.Rollback()
		return err
	}
	session.updateExpireTime()
	return tx.Commit()
}

func (s sesAccess) destroySession(session *Session) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	// TODO
	return tx.Commit()
}

func (s sesAccess) validateSession(session *Session) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	// TODO
	return tx.Commit()
}
