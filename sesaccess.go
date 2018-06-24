package seshandler

import (
	"database/sql"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	databaseCreation  = "CREATE TABLE IF NOT EXISTS sessions (id char(16) NOT NULL, session_hash char(64) NOT NULL, user_id NOT NULL, created timestamp, expiration timestamp, session_only boolean, PRIMARY KEY (id);"
	insertSession     = "INSERT INTO sessions(id, session_hash, user_id, created, expiration, session_only) VALUES($1, $2, $3, $4, $5);"
	userSessionExists = "SELECT count(*) FROM sessions WHERE user_id = $1"
	deleteSession     = "DELETE FROM sessions WHERE id = $1 AND session_hash = $2 AND user_id = $3;"
	getSessionInfo    = "SELECT (id, session_hash, user_id, expiration) FROM sessions WHERE id = $1;"
	updateSession     = "UPDATE sessions SET expiration = $1 WHERE id_hash = $2;"
)

type dataAccessLayer interface {
	createTable() error
	createSession(string, time.Duration, bool) (*Session, error)
	updateSession(*Session, time.Duration) error
	destroySession(*Session) error
	validateSession(*Session) error
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

func (s sesAccess) createSession(username string, maxLifetime time.Duration, sessionOnly bool) (*Session, error) {
	if sessionOnly {
		maxLifetime = 0
	}
	var id, sessionID string
	var err error
	var tx *sql.Tx
	var session *Session
	for true {
		id, sessionID = generateSelectorID(), generateSessionID()
		tx, err = s.Begin()
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		session = newSession(id, sessionID, username, maxLifetime)
		_, err = tx.Exec(insertSession, session.getID(), hashString(session.hashPayload()), username, time.Now(), session.getExpireTime(), maxLifetime == 0)
		if err != nil {
			if e, ok := err.(pq.Error); ok {
				// This error code means that the uniqueness of id has been violated
				// We try again in this case.
				if strings.Compare(string(e.Code), "23505") == 0 {
					continue
				}
			}
			tx.Rollback()
			return nil, err
		}
	}
	return session, tx.Commit()
}

func (s sesAccess) sessionExistsForUser(username string) (bool, error) {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return true, err
	}
	var count int
	err = tx.QueryRow(userSessionExists, username).Scan(&count)
	if err != nil {
		return true, err
	}
	err = tx.Commit()
	if err != nil {
		return true, err
	}
	return count > 0, nil
}

func (s sesAccess) destroySession(session *Session) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(deleteSession, session.getID(), hashString(session.hashPayload()), session.getUsername())
	if err != nil {
		tx.Rollback()
		return err
	}
	session = nil
	return tx.Commit()
}

func (s sesAccess) updateSession(session *Session, maxLifetime time.Duration) error {
	tx, err := s.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec(updateSession, session.getExpireTime().Add(maxLifetime), hashString(session.hashPayload()))
	if err != nil {
		tx.Rollback()
		return err
	}
	session.updateExpireTime(maxLifetime)
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
