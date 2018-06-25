package seshandler

import (
	"database/sql"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	tableCreation     = "CREATE TABLE IF NOT EXISTS sessions (id char(16), session_hash varchar NOT NULL, user_id varchar NOT NULL, created timestamp WITH TIME ZONE NOT NULL, expiration timestamp WITH TIME ZONE NOT NULL, session_only boolean NOT NULL, PRIMARY KEY (id));"
	dropTable         = "DROP TABLE sessions;"
	insertSession     = "INSERT INTO sessions(id, session_hash, user_id, created, expiration, session_only) VALUES($1, $2, $3, $4, $5, $6);"
	userSessionExists = "SELECT count(*) FROM sessions WHERE user_id = $1;"
	deleteSession     = "DELETE FROM sessions WHERE id = $1;"
	getSessionInfo    = "SELECT id, session_hash, user_id, expiration, session_only FROM sessions WHERE id = $1;"
	updateSession     = "UPDATE sessions SET expiration = $1 WHERE id = $2;"
)

type sesDataAccess struct {
	*sql.DB
}

func (s sesDataAccess) createTable() error {
	tx, err := s.Begin()
	if err != nil {
		return databaseTableCreationError()
	}
	_, err = tx.Exec(tableCreation)
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError()
	}
	return tx.Commit()
}

func (s sesDataAccess) dropTable() error {
	tx, err := s.Begin()
	if err != nil {
		return databaseTableCreationError()
	}
	_, err = tx.Exec(dropTable)
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError()
	}
	return tx.Commit()
}

func (s sesDataAccess) createSession(username string, maxLifetime time.Duration, sessionOnly bool) (*Session, error) {
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
			return nil, err
		}
		session = newSession(id, sessionID, username, maxLifetime)
		_, err = tx.Exec(insertSession, session.getID(), hashString(session.hashPayload()), username, time.Now(), session.getExpireTime(), maxLifetime == 0)
		if err != nil {
			if e, ok := err.(pq.Error); ok {
				// This error code means that the uniqueness of id has been violated
				// We try again in this case.
				if strings.Compare(string(e.Code), "23505") == 0 {
					tx.Rollback()
					continue
				}
			}
			tx.Rollback()
			return nil, err
		}
		break
	}
	return session, tx.Commit()
}

func (s sesDataAccess) sessionExistsForUser(username string) (bool, error) {
	tx, err := s.Begin()
	if err != nil {
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

func (s sesDataAccess) destroySession(session *Session) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}

	tx.Exec(deleteSession, session.getID())
	session.destroy()
	return tx.Commit()
}

func (s sesDataAccess) updateSession(session *Session, maxLifetime time.Duration) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	tx.Exec(updateSession, session.getExpireTime().Add(maxLifetime), session.getID())

	session.updateExpireTime(maxLifetime)
	return tx.Commit()
}

func (s sesDataAccess) validateSession(session *Session) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	dbSession := newSession("", session.sessionID, "", 0)
	var dbHash string
	var sessionOnly bool
	err = tx.QueryRow(getSessionInfo, session.getID()).Scan(&dbSession.id, &dbHash, &dbSession.username, &dbSession.cookie.Expires, &sessionOnly)
	if err != nil || !session.Equals(dbSession) {
		tx.Rollback()
		s.destroySession(session)
		return sessionNotInDatabaseError(session.getID())
	}
	if dbSession.isExpired() {
		tx.Rollback()
		s.destroySession(session)
		return sessionExpiredError(session.getID())
	}
	session.cookie.Expires = dbSession.getExpireTime()
	return tx.Commit()
}
