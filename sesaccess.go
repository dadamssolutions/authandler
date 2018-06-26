package seshandler

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lib/pq"
)

const (
	timestampFormat    = "2006-01-02 15:04:05.000 -0700"
	tableCreation      = "CREATE TABLE IF NOT EXISTS sessions (selector char(16), session_hash varchar NOT NULL, user_id varchar NOT NULL, created timestamp WITH TIME ZONE NOT NULL, expiration timestamp WITH TIME ZONE NOT NULL, persistant boolean NOT NULL, PRIMARY KEY (selector));"
	dropTable          = "DROP TABLE sessions;"
	insertSession      = "INSERT INTO sessions(selector, session_hash, user_id, created, expiration, persistant) VALUES('%v', '%v', '%v', '%v', '%v', '%v');"
	userSessionExists  = "SELECT count(*) FROM sessions WHERE user_id = '%v';"
	deleteSession      = "DELETE FROM sessions WHERE selector = '%v';"
	getSessionInfo     = "SELECT selector, session_hash, user_id, expiration, persistant FROM sessions WHERE selector = '%v';"
	updateSession      = "UPDATE sessions SET expiration = '%v' WHERE selector = '%v';"
	cleanUpOldSessions = "DELETE FROM sessions WHERE (NOT persistant AND created < NOW() - INTERVAL '%v MICROSECOND') OR (persistant AND expiration < NOW() - INTERVAL '%v MICROSECOND');"
)

type sesDataAccess struct {
	*sql.DB
	lock *sync.RWMutex
}

func newDataAccess(db *sql.DB, sessionTimeout, persistantSessionTimeout time.Duration) (sesDataAccess, error) {
	sesAccess := sesDataAccess{db, &sync.RWMutex{}}
	if sesAccess.DB == nil {
		log.Println("Cannot connect to the database")
		return sesAccess, nil
	}
	err := sesAccess.createTable()
	if err != nil {
		return sesAccess, err
	}
	c := time.Tick(60 * sessionTimeout)
	// TODO: should we switch this to seconds?
	go sesAccess.cleanUpOldSessions(c, int(sessionTimeout/time.Microsecond), int(persistantSessionTimeout/time.Microsecond))
	return sesAccess, nil
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

func (s sesDataAccess) cleanUpOldSessions(c <-chan time.Time, sessionTimeout, persistantSessionTimeout int) {
	for range c {
		log.Println("Cleaning up old session.")
		tx, err := s.Begin()
		if err != nil {
			log.Println("We have stopped cleaning up old sessions")
			log.Println(err)
			return
		}
		// Clean up old sessions that are not persistant and are older than maxLifetimeSessionOnly
		// Also clean up old expired persistant sessions.
		_, err = tx.Exec(fmt.Sprintf(cleanUpOldSessions, sessionTimeout, persistantSessionTimeout))
		if err != nil {
			tx.Rollback()
			log.Println("We have stopped cleaning up old sessions")
			log.Println(err)
			return
		}
		tx.Commit()
	}
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

func (s sesDataAccess) createSession(username string, maxLifetime time.Duration, persistant bool) (*Session, error) {
	if !persistant {
		maxLifetime = 0
	}
	var selectorID, sessionID string
	var err error
	var tx *sql.Tx
	var session *Session
	for true {
		selectorID, sessionID = generateSelectorID(), generateSessionID()
		tx, err = s.Begin()
		if err != nil {
			return nil, err
		}
		session = newSession(selectorID, sessionID, username, maxLifetime)
		queryString := fmt.Sprintf(insertSession, session.getSelectorID(), hashString(session.hashPayload()), username, time.Now().Format(timestampFormat), session.getExpireTime().Format(timestampFormat), persistant)
		_, err = tx.Exec(queryString)
		if err != nil {
			if e, ok := err.(pq.Error); ok {
				// This error code means that the uniqueness of id has been violated
				// We try again in this case.
				if string(e.Code) == "23505" {
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
	queryString := fmt.Sprintf(userSessionExists, username)
	err = tx.QueryRow(queryString).Scan(&count)
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
	queryString := fmt.Sprintf(deleteSession, session.getSelectorID())
	tx.Exec(queryString)
	session.destroy()
	return tx.Commit()
}

func (s sesDataAccess) updateSession(session *Session, maxLifetime time.Duration) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	queryString := fmt.Sprintf(updateSession, session.getExpireTime().Add(maxLifetime).Format(timestampFormat), session.getSelectorID())
	_, err = tx.Exec(queryString)
	if err != nil {
		tx.Rollback()
		return err
	}
	session.updateExpireTime(maxLifetime)
	return tx.Commit()
}

func (s sesDataAccess) validateSession(session *Session) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	dbSession := newSession("", session.getSessionID(), "", 0)
	var dbHash string
	queryString := fmt.Sprintf(getSessionInfo, session.getSelectorID())
	err = tx.QueryRow(queryString).Scan(&dbSession.selectorID, &dbHash, &dbSession.username, &dbSession.cookie.Expires, &dbSession.persistant)
	if err != nil || !session.Equals(dbSession) {
		tx.Rollback()
		s.destroySession(session)
		return sessionNotInDatabaseError(session.getSelectorID())
	}

	if !dbSession.isValid() {
		tx.Rollback()
		s.destroySession(session)
		return sessionExpiredError(session.getSelectorID())
	}

	session.cookie.Expires = dbSession.getExpireTime()
	return tx.Commit()
}
