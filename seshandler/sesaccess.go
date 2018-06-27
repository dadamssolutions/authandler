package seshandler

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dadamssolutions/authandler/seshandler/session"
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
		return sesAccess, badDatabaseConnectionError()
	}
	err := sesAccess.createTable()
	if err != nil {
		return sesAccess, err
	}

	// Each time this ticks, we will clean the database of old sessions.
	c := time.Tick(sessionTimeout)
	go sesAccess.cleanUpOldSessions(c, int(sessionTimeout/time.Microsecond), int(persistantSessionTimeout/time.Microsecond))
	return sesAccess, nil
}

func (s sesDataAccess) createTable() error {
	tx, err := s.Begin()
	if err != nil {
		return databaseTableCreationError()
	}
	// Create the table we need in the database
	_, err = tx.Exec(tableCreation)
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError()
	}
	log.Println("Sessions table created.")
	return tx.Commit()
}

func (s sesDataAccess) cleanUpOldSessions(c <-chan time.Time, sessionTimeout, persistantSessionTimeout int) {
	log.Println("Waiting to clean old sessions...")
	for range c {
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

// dropTable is used in testing to clear the database each time.
func (s sesDataAccess) dropTable() error {
	tx, err := s.Begin()
	if err != nil {
		return databaseTableCreationError()
	}
	// Drop the sessions table
	_, err = tx.Exec(dropTable)
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError()
	}
	return tx.Commit()
}

func (s sesDataAccess) createSession(username string, maxLifetime time.Duration, persistant bool) (*session.Session, error) {
	if !persistant {
		maxLifetime = 0
	}
	var selectorID, sessionID string
	var err error
	var tx *sql.Tx
	var ses *session.Session

	// We need to loop until we generate unique selector and session IDs
	for true {
		selectorID, sessionID = generateSelectorID(), generateSessionID()
		tx, err = s.Begin()
		if err != nil {
			return nil, err
		}
		ses = session.NewSession(selectorID, sessionID, username, sessionCookieName, maxLifetime)
		queryString := fmt.Sprintf(insertSession, ses.SelectorID(), hashString(ses.HashPayload()), username, time.Now().Format(timestampFormat), ses.ExpireTime().Format(timestampFormat), persistant)
		_, err = tx.Exec(queryString)
		if err != nil {
			if e, ok := err.(pq.Error); ok {
				// This error code means that the uniqueness of ids has been violated
				// We try again in this case.
				if string(e.Code) == "23505" {
					tx.Rollback()
					continue
				}
			}
			tx.Rollback()
			return nil, err
		}
		// We have the ids so we break and return
		break
	}
	return ses, tx.Commit()
}

// getSessionInfo pulls the session out of the database.
// No validation is done here. That must be done elsewhere.
func (s sesDataAccess) getSessionInfo(selectorID, sessionID string, maxLifetime time.Duration) (*session.Session, error) {
	var dbHash, username string
	var expires time.Time
	var persistant bool
	var ses *session.Session
	tx, err := s.Begin()
	if err != nil {
		return nil, err
	}
	queryString := fmt.Sprintf(getSessionInfo, selectorID)
	err = tx.QueryRow(queryString).Scan(&selectorID, &dbHash, &username, &expires, &persistant)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	err = tx.Commit()
	// If the session is persistant, then we set the expiration to maxLifetime
	if persistant {
		ses = session.NewSession(selectorID, sessionID, username, sessionCookieName, maxLifetime)
	} else {
		ses = session.NewSession(selectorID, sessionID, username, sessionCookieName, 0)
	}
	return ses, err
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

func (s sesDataAccess) destroySession(ses *session.Session) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	queryString := fmt.Sprintf(deleteSession, ses.SelectorID())
	tx.Exec(queryString)
	ses.Destroy()
	return tx.Commit()
}

// updateSession indicates that the session is active and the expiration needs to be updated.
func (s sesDataAccess) updateSession(ses *session.Session, maxLifetime time.Duration) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	queryString := fmt.Sprintf(updateSession, ses.ExpireTime().Add(maxLifetime).Format(timestampFormat), ses.SelectorID())
	_, err = tx.Exec(queryString)
	if err != nil {
		tx.Rollback()
		return err
	}
	ses.UpdateExpireTime(maxLifetime)
	return tx.Commit()
}

// validateSession pulls the info for a session out of the database and checks that the session is valid
// i.e. neither destroyed nor expired
func (s sesDataAccess) validateSession(ses *session.Session, maxLifetime time.Duration) error {
	dbSession, err := s.getSessionInfo(ses.SelectorID(), ses.SessionID(), maxLifetime)
	if err != nil || !ses.Equals(dbSession, hashString) {
		s.destroySession(ses)
		return sessionNotInDatabaseError(ses.SelectorID())
	}

	if !ses.IsValid() {
		s.destroySession(ses)
		return sessionExpiredError(ses.SelectorID())
	}
	return nil
}
