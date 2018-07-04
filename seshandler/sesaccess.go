package seshandler

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/dadamssolutions/authandler/seshandler/session"
	"github.com/lib/pq"
)

const (
	timestampFormat    = "2006-01-02 15:04:05.000 -0700"
	tableCreation      = "CREATE TABLE IF NOT EXISTS sessions (selector char(16), session_hash varchar NOT NULL, user_id varchar NOT NULL, created timestamp WITH TIME ZONE NOT NULL, expiration timestamp WITH TIME ZONE NOT NULL, persistant boolean NOT NULL, PRIMARY KEY (selector)); DELETE FROM sessions;"
	dropTable          = "DROP TABLE sessions;"
	insertSession      = "INSERT INTO sessions(selector, session_hash, user_id, created, expiration, persistant) VALUES('%v', '%v', '%v', '%v', '%v', '%v');"
	userSessionExists  = "SELECT count(*) FROM sessions WHERE user_id = '%v';"
	deleteSession      = "DELETE FROM sessions WHERE selector = '%v';"
	getSessionInfo     = "SELECT selector, session_hash, user_id, expiration, persistant FROM sessions WHERE selector = '%v';"
	updateSession      = "UPDATE sessions SET expiration = '%v' WHERE selector = '%v';"
	cleanUpOldSessions = "DELETE FROM sessions WHERE (NOT persistant AND created < NOW() - INTERVAL '%v SECONDS') OR (persistant AND expiration < NOW() - INTERVAL '%v SECONDS') RETURNING selector;"
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
		log.Printf("Could not create the table in the database: %v\n", err)
		return sesAccess, err
	}

	// Each time this ticks, we will clean the database of old sessions.
	c := time.Tick(sessionTimeout)
	go sesAccess.cleanUpOldSessions(c, sessionTimeout.Seconds(), persistantSessionTimeout.Seconds())
	return sesAccess, nil
}

// hashString is a helper function to has the session ID before putting it into the database
func (s sesDataAccess) hashString(data string) string {
	hashBytes := sha256.Sum256([]byte(data))
	return url.QueryEscape(base64.RawURLEncoding.EncodeToString(hashBytes[:]))
}

// generateRandomString is a helper function to find selector and session IDs
func (s sesDataAccess) generateRandomString(length int) string {
	if length <= 0 {
		log.Panicln("Cannot generate a random string of negative length")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	b := make([]byte, length)
	st := ""
	for true {
		_, err := rand.Read(b)
		if err != nil {
			log.Panicf("ERROR: %v\n", err)
		}
		st = base64.RawURLEncoding.EncodeToString(b)[:length]
		if url.QueryEscape(st) == st {
			break
		}
	}
	return st
}

func (s sesDataAccess) generateSelectorID() string {
	return s.generateRandomString(selectorIDLength)
}

func (s sesDataAccess) generateSessionID() string {
	return s.generateRandomString(sessionIDLength)
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
	log.Println("Sessions table created")
	return tx.Commit()
}

func (s sesDataAccess) cleanUpOldSessions(c <-chan time.Time, sessionTimeout, persistantSessionTimeout float64) {
	log.Println("Waiting to clean old sessions...")
	for range c {
		log.Println("Cleaning old sessions...")
		tx, err := s.Begin()
		if err != nil {
			log.Println("We have stopped cleaning up old sessions")
			log.Println(err)
			return
		}
		// Clean up old sessions that are not persistant and are older than maxLifetimeSessionOnly
		// Also clean up old expired persistant sessions.
		rows, err := tx.Query(fmt.Sprintf(cleanUpOldSessions, sessionTimeout, persistantSessionTimeout))
		if err != nil {
			tx.Rollback()
			log.Println("We have stopped cleaning up old sessions")
			log.Println(err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			selectorDeleted := ""
			rows.Scan(&selectorDeleted)
			log.Printf("Deleted session with selector %v\n", selectorDeleted)
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
		selectorID, sessionID = s.generateSelectorID(), s.generateSessionID()
		tx, err = s.Begin()
		if err != nil {
			return nil, err
		}
		ses = session.NewSession(selectorID, sessionID, username, sessionCookieName, maxLifetime)
		queryString := fmt.Sprintf(insertSession, ses.SelectorID(), s.hashString(ses.HashPayload()), username, time.Now().Format(timestampFormat), ses.ExpireTime().Format(timestampFormat), persistant)
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
			log.Println(err)
			return nil, err
		}
		// We have the ids so we break and return
		log.Printf("Session with selector %v created\n", ses.SelectorID())
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
	log.Printf("Session with selector %v destroyed\n", ses.SelectorID())
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
	if err != nil || !ses.Equals(dbSession, s.hashString) {
		s.destroySession(ses)
		return sessionNotInDatabaseError(ses.SelectorID())
	}

	if !ses.IsValid() {
		s.destroySession(ses)
		log.Printf("Session %v is not valid so we destroyed it", ses.SelectorID())
		return sessionExpiredError(ses.SelectorID())
	}
	return nil
}
