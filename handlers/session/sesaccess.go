package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/dadamssolutions/authandler/handlers/session/sessions"
	"github.com/lib/pq"
)

const (
	timestampFormat    = "2006-01-02 15:04:05.000 -0700"
	tableCreation      = "CREATE TABLE IF NOT EXISTS %v (selector char(16), session_hash varchar NOT NULL, user_id varchar NOT NULL, created timestamp WITH TIME ZONE NOT NULL, expiration timestamp WITH TIME ZONE NOT NULL, persistant boolean NOT NULL, PRIMARY KEY (selector)); DELETE FROM %[1]v;"
	dropTable          = "DROP TABLE %v;"
	insertSession      = "INSERT INTO %v(selector, session_hash, user_id, created, expiration, persistant) VALUES('%v', '%v', '%v', '%v', '%v', '%v');"
	userSessionExists  = "SELECT count(*) FROM %v WHERE user_id = '%v';"
	deleteSession      = "DELETE FROM %v WHERE selector = '%v';"
	getSessionInfo     = "SELECT selector, session_hash, user_id, expiration, persistant FROM %v WHERE selector = '%v';"
	updateSession      = "UPDATE %v SET expiration = '%v' WHERE selector = '%v';"
	cleanUpOldSessions = "DELETE FROM %v WHERE (NOT persistant AND created < NOW() - INTERVAL '%v SECONDS') OR (persistant AND expiration < NOW() - INTERVAL '%v SECONDS') RETURNING selector;"
)

type sesDataAccess struct {
	*sql.DB
	tableName string
	secret    []byte
	cipher    cipher.Block
	lock      *sync.RWMutex
}

func newDataAccess(db *sql.DB, tableName string, secret []byte, sessionTimeout, persistantSessionTimeout time.Duration) (sesDataAccess, error) {
	var err error
	sesAccess := sesDataAccess{db, tableName, nil, nil, &sync.RWMutex{}}
	if sesAccess.DB == nil {
		log.Println("Cannot connect to the database")
		return sesAccess, badDatabaseConnectionError()
	}

	// Set up encryption/decryption capabilities.
	if secret == nil {
		secret = []byte(sesAccess.generateRandomString(32))
	}
	sesAccess.secret = secret
	sesAccess.cipher, err = aes.NewCipher(secret)
	if err != nil {
		log.Println("Error creating the cipher for encryption/decryption")
	}
	err = sesAccess.createTable()
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
		return databaseTableCreationError(s.tableName)
	}
	// Create the table we need in the database
	_, err = tx.Exec(fmt.Sprintf(tableCreation, s.tableName))
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError(s.tableName)
	}
	log.Println("Sessions table created")
	return tx.Commit()
}

func (s sesDataAccess) cleanUpOldSessions(c <-chan time.Time, sessionTimeout, persistantSessionTimeout float64) {
	log.Printf("Waiting to clean old %v...\n", s.tableName)
	for range c {
		log.Printf("Cleaning old %v....\n", s.tableName)
		tx, err := s.Begin()
		if err != nil {
			log.Printf("We have stopped cleaning up old %v\n", s.tableName)
			log.Println(err)
			return
		}
		// Clean up old sessions that are not persistant and are older than maxLifetimeSessionOnly
		// Also clean up old expired persistant sessions.
		rows, err := tx.Query(fmt.Sprintf(cleanUpOldSessions, s.tableName, sessionTimeout, persistantSessionTimeout))
		if err != nil {
			tx.Rollback()
			log.Printf("We have stopped cleaning up old %v\n", s.tableName)
			log.Println(err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			selectorDeleted := ""
			rows.Scan(&selectorDeleted)
			log.Printf("Deleted %v with selector %v\n", s.tableName, selectorDeleted)
		}
		tx.Commit()
	}
}

// dropTable is used in testing to clear the database each time.
func (s sesDataAccess) dropTable() error {
	tx, err := s.Begin()
	if err != nil {
		return databaseTableCreationError(s.tableName)
	}
	// Drop the sessions table
	_, err = tx.Exec(fmt.Sprintf(dropTable, s.tableName))
	if err != nil {
		tx.Rollback()
		return databaseTableCreationError(s.tableName)
	}
	return tx.Commit()
}

func (s sesDataAccess) createSession(username string, maxLifetime time.Duration, persistant bool) (*sessions.Session, error) {
	if !persistant {
		maxLifetime = 0
	}
	var selectorID, sessionID string
	var err error
	var tx *sql.Tx
	var ses *sessions.Session

	// We need to loop until we generate unique selector and session IDs
	for true {
		selectorID, sessionID = s.generateSelectorID(), s.generateSessionID()
		tx, err = s.Begin()
		if err != nil {
			return nil, err
		}
		ses = sessions.NewSession(selectorID, sessionID, username, s.encrypt(username, selectorID), SessionCookieName, maxLifetime)
		queryString := fmt.Sprintf(insertSession, s.tableName, ses.SelectorID(), s.hashString(ses.HashPayload()), username, time.Now().Format(timestampFormat), ses.ExpireTime().Format(timestampFormat), persistant)
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
		log.Printf("%v with selector %v created\n", s.tableName, ses.SelectorID())
		break
	}
	return ses, tx.Commit()
}

// getSessionInfo pulls the session out of the database.
// No validation is done here. That must be done elsewhere.
func (s sesDataAccess) getSessionInfo(selectorID, sessionID, encryptedUsername string, maxLifetime time.Duration) (*sessions.Session, error) {
	var dbHash, username string
	var expires time.Time
	var persistant bool
	var ses *sessions.Session
	tx, err := s.Begin()
	if err != nil {
		return nil, err
	}
	queryString := fmt.Sprintf(getSessionInfo, s.tableName, selectorID)
	err = tx.QueryRow(queryString).Scan(&selectorID, &dbHash, &username, &expires, &persistant)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	err = tx.Commit()
	// Check that the encryptedUsername decrypts to the right thing. Otherwise, sessions is not valid
	if !s.decryptAndCompare(encryptedUsername, username, selectorID) {
		return nil, errors.New("Session username is not valid")
	}
	// If the session is persistant, then we set the expiration to maxLifetime
	if persistant {
		ses = sessions.NewSession(selectorID, sessionID, username, encryptedUsername, SessionCookieName, maxLifetime)
	} else {
		ses = sessions.NewSession(selectorID, sessionID, username, encryptedUsername, SessionCookieName, 0)
	}
	return ses, err
}

func (s sesDataAccess) sessionExistsForUser(username string) (bool, error) {
	tx, err := s.Begin()
	if err != nil {
		return true, err
	}
	var count int
	queryString := fmt.Sprintf(userSessionExists, s.tableName, username)
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

func (s sesDataAccess) destroySession(ses *sessions.Session) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	queryString := fmt.Sprintf(deleteSession, s.tableName, ses.SelectorID())
	tx.Exec(queryString)
	ses.Destroy()
	log.Printf("%v with selector %v destroyed\n", s.tableName, ses.SelectorID())
	return tx.Commit()
}

// updateSession indicates that the session is active and the expiration needs to be updated.
func (s sesDataAccess) updateSession(ses *sessions.Session, maxLifetime time.Duration) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	queryString := fmt.Sprintf(updateSession, s.tableName, ses.ExpireTime().Add(maxLifetime).Format(timestampFormat), ses.SelectorID())
	_, err = tx.Exec(queryString)
	if err != nil {
		tx.Rollback()
		return err
	}
	ses.UpdateExpireTime(maxLifetime)
	return tx.Commit()
}

// validateSession pulls the info for a session out of the database and checks that the session is valid
// i.e. neither destroyed nor expired, username and encryptedUsername match
func (s sesDataAccess) validateSession(ses *sessions.Session, maxLifetime time.Duration) error {
	dbSession, err := s.getSessionInfo(ses.SelectorID(), ses.SessionID(), ses.EncryptedUsername(), maxLifetime)
	if err != nil || !ses.Equals(dbSession, s.hashString) {
		s.destroySession(ses)
		return sessionNotInDatabaseError(ses.SelectorID(), s.tableName)
	}

	if !ses.IsValid() {
		s.destroySession(ses)
		log.Printf("%v %v is not valid so we destroyed it", s.tableName, ses.SelectorID())
		return sessionExpiredError(ses.SelectorID(), s.tableName)
	}
	return nil
}

// Encryption functions for hiding the username.
func (s sesDataAccess) padToBlockSize(b []byte) []byte {
	// If the padding is already valid, then we shouldn't pad.
	if _, err := s.isValidPadding(b); err == nil {
		return b
	}
	bytesToAdd := s.cipher.BlockSize() - (len(b) % s.cipher.BlockSize())
	return append(b, bytes.Repeat([]byte{byte(bytesToAdd)}, bytesToAdd)...)
}

func (s sesDataAccess) isValidPadding(b []byte) ([]byte, error) {
	paddedByte := b[len(b)-1]
	// If the last byte is 0 or greater than the block length, then we know the padding is invalid.
	if paddedByte > byte(s.cipher.BlockSize()) || paddedByte <= 0 {
		return b, errors.New("Invalid padding")
	}
	for i := len(b) - 1; i > len(b)-1-int(paddedByte); i-- {
		if b[i] != paddedByte {
			return b, errors.New("Invalid padding")
		}
	}
	return b[:len(b)-int(paddedByte)], nil
}

func (s sesDataAccess) encrypt(d, selectorID string) string {
	mode := cipher.NewCBCEncrypter(s.cipher, []byte(selectorID))
	b := s.padToBlockSize([]byte(d))
	mode.CryptBlocks(b, b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s sesDataAccess) decrypt(e, selectorID string) string {
	b, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		log.Println(err)
		return ""
	}
	mode := cipher.NewCBCDecrypter(s.cipher, []byte(selectorID))
	mode.CryptBlocks(b, b)
	b, err = s.isValidPadding(b)
	if err != nil {
		log.Println(err)
		return ""
	}
	return string(b)
}

func (s sesDataAccess) decryptAndCompare(e, d, selectorID string) bool {
	return d == s.decrypt(e, selectorID)
}
