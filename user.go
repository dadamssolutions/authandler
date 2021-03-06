package authandler

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"time"
)

// Represent roles used for users.
const (
	Member = iota
	Manager
	Supervisor
	Admin

	createUsersTableSQL     = "CREATE TABLE IF NOT EXISTS %v (username varchar, fname varchar DEFAULT '', lname varchar DEFAULT '', email varchar NOT NULL UNIQUE, role int NOT NULL DEFAULT 0, validated boolean DEFAULT false, pass_hash char(80) DEFAULT '', last_access timestamp DEFAULT 'epoch', PRIMARY KEY (username));"
	addUserToDatabaseSQL    = "INSERT INTO %v (username, fname, lname, email, validated, pass_hash) VALUES ('%v','%v','%v','%v',false,'%v');"
	getUserInfoSQL          = "SELECT username, fname, lname, email, role, validated FROM %v WHERE %v = '%v';"
	getUserPasswordHashSQL  = "SELECT pass_hash FROM %v WHERE username = '%v';"
	validateUserSQL         = "UPDATE %v SET validated = true WHERE username = '%v';"
	updateUserPasswordSQL   = "UPDATE %v SET (pass_hash, validated) = ('%v', true) WHERE username = '%v';"
	updateUserLastAccessSQL = "UPDATE %v SET last_access = '%v' WHERE username = '%v';"
	getUserLastAccessSQL    = "SELECT last_access FROM %v WHERE username = '%v';"
	deleteTestTableSQL      = "DROP TABLE %v;"
	dateLayout              = "2006-01-02 15:04:05"
)

// Role is represents the role of a user.
// Roles elevate and have a linear hierarchy.
type Role int

// HasRole returns whether the role has the given permssion level.
func (r Role) HasRole(permission Role) bool {
	return r >= permission
}

// User represents a user to be logged in or signed up represented in the created database.
// For ease, you would want the representation of the user in your app to embed User.
type User struct {
	FirstName, LastName, Email, Greet, Username string
	Role                                        Role
	validated                                   bool
	passHash                                    []byte
}

// GetEmail implements the email.Recipient interface.
func (u User) GetEmail() string {
	return u.Email
}

// Greeting implements the email.Recipient interface.
func (u User) Greeting() string {
	return u.FirstName
}

// HasPermission determines whether the user has the given permission level
func (u User) HasPermission(role Role) bool {
	return u.Role.HasRole(role)
}

// IsValidated returns whether the user has validated their login
func (u User) IsValidated() bool {
	return u.validated
}

func (u User) isValid() bool {
	if u.FirstName == "" || u.LastName == "" || u.Email == "" || u.Username == "" {
		return false
	}
	return true
}

func getUserFromDB(db *sql.DB, tableName, col, search string) *User {
	tx, err := db.Begin()
	if err != nil {
		log.Println("Cannot connect to database")
		return nil
	}
	user := User{}
	err = tx.QueryRow(fmt.Sprintf(getUserInfoSQL, tableName, col, search)).Scan(&user.Username, &user.FirstName, &user.LastName, &user.Email, &user.Role, &user.validated)
	if err != nil {
		fmt.Println(err)
		tx.Rollback()
		return nil
	}
	tx.Commit()

	user.Email, _ = url.QueryUnescape(user.Email)
	user.FirstName, _ = url.QueryUnescape(user.FirstName)
	user.LastName, _ = url.QueryUnescape(user.LastName)
	user.Username, _ = url.QueryUnescape(user.Username)

	user.passHash, _ = getUserPasswordHash(db, tableName, user.Username)

	return &user
}

func usernameOrEmailExists(db *sql.DB, tableName string, user *User) (bool, bool) {
	usernameSearch := getUserFromDB(db, tableName, "username", user.Username)
	emailSearch := getUserFromDB(db, tableName, "email", user.GetEmail())
	return usernameSearch != nil, emailSearch != nil
}

func addUserToDatabase(db *sql.DB, tableName string, user *User) error {
	tx, err := db.Begin()
	if err != nil {
		log.Println("Cannot connect to database")
		return err
	}
	_, err = tx.Exec(fmt.Sprintf(addUserToDatabaseSQL, tableName, user.Username, user.FirstName, user.LastName, user.Email, base64.RawURLEncoding.EncodeToString(user.passHash)))
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func validateUser(db *sql.DB, tableName string, user *User) error {
	tx, err := db.Begin()
	if err != nil {
		log.Println("User cannot be verified")
		return fmt.Errorf("User %v cannot be verified", user.Username)
	}
	_, err = tx.Exec(fmt.Sprintf(validateUserSQL, tableName, user.Username))
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("User %v cannot be verified", user.Username)
	}
	return tx.Commit()
}

func getUserPasswordHash(db *sql.DB, tableName, username string) ([]byte, error) {
	tx, err := db.Begin()
	if err != nil {
		log.Println(err)
		return nil, errors.New("Failed to get password from database")
	}
	var pwHash string
	err = tx.QueryRow(fmt.Sprintf(getUserPasswordHashSQL, tableName, username)).Scan(&pwHash)
	if err != nil {
		tx.Rollback()
		log.Printf("User %v not found in the database\n", username)
		return nil, fmt.Errorf("User %v not found in database", username)
	}
	pwDecoded, err := base64.RawURLEncoding.DecodeString(pwHash)
	if err != nil {
		tx.Rollback()
		log.Println(err)
		log.Println("Error decoding password from database. Database might be corrupted!")
		return nil, errors.New("Failed to get password from database")
	}
	return pwDecoded, tx.Commit()
}

func updateUserPassword(db *sql.DB, tableName, username, passHash string) error {
	tx, err := db.Begin()
	if err != nil {
		return errors.New("Failed to connect to database")
	}
	_, err = tx.Exec(fmt.Sprintf(updateUserPasswordSQL, tableName, passHash, username))
	if err != nil {
		tx.Rollback()
		return errors.New("Failed to update user's last access time")
	}
	tx.Commit()
	return nil
}

func getUserLastAccess(db *sql.DB, tableName, username string) *time.Time {
	tx, err := db.Begin()
	if err != nil {
		return nil
	}
	var t time.Time
	err = tx.QueryRow(fmt.Sprintf(getUserLastAccessSQL, tableName, username)).Scan(&t)
	if err != nil {
		tx.Rollback()
		return nil
	}
	tx.Commit()
	return &t
}

func updateUserLastAccess(db *sql.DB, tableName, username string) error {
	tx, err := db.Begin()
	if err != nil {
		return errors.New("Failed to connect to database")
	}
	_, err = tx.Exec(fmt.Sprintf(updateUserLastAccessSQL, tableName, time.Now().Format(dateLayout), username))
	if err != nil {
		log.Println(err)
		tx.Rollback()
		return errors.New("Failed to update user's access time")
	}
	tx.Commit()
	return nil
}
