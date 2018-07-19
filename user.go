package authandler

import (
	"database/sql"
	"fmt"
	"log"
)

// Represent roles used for users.
const (
	Member = iota
	Manager
	Supervisor
	Admin

	createUsersTableSQL     = "CREATE TABLE IF NOT EXISTS %v (username varchar, fname varchar DEFAULT '', lname varchar DEFAULT '', email varchar NOT NULL UNIQUE, role int NOT NULL DEFAULT 0, valid_code char(64) DEFAULT '', pass_hash char(80) DEFAULT '', PRIMARY KEY (username));"
	getUserInfoSQL          = "SELECT username, fname, lname, email, role, valid_code FROM %v WHERE username = '%v';"
	getUserPasswordHash     = "SELECT pass_hash FROM %v WHERE username = '%v';"
	deleteUsersTestTableSQL = "DROP TABLE %v;"
)

// Role is represents the role of a user.
// Roles elevate and have a linear heirachy.
type Role int

// HasRole returns whether the role has the given permssion level.
func (r Role) HasRole(permission Role) bool {
	return r >= permission
}

// User represents a user to be logged in or signed up represented in the created database.
// For ease, you would want the representation of the user in your app to embed User.
type User struct {
	FirstName, LastName, Email, Username string
	Role                                 Role
	validated                            bool
	passHash                             []byte
}

// HasPermission determines whether the user has the given permission level
func (u User) HasPermission(role Role) bool {
	return u.Role.HasRole(role)
}

// IsValidated returns whether the user has validated their login
func (u User) IsValidated() bool {
	return u.validated
}

func getUserFromDB(db *sql.DB, tableName, username string) *User {
	tx, err := db.Begin()
	if err != nil {
		log.Println("Cannot connect to database")
		return nil
	}
	user := User{}
	var validationCode string
	err = tx.QueryRow(fmt.Sprintf(getUserInfoSQL, tableName, username)).Scan(&user.Username, &user.FirstName, &user.LastName, &user.Email, &user.Role, &validationCode)
	if err != nil {
		tx.Rollback()
		log.Println(err)
		return nil
	}
	tx.Commit()

	user.validated = validationCode == ""
	return &user
}
