package seshandler

import "errors"

func sessionNotFoundError(sessionID string) error {
	return errors.New("The session ID " + sessionID + " was not found")
}

func databaseTableCreationError() error {
	return errors.New("Cannot create sessions table in the database")
}

func sessionForUserExistsError(username string) error {
	return errors.New("Session for username " + username + " already exists")
}

func sessionDestroyedError(username string) error {
	return errors.New("Session for " + username + " has been destroyed")
}

func invalidSessionCookie() error {
	return errors.New("Cookie does not represent a valid session cookie")
}

func sessionExpiredError(sessionID string) error {
	return errors.New("The session ID " + sessionID + " is expired")
}

func sessionNotInDatabaseError(id string) error {
	return errors.New("Session with selector ID " + id + " was not found in the database")
}
