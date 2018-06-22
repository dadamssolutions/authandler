package seshandler

import "errors"

func sessionNotFoundError(sessionID string) error {
	return errors.New("The session ID " + sessionID + " was not found")
}

func sessionExpiredError(sessionID string) error {
	return errors.New("The session ID " + sessionID + " is expired")
}

func databaseTableCreationError() error {
	return errors.New("Cannot create sessions table in the database")
}

func invalidSessionCookie() error {
	return errors.New("Cookie does not represent a valid session cookie")
}

// This is only used in testing
func databaseAccessError() error {
	return errors.New("Cannot access database")
}
