package seshandler

import "errors"

func sessionNotFoundError(sessionID string) error {
	return errors.New("The session ID " + sessionID + " was not found")
}

func databaseTableCreationError() error {
	return errors.New("Cannot create sessions table in the database")
}

// This is only used in testing
func databaseAccessError() error {
	return errors.New("Cannot access database")
}
