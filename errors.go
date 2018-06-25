package seshandler

import "errors"

func badDatabaseConnectionError() error {
	return errors.New("The database connection is not valid")
}
func databaseTableCreationError() error {
	return errors.New("Cannot create sessions table in the database")
}

func invalidSessionCookie() error {
	return errors.New("Cookie does not represent a valid session cookie")
}

func invalidSessionError(ID string) error {
	return errors.New("Session with ID " + ID + " is not valid")
}

func sessionExpiredError(sessionID string) error {
	return errors.New("The session ID " + sessionID + " is expired")
}

func sessionNotInDatabaseError(id string) error {
	return errors.New("Session with selector ID " + id + " was not found in the database")
}

func noSessionCookieFoundInRequest() error {
	return errors.New("No session cookie was found in request")
}
