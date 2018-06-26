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

func invalidSessionError(selectorID string) error {
	return errors.New("Session with selectorID " + selectorID + " is not valid")
}

func sessionExpiredError(selectorID string) error {
	return errors.New("The session ID " + selectorID + " is expired")
}

func sessionNotInDatabaseError(selectorID string) error {
	return errors.New("Session with selector ID " + selectorID + " was not found in the database")
}

func noSessionCookieFoundInRequest() error {
	return errors.New("No session cookie was found in request")
}
