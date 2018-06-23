package session

import "errors"

func invalidSessionCookie() error {
	return errors.New("Cookie does not represent a valid session cookie")
}

func sessionExpiredError(sessionID string) error {
	return errors.New("The session ID " + sessionID + " is expired")
}
