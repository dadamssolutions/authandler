package seshandler

import (
	"database/sql"
	"time"
)

// SesHandler creates and maintains session in a database.
type SesHandler struct {
	dataAccess  dataAccessLayer
	maxLifetime time.Duration
}

// NewSesHandlerWithDB creates a new session handler.
// The database connection should be a pointer to the database connection
// used in the rest of the app, for concurrency purposes.
// If timeout < 0, then it is set to 0.
func NewSesHandlerWithDB(db *sql.DB, timeout time.Duration) (*SesHandler, error) {
	return newSesHandler(sesAccess{db}, timeout)
}

func newSesHandler(da dataAccessLayer, timeout time.Duration) (*SesHandler, error) {
	if timeout < 0 {
		timeout = 0
	}
	ses := &SesHandler{dataAccess: da, maxLifetime: timeout}
	return ses, ses.dataAccess.createTable()
}

// IsValidSession determines if the given session is valid.
func (sh *SesHandler) IsValidSession(session *Session) bool {
	if err := sh.dataAccess.validateSession(session); err != nil {
		return false
	}
	return true
}

// UpdateSession sets the expiration of the session to time.Now.
func (sh *SesHandler) UpdateSession(session *Session) error {
	return sh.dataAccess.updateSession(session, sh.maxLifetime)
}
