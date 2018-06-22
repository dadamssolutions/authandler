package seshandler

import "database/sql"

// SesHandler creates and maintains session in a database.
type SesHandler struct {
	dataAccess dataAccessLayer
	timeout    int
}

// NewSesHandlerWithDB creates a new session handler.
// The database connection should be a pointer to the database connection
// user in the rest of the app, for concurrency purposes.
// If timeout < 0, then it is set to 0.
func NewSesHandlerWithDB(db *sql.DB, timeout int) (*SesHandler, error) {
	return newSesHandler(sesAccess{db}, timeout)
}

func newSesHandler(da dataAccessLayer, timeout int) (*SesHandler, error) {
	if timeout < 0 {
		timeout = 0
	}
	ses := &SesHandler{dataAccess: da, timeout: timeout}
	return ses, ses.dataAccess.createTable()
}
