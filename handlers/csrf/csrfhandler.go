/*Package csrf provides a functionality for creating, destroying, validating, and attaching
Cross-site Forgery Request protection tokens.

The tokens are attached as cookies to the request and are good for a single request. The caller can set a timeout duration as well that enables tokens to expire without being used.
*/
package csrf

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dadamssolutions/authandler/handlers/session"
)

const (
	// CookieName is the key value for the header attached to HTTP responses
	CookieName = "X-CSRF"
)

// Handler handles Cross-site request forgery tokens
type Handler struct {
	*session.Handler
}

// NewHandler creates a new handler using the database pointer.
func NewHandler(db *sql.DB, timeout time.Duration, secret []byte) *Handler {
	sh, err := session.NewHandlerWithDB(db, "csrfs", CookieName, timeout, timeout, secret)
	if err != nil {
		log.Println("There was a problem creating the CSRF handler")
		log.Println(err)
		return nil
	}
	return &Handler{sh}
}

// GenerateNewToken generates a new token for protecting against CSRF. The token is attached to the
// response writer as a cookie.
func (c *Handler) GenerateNewToken(w http.ResponseWriter) error {
	ses, err := c.CreateSession("csrf", false)
	if err != nil {
		log.Println("Error creating a new CSRF token")
		return err
	}
	return c.AttachCookie(w, ses)
}

// ValidToken verifies that a CSRF token is valid and then destroys it.
func (c *Handler) ValidToken(r *http.Request) error {
	ses, err := c.ParseSessionFromRequest(r)
	if err != nil {
		err = fmt.Errorf("CSRF token was not valid")
		log.Println(err)
		return err
	}
	c.DestroySession(ses)
	return nil
}
