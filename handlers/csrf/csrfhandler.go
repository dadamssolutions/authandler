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
	// HeaderName is the key value for the header attached to HTTP responses
	HeaderName = "X-CSRF"
)

// Handler handles Cross-site request forgery tokens
type Handler struct {
	*session.Handler
}

// NewHandler creates a new handler using the database pointer.
func NewHandler(db *sql.DB, timeout time.Duration, secret []byte) *Handler {
	sh, err := session.NewHandlerWithDB(db, "csrfs", timeout, timeout, secret)
	if err != nil {
		log.Println("There was a problem creating the CSRF handler")
		log.Println(err)
		return nil
	}
	return &Handler{sh}
}

// GenerateNewToken generates a new token for protecting against CSRF
func (c *Handler) GenerateNewToken() string {
	ses, err := c.CreateSession("csrf", false)
	if err != nil {
		log.Println("Error creating a new CSRF token")
		return ""
	}
	return ses.CookieValue()
}

// ValidToken verifies that a CSRF token is valid and then destroys it
func (c *Handler) ValidToken(r *http.Request) error {
	token := r.Header.Get(HeaderName)
	ses, err := c.ParseSessionCookie(&http.Cookie{Name: session.SessionCookieName, Value: token})
	if err != nil {
		err = fmt.Errorf("CSRF token %v was not valid", token)
		log.Println(err)
		return err
	}
	c.DestroySession(ses)
	return nil
}