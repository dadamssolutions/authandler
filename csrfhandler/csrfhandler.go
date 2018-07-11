package csrfhandler

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/dadamssolutions/authandler/seshandler"
)

// CSRFHandler handles Cross-site request forgery tokens
type CSRFHandler struct {
	*seshandler.SesHandler
}

// NewCSRFHandler creates a new handler using the database pointer.
func NewCSRFHandler(db *sql.DB, timeout time.Duration) *CSRFHandler {
	sh, err := seshandler.NewSesHandlerWithDB(db, "csrfs", timeout, timeout)
	if err != nil {
		log.Println("There was a problem creating the CSRF handler")
		log.Println(err)
		return nil
	}
	return &CSRFHandler{sh}
}

// GenerateNewToken generates a new token for protecting against CSRF
func (c *CSRFHandler) GenerateNewToken() string {
	ses, err := c.CreateSession("csrf", false)
	if err != nil {
		log.Println("Error creating a new CSRF token")
		return ""
	}
	return ses.CookieValue()
}

// ValidToken verifies that a CSRF token is valid and then destroys it
func (c *CSRFHandler) ValidToken(token string) bool {
	ses, err := c.ParseSessionCookie(&http.Cookie{Name: seshandler.SessionCookieName, Value: token})
	if err != nil {
		log.Printf("CSRF token %v was not valid\n", token)
		log.Println(err)
		return false
	}
	c.DestroySession(ses)
	return true
}
