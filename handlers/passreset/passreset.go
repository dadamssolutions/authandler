package passreset

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dadamssolutions/authandler/handlers/session"
)

const (
	// HeaderName is the header name for post requests
	HeaderName = "X-Post-PassReset"
	queryName  = "resetToken"
)

// Handler handles the creation and validation of password reset tokens
type Handler struct {
	*session.Handler
}

// NewHandler creates a new handler using the database pointer.
func NewHandler(db *sql.DB, timeout time.Duration, secret []byte) *Handler {
	sh, err := session.NewHandlerWithDB(db, "pass_reset_tokens", timeout, timeout, secret)
	if err != nil {
		log.Println("There was a problem creating the password reset handler")
		log.Println(err)
		return nil
	}
	return &Handler{sh}
}

// GenerateNewToken generates a new token for protecting against CSRF
func (c *Handler) GenerateNewToken(username string) string {
	ses, err := c.CreateSession(username, false)
	if err != nil {
		log.Println("Error creating a new password reset token")
		return ""
	}
	return queryName + "=" + ses.CookieValue()
}

// ValidToken verifies that a password reset token is valid and then destroys it.
// Returns the username of the user for a valid token and "" when there is an error.
func (c *Handler) ValidToken(r *http.Request) (string, error) {
	return c.verifyToken(r.URL.Query().Get(queryName))
}

// ValidHeaderToken verifies that a password reset token is valid and then destroys it.
// This method is used in post requests.
func (c *Handler) ValidHeaderToken(r *http.Request) (string, error) {
	return c.verifyToken(strings.Replace(r.Header.Get(HeaderName), queryName+"=", "", 1))
}

func (c *Handler) verifyToken(token string) (string, error) {
	ses, err := c.ParseSessionCookie(&http.Cookie{Name: session.SessionCookieName, Value: token})
	if err != nil {
		err = fmt.Errorf("Password reset token %v was not valid", token)
		log.Println(err)
		return "", err
	}
	c.DestroySession(ses)
	return ses.Username(), nil
}
