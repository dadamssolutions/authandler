package passreset

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dadamssolutions/authandler/handlers/session"
)

const (
	queryName = "resetToken"
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
	token := r.URL.Query().Get(queryName)
	ses, err := c.ParseSessionCookie(&http.Cookie{Name: session.SessionCookieName, Value: token})
	if err != nil {
		err = fmt.Errorf("Password reset token %v was not valid", token)
		log.Println(err)
		return "", err
	}
	c.DestroySession(ses)
	return ses.Username(), nil
}
