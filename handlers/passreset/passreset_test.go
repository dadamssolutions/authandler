package passreset

import (
	"bytes"
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var passHand *Handler

func TestTokenGeneration(t *testing.T) {
	token := passHand.GenerateNewToken("dadams")
	if token == nil {
		t.Error("Could not generate a new token")
	}
	// Create a request so we can validate the token which destroys it as well
	req := httptest.NewRequest(http.MethodGet, "/?"+token.Query(), nil)
	passHand.ValidToken(req)
}

func TestTokenValidation(t *testing.T) {
	token := passHand.GenerateNewToken("dadams")
	req := httptest.NewRequest(http.MethodGet, "/?"+token.Query(), nil)
	if username, err := passHand.ValidToken(req); err != nil || username != "dadams" {
		t.Error("Token should be valid right after it is created")
	}
	if username, err := passHand.ValidToken(req); err == nil || username != "" {
		t.Error("Token should not be valid after it is validated")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	triesLeft := 5
	db, err := sql.Open("postgres", "postgres://authandler:authandler@db:5432/authandler_passreset?sslmode=disable")

	// Wait for the database to be ready.
	for triesLeft > 0 {
		if tx, err := db.Begin(); err == nil {
			tx.Rollback()
			break
		}
		log.Printf("Database not ready, %d tries left", triesLeft)
		triesLeft--
		time.Sleep(10 * time.Second)
	}
	if err != nil {
		log.Fatal(err)
	}
	passHand = NewHandler(db, "pass_reset_tokens", time.Minute, bytes.Repeat([]byte("d"), 16))
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	os.Exit(num)
}
