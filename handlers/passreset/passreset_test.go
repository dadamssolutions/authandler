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

	"github.com/dadamssolutions/authandler/handlers/session"
)

var passHand *Handler
var db, _ = sql.Open("postgres", "user=test dbname=test sslmode=disable")

func TestTokenGeneration(t *testing.T) {
	tx, _ := db.Begin()
	token := passHand.GenerateNewToken(tx, "dadams")
	if token == nil {
		t.Error("Could not generate a new token")
	}
	// Create a request so we can validate the token which destroys it as well
	req := httptest.NewRequest(http.MethodGet, "/?"+token.Query(), nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	passHand.ValidToken(req)
	tx.Commit()
}

func TestTokenValidation(t *testing.T) {
	var username string
	var err error
	tx, _ := db.Begin()
	token := passHand.GenerateNewToken(tx, "dadams")
	req := httptest.NewRequest(http.MethodGet, "/?"+token.Query(), nil)
	req = req.WithContext(session.NewTxContext(req.Context(), tx))
	if username, err = passHand.ValidToken(req); err != nil || username != "dadams" {
		t.Error("Token should be valid right after it is created")
	}
	if username, err = passHand.ValidToken(req); err == nil || username != "" {
		t.Error("Token should not be valid twice")
	}
	tx.Commit()
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	passHand = NewHandler(db, "pass_reset_tokens", time.Minute, bytes.Repeat([]byte("d"), 16))
	num := m.Run()
	os.Exit(num)
}
