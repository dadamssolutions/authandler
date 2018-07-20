package passreset

import (
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

var passHand *Handler
var db, err = sql.Open("postgres", "user=test dbname=house-pts-test sslmode=disable")

func TestTokenGeneration(t *testing.T) {
	token := passHand.GenerateNewToken("dadams")
	if token == "" || !strings.Contains(token, "dadams") {
		t.Error("Could not generate a new token")
	}
	// Create a request so we can validate the token which destroys it as well
	req := httptest.NewRequest(http.MethodGet, "/?"+queryName+"="+token, nil)
	passHand.ValidToken(req)
}

func TestTokenValidation(t *testing.T) {
	token := passHand.GenerateNewToken("dadams")
	req := httptest.NewRequest(http.MethodGet, "/?"+queryName+"="+token, nil)
	if err := passHand.ValidToken(req); err != nil {
		t.Error("Token should be valid right after it is created")
	}
	if err := passHand.ValidToken(req); err == nil {
		t.Error("Token should not be valid after it is validated")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	if err != nil {
		log.Fatal(err)
	}
	passHand = NewHandler(db, time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	os.Exit(num)
}
