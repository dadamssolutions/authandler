package csrfhandler

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

var csrfHand *CSRFHandler
var db, err = sql.Open("postgres", "user=test dbname=postgres sslmode=disable")

func TestTokenGeneration(t *testing.T) {
	token := csrfHand.GenerateNewToken()
	if token == "" || !strings.Contains(token, "csrf") {
		t.Error("Could not generate a new token")
	}
	csrfHand.ValidToken(token)
}

func TestTokenValidation(t *testing.T) {
	token := csrfHand.GenerateNewToken()
	if !csrfHand.ValidToken(token) {
		t.Error("Token should be valid right after it is created")
	}
	if csrfHand.ValidToken(token) {
		t.Error("Token should not be valid after it is validated")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	if err != nil {
		log.Fatal(err)
	}
	csrfHand = NewCSRFHandler(db, time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	os.Exit(num)
}
