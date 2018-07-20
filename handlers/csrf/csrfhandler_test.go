package csrf

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var csrfHand *Handler
var db, err = sql.Open("postgres", "user=test dbname=house-pts-test sslmode=disable")

func TestTokenGeneration(t *testing.T) {
	token := csrfHand.GenerateNewToken()
	if token == "" || !strings.Contains(token, "csrf") {
		t.Error("Could not generate a new token")
	}
	// Create a request so we can validate the token which destroys it as well
	req, _ := http.NewRequest("POST", "", nil)
	req.Header.Set(HeaderName, token)
	csrfHand.ValidToken(req)
}

func TestTokenValidation(t *testing.T) {
	token := csrfHand.GenerateNewToken()
	req, _ := http.NewRequest("POST", "", nil)
	req.Header.Set(HeaderName, token)
	if err := csrfHand.ValidToken(req); err != nil {
		t.Error("Token should be valid right after it is created")
	}
	if err := csrfHand.ValidToken(req); err == nil {
		t.Error("Token should not be valid after it is validated")
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	if err != nil {
		log.Fatal(err)
	}
	csrfHand = NewHandler(db, time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	os.Exit(num)
}
