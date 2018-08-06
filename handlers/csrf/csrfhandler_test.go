package csrf

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

var csrfHand *Handler
var db, err = sql.Open("postgres", "user=test dbname=test sslmode=disable")

func TestTokenGeneration(t *testing.T) {
	w := httptest.NewRecorder()
	err := csrfHand.GenerateNewToken(w)
	if err != nil {
		t.Error("Could not generate a new token")
	}
	// Create a request so we can validate the token which destroys it as well
	req, _ := http.NewRequest("POST", "", nil)
	req.AddCookie(w.Result().Cookies()[0])
	csrfHand.ValidToken(req)
}

func TestTokenValidation(t *testing.T) {
	w := httptest.NewRecorder()
	csrfHand.GenerateNewToken(w)
	req, _ := http.NewRequest("POST", "", nil)
	req.AddCookie(w.Result().Cookies()[0])
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
	csrfHand = NewHandler(db, time.Minute, bytes.Repeat([]byte("d"), 16))
	if err != nil {
		log.Fatal(err)
	}
	num := m.Run()
	os.Exit(num)
}
