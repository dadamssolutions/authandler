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

func TestTokenGeneration(t *testing.T) {
	w := httptest.NewRecorder()
	err := csrfHand.GenerateNewToken(w, nil)
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
	csrfHand.GenerateNewToken(w, nil)
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
	triesLeft := 5
	db, err := sql.Open("postgres", "postgres://authandler:authandler@db:5432/authandler_csrfs?sslmode=disable")

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
