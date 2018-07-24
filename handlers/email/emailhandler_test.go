package email

import (
	"bytes"
	"errors"
	"html/template"
	"io/ioutil"
	"net/mail"
	"net/smtp"
	"os"
	"testing"
)

var eh *Sender
var temp *template.Template

type Receiver struct {
	name, email string
}

func (er *Receiver) Email() string {
	return er.email
}

func (er *Receiver) Greeting() string {
	return er.name
}

// A Test send mail function so actual emails are not sent
func SendMail(hostname string, auth smtp.Auth, from string, to []string, msg []byte) error {
	if len(to) > 1 {
		return errors.New("Message should only be sent to one address")
	}
	message, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(message.Body)
	if err != nil {
		return err
	}
	if message.Header.Get("Content-Type") == "" || message.Header.Get("To") != to[0] || message.Header.Get("From") != from || len(body) == 0 {
		return errors.New("Message was not constructed properly")
	}
	return nil
}

func TestSendMessages(t *testing.T) {
	twoTests := []Recipient{Recipient(&Receiver{"Mr. Adams", testEmail1}), Recipient(&Receiver{"Mr. Donald Adams", testEmail2})}
	data := make(map[string]interface{})
	data["Link"] = "https://thedadams.com"
	err := eh.SendMessage(temp, "Password Reset Test", data, twoTests...)
	if err != nil {
		t.Error(err)
	}
}

func TestSendSignUpMessage(t *testing.T) {
	r := &Receiver{"Mr. Adams", testEmail1}
	err := eh.SendSignUpMessage(temp, r, "https://thedadams.com")
	if err != nil {
		t.Error(err)
	}
}

func TestSendPasswordResetMessage(t *testing.T) {
	r := &Receiver{"Mr. Adams", testEmail1}
	err := eh.SendPasswordResetMessage(temp, r, "https://thedadams.com")
	if err != nil {
		t.Error(err)
	}
}

func TestMain(m *testing.M) {
	eh = NewSender("House Points Test", hostname, "587", testEmail1, password)
	eh.SendMail = SendMail
	temp = template.Must(template.ParseFiles("phony.tmpl.html"))

	exitCode := m.Run()
	os.Exit(exitCode)
}
