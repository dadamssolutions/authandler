package emailhandler

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

var eh *EmailSender

type EmailReceiver struct {
	name, email string
}

func (er *EmailReceiver) Email() string {
	return er.email
}

func (er *EmailReceiver) Greeting() string {
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
	twoTests := []Recipient{Recipient(&EmailReceiver{"Mr. Adams", testEmail1}), Recipient(&EmailReceiver{"Mr. Donald Adams", testEmail2})}
	tmp := template.Must(template.ParseFiles("templates/passwordreset.tmpl.html"))
	data := make(map[string]interface{})
	data["Link"] = "https://thedadams.com"
	err := eh.SendMessage(tmp, "Password Reset Test", data, twoTests...)
	if err != nil {
		t.Error(err)
	}
}

func TestSendSignUpMessage(t *testing.T) {
	r := &EmailReceiver{"Mr. Adams", testEmail1}
	err := eh.SendSignUpMessage(r, "https://thedadams.com")
	if err != nil {
		t.Error(err)
	}
}

func TestSendPasswordResetMessage(t *testing.T) {
	r := &EmailReceiver{"Mr. Adams", testEmail1}
	err := eh.SendPasswordResetMessage(r, "https://thedadams.com")
	if err != nil {
		t.Error(err)
	}
}

func TestMain(m *testing.M) {
	eh = NewEmailSender("House Points Test", hostname, "587", testEmail1, password)
	eh.SendMail = SendMail

	exitCode := m.Run()
	os.Exit(exitCode)
}
