package emailhandler

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/smtp"

	"github.com/dadamssolutions/authandler/emailhandler/smtpauth"
)

// Recipient interface represents someone who can receive an email message.
type Recipient interface {
	Email() string
	Greeting() string
}

// EmailSender handles all the sending of email messages like password reset and sign up.
type EmailSender struct {
	hostname, port, username string
	// You can include {{.Organization}} in you templates and get the name of the organization in your messages.
	Organization string
	// Templates used when sending these email messages
	PasswordResetTemp, SignUpTemp string
	auth                          smtp.Auth

	// A function used to send an individual message.
	// This should almost never be used. SendMessage should be used instead.
	SendMail func(string, smtp.Auth, string, []string, []byte) error
}

// NewEmailSender returns an email handler for sending messages from a single address.
func NewEmailSender(organization, hostname, port, username, password string) *EmailSender {
	return &EmailSender{hostname, port, username, organization, "templates/passwordreset.tmpl.html", "templates/signup.tmpl.html", smtpauth.NewLoginAuth(username, password), smtp.SendMail}
}

// SendMessage sends the message (as an HTML template) to the recipients
// Then template may include .Greeting or .Email for the information for the corresponding recipient.
func (e *EmailSender) SendMessage(tmpl *template.Template, subject string, data map[string]interface{}, recipientList ...Recipient) error {
	// Headers for HTML message and subject info
	headers := []byte(fmt.Sprintf("Subject: %v\r\nFrom: %v\r\nMIME-version: 1.0; \r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n", subject, e.username))
	buf := new(bytes.Buffer)
	// Add Organization info in case the template wants it
	data["Organization"] = e.Organization
	for _, r := range recipientList {
		// Reset the buffer and add the header info with To:...
		buf.Reset()
		buf.Write(append([]byte("To: "+r.Email()+"\r\n"), headers...))
		// Add Greeting and Email info if the template wants it.
		data["Greeting"] = r.Greeting()
		data["Email"] = r.Email()
		// Execute the template and send the message
		tmpl.Execute(buf, data)
		log.Printf("Sending message to %v\n", r.Email())
		err := e.SendMail(e.hostname+":"+e.port, e.auth, e.username, []string{r.Email()}, buf.Bytes())

		if err != nil {
			log.Printf("Error sending message to %v\n", r.Email())
			return err
		}
		log.Println("Message sent!")
	}
	return nil
}

// SendPasswordResetMessage sends a password reset message to the given email address.
func (e *EmailSender) SendPasswordResetMessage(receiver Recipient, resetURL string) error {
	tmpl := template.Must(template.ParseFiles(e.PasswordResetTemp))
	if tmpl == nil {
		return errors.New("Cannot find password reset template")
	}
	data := make(map[string]interface{})
	data["Link"] = resetURL
	return e.SendMessage(tmpl, "Password Reset", data, receiver)
}

// SendSignUpMessage sends a password reset message to the given email address.
func (e *EmailSender) SendSignUpMessage(receiver Recipient, resetURL string) error {
	tmpl := template.Must(template.ParseFiles(e.SignUpTemp))
	if tmpl == nil {
		return errors.New("Cannot find sign up template")
	}
	data := make(map[string]interface{})
	data["Link"] = resetURL
	return e.SendMessage(tmpl, "Welcome! One more step", data, receiver)
}
