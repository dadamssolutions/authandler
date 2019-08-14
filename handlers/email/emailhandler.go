/*Package email is an email handler used for sending email messages like sign up verifications and password reset requests.
 */
package email

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/smtp"

	"github.com/dadamssolutions/authandler/handlers/email/smtpauth"
)

// Recipient interface represents someone who can receive an email message.
type Recipient interface {
	GetEmail() string
	Greeting() string
}

// Sender handles all the sending of email messages like password reset and sign up.
type Sender struct {
	hostname, port, username string
	// You can include {{.Organization}} in you templates and get the name of the organization in your messages.
	Organization string
	auth         smtp.Auth

	// A function used to send an individual message.
	// This should almost never be used. SendMessage should be used instead.
	SendMail func(string, smtp.Auth, string, []string, []byte) error
}

// NewSender returns an email handler for sending messages from a single address.
func NewSender(organization, hostname, port, username, password string) *Sender {
	return NewSenderAuth(organization, hostname, port, username, smtpauth.NewLoginAuth(username, password))
}

// NewSenderAuth returns an email handler for sending messages from a single address provided an smtp.Auth.
func NewSenderAuth(organization, hostname, port, email string, auth smtp.Auth) *Sender {
	return &Sender{
		Organization: organization,
		hostname:     hostname,
		port:         port,
		username:     email,
		auth:         auth,
		SendMail:     smtp.SendMail}
}

// SendMessage sends the message (as an HTML template) to the recipients
// Then template may include .Greeting or .Email for the information for the corresponding recipient.
func (e *Sender) SendMessage(tmpl *template.Template, subject string, data map[string]interface{}, recipientList ...Recipient) error {
	// Headers for HTML message and subject info
	headers := []byte(fmt.Sprintf("Subject: %v\r\nFrom: %v\r\nMIME-version: 1.0; \r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n", subject, e.username))
	buf := new(bytes.Buffer)
	// Add Organization info in case the template wants it
	data["Organization"] = e.Organization
	for _, r := range recipientList {
		// Reset the buffer and add the header info with To:...
		buf.Reset()
		buf.Write(append([]byte("To: "+r.GetEmail()+"\r\n"), headers...))
		// Add Greeting and Email info if the template wants it.
		data["Greeting"] = r.Greeting()
		data["Email"] = r.GetEmail()
		// Execute the template and send the message
		tmpl.Execute(buf, data)
		log.Printf("Sending message to %v\n", r.GetEmail())
		err := e.SendMail(e.hostname+":"+e.port, e.auth, e.username, []string{r.GetEmail()}, buf.Bytes())

		if err != nil {
			log.Printf("Error sending message to %v\n", r.GetEmail())
			return err
		}
		log.Printf("Message sent to %v!\n", r.GetEmail())
	}
	return nil
}

// SendPasswordResetMessage sends a password reset message to the given email address.
func (e *Sender) SendPasswordResetMessage(temp *template.Template, receiver Recipient, resetURL string) error {
	data := make(map[string]interface{})
	data["Link"] = resetURL
	return e.SendMessage(temp, "Password Reset", data, receiver)
}

// SendSignUpMessage sends a password reset message to the given email address.
func (e *Sender) SendSignUpMessage(temp *template.Template, receiver Recipient, resetURL string) error {
	data := make(map[string]interface{})
	data["Link"] = resetURL
	return e.SendMessage(temp, "Welcome! One more step", data, receiver)
}
