package mailer

import (
	"bytes"
	"embed"
	"text/template"
	"time"

	"github.com/go-mail/mail/v2"
)

//go:embed "templates"
var templateFS embed.FS

type Mailer struct {
	dialer *mail.Dialer
	sender string
}

func New(host string, port int, username, password, sender string) Mailer {
	// Initialize a new mail.Dialer instance with the given SMTP server settings. We
	// also configure this to use a 5-second timeout whenever we send an email.
	dialer := mail.NewDialer(host, port, username, password)
	dialer.Timeout = 5 * time.Second
	// Return a Mailer instance containing the dialer and sender information.
	return Mailer{
		dialer: dialer,
		sender: sender,
	}
}

func (m Mailer) Send(recipient, templateFile string, data interface{}) error {
	// Use the ParseFS() method to parse the required template file from the embedded
	// file system.
	tmpl, err := template.New("email").ParseFS(templateFS, "templates/"+templateFile)
	if err != nil {
		return err
	}
	// Execute the named template "subject", passing in the dynamic data and storing the
	// result in a bytes.Buffer variable.
	subject := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(subject, "subject", data)
	if err != nil {
		return err
	}
	// Follow the same pattern to execute the "plainBody" template and store the result
	// in the plainBody variable.
	plainBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(plainBody, "plainBody", data)
	if err != nil {
		return err
	}
	// And likewise with the "htmlBody" template.
	htmlBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(htmlBody, "htmlBody", data)
	if err != nil {
		return err
	}

	msg := mail.NewMessage()
	msg.SetHeader("To", recipient)
	msg.SetHeader("From", m.sender)
	msg.SetHeader("Subject", subject.String())
	msg.SetBody("text/plain", plainBody.String())
	msg.AddAlternative("text/html", htmlBody.String())
	// Call the DialAndSend() method on the dialer, passing in the message to send. This
	// opens a connection to the SMTP server, sends the message, then closes the
	// connection. If there is a timeout, it will return a "dial tcp: i/o timeout"
	// error.
	err = m.dialer.DialAndSend(msg)
	if err != nil {
		return err
	}
	return nil
}