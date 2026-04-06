// Package goemail is a small, self-hosted HTTP email gateway with per-user
// API keys, bcrypt-hashed passwords, and daily/monthly send limits.
//
// Callers authenticate to POST /v1/emails with an API key; members and
// admins manage keys + users via HTTP Basic auth with their account
// password. All state lives in a single SQLite database.
package goemail

import (
	"errors"
	"fmt"
)

// Message is the wire format for POST /v1/emails.
type Message struct {
	From    Address   `json:"from"`
	To      []Address `json:"to"`
	Subject string    `json:"subject"`
	HTML    string    `json:"html,omitempty"`
	Text    string    `json:"text,omitempty"`
	ReplyTo *Address  `json:"reply_to,omitempty"`
	Tags    []string  `json:"tags,omitempty"`
}

// Address is an RFC 5322 email address with an optional display name.
type Address struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// Validate returns an error if the message is missing required fields.
func (m *Message) Validate() error {
	if m.From.Email == "" {
		return errors.New("from.email is required")
	}
	if len(m.To) == 0 {
		return errors.New("to must contain at least one recipient")
	}
	for i, r := range m.To {
		if r.Email == "" {
			return fmt.Errorf("to[%d].email is required", i)
		}
	}
	if m.Subject == "" {
		return errors.New("subject is required")
	}
	if m.HTML == "" && m.Text == "" {
		return errors.New("either html or text body is required")
	}
	return nil
}

// Sender relays a single email. Implementations are expected to be
// safe for concurrent use.
type Sender interface {
	Send(msg Message) error
}

// Logger is a minimal structured logger.
type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}
