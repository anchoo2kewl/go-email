package goemail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConfig describes how to reach an SMTP relay (Mailcow, Postfix, etc.).
type SMTPConfig struct {
	Host     string // e.g. "mail.biswas.me"
	Port     int    // 587 (STARTTLS) or 465 (implicit TLS)
	Username string
	Password string
	// InsecureSkipVerify is for dev/staging only. Leave false in production.
	InsecureSkipVerify bool
}

// SMTPSender is a Sender that relays via SMTP with STARTTLS or implicit TLS.
type SMTPSender struct {
	cfg SMTPConfig
}

// NewSMTPSender validates the config and returns a Sender.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if cfg.Host == "" {
		return nil, errors.New("smtp host is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("smtp username and password are required")
	}
	return &SMTPSender{cfg: cfg}, nil
}

// Send formats an RFC 5322 message and relays it via SMTP.
func (s *SMTPSender) Send(msg Message) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	body, err := buildMIME(msg)
	if err != nil {
		return fmt.Errorf("building message: %w", err)
	}

	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	to := make([]string, 0, len(msg.To))
	for _, r := range msg.To {
		to = append(to, r.Email)
	}

	switch s.cfg.Port {
	case 465:
		return s.sendImplicitTLS(addr, auth, msg.From.Email, to, body)
	default:
		return s.sendSTARTTLS(addr, auth, msg.From.Email, to, body)
	}
}

// sendSTARTTLS opens a plain TCP connection, then upgrades to TLS via STARTTLS
// (the normal submission flow on port 587).
func (s *SMTPSender) sendSTARTTLS(addr string, auth smtp.Auth, from string, to []string, body []byte) error {
	client, err := dialSMTP(addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Hello("goemail.local"); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: s.cfg.Host, InsecureSkipVerify: s.cfg.InsecureSkipVerify} //nolint:gosec
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	return writeSMTP(client, auth, from, to, body)
}

// sendImplicitTLS wraps the TCP socket in TLS from the start (port 465).
func (s *SMTPSender) sendImplicitTLS(addr string, auth smtp.Auth, from string, to []string, body []byte) error {
	tlsCfg := &tls.Config{ServerName: s.cfg.Host, InsecureSkipVerify: s.cfg.InsecureSkipVerify} //nolint:gosec
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if err := client.Hello("goemail.local"); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	return writeSMTP(client, auth, from, to, body)
}

func writeSMTP(client *smtp.Client, auth smtp.Auth, from string, to []string, body []byte) error {
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("AUTH: %w", err)
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, r := range to {
		if err := client.Rcpt(r); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", r, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close DATA: %w", err)
	}
	return client.Quit()
}

func dialSMTP(addr string, timeout time.Duration) (*smtp.Client, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse addr: %w", err)
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smtp client: %w", err)
	}
	return c, nil
}

// buildMIME renders a multipart/alternative RFC 5322 message. Subject and
// display names are encoded using RFC 2047 'Q' encoding so non-ASCII characters
// survive transport.
func buildMIME(m Message) ([]byte, error) {
	var b strings.Builder
	boundary := "goemail_" + randomHex(12)

	b.WriteString("From: " + encodeAddress(m.From) + "\r\n")
	toLine := make([]string, 0, len(m.To))
	for _, r := range m.To {
		toLine = append(toLine, encodeAddress(r))
	}
	b.WriteString("To: " + strings.Join(toLine, ", ") + "\r\n")
	if m.ReplyTo != nil {
		b.WriteString("Reply-To: " + encodeAddress(*m.ReplyTo) + "\r\n")
	}
	b.WriteString("Subject: " + encodeHeader(m.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + randomHex(16) + "@goemail.local>\r\n")

	switch {
	case m.HTML != "" && m.Text != "":
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.Text + "\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.HTML + "\r\n")
		b.WriteString("--" + boundary + "--\r\n")
	case m.HTML != "":
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.HTML)
	default:
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.Text)
	}
	return []byte(b.String()), nil
}

// encodeAddress formats a single address header value. Display names with
// non-ASCII characters are Q-encoded per RFC 2047.
func encodeAddress(a Address) string {
	if a.Name == "" {
		return a.Email
	}
	return fmt.Sprintf("%s <%s>", encodeHeader(a.Name), a.Email)
}

// encodeHeader wraps a string in RFC 2047 quoted-printable if it contains
// non-ASCII characters; otherwise returns it as-is.
func encodeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?Q?" + qEncode(s) + "?="
		}
	}
	return s
}

func qEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c == ' ':
			b.WriteByte('_')
		case c == '=' || c == '?' || c == '_' || c < 33 || c > 126:
			b.WriteString(fmt.Sprintf("=%02X", c))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func randomHex(n int) string {
	const alphabet = "abcdef0123456789"
	b := make([]byte, n)
	now := time.Now().UnixNano()
	for i := range b {
		b[i] = alphabet[(now>>uint(i*4))&0xf]
	}
	return string(b)
}
