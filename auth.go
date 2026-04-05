package goemail

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// keyPrefix is the human-readable prefix of every org-scoped API key.
const keyPrefix = "gek_"

// serviceKeyPrefix marks platform-level super-admin keys.
const serviceKeyPrefix = "gsa_"

// generateAPIKey returns a new raw API key of the form "gek_<32 base32 chars>".
// Only the caller sees the raw value; we store bcrypt(raw) + a short prefix.
func generateAPIKey() (raw string, storedPrefix string, hash string, err error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", err
	}
	body := strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "=")
	body = strings.ToLower(body)
	raw = keyPrefix + body
	storedPrefix = raw[:12]
	h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", err
	}
	return raw, storedPrefix, string(h), nil
}

// verifyAPIKey returns nil if rawKey matches the stored bcrypt hash.
func verifyAPIKey(rawKey, storedHash string) error {
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(rawKey))
}

// hashPassword returns a bcrypt hash of the password.
func hashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// verifyPassword returns nil if password matches the hash.
func verifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// extractKeyPrefix returns the 12-char prefix we use as a lookup index.
func extractKeyPrefix(raw string) string {
	if !strings.HasPrefix(raw, keyPrefix) || len(raw) < 12 {
		return ""
	}
	return raw[:12]
}

// generateServiceKey returns a new platform admin key "gsa_<32 base32 chars>".
func generateServiceKey() (raw string, storedPrefix string, hash string, err error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", err
	}
	body := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "="))
	raw = serviceKeyPrefix + body
	storedPrefix = raw[:12]
	h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", err
	}
	return raw, storedPrefix, string(h), nil
}

// extractServicePrefix pulls the 12-char lookup prefix for a gsa_* key.
func extractServicePrefix(raw string) string {
	if !strings.HasPrefix(raw, serviceKeyPrefix) || len(raw) < 12 {
		return ""
	}
	return raw[:12]
}

// generateVerificationToken returns a short hex token to place in a DNS TXT
// record for domain ownership verification.
func generateVerificationToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "goemail-verify=" + hex.EncodeToString(b), nil
}

// slugify turns a name into a URL-safe slug ("My Org Name" → "my-org-name").
var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "org"
	}
	return s
}
