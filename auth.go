package goemail

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// keyPrefix is the human-readable prefix of every generated API key. The first
// ~8 chars after the prefix are stored unhashed so we can look up which row
// corresponds to a given key without iterating every row.
const keyPrefix = "gek_"

// generateAPIKey returns a new raw API key of the form "gek_<32 base32 chars>".
// Only the caller sees the raw value; we store bcrypt(raw) + a short prefix.
func generateAPIKey() (raw string, storedPrefix string, hash string, err error) {
	// 20 bytes → 32 base32 chars (no padding)
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", err
	}
	body := strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "=")
	body = strings.ToLower(body)
	raw = keyPrefix + body
	// storedPrefix is the first 12 chars of the raw key ("gek_" + 8 body chars).
	// It's not secret — it's used to identify which row to compare against.
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

// BootstrapAdmin creates the first admin user in an empty store. It's a no-op
// if any users already exist. Intended to be called from main() on first boot.
func BootstrapAdmin(store Store, email, password string) error {
	n, err := store.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return store.CreateUser(&User{
		Email:               email,
		PasswordHash:        hash,
		Role:                RoleAdmin,
		DefaultDailyLimit:   1000,
		DefaultMonthlyLimit: 30000,
	})
}

// extractKeyPrefix returns the 12-char prefix we store as a lookup index.
// Returns empty string if the key is not in our expected format.
func extractKeyPrefix(raw string) string {
	if !strings.HasPrefix(raw, keyPrefix) || len(raw) < 12 {
		return ""
	}
	return raw[:12]
}
