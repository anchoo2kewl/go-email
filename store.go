package goemail

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Role controls what a user can do in the admin/member APIs.
type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
)

// User is someone who can log in and manage their own API keys. Admins can
// also manage other users and edit any key's limits.
type User struct {
	ID                  int64
	Email               string
	PasswordHash        string
	Role                Role
	DefaultDailyLimit   int // applied when the user creates a key without specifying
	DefaultMonthlyLimit int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// APIKey is a credential a user creates to call POST /v1/emails. The raw key
// is only returned once at creation — we store the bcrypt hash.
type APIKey struct {
	ID           int64
	UserID       int64
	Label        string // e.g. "pingrly", "flagtgl"
	KeyPrefix    string // first 8 chars of the raw key, for identification (not secret)
	KeyHash      string // bcrypt of the raw key
	DailyLimit   int
	MonthlyLimit int
	Status       string // active | revoked
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// SendLog is one row per attempted send. Stored for audit + rate limiting.
type SendLog struct {
	ID        int64
	APIKeyID  int64
	FromEmail string
	ToEmail   string
	Subject   string
	Status    string // sent | failed
	Error     string
	SentAt    time.Time
}

// ErrNotFound is returned by store lookups when the row doesn't exist.
var ErrNotFound = errors.New("not found")

// Session is a browser login session keyed by a random token stored in a
// cookie. It is separate from API keys (which authenticate machine clients).
type Session struct {
	ID        string // random opaque token
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store is the persistence interface.
type Store interface {
	// Users
	CreateUser(u *User) error
	GetUserByID(id int64) (*User, error)
	GetUserByEmail(email string) (*User, error)
	ListUsers() ([]User, error)
	UpdateUser(u *User) error
	DeleteUser(id int64) error
	CountUsers() (int, error)

	// API keys
	CreateAPIKey(k *APIKey) error
	GetAPIKeyByID(id int64) (*APIKey, error)
	GetAPIKeyByPrefix(prefix string) (*APIKey, error)
	ListAPIKeysForUser(userID int64) ([]APIKey, error)
	ListAllAPIKeys() ([]APIKey, error)
	UpdateAPIKey(k *APIKey) error
	TouchAPIKey(id int64, t time.Time) error

	// Logs
	RecordSend(log *SendLog) error
	CountSendsSince(apiKeyID int64, since time.Time) (int, error)
	ListRecentSends(apiKeyID int64, limit int) ([]SendLog, error)

	// Sessions
	CreateSession(s *Session) error
	GetSession(id string) (*Session, error)
	DeleteSession(id string) error
	DeleteExpiredSessions(now time.Time) error

	Close() error
}

// sqliteStore implements Store backed by SQLite (via modernc.org/sqlite, pure Go).
type sqliteStore struct {
	db *sql.DB
}

// OpenStore opens (or creates) a SQLite database at the given path and runs
// the schema migrations.
func OpenStore(path string) (Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &sqliteStore{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *sqliteStore) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			default_daily_limit INTEGER NOT NULL DEFAULT 100,
			default_monthly_limit INTEGER NOT NULL DEFAULT 1000,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			label TEXT NOT NULL,
			key_prefix TEXT NOT NULL UNIQUE,
			key_hash TEXT NOT NULL,
			daily_limit INTEGER NOT NULL DEFAULT 100,
			monthly_limit INTEGER NOT NULL DEFAULT 1000,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)`,
		`CREATE TABLE IF NOT EXISTS send_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
			from_email TEXT NOT NULL,
			to_email TEXT NOT NULL,
			subject TEXT NOT NULL,
			status TEXT NOT NULL,
			error TEXT NOT NULL DEFAULT '',
			sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_send_log_key_time ON send_log(api_key_id, sent_at)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migration %q: %w", q, err)
		}
	}
	return nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

// --- Users ---

func (s *sqliteStore) CreateUser(u *User) error {
	if u.Role == "" {
		u.Role = RoleMember
	}
	res, err := s.db.Exec(
		`INSERT INTO users (email, password_hash, role, default_daily_limit, default_monthly_limit)
		 VALUES (?, ?, ?, ?, ?)`,
		u.Email, u.PasswordHash, u.Role, u.DefaultDailyLimit, u.DefaultMonthlyLimit,
	)
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) GetUserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, role, default_daily_limit, default_monthly_limit, created_at, updated_at
		 FROM users WHERE id = ?`, id,
	))
}

func (s *sqliteStore) GetUserByEmail(email string) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, role, default_daily_limit, default_monthly_limit, created_at, updated_at
		 FROM users WHERE email = ?`, email,
	))
}

func (s *sqliteStore) ListUsers() ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, email, password_hash, role, default_daily_limit, default_monthly_limit, created_at, updated_at
		 FROM users ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateUser(u *User) error {
	_, err := s.db.Exec(
		`UPDATE users SET email=?, password_hash=?, role=?, default_daily_limit=?, default_monthly_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		u.Email, u.PasswordHash, u.Role, u.DefaultDailyLimit, u.DefaultMonthlyLimit, u.ID,
	)
	return err
}

func (s *sqliteStore) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *sqliteStore) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// --- API keys ---

func (s *sqliteStore) CreateAPIKey(k *APIKey) error {
	if k.Status == "" {
		k.Status = "active"
	}
	res, err := s.db.Exec(
		`INSERT INTO api_keys (user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.UserID, k.Label, k.KeyPrefix, k.KeyHash, k.DailyLimit, k.MonthlyLimit, k.Status,
	)
	if err != nil {
		return err
	}
	k.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) GetAPIKeyByID(id int64) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRow(
		`SELECT id, user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys WHERE id=?`, id,
	))
}

func (s *sqliteStore) GetAPIKeyByPrefix(prefix string) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRow(
		`SELECT id, user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys WHERE key_prefix=?`, prefix,
	))
}

func (s *sqliteStore) ListAPIKeysForUser(userID int64) ([]APIKey, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys WHERE user_id=? ORDER BY id`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (s *sqliteStore) ListAllAPIKeys() ([]APIKey, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys ORDER BY user_id, id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateAPIKey(k *APIKey) error {
	_, err := s.db.Exec(
		`UPDATE api_keys SET label=?, daily_limit=?, monthly_limit=?, status=? WHERE id=?`,
		k.Label, k.DailyLimit, k.MonthlyLimit, k.Status, k.ID,
	)
	return err
}

func (s *sqliteStore) TouchAPIKey(id int64, t time.Time) error {
	_, err := s.db.Exec(`UPDATE api_keys SET last_used_at=? WHERE id=?`, t, id)
	return err
}

// --- Logs ---

func (s *sqliteStore) RecordSend(log *SendLog) error {
	res, err := s.db.Exec(
		`INSERT INTO send_log (api_key_id, from_email, to_email, subject, status, error, sent_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		log.APIKeyID, log.FromEmail, log.ToEmail, log.Subject, log.Status, log.Error, log.SentAt,
	)
	if err != nil {
		return err
	}
	log.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) CountSendsSince(apiKeyID int64, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM send_log WHERE api_key_id=? AND sent_at >= ? AND status='sent'`,
		apiKeyID, since,
	).Scan(&n)
	return n, err
}

func (s *sqliteStore) ListRecentSends(apiKeyID int64, limit int) ([]SendLog, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, api_key_id, from_email, to_email, subject, status, error, sent_at
		 FROM send_log WHERE api_key_id=? ORDER BY sent_at DESC LIMIT ?`, apiKeyID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SendLog
	for rows.Next() {
		var l SendLog
		if err := rows.Scan(&l.ID, &l.APIKeyID, &l.FromEmail, &l.ToEmail, &l.Subject, &l.Status, &l.Error, &l.SentAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// --- sessions ---

func (s *sqliteStore) CreateSession(sess *Session) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.CreatedAt, sess.ExpiresAt,
	)
	return err
}

func (s *sqliteStore) GetSession(id string) (*Session, error) {
	var out Session
	err := s.db.QueryRow(
		`SELECT id, user_id, created_at, expires_at FROM sessions WHERE id=?`, id,
	).Scan(&out.ID, &out.UserID, &out.CreatedAt, &out.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &out, nil
}

func (s *sqliteStore) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (s *sqliteStore) DeleteExpiredSessions(now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now)
	return err
}

// --- helpers ---

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*User, error) {
	var u User
	var roleStr string
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &roleStr,
		&u.DefaultDailyLimit, &u.DefaultMonthlyLimit, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.Role = Role(roleStr)
	return &u, nil
}

func scanAPIKey(row rowScanner) (*APIKey, error) {
	var k APIKey
	var lastUsed sql.NullTime
	if err := row.Scan(&k.ID, &k.UserID, &k.Label, &k.KeyPrefix, &k.KeyHash,
		&k.DailyLimit, &k.MonthlyLimit, &k.Status, &k.CreatedAt, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if lastUsed.Valid {
		k.LastUsedAt = &lastUsed.Time
	}
	return &k, nil
}
