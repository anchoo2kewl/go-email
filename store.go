package goemail

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Role a user holds within a specific organization.
type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
	RoleOwner  Role = "owner"
)

// User is a global login account. Belongs to 0 or more organizations via
// org_members. The is_super_admin flag is reserved for service operators.
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	IsSuperAdmin bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Organization is a tenant. Users are added via org_members.
type Organization struct {
	ID                  int64
	Name                string
	Slug                string // URL-safe identifier
	DefaultDailyLimit   int    // default for new keys in this org
	DefaultMonthlyLimit int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// OrgMember ties a user to an organization with a role.
type OrgMember struct {
	OrgID     int64
	UserID    int64
	Role      Role
	CreatedAt time.Time
	// Loaded joins
	UserEmail string `json:"-"`
}

// Domain is a sending domain owned by an organization.
//
// Ownership verification: TXT at _goemail-challenge.<domain> containing
// VerificationToken.
//
// Deliverability: DKIMSelector + DKIMPublicKey are the public half of the
// DKIM keypair that signs mail for this domain (pasted in after the admin
// creates the domain in their SMTP backend like Mailcow). SPF + DMARC
// records are derived at render time from the server IP / admin contact.
type Domain struct {
	ID                int64
	OrgID             int64
	Domain            string
	VerificationToken string
	VerifiedAt        *time.Time
	DKIMSelector      string // e.g. "dkim" (default for Mailcow)
	DKIMPublicKey     string // "v=DKIM1; k=rsa; p=..." or just the base64 p= value
	CreatedAt         time.Time
}

// APIKey is an org-scoped credential for calling POST /v1/emails.
type APIKey struct {
	ID              int64
	OrgID           int64
	CreatedByUserID int64
	Label           string
	KeyPrefix       string // first 12 chars of raw key (not secret)
	KeyHash         string // bcrypt of raw key
	DailyLimit      int
	MonthlyLimit    int
	Status          string // active | revoked
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// SendLog is one row per attempted send.
type SendLog struct {
	ID          int64
	APIKeyID    int64
	OrgID       int64
	FromEmail   string
	ToEmail     string
	Subject     string
	Status      string // sent | failed
	Error       string
	SentAt      time.Time
	Tags        string
	APIKeyLabel string
}

// SearchOpts controls filtering and pagination for SearchSendsForOrg.
type SearchOpts struct {
	Query     string    // LIKE search across subject, from_email, to_email
	Status    string    // "sent" | "failed" | "" (all)
	Tag       string    // filter where tags LIKE %tag%
	FromDate  time.Time // zero value = no lower bound
	ToDate    time.Time // zero value = no upper bound
	APIKeyID  int64     // 0 = all keys
	Limit     int       // 0 defaults to 50
	Offset    int
}

// ServiceAPIKey is a platform-level credential for automating org/domain/key
// management across ALL tenants. Distinct from org APIKey (which only sends
// email). Only super-admins can create these.
type ServiceAPIKey struct {
	ID              int64
	Label           string
	KeyPrefix       string
	KeyHash         string
	CreatedByUserID int64
	Status          string
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

// Session is a browser login session.
type Session struct {
	ID        string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ErrNotFound is returned by store lookups when the row doesn't exist.
var ErrNotFound = errors.New("not found")

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

	// Organizations
	CreateOrg(o *Organization) error
	GetOrgByID(id int64) (*Organization, error)
	GetOrgBySlug(slug string) (*Organization, error)
	ListOrgs() ([]Organization, error)
	ListOrgsForUser(userID int64) ([]Organization, error)
	UpdateOrg(o *Organization) error
	DeleteOrg(id int64) error

	// Org members
	AddOrgMember(orgID, userID int64, role Role) error
	GetOrgMember(orgID, userID int64) (*OrgMember, error)
	ListOrgMembers(orgID int64) ([]OrgMember, error)
	UpdateOrgMemberRole(orgID, userID int64, role Role) error
	RemoveOrgMember(orgID, userID int64) error

	// Domains
	CreateDomain(d *Domain) error
	GetDomainByID(id int64) (*Domain, error)
	GetDomainByName(orgID int64, domain string) (*Domain, error)
	ListDomainsForOrg(orgID int64) ([]Domain, error)
	MarkDomainVerified(id int64, t time.Time) error
	UpdateDomainDKIM(id int64, selector, publicKey string) error
	DeleteDomain(id int64) error
	FindVerifiedDomain(orgID int64, domain string) (*Domain, error)

	// API keys
	CreateAPIKey(k *APIKey) error
	GetAPIKeyByID(id int64) (*APIKey, error)
	GetAPIKeyByPrefix(prefix string) (*APIKey, error)
	ListAPIKeysForOrg(orgID int64) ([]APIKey, error)
	ListAllAPIKeys() ([]APIKey, error)
	UpdateAPIKey(k *APIKey) error
	TouchAPIKey(id int64, t time.Time) error

	// Logs
	RecordSend(log *SendLog) error
	CountSendsSince(apiKeyID int64, since time.Time) (int, error)
	ListRecentSendsForKey(apiKeyID int64, limit int) ([]SendLog, error)
	ListRecentSendsForOrg(orgID int64, limit int) ([]SendLog, error)
	SearchSendsForOrg(orgID int64, opts SearchOpts) ([]SendLog, int, error)

	// Service API keys (super-admin scoped)
	CreateServiceAPIKey(k *ServiceAPIKey) error
	GetServiceAPIKeyByPrefix(prefix string) (*ServiceAPIKey, error)
	ListServiceAPIKeys() ([]ServiceAPIKey, error)
	UpdateServiceAPIKey(k *ServiceAPIKey) error
	TouchServiceAPIKey(id int64, t time.Time) error

	// Sessions
	CreateSession(s *Session) error
	GetSession(id string) (*Session, error)
	DeleteSession(id string) error
	DeleteExpiredSessions(now time.Time) error

	Close() error
}

// sqliteStore implements Store backed by SQLite (modernc.org/sqlite, pure Go).
type sqliteStore struct {
	db *sql.DB
}

// OpenStore opens (or creates) a SQLite database and runs migrations.
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
			is_super_admin INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS organizations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			default_daily_limit INTEGER NOT NULL DEFAULT 100,
			default_monthly_limit INTEGER NOT NULL DEFAULT 1000,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS org_members (
			org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role TEXT NOT NULL DEFAULT 'member',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id)`,
		`CREATE TABLE IF NOT EXISTS domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			domain TEXT NOT NULL,
			verification_token TEXT NOT NULL,
			verified_at DATETIME,
			dkim_selector TEXT NOT NULL DEFAULT 'dkim',
			dkim_public_key TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (org_id, domain)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_domains_org ON domains(org_id)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			created_by_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
			label TEXT NOT NULL,
			key_prefix TEXT NOT NULL UNIQUE,
			key_hash TEXT NOT NULL,
			daily_limit INTEGER NOT NULL DEFAULT 100,
			monthly_limit INTEGER NOT NULL DEFAULT 1000,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id)`,
		`CREATE TABLE IF NOT EXISTS send_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			api_key_id INTEGER NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
			org_id INTEGER NOT NULL,
			from_email TEXT NOT NULL,
			to_email TEXT NOT NULL,
			subject TEXT NOT NULL,
			status TEXT NOT NULL,
			error TEXT NOT NULL DEFAULT '',
			sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			tags TEXT NOT NULL DEFAULT '',
			api_key_label TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_send_log_key_time ON send_log(api_key_id, sent_at)`,
		`CREATE INDEX IF NOT EXISTS idx_send_log_org_time ON send_log(org_id, sent_at)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE TABLE IF NOT EXISTS service_api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			label TEXT NOT NULL,
			key_prefix TEXT NOT NULL UNIQUE,
			key_hash TEXT NOT NULL,
			created_by_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME
		)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migration %q: %w", q, err)
		}
	}
	// Additive column migrations for existing tables (ALTER TABLE is safe to
	// retry — SQLite returns "duplicate column" which we ignore).
	alters := []string{
		`ALTER TABLE send_log ADD COLUMN tags TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE send_log ADD COLUMN api_key_label TEXT NOT NULL DEFAULT ''`,
	}
	for _, q := range alters {
		if _, err := s.db.Exec(q); err != nil {
			// "duplicate column name" means it already exists — safe to ignore.
			if !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("alter migration: %w", err)
			}
		}
	}
	return nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

// --- Users ---

func (s *sqliteStore) CreateUser(u *User) error {
	res, err := s.db.Exec(
		`INSERT INTO users (email, password_hash, is_super_admin) VALUES (?, ?, ?)`,
		strings.ToLower(strings.TrimSpace(u.Email)), u.PasswordHash, boolInt(u.IsSuperAdmin),
	)
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) GetUserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, is_super_admin, created_at, updated_at FROM users WHERE id=?`, id,
	))
}

func (s *sqliteStore) GetUserByEmail(email string) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, is_super_admin, created_at, updated_at FROM users WHERE email=?`,
		strings.ToLower(strings.TrimSpace(email)),
	))
}

func (s *sqliteStore) ListUsers() ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, email, password_hash, is_super_admin, created_at, updated_at FROM users ORDER BY id`,
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
		`UPDATE users SET email=?, password_hash=?, is_super_admin=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		strings.ToLower(strings.TrimSpace(u.Email)), u.PasswordHash, boolInt(u.IsSuperAdmin), u.ID,
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

// --- Organizations ---

func (s *sqliteStore) CreateOrg(o *Organization) error {
	if o.DefaultDailyLimit <= 0 {
		o.DefaultDailyLimit = 100
	}
	if o.DefaultMonthlyLimit <= 0 {
		o.DefaultMonthlyLimit = 1000
	}
	res, err := s.db.Exec(
		`INSERT INTO organizations (name, slug, default_daily_limit, default_monthly_limit) VALUES (?, ?, ?, ?)`,
		o.Name, o.Slug, o.DefaultDailyLimit, o.DefaultMonthlyLimit,
	)
	if err != nil {
		return err
	}
	o.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) GetOrgByID(id int64) (*Organization, error) {
	return scanOrg(s.db.QueryRow(
		`SELECT id, name, slug, default_daily_limit, default_monthly_limit, created_at, updated_at FROM organizations WHERE id=?`, id,
	))
}

func (s *sqliteStore) GetOrgBySlug(slug string) (*Organization, error) {
	return scanOrg(s.db.QueryRow(
		`SELECT id, name, slug, default_daily_limit, default_monthly_limit, created_at, updated_at FROM organizations WHERE slug=?`, slug,
	))
}

func (s *sqliteStore) ListOrgs() ([]Organization, error) {
	rows, err := s.db.Query(
		`SELECT id, name, slug, default_daily_limit, default_monthly_limit, created_at, updated_at FROM organizations ORDER BY name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

func (s *sqliteStore) ListOrgsForUser(userID int64) ([]Organization, error) {
	rows, err := s.db.Query(`
		SELECT o.id, o.name, o.slug, o.default_daily_limit, o.default_monthly_limit, o.created_at, o.updated_at
		FROM organizations o
		JOIN org_members m ON m.org_id = o.id
		WHERE m.user_id = ?
		ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateOrg(o *Organization) error {
	_, err := s.db.Exec(
		`UPDATE organizations SET name=?, slug=?, default_daily_limit=?, default_monthly_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		o.Name, o.Slug, o.DefaultDailyLimit, o.DefaultMonthlyLimit, o.ID,
	)
	return err
}

func (s *sqliteStore) DeleteOrg(id int64) error {
	_, err := s.db.Exec(`DELETE FROM organizations WHERE id=?`, id)
	return err
}

// --- Org members ---

func (s *sqliteStore) AddOrgMember(orgID, userID int64, role Role) error {
	if role == "" {
		role = RoleMember
	}
	_, err := s.db.Exec(
		`INSERT INTO org_members (org_id, user_id, role) VALUES (?, ?, ?)`,
		orgID, userID, role,
	)
	return err
}

func (s *sqliteStore) GetOrgMember(orgID, userID int64) (*OrgMember, error) {
	var m OrgMember
	var roleStr string
	err := s.db.QueryRow(
		`SELECT org_id, user_id, role, created_at FROM org_members WHERE org_id=? AND user_id=?`,
		orgID, userID,
	).Scan(&m.OrgID, &m.UserID, &roleStr, &m.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	m.Role = Role(roleStr)
	return &m, nil
}

func (s *sqliteStore) ListOrgMembers(orgID int64) ([]OrgMember, error) {
	rows, err := s.db.Query(`
		SELECT m.org_id, m.user_id, m.role, m.created_at, u.email
		FROM org_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.org_id = ?
		ORDER BY m.created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgMember
	for rows.Next() {
		var m OrgMember
		var roleStr string
		if err := rows.Scan(&m.OrgID, &m.UserID, &roleStr, &m.CreatedAt, &m.UserEmail); err != nil {
			return nil, err
		}
		m.Role = Role(roleStr)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateOrgMemberRole(orgID, userID int64, role Role) error {
	_, err := s.db.Exec(`UPDATE org_members SET role=? WHERE org_id=? AND user_id=?`, role, orgID, userID)
	return err
}

func (s *sqliteStore) RemoveOrgMember(orgID, userID int64) error {
	_, err := s.db.Exec(`DELETE FROM org_members WHERE org_id=? AND user_id=?`, orgID, userID)
	return err
}

// --- Domains ---

func (s *sqliteStore) CreateDomain(d *Domain) error {
	res, err := s.db.Exec(
		`INSERT INTO domains (org_id, domain, verification_token) VALUES (?, ?, ?)`,
		d.OrgID, strings.ToLower(d.Domain), d.VerificationToken,
	)
	if err != nil {
		return err
	}
	d.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) GetDomainByID(id int64) (*Domain, error) {
	return scanDomain(s.db.QueryRow(
		`SELECT id, org_id, domain, verification_token, verified_at, dkim_selector, dkim_public_key, created_at FROM domains WHERE id=?`, id,
	))
}

func (s *sqliteStore) GetDomainByName(orgID int64, domain string) (*Domain, error) {
	return scanDomain(s.db.QueryRow(
		`SELECT id, org_id, domain, verification_token, verified_at, dkim_selector, dkim_public_key, created_at FROM domains WHERE org_id=? AND domain=?`,
		orgID, strings.ToLower(domain),
	))
}

func (s *sqliteStore) ListDomainsForOrg(orgID int64) ([]Domain, error) {
	rows, err := s.db.Query(
		`SELECT id, org_id, domain, verification_token, verified_at, dkim_selector, dkim_public_key, created_at FROM domains WHERE org_id=? ORDER BY domain`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (s *sqliteStore) MarkDomainVerified(id int64, t time.Time) error {
	_, err := s.db.Exec(`UPDATE domains SET verified_at=? WHERE id=?`, t, id)
	return err
}

func (s *sqliteStore) UpdateDomainDKIM(id int64, selector, publicKey string) error {
	if selector == "" {
		selector = "dkim"
	}
	_, err := s.db.Exec(`UPDATE domains SET dkim_selector=?, dkim_public_key=? WHERE id=?`, selector, publicKey, id)
	return err
}

func (s *sqliteStore) DeleteDomain(id int64) error {
	_, err := s.db.Exec(`DELETE FROM domains WHERE id=?`, id)
	return err
}

func (s *sqliteStore) FindVerifiedDomain(orgID int64, domain string) (*Domain, error) {
	return scanDomain(s.db.QueryRow(
		`SELECT id, org_id, domain, verification_token, verified_at, dkim_selector, dkim_public_key, created_at
		 FROM domains WHERE org_id=? AND domain=? AND verified_at IS NOT NULL`,
		orgID, strings.ToLower(domain),
	))
}

// --- API keys ---

func (s *sqliteStore) CreateAPIKey(k *APIKey) error {
	if k.Status == "" {
		k.Status = "active"
	}
	res, err := s.db.Exec(
		`INSERT INTO api_keys (org_id, created_by_user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.OrgID, k.CreatedByUserID, k.Label, k.KeyPrefix, k.KeyHash, k.DailyLimit, k.MonthlyLimit, k.Status,
	)
	if err != nil {
		return err
	}
	k.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) GetAPIKeyByID(id int64) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRow(
		`SELECT id, org_id, created_by_user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys WHERE id=?`, id,
	))
}

func (s *sqliteStore) GetAPIKeyByPrefix(prefix string) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRow(
		`SELECT id, org_id, created_by_user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys WHERE key_prefix=?`, prefix,
	))
}

func (s *sqliteStore) ListAPIKeysForOrg(orgID int64) ([]APIKey, error) {
	rows, err := s.db.Query(
		`SELECT id, org_id, created_by_user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys WHERE org_id=? ORDER BY id`, orgID,
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
		`SELECT id, org_id, created_by_user_id, label, key_prefix, key_hash, daily_limit, monthly_limit, status, created_at, last_used_at
		 FROM api_keys ORDER BY org_id, id`,
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
		`INSERT INTO send_log (api_key_id, org_id, from_email, to_email, subject, status, error, sent_at, tags, api_key_label)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		log.APIKeyID, log.OrgID, log.FromEmail, log.ToEmail, log.Subject, log.Status, log.Error, log.SentAt, log.Tags, log.APIKeyLabel,
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

func (s *sqliteStore) ListRecentSendsForKey(apiKeyID int64, limit int) ([]SendLog, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.queryLogs(
		`SELECT id, api_key_id, org_id, from_email, to_email, subject, status, error, sent_at, tags, api_key_label
		 FROM send_log WHERE api_key_id=? ORDER BY sent_at DESC LIMIT ?`,
		apiKeyID, limit,
	)
}

func (s *sqliteStore) ListRecentSendsForOrg(orgID int64, limit int) ([]SendLog, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.queryLogs(
		`SELECT id, api_key_id, org_id, from_email, to_email, subject, status, error, sent_at, tags, api_key_label
		 FROM send_log WHERE org_id=? ORDER BY sent_at DESC LIMIT ?`,
		orgID, limit,
	)
}

func (s *sqliteStore) queryLogs(query string, args ...any) ([]SendLog, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SendLog
	for rows.Next() {
		var l SendLog
		if err := rows.Scan(&l.ID, &l.APIKeyID, &l.OrgID, &l.FromEmail, &l.ToEmail, &l.Subject, &l.Status, &l.Error, &l.SentAt, &l.Tags, &l.APIKeyLabel); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SearchSendsForOrg queries send_log with optional filters and pagination.
// Returns (results, totalCount, error).
func (s *sqliteStore) SearchSendsForOrg(orgID int64, opts SearchOpts) ([]SendLog, int, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	// Build WHERE clauses dynamically
	where := []string{"org_id = ?"}
	args := []any{orgID}

	if opts.Query != "" {
		like := "%" + opts.Query + "%"
		where = append(where, "(subject LIKE ? OR from_email LIKE ? OR to_email LIKE ?)")
		args = append(args, like, like, like)
	}
	if opts.Status != "" {
		where = append(where, "status = ?")
		args = append(args, opts.Status)
	}
	if opts.Tag != "" {
		where = append(where, "tags LIKE ?")
		args = append(args, "%"+opts.Tag+"%")
	}
	if !opts.FromDate.IsZero() {
		where = append(where, "sent_at >= ?")
		args = append(args, opts.FromDate)
	}
	if !opts.ToDate.IsZero() {
		where = append(where, "sent_at < ?")
		args = append(args, opts.ToDate)
	}
	if opts.APIKeyID != 0 {
		where = append(where, "api_key_id = ?")
		args = append(args, opts.APIKeyID)
	}

	whereClause := strings.Join(where, " AND ")

	// Count query
	var total int
	countQuery := "SELECT COUNT(*) FROM send_log WHERE " + whereClause
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data query
	dataQuery := `SELECT id, api_key_id, org_id, from_email, to_email, subject, status, error, sent_at, tags, api_key_label
		 FROM send_log WHERE ` + whereClause + ` ORDER BY sent_at DESC LIMIT ? OFFSET ?`
	dataArgs := append(args, opts.Limit, opts.Offset)
	results, err := s.queryLogs(dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, err
	}
	return results, total, nil
}

// --- Service API keys ---

func (s *sqliteStore) CreateServiceAPIKey(k *ServiceAPIKey) error {
	if k.Status == "" {
		k.Status = "active"
	}
	res, err := s.db.Exec(
		`INSERT INTO service_api_keys (label, key_prefix, key_hash, created_by_user_id, status)
		 VALUES (?, ?, ?, ?, ?)`,
		k.Label, k.KeyPrefix, k.KeyHash, k.CreatedByUserID, k.Status,
	)
	if err != nil {
		return err
	}
	k.ID, _ = res.LastInsertId()
	return nil
}

func (s *sqliteStore) GetServiceAPIKeyByPrefix(prefix string) (*ServiceAPIKey, error) {
	return scanServiceAPIKey(s.db.QueryRow(
		`SELECT id, label, key_prefix, key_hash, created_by_user_id, status, created_at, last_used_at
		 FROM service_api_keys WHERE key_prefix=?`, prefix,
	))
}

func (s *sqliteStore) ListServiceAPIKeys() ([]ServiceAPIKey, error) {
	rows, err := s.db.Query(
		`SELECT id, label, key_prefix, key_hash, created_by_user_id, status, created_at, last_used_at
		 FROM service_api_keys ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceAPIKey
	for rows.Next() {
		k, err := scanServiceAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

func (s *sqliteStore) UpdateServiceAPIKey(k *ServiceAPIKey) error {
	_, err := s.db.Exec(`UPDATE service_api_keys SET label=?, status=? WHERE id=?`, k.Label, k.Status, k.ID)
	return err
}

func (s *sqliteStore) TouchServiceAPIKey(id int64, t time.Time) error {
	_, err := s.db.Exec(`UPDATE service_api_keys SET last_used_at=? WHERE id=?`, t, id)
	return err
}

// --- Sessions ---

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
	var sa int
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &sa, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.IsSuperAdmin = sa != 0
	return &u, nil
}

func scanOrg(row rowScanner) (*Organization, error) {
	var o Organization
	if err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.DefaultDailyLimit, &o.DefaultMonthlyLimit, &o.CreatedAt, &o.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &o, nil
}

func scanDomain(row rowScanner) (*Domain, error) {
	var d Domain
	var verified sql.NullTime
	if err := row.Scan(&d.ID, &d.OrgID, &d.Domain, &d.VerificationToken, &verified,
		&d.DKIMSelector, &d.DKIMPublicKey, &d.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if verified.Valid {
		d.VerifiedAt = &verified.Time
	}
	return &d, nil
}

func scanServiceAPIKey(row rowScanner) (*ServiceAPIKey, error) {
	var k ServiceAPIKey
	var lastUsed sql.NullTime
	if err := row.Scan(&k.ID, &k.Label, &k.KeyPrefix, &k.KeyHash, &k.CreatedByUserID,
		&k.Status, &k.CreatedAt, &lastUsed); err != nil {
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

func scanAPIKey(row rowScanner) (*APIKey, error) {
	var k APIKey
	var lastUsed sql.NullTime
	if err := row.Scan(&k.ID, &k.OrgID, &k.CreatedByUserID, &k.Label, &k.KeyPrefix, &k.KeyHash,
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

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
