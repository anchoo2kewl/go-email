package goemail

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Server wires Store + Sender into an http.Handler with all routes.
type Server struct {
	store        Store
	sender       Sender
	logger       Logger
	maxBodyKB    int64
	cookieSecure bool // set to true behind HTTPS proxy in production
	templates    map[string]*template.Template
}

// Option configures the Server.
type Option func(*Server)

// WithStore sets the persistence layer (required).
func WithStore(s Store) Option { return func(srv *Server) { srv.store = s } }

// WithSender sets the SMTP relay (required).
func WithSender(s Sender) Option { return func(srv *Server) { srv.sender = s } }

// WithLogger attaches a logger.
func WithLogger(l Logger) Option { return func(srv *Server) { srv.logger = l } }

// WithMaxBodyKB caps inbound request body size (default 256 KB).
func WithMaxBodyKB(kb int64) Option { return func(srv *Server) { srv.maxBodyKB = kb } }

// WithCookieSecure sets the Secure flag on session cookies. Enable in
// production behind an HTTPS reverse proxy.
func WithCookieSecure(secure bool) Option {
	return func(srv *Server) { srv.cookieSecure = secure }
}

// New constructs a Server.
func New(opts ...Option) (*Server, error) {
	s := &Server{
		logger:    nopLogger{},
		maxBodyKB: 256,
		templates: make(map[string]*template.Template),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.store == nil {
		return nil, errors.New("goemail.New: Store is required (WithStore)")
	}
	if s.sender == nil {
		return nil, errors.New("goemail.New: Sender is required (WithSender)")
	}
	if err := s.initTemplates(); err != nil {
		return nil, errors.New("goemail.New: loading templates: " + err.Error())
	}
	return s, nil
}

// Handler returns the routed http.Handler:
//
//	POST /v1/emails               — send (API key)
//	GET  /health                  — unauthenticated health check
//	GET  /api/me                  — basic auth
//	GET  /api/keys                — my keys (basic auth)
//	POST /api/keys                — create key (basic auth)
//	DELETE /api/keys/{id}         — revoke key (basic auth; own keys only unless admin)
//	PATCH  /api/keys/{id}         — update key (label/limits; admins can change any)
//	GET  /api/keys/{id}/usage     — usage + recent sends
//	GET  /admin/users             — list users (admin)
//	POST /admin/users             — create user (admin)
//	PATCH /admin/users/{id}       — update user (admin)
//	DELETE /admin/users/{id}      — delete user (admin)
//	GET  /admin/keys              — list all keys (admin)
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Public / machine-client routes
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/emails", s.handleSend)
	// JSON API (Basic auth with email+password) — kept for scripting.
	mux.HandleFunc("/api/me", s.basicAuth(s.handleMe))
	mux.HandleFunc("/api/keys", s.basicAuth(s.handleMyKeys))
	mux.HandleFunc("/api/keys/", s.basicAuth(s.handleMyKeyByID))
	mux.HandleFunc("/api/admin/users", s.basicAuth(s.requireAdmin(s.handleAdminUsers)))
	mux.HandleFunc("/api/admin/users/", s.basicAuth(s.requireAdmin(s.handleAdminUserByID)))
	mux.HandleFunc("/api/admin/keys", s.basicAuth(s.requireAdmin(s.handleAdminKeys)))
	// HTML UI (session-cookie auth) — landing, login, dashboard, admin.
	mux.Handle("/", s.webHandler())
	return mux
}

// --- public endpoints ---

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	key, err := s.authAPIKey(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if key.Status != "active" {
		writeError(w, http.StatusForbidden, "api key is "+key.Status)
		return
	}

	// Rate limits
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	daily, _ := s.store.CountSendsSince(key.ID, startOfDay)
	if key.DailyLimit > 0 && daily >= key.DailyLimit {
		writeError(w, http.StatusTooManyRequests, "daily send limit reached")
		return
	}
	monthly, _ := s.store.CountSendsSince(key.ID, startOfMonth)
	if key.MonthlyLimit > 0 && monthly >= key.MonthlyLimit {
		writeError(w, http.StatusTooManyRequests, "monthly send limit reached")
		return
	}

	// Parse + validate
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyKB*1024)
	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if err := msg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Send + log
	sendErr := s.sender.Send(msg)
	logEntry := &SendLog{
		APIKeyID:  key.ID,
		FromEmail: msg.From.Email,
		ToEmail:   msg.To[0].Email,
		Subject:   truncate(msg.Subject, 200),
		Status:    "sent",
		SentAt:    time.Now(),
	}
	if sendErr != nil {
		logEntry.Status = "failed"
		logEntry.Error = truncate(sendErr.Error(), 500)
	}
	_ = s.store.RecordSend(logEntry)
	_ = s.store.TouchAPIKey(key.ID, logEntry.SentAt)

	if sendErr != nil {
		s.logger.Errorf("relay failed key=%s to=%s err=%v", key.KeyPrefix, msg.To[0].Email, sendErr)
		writeError(w, http.StatusBadGateway, "relay failed: "+sendErr.Error())
		return
	}
	s.logger.Infof("sent key=%s to=%s subject=%q daily=%d/%d monthly=%d/%d",
		key.KeyPrefix, msg.To[0].Email, msg.Subject,
		daily+1, key.DailyLimit, monthly+1, key.MonthlyLimit)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "sent",
		"to":      len(msg.To),
		"daily":   map[string]int{"used": daily + 1, "limit": key.DailyLimit},
		"monthly": map[string]int{"used": monthly + 1, "limit": key.MonthlyLimit},
	})
}

// --- member endpoints ---

type userInfo struct {
	ID                  int64  `json:"id"`
	Email               string `json:"email"`
	Role                Role   `json:"role"`
	DefaultDailyLimit   int    `json:"default_daily_limit"`
	DefaultMonthlyLimit int    `json:"default_monthly_limit"`
	CreatedAt           string `json:"created_at"`
}

func toUserInfo(u *User) userInfo {
	return userInfo{
		ID: u.ID, Email: u.Email, Role: u.Role,
		DefaultDailyLimit: u.DefaultDailyLimit, DefaultMonthlyLimit: u.DefaultMonthlyLimit,
		CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	writeJSON(w, http.StatusOK, toUserInfo(u))
}

type keyInfo struct {
	ID           int64   `json:"id"`
	UserID       int64   `json:"user_id"`
	Label        string  `json:"label"`
	KeyPrefix    string  `json:"key_prefix"`
	DailyLimit   int     `json:"daily_limit"`
	MonthlyLimit int     `json:"monthly_limit"`
	Status       string  `json:"status"`
	CreatedAt    string  `json:"created_at"`
	LastUsedAt   *string `json:"last_used_at,omitempty"`
}

func toKeyInfo(k *APIKey) keyInfo {
	ki := keyInfo{
		ID: k.ID, UserID: k.UserID, Label: k.Label, KeyPrefix: k.KeyPrefix,
		DailyLimit: k.DailyLimit, MonthlyLimit: k.MonthlyLimit, Status: k.Status,
		CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339),
	}
	if k.LastUsedAt != nil {
		t := k.LastUsedAt.UTC().Format(time.RFC3339)
		ki.LastUsedAt = &t
	}
	return ki
}

type createKeyRequest struct {
	Label        string `json:"label"`
	DailyLimit   int    `json:"daily_limit"`
	MonthlyLimit int    `json:"monthly_limit"`
}

func (s *Server) handleMyKeys(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	switch r.Method {
	case http.MethodGet:
		keys, err := s.store.ListAPIKeysForUser(u.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]keyInfo, 0, len(keys))
		for i := range keys {
			out = append(out, toKeyInfo(&keys[i]))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req createKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if req.Label == "" {
			writeError(w, http.StatusBadRequest, "label is required")
			return
		}
		// Members cannot exceed their own defaults; admins can.
		daily := req.DailyLimit
		if daily <= 0 {
			daily = u.DefaultDailyLimit
		}
		monthly := req.MonthlyLimit
		if monthly <= 0 {
			monthly = u.DefaultMonthlyLimit
		}
		if u.Role != RoleAdmin {
			if daily > u.DefaultDailyLimit {
				daily = u.DefaultDailyLimit
			}
			if monthly > u.DefaultMonthlyLimit {
				monthly = u.DefaultMonthlyLimit
			}
		}
		raw, prefix, hash, err := generateAPIKey()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate key")
			return
		}
		k := &APIKey{
			UserID: u.ID, Label: req.Label, KeyPrefix: prefix, KeyHash: hash,
			DailyLimit: daily, MonthlyLimit: monthly, Status: "active",
		}
		if err := s.store.CreateAPIKey(k); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp := toKeyInfo(k)
		writeJSON(w, http.StatusCreated, map[string]any{
			"key":     raw, // shown once
			"details": resp,
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMyKeyByID(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	// /api/keys/{id} or /api/keys/{id}/usage
	rest := strings.TrimPrefix(r.URL.Path, "/api/keys/")
	parts := strings.Split(rest, "/")
	idStr := parts[0]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid key id")
		return
	}
	key, err := s.store.GetAPIKeyByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if key.UserID != u.ID && u.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "not your key")
		return
	}
	if len(parts) == 2 && parts[1] == "usage" {
		s.handleKeyUsage(w, key)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, toKeyInfo(key))
	case http.MethodDelete:
		key.Status = "revoked"
		if err := s.store.UpdateAPIKey(key); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	case http.MethodPatch:
		var req createKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if req.Label != "" {
			key.Label = req.Label
		}
		// Limit changes: members constrained to their own defaults, admins free.
		if req.DailyLimit > 0 {
			if u.Role != RoleAdmin && req.DailyLimit > u.DefaultDailyLimit {
				req.DailyLimit = u.DefaultDailyLimit
			}
			key.DailyLimit = req.DailyLimit
		}
		if req.MonthlyLimit > 0 {
			if u.Role != RoleAdmin && req.MonthlyLimit > u.DefaultMonthlyLimit {
				req.MonthlyLimit = u.DefaultMonthlyLimit
			}
			key.MonthlyLimit = req.MonthlyLimit
		}
		if err := s.store.UpdateAPIKey(key); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, toKeyInfo(key))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleKeyUsage(w http.ResponseWriter, key *APIKey) {
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	daily, _ := s.store.CountSendsSince(key.ID, startOfDay)
	monthly, _ := s.store.CountSendsSince(key.ID, startOfMonth)
	recent, _ := s.store.ListRecentSends(key.ID, 20)
	writeJSON(w, http.StatusOK, map[string]any{
		"key":     toKeyInfo(key),
		"daily":   map[string]int{"used": daily, "limit": key.DailyLimit},
		"monthly": map[string]int{"used": monthly, "limit": key.MonthlyLimit},
		"recent":  recent,
	})
}

// --- admin endpoints ---

type createUserRequest struct {
	Email               string `json:"email"`
	Password            string `json:"password"`
	Role                Role   `json:"role"`
	DefaultDailyLimit   int    `json:"default_daily_limit"`
	DefaultMonthlyLimit int    `json:"default_monthly_limit"`
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.store.ListUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]userInfo, 0, len(users))
		for i := range users {
			out = append(out, toUserInfo(&users[i]))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "email and password are required")
			return
		}
		if req.Role == "" {
			req.Role = RoleMember
		}
		if req.Role != RoleMember && req.Role != RoleAdmin {
			writeError(w, http.StatusBadRequest, "role must be 'member' or 'admin'")
			return
		}
		if req.DefaultDailyLimit <= 0 {
			req.DefaultDailyLimit = 100
		}
		if req.DefaultMonthlyLimit <= 0 {
			req.DefaultMonthlyLimit = 1000
		}
		hash, err := hashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		u := &User{
			Email: strings.ToLower(strings.TrimSpace(req.Email)), PasswordHash: hash, Role: req.Role,
			DefaultDailyLimit: req.DefaultDailyLimit, DefaultMonthlyLimit: req.DefaultMonthlyLimit,
		}
		if err := s.store.CreateUser(u); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, toUserInfo(u))
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type updateUserRequest struct {
	Password            string `json:"password,omitempty"`
	Role                Role   `json:"role,omitempty"`
	DefaultDailyLimit   int    `json:"default_daily_limit,omitempty"`
	DefaultMonthlyLimit int    `json:"default_monthly_limit,omitempty"`
}

func (s *Server) handleAdminUserByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	id, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	u, err := s.store.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req updateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if req.Password != "" {
			h, err := hashPassword(req.Password)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			u.PasswordHash = h
		}
		if req.Role != "" {
			if req.Role != RoleMember && req.Role != RoleAdmin {
				writeError(w, http.StatusBadRequest, "role must be 'member' or 'admin'")
				return
			}
			u.Role = req.Role
		}
		if req.DefaultDailyLimit > 0 {
			u.DefaultDailyLimit = req.DefaultDailyLimit
		}
		if req.DefaultMonthlyLimit > 0 {
			u.DefaultMonthlyLimit = req.DefaultMonthlyLimit
		}
		if err := s.store.UpdateUser(u); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, toUserInfo(u))
	case http.MethodDelete:
		if err := s.store.DeleteUser(id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	keys, err := s.store.ListAllAPIKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]keyInfo, 0, len(keys))
	for i := range keys {
		out = append(out, toKeyInfo(&keys[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// --- auth middleware ---

type ctxKey string

const userCtxKey ctxKey = "goemail.user"

func (s *Server) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="go-email"`)
			writeError(w, http.StatusUnauthorized, "basic auth required")
			return
		}
		u, err := s.store.GetUserByEmail(strings.ToLower(strings.TrimSpace(email)))
		if err != nil || verifyPassword(pass, u.PasswordHash) != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		r = r.WithContext(withUser(r.Context(), u))
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFromCtx(r)
		if u == nil || u.Role != RoleAdmin {
			writeError(w, http.StatusForbidden, "admin only")
			return
		}
		next(w, r)
	}
}

// authAPIKey pulls the Bearer token from the Authorization header (or
// X-API-Key), looks up the key by prefix, and bcrypt-verifies the rest.
func (s *Server) authAPIKey(r *http.Request) (*APIKey, error) {
	raw := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		raw = strings.TrimPrefix(auth, "Bearer ")
	} else if k := r.Header.Get("X-API-Key"); k != "" {
		raw = k
	}
	if raw == "" {
		return nil, errors.New("missing API key (Authorization: Bearer <key>)")
	}
	prefix := extractKeyPrefix(raw)
	if prefix == "" {
		return nil, errors.New("invalid API key format")
	}
	key, err := s.store.GetAPIKeyByPrefix(prefix)
	if err != nil {
		return nil, errors.New("invalid API key")
	}
	if verifyAPIKey(raw, key.KeyHash) != nil {
		return nil, errors.New("invalid API key")
	}
	return key, nil
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// context helpers
func withUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userCtxKey, u)
}
func userFromCtx(r *http.Request) *User {
	if v := r.Context().Value(userCtxKey); v != nil {
		if u, ok := v.(*User); ok {
			return u
		}
	}
	return nil
}
