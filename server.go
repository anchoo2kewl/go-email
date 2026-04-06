package goemail

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// Server wires Store + Sender + DomainVerifier into an http.Handler.
type Server struct {
	store        Store
	sender       Sender
	verifier     DomainVerifier
	logger       Logger
	maxBodyKB    int64
	cookieSecure bool
	templates    map[string]*template.Template
	// DNS helpers: used only to render the suggested SPF / DMARC records.
	serverIP       string
	dmarcReportTo  string
}

// Option configures the Server.
type Option func(*Server)

// WithStore sets the persistence layer (required).
func WithStore(s Store) Option { return func(srv *Server) { srv.store = s } }

// WithSender sets the SMTP relay (required).
func WithSender(s Sender) Option { return func(srv *Server) { srv.sender = s } }

// WithVerifier sets the domain verifier (default: DNS resolver).
func WithVerifier(v DomainVerifier) Option { return func(srv *Server) { srv.verifier = v } }

// WithLogger attaches a logger.
func WithLogger(l Logger) Option { return func(srv *Server) { srv.logger = l } }

// WithMaxBodyKB caps inbound request body size (default 256 KB).
func WithMaxBodyKB(kb int64) Option { return func(srv *Server) { srv.maxBodyKB = kb } }

// WithCookieSecure marks session cookies Secure. Enable in prod.
func WithCookieSecure(secure bool) Option { return func(srv *Server) { srv.cookieSecure = secure } }

// WithServerIP is the public IP of the SMTP relay — used only to render the
// suggested SPF record on the Domains page.
func WithServerIP(ip string) Option { return func(srv *Server) { srv.serverIP = ip } }

// WithDMARCReportTo is the mailto: address used in the suggested DMARC record.
func WithDMARCReportTo(email string) Option {
	return func(srv *Server) { srv.dmarcReportTo = email }
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
	if s.verifier == nil {
		s.verifier = NewDNSVerifier()
	}
	if err := s.initTemplates(); err != nil {
		return nil, errors.New("goemail.New: loading templates: " + err.Error())
	}
	return s, nil
}

// Handler returns the routed http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Machine endpoints
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/v1/emails", s.handleSend)
	// Service-admin JSON API (gsa_* Bearer auth)
	mux.Handle("/admin/v1/", s.adminAPIHandler())
	// HTML UI (session-cookie auth)
	mux.Handle("/", s.webHandler())
	return mux
}

// --- health + send ---

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

	// Rate limits (per key)
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

	// Verify the from-domain belongs to this key's org AND is verified.
	fromDomain := parseFromDomain(msg.From.Email)
	if fromDomain == "" {
		writeError(w, http.StatusBadRequest, "from.email has no domain")
		return
	}
	if _, err := s.store.FindVerifiedDomain(key.OrgID, fromDomain); err != nil {
		writeError(w, http.StatusForbidden, "from domain "+fromDomain+" is not a verified domain for this organization")
		return
	}

	// Merge tags from JSON body and X-GoEmail-Tags header
	tagSet := make(map[string]struct{})
	for _, t := range msg.Tags {
		if t = strings.TrimSpace(t); t != "" {
			tagSet[t] = struct{}{}
		}
	}
	if hdrTags := r.Header.Get("X-GoEmail-Tags"); hdrTags != "" {
		for _, t := range strings.Split(hdrTags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tagSet[t] = struct{}{}
			}
		}
	}
	tagParts := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tagParts = append(tagParts, t)
	}
	tagsStr := strings.Join(tagParts, ",")

	// Relay + log
	sendErr := s.sender.Send(msg)
	logEntry := &SendLog{
		APIKeyID:    key.ID,
		OrgID:       key.OrgID,
		FromEmail:   msg.From.Email,
		ToEmail:     msg.To[0].Email,
		Subject:     truncate(msg.Subject, 200),
		Status:      "sent",
		SentAt:      time.Now(),
		Tags:        tagsStr,
		APIKeyLabel: key.Label,
	}
	if sendErr != nil {
		logEntry.Status = "failed"
		logEntry.Error = truncate(sendErr.Error(), 500)
	}
	_ = s.store.RecordSend(logEntry)
	_ = s.store.TouchAPIKey(key.ID, logEntry.SentAt)

	if sendErr != nil {
		s.logger.Errorf("relay failed org=%d key=%s to=%s err=%v", key.OrgID, key.KeyPrefix, msg.To[0].Email, sendErr)
		writeError(w, http.StatusBadGateway, "relay failed: "+sendErr.Error())
		return
	}
	s.logger.Infof("sent org=%d key=%s to=%s subject=%q (daily=%d/%d monthly=%d/%d)",
		key.OrgID, key.KeyPrefix, msg.To[0].Email, msg.Subject,
		daily+1, key.DailyLimit, monthly+1, key.MonthlyLimit)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "sent",
		"to":      len(msg.To),
		"daily":   map[string]int{"used": daily + 1, "limit": key.DailyLimit},
		"monthly": map[string]int{"used": monthly + 1, "limit": key.MonthlyLimit},
	})
}

// --- auth helpers ---

type ctxKey string

const (
	userCtxKey ctxKey = "goemail.user"
	orgCtxKey  ctxKey = "goemail.org"
	roleCtxKey ctxKey = "goemail.role"
)

// authAPIKey extracts & verifies the Bearer token, returns the APIKey row.
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

// --- response helpers ---

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
func withOrgAndRole(ctx context.Context, o *Organization, role Role) context.Context {
	ctx = context.WithValue(ctx, orgCtxKey, o)
	ctx = context.WithValue(ctx, roleCtxKey, role)
	return ctx
}
func userFromCtx(r *http.Request) *User {
	if v := r.Context().Value(userCtxKey); v != nil {
		if u, ok := v.(*User); ok {
			return u
		}
	}
	return nil
}
func orgFromCtx(r *http.Request) *Organization {
	if v := r.Context().Value(orgCtxKey); v != nil {
		if o, ok := v.(*Organization); ok {
			return o
		}
	}
	return nil
}
func roleFromCtx(r *http.Request) Role {
	if v := r.Context().Value(roleCtxKey); v != nil {
		if role, ok := v.(Role); ok {
			return role
		}
	}
	return ""
}
