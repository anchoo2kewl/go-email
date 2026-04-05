package goemail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// adminAPIHandler is the HTTP router for the /admin/v1/* service-admin API.
// Every route is authenticated with a gsa_* service key.
func (s *Server) adminAPIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/whoami", s.requireServiceKey(s.adminWhoami))
	mux.HandleFunc("/admin/v1/orgs", s.requireServiceKey(s.adminOrgsCollection))
	mux.HandleFunc("/admin/v1/orgs/", s.requireServiceKey(s.adminOrgRoutes))
	return mux
}

// --- service key middleware ---

type serviceKeyCtxKey string

const serviceKeyValKey serviceKeyCtxKey = "goemail.service_key"

func (s *Server) authServiceKey(r *http.Request) (*ServiceAPIKey, error) {
	raw := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		raw = strings.TrimPrefix(auth, "Bearer ")
	} else if k := r.Header.Get("X-API-Key"); k != "" {
		raw = k
	}
	if raw == "" {
		return nil, errors.New("missing service API key (Authorization: Bearer gsa_...)")
	}
	prefix := extractServicePrefix(raw)
	if prefix == "" {
		return nil, errors.New("invalid service key format (expected gsa_*)")
	}
	key, err := s.store.GetServiceAPIKeyByPrefix(prefix)
	if err != nil {
		return nil, errors.New("invalid service API key")
	}
	if verifyAPIKey(raw, key.KeyHash) != nil {
		return nil, errors.New("invalid service API key")
	}
	if key.Status != "active" {
		return nil, errors.New("service key is " + key.Status)
	}
	return key, nil
}

func (s *Server) requireServiceKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := s.authServiceKey(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		_ = s.store.TouchServiceAPIKey(key.ID, time.Now())
		r = r.WithContext(context.WithValue(r.Context(), serviceKeyValKey, key))
		next(w, r)
	}
}

// --- handlers ---

func (s *Server) adminWhoami(w http.ResponseWriter, r *http.Request) {
	key := r.Context().Value(serviceKeyValKey).(*ServiceAPIKey)
	writeJSON(w, http.StatusOK, map[string]any{
		"label":      key.Label,
		"key_prefix": key.KeyPrefix,
		"created_at": key.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// GET/POST /admin/v1/orgs
func (s *Server) adminOrgsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		orgs, err := s.store.ListOrgs()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, orgs)
	case http.MethodPost:
		var req struct {
			Name                string `json:"name"`
			Slug                string `json:"slug"`
			DefaultDailyLimit   int    `json:"default_daily_limit"`
			DefaultMonthlyLimit int    `json:"default_monthly_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		slug := req.Slug
		if slug == "" {
			slug = slugify(req.Name)
		} else {
			slug = slugify(slug)
		}
		org := &Organization{
			Name: req.Name, Slug: slug,
			DefaultDailyLimit: req.DefaultDailyLimit, DefaultMonthlyLimit: req.DefaultMonthlyLimit,
		}
		if err := s.store.CreateOrg(org); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, org)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// /admin/v1/orgs/{slug}[/domains|/members|/keys][/id]
func (s *Server) adminOrgRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/admin/v1/orgs/")
	parts := strings.Split(rest, "/")
	slug := parts[0]
	org, err := s.store.GetOrgBySlug(slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "org not found")
		return
	}

	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}
	switch sub {
	case "":
		s.adminOrgResource(w, r, org)
	case "domains":
		s.adminOrgDomains(w, r, org, parts[2:])
	case "members":
		s.adminOrgMembers(w, r, org, parts[2:])
	case "keys":
		s.adminOrgKeys(w, r, org, parts[2:])
	default:
		writeError(w, http.StatusNotFound, "unknown resource")
	}
}

func (s *Server) adminOrgResource(w http.ResponseWriter, r *http.Request, org *Organization) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, org)
	case http.MethodPatch:
		var req struct {
			Name                string `json:"name"`
			DefaultDailyLimit   *int   `json:"default_daily_limit"`
			DefaultMonthlyLimit *int   `json:"default_monthly_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name != "" {
			org.Name = req.Name
		}
		if req.DefaultDailyLimit != nil {
			org.DefaultDailyLimit = *req.DefaultDailyLimit
		}
		if req.DefaultMonthlyLimit != nil {
			org.DefaultMonthlyLimit = *req.DefaultMonthlyLimit
		}
		if err := s.store.UpdateOrg(org); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, org)
	case http.MethodDelete:
		if err := s.store.DeleteOrg(org.ID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// /admin/v1/orgs/{slug}/domains[/{id}[/verify|/dkim]]
func (s *Server) adminOrgDomains(w http.ResponseWriter, r *http.Request, org *Organization, rest []string) {
	if len(rest) == 0 || rest[0] == "" {
		switch r.Method {
		case http.MethodGet:
			domains, _ := s.store.ListDomainsForOrg(org.ID)
			writeJSON(w, http.StatusOK, domains)
		case http.MethodPost:
			var req struct {
				Domain string `json:"domain"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if req.Domain == "" {
				writeError(w, http.StatusBadRequest, "domain is required")
				return
			}
			token, _ := generateVerificationToken()
			d := &Domain{OrgID: org.ID, Domain: req.Domain, VerificationToken: token}
			if err := s.store.CreateDomain(d); err != nil {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{
				"domain":  d,
				"records": BuildDNSRecords(d, s.serverIP, s.dmarcReportTo),
			})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	id, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad domain id")
		return
	}
	d, err := s.store.GetDomainByID(id)
	if err != nil || d.OrgID != org.ID {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	action := ""
	if len(rest) > 1 {
		action = rest[1]
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"domain":  d,
			"records": BuildDNSRecords(d, s.serverIP, s.dmarcReportTo),
		})
	case action == "" && r.Method == http.MethodDelete:
		_ = s.store.DeleteDomain(id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case action == "verify" && r.Method == http.MethodPost:
		ok, msg, _ := checkAndMarkDomainVerified(r.Context(), s.store, s.verifier, d)
		writeJSON(w, http.StatusOK, map[string]any{"verified": ok, "message": msg})
	case action == "dkim" && r.Method == http.MethodPut:
		var req struct {
			Selector  string `json:"selector"`
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.store.UpdateDomainDKIM(id, req.Selector, req.PublicKey); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) adminOrgMembers(w http.ResponseWriter, r *http.Request, org *Organization, rest []string) {
	if len(rest) == 0 || rest[0] == "" {
		switch r.Method {
		case http.MethodGet:
			members, _ := s.store.ListOrgMembers(org.ID)
			writeJSON(w, http.StatusOK, members)
		case http.MethodPost:
			var req struct {
				Email    string `json:"email"`
				Password string `json:"password"`
				Role     Role   `json:"role"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if req.Email == "" {
				writeError(w, http.StatusBadRequest, "email is required")
				return
			}
			role := req.Role
			if role == "" {
				role = RoleMember
			}
			user, err := s.store.GetUserByEmail(req.Email)
			if err != nil {
				if req.Password == "" {
					writeError(w, http.StatusBadRequest, "user does not exist; provide a password to create them")
					return
				}
				hash, err := hashPassword(req.Password)
				if err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				user = &User{Email: req.Email, PasswordHash: hash}
				if err := s.store.CreateUser(user); err != nil {
					writeError(w, http.StatusConflict, err.Error())
					return
				}
			}
			if err := s.store.AddOrgMember(org.ID, user.ID, role); err != nil {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{"user_id": user.ID, "email": user.Email, "role": role})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	userID, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad user id")
		return
	}
	if r.Method == http.MethodDelete {
		_ = s.store.RemoveOrgMember(org.ID, userID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *Server) adminOrgKeys(w http.ResponseWriter, r *http.Request, org *Organization, rest []string) {
	if len(rest) == 0 || rest[0] == "" {
		switch r.Method {
		case http.MethodGet:
			keys, _ := s.store.ListAPIKeysForOrg(org.ID)
			// strip hashes
			out := make([]map[string]any, 0, len(keys))
			for i := range keys {
				out = append(out, map[string]any{
					"id": keys[i].ID, "label": keys[i].Label, "key_prefix": keys[i].KeyPrefix,
					"daily_limit": keys[i].DailyLimit, "monthly_limit": keys[i].MonthlyLimit,
					"status": keys[i].Status, "created_at": keys[i].CreatedAt,
					"last_used_at": keys[i].LastUsedAt,
				})
			}
			writeJSON(w, http.StatusOK, out)
		case http.MethodPost:
			var req struct {
				Label        string `json:"label"`
				DailyLimit   int    `json:"daily_limit"`
				MonthlyLimit int    `json:"monthly_limit"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if req.Label == "" {
				writeError(w, http.StatusBadRequest, "label is required")
				return
			}
			daily := req.DailyLimit
			if daily <= 0 {
				daily = org.DefaultDailyLimit
			}
			monthly := req.MonthlyLimit
			if monthly <= 0 {
				monthly = org.DefaultMonthlyLimit
			}
			raw, prefix, hash, err := generateAPIKey()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "failed to generate key")
				return
			}
			svcKey := r.Context().Value(serviceKeyValKey).(*ServiceAPIKey)
			k := &APIKey{
				OrgID: org.ID, CreatedByUserID: svcKey.CreatedByUserID, Label: req.Label,
				KeyPrefix: prefix, KeyHash: hash,
				DailyLimit: daily, MonthlyLimit: monthly, Status: "active",
			}
			if err := s.store.CreateAPIKey(k); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, map[string]any{
				"key":           raw, // shown once
				"id":            k.ID,
				"label":         k.Label,
				"key_prefix":    k.KeyPrefix,
				"daily_limit":   k.DailyLimit,
				"monthly_limit": k.MonthlyLimit,
			})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	id, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad key id")
		return
	}
	k, err := s.store.GetAPIKeyByID(id)
	if err != nil || k.OrgID != org.ID {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}
	if r.Method == http.MethodDelete {
		k.Status = "revoked"
		_ = s.store.UpdateAPIKey(k)
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}
