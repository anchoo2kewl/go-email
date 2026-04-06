package goemail

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type pageData struct {
	Title string
	Host  string
	User  *User
	Org   *Organization // current org context (if any)
	Role  Role          // user's role in current org
	Orgs  []Organization
	Flash *flashMessage

	// page-specific payloads are embedded at the top level for template ease
	Error     string
	Next      string
	Email     string
	NewKey    string
	Keys      []dashboardKey
	Domains   []domainRow
	Members   []memberRow
	AllOrgs       []orgRow
	ServiceKeys   []serviceKeyRow
	NewServiceKey string
	ChallHost     string // for domain-add page
	Token         string
	RecentLog     []SendLog

	// Search / filter state for org_overview
	SearchQuery    string
	SearchStatus   string
	SearchTag      string
	SearchFromDate string
	SearchToDate   string
	SearchKeyID    int64
	SearchPage     int
	TotalResults   int
	HasNextPage    bool
	HasPrevPage    bool
}

type flashMessage struct {
	Kind    string
	Message string
}

type dashboardKey struct {
	ID              int64
	Label           string
	KeyPrefix       string
	DailyLimit      int
	MonthlyLimit    int
	DailyUsed       int
	MonthlyUsed     int
	Status          string
	CreatedDisplay  string
	LastUsedDisplay string
}

type domainRow struct {
	ID              int64
	Domain          string
	Verified        bool
	VerifiedDisplay string
	CreatedDisplay  string
	DKIMSelector    string
	DKIMPublicKey   string
	Records         []DNSRecord
}

type memberRow struct {
	UserID         int64
	Email          string
	Role           Role
	CreatedDisplay string
}

type orgRow struct {
	ID             int64
	Name           string
	Slug           string
	MemberCount    int
	DomainCount    int
	KeyCount       int
	CreatedDisplay string
}

type serviceKeyRow struct {
	ID              int64
	Label           string
	KeyPrefix       string
	Status          string
	CreatedDisplay  string
	LastUsedDisplay string
}

// templateFuncs are shared helper functions available in all page templates.
var templateFuncs = template.FuncMap{
	"splitComma": func(s string) []string {
		if s == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	},
	"inc": func(n int) int { return n + 1 },
	"dec": func(n int) int { return n - 1 },
}

func (s *Server) initTemplates() error {
	pages := []string{"landing", "login", "orgs", "org_overview", "org_keys", "org_domains", "org_members", "admin"}
	for _, name := range pages {
		// Each page gets its own independent template set so {{define "content"}}
		// blocks don't overwrite each other across pages.
		t, err := template.New(name).Funcs(templateFuncs).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return err
		}
		s.templates[name] = t
	}
	return nil
}

func (s *Server) renderPage(w http.ResponseWriter, name string, data pageData) {
	t, ok := s.templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Dynamic admin pages must never be cached by the browser or an upstream
	// CDN — otherwise a stale "No organizations yet" etc. sticks around.
	w.Header().Set("Cache-Control", "no-store, private, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Errorf("render %s: %v", name, err)
	}
}

// --- router ---

func (s *Server) webHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleLanding)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	mux.HandleFunc("/orgs", s.requireLoginHTML(s.handleOrgsList))
	mux.HandleFunc("/orgs/", s.requireLoginHTML(s.handleOrgRoutes))

	mux.HandleFunc("/admin", s.requireLoginHTML(s.requireSuperAdmin(s.handleAdminPage)))
	mux.HandleFunc("/admin/orgs", s.requireLoginHTML(s.requireSuperAdmin(s.handleAdminCreateOrg)))
	mux.HandleFunc("/admin/service-keys", s.requireLoginHTML(s.requireSuperAdmin(s.handleAdminServiceKeys)))
	mux.HandleFunc("/admin/service-keys/", s.requireLoginHTML(s.requireSuperAdmin(s.handleAdminServiceKeyAction)))

	subFS, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(subFS))))
	return mux
}

func (s *Server) requireSuperAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFromCtx(r)
		if u == nil || !u.IsSuperAdmin {
			http.Error(w, "forbidden: super admin only", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --- landing / login ---

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, "landing", pageData{
		Title: "Self-hosted email gateway",
		Host:  r.Host,
		User:  s.userFromSession(r),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/orgs"
	}
	switch r.Method {
	case http.MethodGet:
		if s.userFromSession(r) != nil {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		s.renderPage(w, "login", pageData{Title: "Log in", Next: next})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderPage(w, "login", pageData{Title: "Log in", Next: next, Error: "invalid form"})
			return
		}
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		password := r.FormValue("password")
		u, err := s.store.GetUserByEmail(email)
		if err != nil || verifyPassword(password, u.PasswordHash) != nil {
			s.renderPage(w, "login", pageData{Title: "Log in", Next: next, Email: email, Error: "invalid credentials"})
			return
		}
		if err := s.createSession(w, u); err != nil {
			s.renderPage(w, "login", pageData{Title: "Log in", Next: next, Email: email, Error: "could not create session"})
			return
		}
		http.Redirect(w, r, next, http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

// --- orgs list ---

func (s *Server) handleOrgsList(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	orgs, err := s.store.ListOrgsForUser(u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderPage(w, "orgs", pageData{Title: "Organizations", User: u, Orgs: orgs})
}

// --- per-org routes: /orgs/{slug}/... ---

func (s *Server) handleOrgRoutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/orgs/")
	parts := strings.SplitN(rest, "/", 2)
	slug := parts[0]
	if slug == "" {
		http.Redirect(w, r, "/orgs", http.StatusFound)
		return
	}

	u := userFromCtx(r)
	org, err := s.store.GetOrgBySlug(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Authorize: user must be an org member, OR super admin.
	var role Role
	member, err := s.store.GetOrgMember(org.ID, u.ID)
	if err == nil {
		role = member.Role
	} else if u.IsSuperAdmin {
		role = RoleOwner // super admins act as owner within any org
	} else {
		http.Error(w, "forbidden: not a member of this organization", http.StatusForbidden)
		return
	}
	r = r.WithContext(withOrgAndRole(r.Context(), org, role))

	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}
	switch {
	case sub == "":
		s.handleOrgOverview(w, r)
	case sub == "keys":
		s.handleOrgKeys(w, r)
	case strings.HasPrefix(sub, "keys/"):
		s.handleOrgKeyAction(w, r, strings.TrimPrefix(sub, "keys/"))
	case sub == "domains":
		s.handleOrgDomains(w, r)
	case strings.HasPrefix(sub, "domains/"):
		s.handleOrgDomainAction(w, r, strings.TrimPrefix(sub, "domains/"))
	case sub == "members":
		s.handleOrgMembers(w, r)
	case strings.HasPrefix(sub, "members/"):
		s.handleOrgMemberAction(w, r, strings.TrimPrefix(sub, "members/"))
	default:
		http.NotFound(w, r)
	}
}

// --- per-org: overview ---

func (s *Server) handleOrgOverview(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	org := orgFromCtx(r)
	role := roleFromCtx(r)

	const pageSize = 20

	q := r.URL.Query()
	searchQuery := q.Get("q")
	searchStatus := q.Get("status")
	searchTag := q.Get("tag")
	searchFromDate := q.Get("from_date")
	searchToDate := q.Get("to_date")
	keyIDStr := q.Get("key_id")
	pageStr := q.Get("page")

	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	keyID, _ := strconv.ParseInt(keyIDStr, 10, 64)

	opts := SearchOpts{
		Query:    searchQuery,
		Status:   searchStatus,
		Tag:      searchTag,
		APIKeyID: keyID,
		Limit:    pageSize,
		Offset:   (page - 1) * pageSize,
	}

	if searchFromDate != "" {
		if t, err := time.ParseInLocation("2006-01-02", searchFromDate, time.UTC); err == nil {
			opts.FromDate = t
		}
	}
	if searchToDate != "" {
		if t, err := time.ParseInLocation("2006-01-02", searchToDate, time.UTC); err == nil {
			opts.ToDate = t.AddDate(0, 0, 1) // include full end day
		}
	}

	results, total, _ := s.store.SearchSendsForOrg(org.ID, opts)

	s.renderPage(w, "org_overview", pageData{
		Title: org.Name, User: u, Org: org, Role: role, RecentLog: results,
		SearchQuery:    searchQuery,
		SearchStatus:   searchStatus,
		SearchTag:      searchTag,
		SearchFromDate: searchFromDate,
		SearchToDate:   searchToDate,
		SearchKeyID:    keyID,
		SearchPage:     page,
		TotalResults:   total,
		HasNextPage:    opts.Offset+pageSize < total,
		HasPrevPage:    page > 1,
	})
}

// --- per-org: keys ---

func (s *Server) handleOrgKeys(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	org := orgFromCtx(r)
	role := roleFromCtx(r)

	if r.Method == http.MethodPost {
		// create key
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		label := strings.TrimSpace(r.FormValue("label"))
		if label == "" {
			http.Redirect(w, r, "/orgs/"+org.Slug+"/keys", http.StatusFound)
			return
		}
		daily, _ := strconv.Atoi(r.FormValue("daily_limit"))
		monthly, _ := strconv.Atoi(r.FormValue("monthly_limit"))
		if daily <= 0 || daily > org.DefaultDailyLimit {
			if role != RoleOwner && role != RoleAdmin {
				daily = org.DefaultDailyLimit
			} else if daily <= 0 {
				daily = org.DefaultDailyLimit
			}
		}
		if monthly <= 0 || monthly > org.DefaultMonthlyLimit {
			if role != RoleOwner && role != RoleAdmin {
				monthly = org.DefaultMonthlyLimit
			} else if monthly <= 0 {
				monthly = org.DefaultMonthlyLimit
			}
		}
		raw, prefix, hash, err := generateAPIKey()
		if err != nil {
			http.Error(w, "failed to generate key", http.StatusInternalServerError)
			return
		}
		if err := s.store.CreateAPIKey(&APIKey{
			OrgID: org.ID, CreatedByUserID: u.ID, Label: label,
			KeyPrefix: prefix, KeyHash: hash,
			DailyLimit: daily, MonthlyLimit: monthly, Status: "active",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/orgs/"+org.Slug+"/keys?key="+raw, http.StatusFound)
		return
	}

	keys, _ := s.store.ListAPIKeysForOrg(org.ID)
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	rows := make([]dashboardKey, 0, len(keys))
	for i := range keys {
		d, _ := s.store.CountSendsSince(keys[i].ID, startOfDay)
		m, _ := s.store.CountSendsSince(keys[i].ID, startOfMonth)
		last := "—"
		if keys[i].LastUsedAt != nil {
			last = keys[i].LastUsedAt.Format("Jan 2, 15:04 UTC")
		}
		rows = append(rows, dashboardKey{
			ID: keys[i].ID, Label: keys[i].Label, KeyPrefix: keys[i].KeyPrefix,
			DailyLimit: keys[i].DailyLimit, MonthlyLimit: keys[i].MonthlyLimit,
			DailyUsed: d, MonthlyUsed: m, Status: keys[i].Status,
			CreatedDisplay: keys[i].CreatedAt.Format("Jan 2, 2006"),
			LastUsedDisplay: last,
		})
	}
	s.renderPage(w, "org_keys", pageData{
		Title: "API keys · " + org.Name, User: u, Org: org, Role: role,
		Keys: rows, NewKey: r.URL.Query().Get("key"),
	})
}

func (s *Server) handleOrgKeyAction(w http.ResponseWriter, r *http.Request, rest string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	org := orgFromCtx(r)
	parts := strings.Split(rest, "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	key, err := s.store.GetAPIKeyByID(id)
	if err != nil || key.OrgID != org.ID {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" {
		key.Status = "revoked"
		_ = s.store.UpdateAPIKey(key)
	}
	http.Redirect(w, r, "/orgs/"+org.Slug+"/keys", http.StatusFound)
}

// --- per-org: domains ---

func (s *Server) handleOrgDomains(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	org := orgFromCtx(r)
	role := roleFromCtx(r)

	if r.Method == http.MethodPost {
		if role != RoleOwner && role != RoleAdmin {
			http.Error(w, "forbidden: admin only", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
		if domain == "" {
			http.Redirect(w, r, "/orgs/"+org.Slug+"/domains", http.StatusFound)
			return
		}
		token, _ := generateVerificationToken()
		if err := s.store.CreateDomain(&Domain{
			OrgID: org.ID, Domain: domain, VerificationToken: token,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/orgs/"+org.Slug+"/domains", http.StatusFound)
		return
	}

	domains, _ := s.store.ListDomainsForOrg(org.ID)
	rows := make([]domainRow, 0, len(domains))
	for i := range domains {
		d := domains[i]
		verifiedStr := "—"
		if d.VerifiedAt != nil {
			verifiedStr = d.VerifiedAt.Format("Jan 2, 2006")
		}
		rows = append(rows, domainRow{
			ID: d.ID, Domain: d.Domain,
			Verified:        d.VerifiedAt != nil,
			VerifiedDisplay: verifiedStr,
			CreatedDisplay:  d.CreatedAt.Format("Jan 2, 2006"),
			DKIMSelector:    d.DKIMSelector,
			DKIMPublicKey:   d.DKIMPublicKey,
			Records:         BuildDNSRecords(&d, s.serverIP, s.dmarcReportTo),
		})
	}
	s.renderPage(w, "org_domains", pageData{
		Title: "Domains · " + org.Name, User: u, Org: org, Role: role, Domains: rows,
	})
}

func (s *Server) handleOrgDomainAction(w http.ResponseWriter, r *http.Request, rest string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	org := orgFromCtx(r)
	role := roleFromCtx(r)
	if role != RoleOwner && role != RoleAdmin {
		http.Error(w, "forbidden: admin only", http.StatusForbidden)
		return
	}
	parts := strings.Split(rest, "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	d, err := s.store.GetDomainByID(id)
	if err != nil || d.OrgID != org.ID {
		http.NotFound(w, r)
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch action {
	case "verify":
		_, _, _ = checkAndMarkDomainVerified(r.Context(), s.store, s.verifier, d)
	case "dkim":
		_ = r.ParseForm()
		selector := strings.TrimSpace(r.FormValue("selector"))
		pub := strings.TrimSpace(r.FormValue("public_key"))
		_ = s.store.UpdateDomainDKIM(id, selector, pub)
	case "delete":
		_ = s.store.DeleteDomain(id)
	}
	http.Redirect(w, r, "/orgs/"+org.Slug+"/domains", http.StatusFound)
}

// --- per-org: members ---

func (s *Server) handleOrgMembers(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	org := orgFromCtx(r)
	role := roleFromCtx(r)

	if r.Method == http.MethodPost {
		if role != RoleOwner && role != RoleAdmin {
			http.Error(w, "forbidden: admin only", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		pass := r.FormValue("password")
		roleStr := r.FormValue("role")
		if email == "" {
			http.Redirect(w, r, "/orgs/"+org.Slug+"/members", http.StatusFound)
			return
		}
		newRole := Role(roleStr)
		if newRole != RoleOwner && newRole != RoleAdmin && newRole != RoleMember {
			newRole = RoleMember
		}
		// Only owners can promote to owner.
		if newRole == RoleOwner && role != RoleOwner {
			newRole = RoleAdmin
		}
		target, err := s.store.GetUserByEmail(email)
		if err != nil {
			// create user if password provided
			if pass == "" {
				http.Error(w, "user does not exist — provide a password to create them", http.StatusBadRequest)
				return
			}
			hash, err := hashPassword(pass)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			target = &User{Email: email, PasswordHash: hash}
			if err := s.store.CreateUser(target); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
		}
		_ = s.store.AddOrgMember(org.ID, target.ID, newRole)
		http.Redirect(w, r, "/orgs/"+org.Slug+"/members", http.StatusFound)
		return
	}

	members, _ := s.store.ListOrgMembers(org.ID)
	rows := make([]memberRow, 0, len(members))
	for _, m := range members {
		rows = append(rows, memberRow{
			UserID: m.UserID, Email: m.UserEmail, Role: m.Role,
			CreatedDisplay: m.CreatedAt.Format("Jan 2, 2006"),
		})
	}
	s.renderPage(w, "org_members", pageData{
		Title: "Members · " + org.Name, User: u, Org: org, Role: role, Members: rows,
	})
}

func (s *Server) handleOrgMemberAction(w http.ResponseWriter, r *http.Request, rest string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	org := orgFromCtx(r)
	role := roleFromCtx(r)
	if role != RoleOwner && role != RoleAdmin {
		http.Error(w, "forbidden: admin only", http.StatusForbidden)
		return
	}
	parts := strings.Split(rest, "/")
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if len(parts) == 2 && parts[1] == "remove" {
		_ = s.store.RemoveOrgMember(org.ID, userID)
	}
	http.Redirect(w, r, "/orgs/"+org.Slug+"/members", http.StatusFound)
}

// --- super-admin panel ---

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	orgs, _ := s.store.ListOrgs()
	rows := make([]orgRow, 0, len(orgs))
	for i := range orgs {
		mems, _ := s.store.ListOrgMembers(orgs[i].ID)
		doms, _ := s.store.ListDomainsForOrg(orgs[i].ID)
		keys, _ := s.store.ListAPIKeysForOrg(orgs[i].ID)
		rows = append(rows, orgRow{
			ID: orgs[i].ID, Name: orgs[i].Name, Slug: orgs[i].Slug,
			MemberCount: len(mems), DomainCount: len(doms), KeyCount: len(keys),
			CreatedDisplay: orgs[i].CreatedAt.Format("Jan 2, 2006"),
		})
	}
	svc, _ := s.store.ListServiceAPIKeys()
	svcRows := make([]serviceKeyRow, 0, len(svc))
	for i := range svc {
		last := "—"
		if svc[i].LastUsedAt != nil {
			last = svc[i].LastUsedAt.Format("Jan 2, 15:04 UTC")
		}
		svcRows = append(svcRows, serviceKeyRow{
			ID: svc[i].ID, Label: svc[i].Label, KeyPrefix: svc[i].KeyPrefix, Status: svc[i].Status,
			CreatedDisplay: svc[i].CreatedAt.Format("Jan 2, 2006"), LastUsedDisplay: last,
		})
	}
	s.renderPage(w, "admin", pageData{
		Title: "Admin", User: u, AllOrgs: rows,
		ServiceKeys: svcRows, NewServiceKey: r.URL.Query().Get("svckey"),
	})
}

// POST /admin/service-keys — create a new platform admin API key
func (s *Server) handleAdminServiceKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u := userFromCtx(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	raw, prefix, hash, err := generateServiceKey()
	if err != nil {
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateServiceAPIKey(&ServiceAPIKey{
		Label: label, KeyPrefix: prefix, KeyHash: hash,
		CreatedByUserID: u.ID, Status: "active",
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin?svckey="+raw, http.StatusFound)
}

// POST /admin/service-keys/{id}/revoke
func (s *Server) handleAdminServiceKeyAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/admin/service-keys/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "revoke" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	keys, _ := s.store.ListServiceAPIKeys()
	for i := range keys {
		if keys[i].ID == id {
			keys[i].Status = "revoked"
			_ = s.store.UpdateServiceAPIKey(&keys[i])
			break
		}
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) handleAdminCreateOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	slug := r.FormValue("slug")
	if slug == "" {
		slug = slugify(name)
	} else {
		slug = slugify(slug)
	}
	daily, _ := strconv.Atoi(r.FormValue("default_daily_limit"))
	monthly, _ := strconv.Atoi(r.FormValue("default_monthly_limit"))
	ownerEmail := strings.ToLower(strings.TrimSpace(r.FormValue("owner_email")))
	org := &Organization{
		Name: name, Slug: slug,
		DefaultDailyLimit: daily, DefaultMonthlyLimit: monthly,
	}
	if err := s.store.CreateOrg(org); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Optionally seed an owner.
	if ownerEmail != "" {
		if owner, err := s.store.GetUserByEmail(ownerEmail); err == nil {
			_ = s.store.AddOrgMember(org.ID, owner.ID, RoleOwner)
		}
	}
	http.Redirect(w, r, "/orgs/"+org.Slug, http.StatusFound)
}
