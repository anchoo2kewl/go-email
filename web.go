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

// pageData is the shared template struct for every HTML route.
type pageData struct {
	Title string
	Host  string
	User  *User
	Flash *flashMessage
	// page-specific payload lives in Data
	Data any
	// login-specific (kept at top level so templates can access it directly)
	Error string
	Next  string
	Email string
	// dashboard-specific
	NewKey string
	Keys   []dashboardKey
	Users  []adminUser
}

type flashMessage struct {
	Kind    string // "success" | "error"
	Message string
}

type dashboardKey struct {
	keyInfo
	DailyUsed       int
	MonthlyUsed     int
	LastUsedDisplay string
}

type adminUser struct {
	userInfo
	CreatedDisplay string
}

func (s *Server) initTemplates() error {
	// Parse layout + each content template together into its own tree so
	// blocks are correctly overridden per-page.
	tmpl := template.New("")
	pages := []string{"landing", "login", "dashboard", "admin"}
	for _, name := range pages {
		t, err := tmpl.New(name).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
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
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Errorf("render %s: %v", name, err)
	}
}

// --- routes ---

func (s *Server) webHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleLanding)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/dashboard", s.requireLoginHTML(s.handleDashboard))
	mux.HandleFunc("/dashboard/keys", s.requireLoginHTML(s.handleCreateKeyForm))
	mux.HandleFunc("/dashboard/keys/", s.requireLoginHTML(s.handleKeyAction))
	mux.HandleFunc("/admin", s.requireLoginHTML(s.requireAdminHTML(s.handleAdminUsersPage)))
	mux.HandleFunc("/admin/users", s.requireLoginHTML(s.requireAdminHTML(s.handleAdminUsersForm)))
	mux.HandleFunc("/admin/users/", s.requireLoginHTML(s.requireAdminHTML(s.handleAdminUserForm)))

	// static files under /static/*
	subFS, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(subFS))))
	return mux
}

func (s *Server) requireAdminHTML(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFromCtx(r)
		if u == nil || u.Role != RoleAdmin {
			http.Error(w, "forbidden: admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --- landing ---

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

// --- login / logout ---

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/dashboard"
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
		if email == "" || password == "" {
			s.renderPage(w, "login", pageData{Title: "Log in", Next: next, Email: email, Error: "email and password are required"})
			return
		}
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

// --- dashboard ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	u := userFromCtx(r)
	keys, err := s.store.ListAPIKeysForUser(u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dashKeys := make([]dashboardKey, 0, len(keys))
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	for i := range keys {
		d, _ := s.store.CountSendsSince(keys[i].ID, startOfDay)
		m, _ := s.store.CountSendsSince(keys[i].ID, startOfMonth)
		last := "—"
		if keys[i].LastUsedAt != nil {
			last = keys[i].LastUsedAt.Format("Jan 2, 15:04 UTC")
		}
		dashKeys = append(dashKeys, dashboardKey{
			keyInfo:         toKeyInfo(&keys[i]),
			DailyUsed:       d,
			MonthlyUsed:     m,
			LastUsedDisplay: last,
		})
	}
	s.renderPage(w, "dashboard", pageData{
		Title:  "Dashboard",
		User:   u,
		Keys:   dashKeys,
		NewKey: r.URL.Query().Get("key"),
	})
}

// POST /dashboard/keys — create a key from the modal form and redirect back
// to /dashboard?key=<raw> so the user sees it once.
func (s *Server) handleCreateKeyForm(w http.ResponseWriter, r *http.Request) {
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
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	daily, _ := strconv.Atoi(r.FormValue("daily_limit"))
	monthly, _ := strconv.Atoi(r.FormValue("monthly_limit"))
	if daily <= 0 {
		daily = u.DefaultDailyLimit
	}
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
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateAPIKey(&APIKey{
		UserID: u.ID, Label: label, KeyPrefix: prefix, KeyHash: hash,
		DailyLimit: daily, MonthlyLimit: monthly, Status: "active",
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/dashboard?key="+raw, http.StatusFound)
}

// POST /dashboard/keys/{id}/revoke
func (s *Server) handleKeyAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u := userFromCtx(r)
	rest := strings.TrimPrefix(r.URL.Path, "/dashboard/keys/")
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
	key, err := s.store.GetAPIKeyByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if key.UserID != u.ID && u.Role != RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	key.Status = "revoked"
	_ = s.store.UpdateAPIKey(key)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// --- admin UI ---

func (s *Server) handleAdminUsersPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	u := userFromCtx(r)
	users, err := s.store.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	au := make([]adminUser, 0, len(users))
	for i := range users {
		au = append(au, adminUser{
			userInfo:       toUserInfo(&users[i]),
			CreatedDisplay: users[i].CreatedAt.Format("Jan 2, 2006"),
		})
	}
	s.renderPage(w, "admin", pageData{Title: "Admin", User: u, Users: au})
}

// POST /admin/users — create
func (s *Server) handleAdminUsersForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	pass := r.FormValue("password")
	role := Role(r.FormValue("role"))
	if role != RoleAdmin {
		role = RoleMember
	}
	daily, _ := strconv.Atoi(r.FormValue("default_daily_limit"))
	monthly, _ := strconv.Atoi(r.FormValue("default_monthly_limit"))
	if daily <= 0 {
		daily = 100
	}
	if monthly <= 0 {
		monthly = 1000
	}
	hash, err := hashPassword(pass)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.CreateUser(&User{
		Email: email, PasswordHash: hash, Role: role,
		DefaultDailyLimit: daily, DefaultMonthlyLimit: monthly,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// POST /admin/users/{id}        — edit
// POST /admin/users/{id}/delete — delete
func (s *Server) handleAdminUserForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	parts := strings.Split(rest, "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	u, err := s.store.GetUserByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "delete" {
		if err := s.store.DeleteUser(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	// edit
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if p := r.FormValue("password"); p != "" {
		if h, err := hashPassword(p); err == nil {
			u.PasswordHash = h
		}
	}
	if role := r.FormValue("role"); role != "" {
		r := Role(role)
		if r == RoleAdmin || r == RoleMember {
			u.Role = r
		}
	}
	if d, err := strconv.Atoi(r.FormValue("default_daily_limit")); err == nil && d > 0 {
		u.DefaultDailyLimit = d
	}
	if m, err := strconv.Atoi(r.FormValue("default_monthly_limit")); err == nil && m > 0 {
		u.DefaultMonthlyLimit = m
	}
	if err := s.store.UpdateUser(u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}
