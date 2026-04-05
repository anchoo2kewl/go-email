package goemail

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeSender struct {
	got Message
	err error
}

func (f *fakeSender) Send(m Message) error {
	f.got = m
	return f.err
}

// fakeVerifier returns whatever we tell it to for a given domain.
type fakeVerifier struct {
	results map[string]bool // domain -> match
	err     error
}

func (f *fakeVerifier) Verify(_ context.Context, domain, _ string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.results[domain], nil
}

// testSetup seeds a store with: super-admin anshuman@biswas.me, org "acme",
// owner-owner bob@acme.com, member alice@acme.com, verified domain acme.com,
// and one active API key for acme.
type testSetup struct {
	store    Store
	srv      *Server
	admin    *User
	owner    *User
	member   *User
	org      *Organization
	domain   *Domain
	rawKey   string
	key      *APIKey
	verifier *fakeVerifier
}

func newTestSetup(t *testing.T, sendErr error) *testSetup {
	t.Helper()
	st, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	_ = Bootstrap(st, BootstrapConfig{
		AdminEmail: "anshuman@biswas.me", AdminPassword: "adminpass1",
		OrgName: "biswas-me", OrgSlug: "biswas-me", InitialDomain: "biswas.me",
	})
	admin, _ := st.GetUserByEmail("anshuman@biswas.me")

	// Create a second, independent org for the tests
	org := &Organization{Name: "Acme", Slug: "acme", DefaultDailyLimit: 10, DefaultMonthlyLimit: 100}
	if err := st.CreateOrg(org); err != nil {
		t.Fatal(err)
	}
	ownerHash, _ := hashPassword("bobpass12")
	owner := &User{Email: "bob@acme.com", PasswordHash: ownerHash}
	if err := st.CreateUser(owner); err != nil {
		t.Fatal(err)
	}
	_ = st.AddOrgMember(org.ID, owner.ID, RoleOwner)

	memHash, _ := hashPassword("alicepass1")
	member := &User{Email: "alice@acme.com", PasswordHash: memHash}
	_ = st.CreateUser(member)
	_ = st.AddOrgMember(org.ID, member.ID, RoleMember)

	// Pre-verified domain
	domain := &Domain{OrgID: org.ID, Domain: "acme.com", VerificationToken: "goemail-verify=test"}
	_ = st.CreateDomain(domain)
	_ = st.MarkDomainVerified(domain.ID, time.Now())
	domain, _ = st.GetDomainByID(domain.ID)

	raw, prefix, hash, _ := generateAPIKey()
	key := &APIKey{
		OrgID: org.ID, CreatedByUserID: owner.ID, Label: "test",
		KeyPrefix: prefix, KeyHash: hash,
		DailyLimit: 5, MonthlyLimit: 50, Status: "active",
	}
	_ = st.CreateAPIKey(key)

	verifier := &fakeVerifier{results: make(map[string]bool)}
	srv, err := New(WithStore(st), WithSender(&fakeSender{err: sendErr}), WithVerifier(verifier))
	if err != nil {
		t.Fatal(err)
	}
	return &testSetup{
		store: st, srv: srv, admin: admin, owner: owner, member: member,
		org: org, domain: domain, rawKey: raw, key: key, verifier: verifier,
	}
}

func postJSON(srv *Server, path, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func TestSend_Happy(t *testing.T) {
	ts := newTestSetup(t, nil)
	body := `{"from":{"email":"alerts@acme.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	w := postJSON(ts.srv, "/v1/emails", body, ts.rawKey)
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSend_UnverifiedDomain(t *testing.T) {
	ts := newTestSetup(t, nil)
	body := `{"from":{"email":"alerts@evil.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	w := postJSON(ts.srv, "/v1/emails", body, ts.rawKey)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not a verified domain") {
		t.Errorf("expected verified-domain error, got %s", w.Body.String())
	}
}

func TestSend_MissingKey(t *testing.T) {
	ts := newTestSetup(t, nil)
	w := postJSON(ts.srv, "/v1/emails", `{}`, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestSend_RevokedKey(t *testing.T) {
	ts := newTestSetup(t, nil)
	ts.key.Status = "revoked"
	_ = ts.store.UpdateAPIKey(ts.key)
	body := `{"from":{"email":"alerts@acme.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	w := postJSON(ts.srv, "/v1/emails", body, ts.rawKey)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSend_DailyLimit(t *testing.T) {
	ts := newTestSetup(t, nil)
	body := `{"from":{"email":"alerts@acme.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	for i := 0; i < 5; i++ {
		w := postJSON(ts.srv, "/v1/emails", body, ts.rawKey)
		if w.Code != http.StatusAccepted {
			t.Fatalf("send %d: want 202, got %d", i, w.Code)
		}
	}
	w := postJSON(ts.srv, "/v1/emails", body, ts.rawKey)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("6th send: want 429, got %d", w.Code)
	}
}

func TestSend_RelayFailureReturns502(t *testing.T) {
	ts := newTestSetup(t, errors.New("relay down"))
	body := `{"from":{"email":"alerts@acme.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	w := postJSON(ts.srv, "/v1/emails", body, ts.rawKey)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", w.Code)
	}
}

func TestDomainVerification(t *testing.T) {
	ts := newTestSetup(t, nil)
	// Add a new unverified domain
	token, _ := generateVerificationToken()
	d := &Domain{OrgID: ts.org.ID, Domain: "newsite.com", VerificationToken: token}
	_ = ts.store.CreateDomain(d)

	// Fail: verifier says no match
	ok, msg, _ := checkAndMarkDomainVerified(context.Background(), ts.store, ts.verifier, d)
	if ok {
		t.Errorf("expected verification to fail, got success: %s", msg)
	}

	// Succeed
	ts.verifier.results["newsite.com"] = true
	ok, _, _ = checkAndMarkDomainVerified(context.Background(), ts.store, ts.verifier, d)
	if !ok {
		t.Fatalf("expected verification to succeed")
	}
	got, _ := ts.store.GetDomainByID(d.ID)
	if got.VerifiedAt == nil {
		t.Errorf("VerifiedAt should be set")
	}
}

func TestParseFromDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"support@pingrly.com", "pingrly.com"},
		{"user+tag@Example.COM", "example.com"},
		{"no-at-sign", ""},
		{"trailing@", ""},
	}
	for _, c := range cases {
		if got := parseFromDomain(c.in); got != c.want {
			t.Errorf("parseFromDomain(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSlugify(t *testing.T) {
	cases := []struct{ in, want string }{
		{"My Org Name", "my-org-name"},
		{"biswas-me", "biswas-me"},
		{"  Hello  ", "hello"},
		{"", "org"},
	}
	for _, c := range cases {
		if got := slugify(c.in); got != c.want {
			t.Errorf("slugify(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestBootstrap(t *testing.T) {
	st, _ := OpenStore(":memory:")
	defer st.Close()
	err := Bootstrap(st, BootstrapConfig{
		AdminEmail: "a@b.com", AdminPassword: "pass12345",
		OrgName: "Acme", InitialDomain: "acme.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := st.GetUserByEmail("a@b.com")
	if u == nil || !u.IsSuperAdmin {
		t.Fatal("admin not created or not super-admin")
	}
	o, _ := st.GetOrgBySlug("acme")
	if o == nil {
		t.Fatal("org not created")
	}
	d, _ := st.GetDomainByName(o.ID, "acme.com")
	if d == nil || d.VerifiedAt != nil {
		t.Fatal("domain not seeded or wrongly pre-verified")
	}
	// second call is a no-op
	_ = Bootstrap(st, BootstrapConfig{AdminEmail: "x@y.com", AdminPassword: "otherpass"})
	if n, _ := st.CountUsers(); n != 1 {
		t.Errorf("bootstrap should be idempotent; got %d users", n)
	}
}

func TestMessageValidate(t *testing.T) {
	cases := []struct {
		msg       Message
		wantError bool
	}{
		{Message{From: Address{Email: "a@x.com"}, To: []Address{{Email: "b@x.com"}}, Subject: "s", Text: "t"}, false},
		{Message{To: []Address{{Email: "b@x.com"}}, Subject: "s", Text: "t"}, true},
		{Message{From: Address{Email: "a@x.com"}, Subject: "s", Text: "t"}, true},
	}
	for _, c := range cases {
		err := c.msg.Validate()
		if (err != nil) != c.wantError {
			t.Errorf("msg=%+v: wantError=%v, got=%v", c.msg, c.wantError, err)
		}
	}
}

func TestEncodeHeader_Unicode(t *testing.T) {
	got := encodeHeader("Héllo")
	if !strings.HasPrefix(got, "=?UTF-8?Q?") {
		t.Errorf("expected Q-encoded header, got %q", got)
	}
}
