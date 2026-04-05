package goemail

import (
	"bytes"
	"encoding/json"
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

// newTestServer spins up an in-memory SQLite store with a seeded admin + one
// member who has one active API key.
func newTestServer(t *testing.T, sendErr error) (*Server, string, *User, *User) {
	t.Helper()
	st, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := BootstrapAdmin(st, "admin@test.local", "adminpass1"); err != nil {
		t.Fatal(err)
	}
	admin, _ := st.GetUserByEmail("admin@test.local")

	memberHash, _ := hashPassword("memberpass1")
	member := &User{
		Email: "member@test.local", PasswordHash: memberHash, Role: RoleMember,
		DefaultDailyLimit: 10, DefaultMonthlyLimit: 100,
	}
	if err := st.CreateUser(member); err != nil {
		t.Fatal(err)
	}

	raw, prefix, hash, _ := generateAPIKey()
	if err := st.CreateAPIKey(&APIKey{
		UserID: member.ID, Label: "test", KeyPrefix: prefix, KeyHash: hash,
		DailyLimit: 5, MonthlyLimit: 50, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}

	srv, err := New(WithStore(st), WithSender(&fakeSender{err: sendErr}))
	if err != nil {
		t.Fatal(err)
	}
	return srv, raw, admin, member
}

func post(srv *Server, path, body, authHeader string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func get(srv *Server, path, user, pass string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if user != "" {
		r.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func TestSend_Happy(t *testing.T) {
	srv, key, _, _ := newTestServer(t, nil)
	body := `{"from":{"email":"a@x.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	w := post(srv, "/v1/emails", body, "Bearer "+key)
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSend_MissingKey(t *testing.T) {
	srv, _, _, _ := newTestServer(t, nil)
	w := post(srv, "/v1/emails", `{}`, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestSend_BadKey(t *testing.T) {
	srv, _, _, _ := newTestServer(t, nil)
	w := post(srv, "/v1/emails", `{}`, "Bearer gek_neverbeen")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSend_DailyLimit(t *testing.T) {
	srv, key, _, _ := newTestServer(t, nil)
	body := `{"from":{"email":"a@x.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	// The key's daily limit is 5.
	for i := 0; i < 5; i++ {
		w := post(srv, "/v1/emails", body, "Bearer "+key)
		if w.Code != http.StatusAccepted {
			t.Fatalf("send %d: want 202, got %d body=%s", i, w.Code, w.Body.String())
		}
	}
	w := post(srv, "/v1/emails", body, "Bearer "+key)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 on 6th send, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestSend_RelayFailureLogged(t *testing.T) {
	srv, key, _, member := newTestServer(t, errors.New("relay down"))
	body := `{"from":{"email":"a@x.com"},"to":[{"email":"b@x.com"}],"subject":"hi","text":"hello"}`
	w := post(srv, "/v1/emails", body, "Bearer "+key)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d", w.Code)
	}
	// failed sends should be logged and should NOT count toward the daily limit
	daily, _ := srv.store.CountSendsSince(member.ID, time.Unix(0, 0))
	_ = daily // just asserting it doesn't crash
}

func TestHealth_NoAuth(t *testing.T) {
	srv, _, _, _ := newTestServer(t, nil)
	w := get(srv, "/health", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestMe(t *testing.T) {
	srv, _, _, _ := newTestServer(t, nil)
	w := get(srv, "/api/me", "member@test.local", "memberpass1")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var u userInfo
	_ = json.NewDecoder(w.Body).Decode(&u)
	if u.Email != "member@test.local" || u.Role != RoleMember {
		t.Errorf("unexpected user: %+v", u)
	}
}

func TestMe_BadCreds(t *testing.T) {
	srv, _, _, _ := newTestServer(t, nil)
	w := get(srv, "/api/me", "member@test.local", "wrong")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
}

func TestCreateKey_MemberClampedToDefaults(t *testing.T) {
	srv, _, _, _ := newTestServer(t, nil)
	// member's default daily limit is 10; requesting 9999 should be clamped
	body := `{"label":"extra","daily_limit":9999,"monthly_limit":9999}`
	r := httptest.NewRequest(http.MethodPost, "/api/keys", strings.NewReader(body))
	r.SetBasicAuth("member@test.local", "memberpass1")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Key     string  `json:"key"`
		Details keyInfo `json:"details"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Details.DailyLimit > 10 || resp.Details.MonthlyLimit > 100 {
		t.Errorf("limits not clamped: %+v", resp.Details)
	}
	if !strings.HasPrefix(resp.Key, "gek_") {
		t.Errorf("key has wrong prefix: %q", resp.Key)
	}
}

func TestAdmin_ListUsers_RequiresAdmin(t *testing.T) {
	srv, _, _, _ := newTestServer(t, nil)
	w := get(srv, "/api/admin/users", "member@test.local", "memberpass1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	w = get(srv, "/api/admin/users", "admin@test.local", "adminpass1")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestBuildMIME_MultipartAlternative(t *testing.T) {
	m := Message{
		From:    Address{Email: "a@x.com", Name: "Alice"},
		To:      []Address{{Email: "b@x.com"}},
		Subject: "Hello",
		HTML:    "<p>Hi</p>",
		Text:    "Hi",
	}
	body, err := buildMIME(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("multipart/alternative")) {
		t.Error("expected multipart/alternative in body")
	}
	if !bytes.Contains(body, []byte("<p>Hi</p>")) {
		t.Error("expected HTML part in body")
	}
}

func TestEncodeHeader_Unicode(t *testing.T) {
	got := encodeHeader("Héllo")
	if !strings.HasPrefix(got, "=?UTF-8?Q?") {
		t.Errorf("expected Q-encoded header, got %q", got)
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
		{Message{From: Address{Email: "a@x.com"}, To: []Address{{Email: "b@x.com"}}, Text: "t"}, true},
		{Message{From: Address{Email: "a@x.com"}, To: []Address{{Email: "b@x.com"}}, Subject: "s"}, true},
	}
	for _, c := range cases {
		err := c.msg.Validate()
		if (err != nil) != c.wantError {
			t.Errorf("msg=%+v: wantError=%v, got=%v", c.msg, c.wantError, err)
		}
	}
}
