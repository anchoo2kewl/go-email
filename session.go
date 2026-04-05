package goemail

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

const sessionCookieName = "goemail_session"
const sessionDuration = 30 * 24 * time.Hour

// newSessionID returns 32 bytes of randomness, URL-safe base64.
func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// createSession persists a session for the user and returns a Set-Cookie for
// the response. Use Secure=false only in dev; the emaild binary is expected
// to sit behind an HTTPS reverse proxy in production.
func (s *Server) createSession(w http.ResponseWriter, u *User) error {
	id, err := newSessionID()
	if err != nil {
		return err
	}
	now := time.Now()
	if err := s.store.CreateSession(&Session{
		ID: id, UserID: u.ID,
		CreatedAt: now, ExpiresAt: now.Add(sessionDuration),
	}); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  now.Add(sessionDuration),
	})
	return nil
}

// clearSession invalidates the user's session server-side and expires the cookie.
func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		_ = s.store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// userFromSession returns the user tied to the request's session cookie, or
// nil if the cookie is missing / expired / belongs to a deleted user.
func (s *Server) userFromSession(r *http.Request) *User {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := s.store.GetSession(c.Value)
	if err != nil {
		return nil
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.store.DeleteSession(sess.ID)
		return nil
	}
	u, err := s.store.GetUserByID(sess.UserID)
	if err != nil {
		return nil
	}
	return u
}

// requireLoginHTML is middleware for HTML routes: redirects to /login if no
// valid session, otherwise injects the user into the request context.
func (s *Server) requireLoginHTML(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.userFromSession(r)
		if u == nil {
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
			return
		}
		r = r.WithContext(withUser(r.Context(), u))
		next(w, r)
	}
}
