# go-email

A self-hosted HTTP email gateway backed by your own SMTP server (Mailcow,
Postfix, etc.). Supports multiple users, per-key rate limits, and usage
tracking — all stored in a single SQLite database.

## Why

Transactional providers (Brevo, SendGrid, MailerSend…) each have their own
suspensions, trial gotchas, and schemas. If you already run SMTP, put a small
HTTP service in front of it and have every app speak the same API.

## Concepts

- **Users** have role `admin` or `member`, with per-user default send limits.
- **Members** can create their own API keys (clamped to their defaults).
- **Admins** can create/edit/delete users and override limits on any key.
- **API keys** are generated server-side, shown once, stored as bcrypt hash.
- **Send limits** (daily + monthly) are enforced at send time and logged.

## Endpoints

### Send (API key auth)

```
POST /v1/emails
Authorization: Bearer gek_<key>
Content-Type: application/json

{
  "from":    { "email": "alerts@example.com", "name": "App" },
  "to":      [ { "email": "user@example.com", "name": "User" } ],
  "subject": "Hello",
  "html":    "<p>Hi</p>",
  "text":    "Hi"
}
```

Responses: `202` sent, `400` bad request, `401` bad key, `403` revoked key,
`429` limit exceeded, `502` relay failed.

### Member (HTTP Basic auth, email + password)

```
GET    /api/me
GET    /api/keys                   — list my keys
POST   /api/keys                   — create key  {label, daily_limit, monthly_limit}
GET    /api/keys/{id}              — one key
PATCH  /api/keys/{id}              — update label/limits
DELETE /api/keys/{id}              — revoke
GET    /api/keys/{id}/usage        — counters + recent sends
```

### Admin (HTTP Basic + admin role)

```
GET    /admin/users
POST   /admin/users                — create  {email, password, role, default_daily_limit, default_monthly_limit}
PATCH  /admin/users/{id}
DELETE /admin/users/{id}
GET    /admin/keys                 — all keys across all users
```

## Run

```bash
DB_PATH=./data/emaild.db \
SMTP_HOST=mail.example.com \
SMTP_PORT=587 \
SMTP_USERNAME=noreply@example.com \
SMTP_PASSWORD=xxxxx \
ADMIN_EMAIL=admin@example.com \
ADMIN_PASSWORD=changemenow \
go run ./cmd/emaild
```

First boot with an empty DB will create the admin user. After that, log in
and create members + keys via the API.

## Docker

Put this next to Mailcow's `docker-compose.yml`:

```bash
cp .env.example .env
# edit .env
docker compose up -d
curl http://localhost:8095/health
```

## Typical flow

```bash
# Admin creates a member
curl -u admin@example.com:adminpass \
  -H "Content-Type: application/json" \
  -d '{"email":"pingrly@example.com","password":"tempPass123","role":"member","default_daily_limit":200,"default_monthly_limit":5000}' \
  http://localhost:8095/admin/users

# Member creates an API key
curl -u pingrly@example.com:tempPass123 \
  -H "Content-Type: application/json" \
  -d '{"label":"pingrly-prod","daily_limit":100,"monthly_limit":2000}' \
  http://localhost:8095/api/keys
# → {"key":"gek_...","details":{...}}  (key shown once!)

# App sends email
curl -H "Authorization: Bearer gek_..." \
  -H "Content-Type: application/json" \
  -d '{"from":{"email":"alerts@example.com"},"to":[{"email":"user@example.com"}],"subject":"Hi","text":"hello"}' \
  http://localhost:8095/v1/emails
```
