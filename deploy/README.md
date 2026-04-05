# Deploying go-email

This directory has the glue for running go-email behind a host nginx with a
Cloudflare Origin Certificate — matching the pattern used by the rest of the
biswas.me services.

## Pre-requisites (on the target host)

- Docker + docker compose
- nginx on the host
- An SMTP relay you can authenticate to (e.g. a Mailcow mailbox)

## 1. Create the Cloudflare Origin Certificate

1. Log in to the Cloudflare dashboard → `biswas.me` zone → **SSL/TLS → Origin Server**.
2. Click **Create Certificate** → leave RSA-2048 default → add hostname `email.biswas.me`.
3. Save the two PEM blocks onto the server:
   - Certificate → `/etc/ssl/cloudflare/email.biswas.me.pem`
   - Private key → `/etc/ssl/cloudflare/email.biswas.me.key`
4. `chmod 600` the `.key` file.

## 2. Deploy the container

```bash
cd /opt
sudo git clone https://github.com/biswas-dev/go-email.git
cd go-email
sudo cp .env.example .env
sudo vi .env   # fill in SMTP_* and ADMIN_PASSWORD
sudo mkdir -p data
sudo docker compose up -d
curl -sf http://127.0.0.1:8096/health
```

## 3. Add the nginx site

```bash
sudo cp deploy/email.biswas.me.nginx.conf /etc/nginx/sites-enabled/email.biswas.me
sudo nginx -t && sudo nginx -s reload
```

## 4. Verify

- Browse to <https://email.biswas.me> — landing page.
- Log in with `anshuman@biswas.me` + the password set in `ADMIN_PASSWORD`.
- Create a member, then an API key, then curl `POST /v1/emails`.
