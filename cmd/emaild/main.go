// emaild is the standalone HTTP entrypoint for go-email.
//
// Configuration (env vars):
//
//	PORT                   default 8095
//	DB_PATH                default /data/emaild.db
//	SMTP_HOST              required, e.g. mail.biswas.me
//	SMTP_PORT              default 587 (use 465 for implicit TLS)
//	SMTP_USERNAME          required
//	SMTP_PASSWORD          required
//	SMTP_SKIP_VERIFY       "true" disables TLS cert verification (dev only)
//	MAX_BODY_KB            default 256
//	COOKIE_SECURE          "true" marks session cookies Secure (default true)
//	SERVER_IP              public IPv4 for the suggested SPF record
//	DMARC_REPORT_TO        mailto for suggested DMARC (default postmaster@<domain>)
//
// First-boot seed (only used when DB has zero users):
//
//	BOOTSTRAP_ADMIN_EMAIL     default anshuman@biswas.me
//	BOOTSTRAP_ADMIN_PASSWORD  required for first boot
//	BOOTSTRAP_ORG_NAME        default "biswas-me"
//	BOOTSTRAP_ORG_SLUG        default "biswas-me"
//	BOOTSTRAP_DOMAIN          default pingrly.com
package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	goemail "github.com/anchoo2kewl/go-email"
)

func main() {
	port := envOr("PORT", "8095")
	dbPath := envOr("DB_PATH", "/data/emaild.db")

	smtpPort, err := strconv.Atoi(envOr("SMTP_PORT", "587"))
	if err != nil {
		log.Fatalf("invalid SMTP_PORT: %v", err)
	}
	sender, err := goemail.NewSMTPSender(goemail.SMTPConfig{
		Host:               requireEnv("SMTP_HOST"),
		Port:               smtpPort,
		Username:           requireEnv("SMTP_USERNAME"),
		Password:           requireEnv("SMTP_PASSWORD"),
		InsecureSkipVerify: os.Getenv("SMTP_SKIP_VERIFY") == "true",
	})
	if err != nil {
		log.Fatalf("smtp config: %v", err)
	}

	store, err := goemail.OpenStore(dbPath)
	if err != nil {
		log.Fatalf("open store at %s: %v", dbPath, err)
	}
	defer store.Close()

	if n, _ := store.CountUsers(); n == 0 {
		cfg := goemail.BootstrapConfig{
			AdminEmail:    strings.ToLower(envOr("BOOTSTRAP_ADMIN_EMAIL", "anshuman@biswas.me")),
			AdminPassword: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),
			OrgName:       envOr("BOOTSTRAP_ORG_NAME", "biswas-me"),
			OrgSlug:       envOr("BOOTSTRAP_ORG_SLUG", "biswas-me"),
			InitialDomain: envOr("BOOTSTRAP_DOMAIN", "pingrly.com"),
		}
		if err := goemail.Bootstrap(store, cfg); err != nil {
			log.Fatalf("bootstrap: %v", err)
		}
		log.Printf("bootstrapped: super-admin=%s org=%s domain=%s", cfg.AdminEmail, cfg.OrgSlug, cfg.InitialDomain)
	}

	cookieSecure := envOr("COOKIE_SECURE", "true") == "true"
	opts := []goemail.Option{
		goemail.WithStore(store),
		goemail.WithSender(sender),
		goemail.WithLogger(stdLogger{}),
		goemail.WithCookieSecure(cookieSecure),
		goemail.WithServerIP(os.Getenv("SERVER_IP")),
		goemail.WithDMARCReportTo(os.Getenv("DMARC_REPORT_TO")),
	}
	if mb := os.Getenv("MAX_BODY_KB"); mb != "" {
		if kb, err := strconv.ParseInt(mb, 10, 64); err == nil {
			opts = append(opts, goemail.WithMaxBodyKB(kb))
		}
	}

	srv, err := goemail.New(opts...)
	if err != nil {
		log.Fatalf("goemail: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              ":" + port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("go-email listening on :%s (db=%s smtp=%s:%d)", port, dbPath, os.Getenv("SMTP_HOST"), smtpPort)
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}

type stdLogger struct{}

func (stdLogger) Infof(format string, args ...any)  { log.Printf("info: "+format, args...) }
func (stdLogger) Errorf(format string, args ...any) { log.Printf("error: "+format, args...) }
