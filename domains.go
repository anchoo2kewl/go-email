package goemail

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DomainVerifier checks whether the expected token is present in the TXT
// records of _goemail-challenge.<domain>. A nil verifier falls back to a
// real DNS lookup via net.Resolver.
type DomainVerifier interface {
	Verify(ctx context.Context, domain, token string) (bool, error)
}

// dnsVerifier uses Go's stdlib resolver to look up TXT records.
type dnsVerifier struct {
	resolver *net.Resolver
}

// NewDNSVerifier returns a DomainVerifier backed by the system resolver.
func NewDNSVerifier() DomainVerifier { return &dnsVerifier{resolver: net.DefaultResolver} }

// Verify looks up TXT records at _goemail-challenge.<domain> and returns
// true if any record (trimmed of quotes / whitespace) equals the token.
func (d *dnsVerifier) Verify(ctx context.Context, domain, token string) (bool, error) {
	host := "_goemail-challenge." + strings.TrimSpace(strings.ToLower(domain))
	records, err := d.resolver.LookupTXT(ctx, host)
	if err != nil {
		return false, fmt.Errorf("DNS lookup failed for %s: %w", host, err)
	}
	wanted := strings.TrimSpace(token)
	for _, r := range records {
		if strings.TrimSpace(r) == wanted {
			return true, nil
		}
	}
	return false, nil
}

// challengeHost returns the TXT record hostname a user must publish.
func challengeHost(domain string) string {
	return "_goemail-challenge." + strings.ToLower(strings.TrimSpace(domain))
}

// checkAndMarkDomainVerified runs verification against DNS and updates the
// store when it succeeds. Returns a user-friendly message either way.
func checkAndMarkDomainVerified(ctx context.Context, store Store, verifier DomainVerifier, d *Domain) (bool, string, error) {
	if d.VerifiedAt != nil {
		return true, "already verified", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ok, err := verifier.Verify(ctx, d.Domain, d.VerificationToken)
	if err != nil {
		return false, "DNS lookup failed: " + err.Error(), nil
	}
	if !ok {
		return false, "TXT record at " + challengeHost(d.Domain) + " did not match the expected token", nil
	}
	if err := store.MarkDomainVerified(d.ID, time.Now()); err != nil {
		return false, "", err
	}
	return true, "verified", nil
}

// DNSRecord is one row of DNS config shown on the Domains page.
type DNSRecord struct {
	Purpose string // "Ownership verification", "SPF", "DKIM", "DMARC"
	Host    string
	Type    string
	Value   string
	Note    string
}

// BuildDNSRecords returns the set of DNS records the user should publish for a
// domain. Missing pieces (like an unset DKIM public key) are included with an
// explanatory note.
func BuildDNSRecords(d *Domain, serverIP, dmarcReportTo string) []DNSRecord {
	recs := []DNSRecord{}
	if d.VerifiedAt == nil {
		recs = append(recs, DNSRecord{
			Purpose: "Ownership verification",
			Host:    "_goemail-challenge." + d.Domain,
			Type:    "TXT",
			Value:   d.VerificationToken,
			Note:    "Publish this TXT, then click Verify.",
		})
	}
	spfValue := "v=spf1 -all"
	if serverIP != "" {
		spfValue = "v=spf1 ip4:" + serverIP + " -all"
	}
	recs = append(recs, DNSRecord{
		Purpose: "SPF",
		Host:    d.Domain,
		Type:    "TXT",
		Value:   spfValue,
		Note:    "Authorizes the go-email server to send on behalf of this domain.",
	})
	selector := d.DKIMSelector
	if selector == "" {
		selector = "dkim"
	}
	dkimValue := d.DKIMPublicKey
	dkimNote := "Paste the DKIM public key from your SMTP backend (Mailcow → Configuration → Domains → " + d.Domain + " → DKIM key)."
	if dkimValue == "" {
		dkimValue = "(not set — add the domain in Mailcow first, then paste its DKIM key below)"
	} else if !strings.HasPrefix(strings.ToLower(dkimValue), "v=dkim1") {
		// Allow users to paste just the p= portion; normalise to a full record.
		dkimValue = "v=DKIM1; k=rsa; p=" + dkimValue
	}
	recs = append(recs, DNSRecord{
		Purpose: "DKIM",
		Host:    selector + "._domainkey." + d.Domain,
		Type:    "TXT",
		Value:   dkimValue,
		Note:    dkimNote,
	})
	reportTo := dmarcReportTo
	if reportTo == "" {
		reportTo = "postmaster@" + d.Domain
	}
	recs = append(recs, DNSRecord{
		Purpose: "DMARC",
		Host:    "_dmarc." + d.Domain,
		Type:    "TXT",
		Value:   "v=DMARC1; p=none; rua=mailto:" + reportTo,
		Note:    "Start with p=none for monitoring; tighten to p=quarantine or p=reject later.",
	})
	return recs
}

// parseFromDomain extracts the domain portion of an email address.
// Returns "" if the address is malformed.
func parseFromDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:]))
}
