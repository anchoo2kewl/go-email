package goemail

import "errors"

// BootstrapConfig tells goemail what to seed on first boot.
type BootstrapConfig struct {
	AdminEmail    string // super-admin user
	AdminPassword string
	OrgName       string // first org to create
	OrgSlug       string
	InitialDomain string // first domain to add (unverified)
}

// Bootstrap creates the first super-admin user, first org, and adds the
// admin as the org owner. It is a no-op if any users already exist. Safe
// to call on every boot.
func Bootstrap(store Store, cfg BootstrapConfig) error {
	n, err := store.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if cfg.AdminEmail == "" || cfg.AdminPassword == "" {
		return errors.New("bootstrap: AdminEmail and AdminPassword are required on first run")
	}
	hash, err := hashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	admin := &User{Email: cfg.AdminEmail, PasswordHash: hash, IsSuperAdmin: true}
	if err := store.CreateUser(admin); err != nil {
		return err
	}
	if cfg.OrgName == "" {
		return nil
	}
	slug := cfg.OrgSlug
	if slug == "" {
		slug = slugify(cfg.OrgName)
	}
	org := &Organization{
		Name: cfg.OrgName, Slug: slug,
		DefaultDailyLimit: 200, DefaultMonthlyLimit: 5000,
	}
	if err := store.CreateOrg(org); err != nil {
		return err
	}
	if err := store.AddOrgMember(org.ID, admin.ID, RoleOwner); err != nil {
		return err
	}
	if cfg.InitialDomain != "" {
		token, _ := generateVerificationToken()
		_ = store.CreateDomain(&Domain{
			OrgID: org.ID, Domain: cfg.InitialDomain, VerificationToken: token,
		})
	}
	return nil
}
