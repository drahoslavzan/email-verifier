package emailverifier

import (
	"strings"
)

// IsRoleAccount checks if username is a role-based account
func (v *Verifier) IsRoleAccount(username string) bool {
	return roleAccounts[strings.ToLower(username)]
}

// IsFreeDomain checks if domain is a free domain
func (v *Verifier) IsFreeDomain(domain string) bool {
	return freeDomains[domain]
}

// IsDisposable checks if domain is a disposable domain
func (v *Verifier) IsDisposable(domain string) bool {
	domain = DomainToASCII(domain)
	return v.disposableRepo.IsDomainDisposable(domain)
}
