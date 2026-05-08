package brute

import (
	"fmt"
	"strings"
)

type Policy struct {
	Enabled               bool
	MaxAttemptsPerService int
	RateLimit             int
	StopOnSuccess         bool
	MaskPassword          bool
	AllowedTargets        []string
}

func (p Policy) Validate() error {
	if !p.Enabled {
		return nil
	}
	if p.MaxAttemptsPerService <= 0 || p.MaxAttemptsPerService > 100 {
		return fmt.Errorf("invalid brute force attempt cap: %d", p.MaxAttemptsPerService)
	}
	if p.RateLimit <= 0 {
		return fmt.Errorf("brute force requires a positive rate limit")
	}
	if !p.MaskPassword {
		return fmt.Errorf("brute force reports must mask passwords")
	}
	if len(p.AllowedTargets) == 0 {
		return fmt.Errorf("brute force requires an explicit allowed target whitelist")
	}
	return nil
}

func MaskCredential(username, password string) string {
	if password == "" {
		return username + ":<empty>"
	}
	if len(password) <= 2 {
		return username + ":" + strings.Repeat("*", len(password))
	}
	return username + ":" + password[:1] + strings.Repeat("*", len(password)-2) + password[len(password)-1:]
}
