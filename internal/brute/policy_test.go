package brute

import "testing"

func TestPolicyRequiresWhitelistWhenEnabled(t *testing.T) {
	err := Policy{Enabled: true, MaxAttemptsPerService: 20, RateLimit: 5, MaskPassword: true}.Validate()
	if err == nil {
		t.Fatal("expected whitelist validation error")
	}
}

func TestMaskCredential(t *testing.T) {
	got := MaskCredential("admin", "secret")
	if got != "admin:s****t" {
		t.Fatalf("unexpected mask: %s", got)
	}
}
