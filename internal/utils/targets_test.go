package utils

import "testing"

func TestParseTargetsCIDRExcludesNetworkAndBroadcast(t *testing.T) {
	targets, err := ParseTargets([]string{"192.0.2.0/30"}, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if targets[0].Host != "192.0.2.1" || targets[1].Host != "192.0.2.2" {
		t.Fatalf("unexpected targets: %+v", targets)
	}
}

func TestParseTargetsURL(t *testing.T) {
	targets, err := ParseTargets([]string{"https://example.com/app"}, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Host != "example.com" || targets[0].Scheme != "https" {
		t.Fatalf("unexpected URL parse result: %+v", targets)
	}
}
