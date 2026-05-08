package intel

import "testing"

func TestDedupeMergesReferences(t *testing.T) {
	got := dedupe([]Record{
		{ID: "CVE-TEST-1", Source: "nvd", References: []string{"https://a"}},
		{ID: "CVE-TEST-1", Source: "kev", References: []string{"https://b"}, ExploitObserved: true},
	})
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if !got[0].ExploitObserved || len(got[0].References) != 2 {
		t.Fatalf("record was not merged: %+v", got[0])
	}
}

func TestCandidatesAreSafeOnly(t *testing.T) {
	c := candidates([]Record{{ID: "CVE-TEST-1", Severity: "HIGH"}})
	if len(c) != 1 || !c[0].SafeCheckOnly || c[0].Status != "manual-safe-check-required" {
		t.Fatalf("unexpected candidate: %+v", c)
	}
}
