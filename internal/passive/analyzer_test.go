package passive

import (
	"net/http"
	"testing"
)

func TestAnalyzeMissingSecurityHeaders(t *testing.T) {
	findings := NewAnalyzer().Analyze(Exchange{
		Method:      http.MethodGet,
		URL:         "http://example.test/",
		StatusCode:  200,
		RespHeaders: http.Header{},
	})
	if len(findings) < 3 {
		t.Fatalf("expected missing header findings, got %d", len(findings))
	}
}

func TestAnalyzeReducesSensitiveExposureToFinding(t *testing.T) {
	findings := NewAnalyzer().Analyze(Exchange{
		Method:      http.MethodGet,
		URL:         "http://example.test/",
		StatusCode:  200,
		RespHeaders: http.Header{"X-Frame-Options": []string{"DENY"}, "Content-Security-Policy": []string{"default-src 'self'"}, "X-Content-Type-Options": []string{"nosniff"}},
		RespBody:    "api_key = abcdefghijklmnopqrstuvwxyz",
	})
	if len(findings) != 1 || findings[0].Type != "Possible Access Token Exposure" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}
