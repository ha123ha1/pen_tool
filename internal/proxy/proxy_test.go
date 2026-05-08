package proxy

import (
	"net/http"
	"testing"
)

func TestAllowedHosts(t *testing.T) {
	s := &Server{cfg: Config{AllowHosts: []string{"example.com", "*.example.org", ".example.net"}}}
	for _, host := range []string{"example.com", "api.example.org", "www.example.net"} {
		if !s.allowed(host) {
			t.Fatalf("expected host to be allowed: %s", host)
		}
	}
	if s.allowed("evil.test") {
		t.Fatal("unexpected allowed host")
	}
}

func TestRedactInlineSecrets(t *testing.T) {
	got := redactInlineSecrets("username=a&password=secret&token=abcdef")
	if got != "username=a&password=<redacted>&token=<redacted>" {
		t.Fatalf("unexpected redaction: %s", got)
	}
}

func TestAbsoluteURLFromOriginForm(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/path?q=1", nil)
	req.Host = "example.com"
	u := absoluteURL(req)
	if u == nil || u.String() != "http://example.com/path?q=1" {
		t.Fatalf("unexpected URL: %v", u)
	}
}
