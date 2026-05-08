package passive

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"scanner/internal/core"
)

type Exchange struct {
	Method      string
	URL         string
	Host        string
	StatusCode  int
	ReqHeaders  http.Header
	RespHeaders http.Header
	ReqBody     string
	RespBody    string
}

type Analyzer struct{}

func NewAnalyzer() Analyzer {
	return Analyzer{}
}

func (a Analyzer) Analyze(ex Exchange) []core.Finding {
	var findings []core.Finding
	findings = append(findings, checkSecurityHeaders(ex)...)
	findings = append(findings, checkCookieFlags(ex)...)
	findings = append(findings, checkSensitiveContent(ex)...)
	findings = append(findings, checkExposureMarkers(ex)...)
	return findings
}

func checkSecurityHeaders(ex Exchange) []core.Finding {
	if ex.StatusCode == 0 {
		return nil
	}
	checks := []struct {
		header string
		typ    string
		rec    string
	}{
		{"X-Frame-Options", "Missing X-Frame-Options", "Set X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk."},
		{"Content-Security-Policy", "Missing Content-Security-Policy", "Add a restrictive Content-Security-Policy and tune it for the application."},
		{"X-Content-Type-Options", "Missing X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."},
	}
	var out []core.Finding
	for _, c := range checks {
		if ex.RespHeaders.Get(c.header) == "" {
			out = append(out, finding(ex, c.typ, "Low", "response header", c.header+" is absent", c.rec))
		}
	}
	return out
}

func checkCookieFlags(ex Exchange) []core.Finding {
	var out []core.Finding
	for _, cookie := range ex.RespHeaders.Values("Set-Cookie") {
		lower := strings.ToLower(cookie)
		name := strings.SplitN(cookie, "=", 2)[0]
		if !strings.Contains(lower, "httponly") {
			out = append(out, finding(ex, "Cookie Missing HttpOnly", "Low", "Set-Cookie: "+name, "cookie flag HttpOnly is absent", "Set HttpOnly on session and sensitive cookies."))
		}
		if strings.HasPrefix(strings.ToLower(ex.URL), "https://") && !strings.Contains(lower, "secure") {
			out = append(out, finding(ex, "Cookie Missing Secure", "Low", "Set-Cookie: "+name, "cookie flag Secure is absent", "Set Secure on cookies used over HTTPS."))
		}
		if !strings.Contains(lower, "samesite") {
			out = append(out, finding(ex, "Cookie Missing SameSite", "Low", "Set-Cookie: "+name, "cookie flag SameSite is absent", "Set SameSite=Lax or Strict where compatible."))
		}
	}
	return out
}

func checkSensitiveContent(ex Exchange) []core.Finding {
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"Possible Access Token Exposure", regexp.MustCompile(`(?i)(access[_-]?token|api[_-]?key|secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9._\-]{12,}`)},
		{"Private IP Exposure", regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)},
		{"Stack Trace Disclosure", regexp.MustCompile(`(?i)(java\.lang\.|traceback \(most recent call last\)|at\s+[\w.$]+\([\w.$]+:\d+\)|warning:\s+.* on line \d+)`)},
	}
	blob := ex.RespBody + "\n" + ex.ReqBody
	var out []core.Finding
	for _, p := range patterns {
		if p.re.MatchString(blob) {
			out = append(out, finding(ex, p.name, "Medium", ex.Method+" "+ex.URL, "response/request matched safe passive pattern", "Remove secrets and debug details from HTTP traffic and rotate exposed credentials if confirmed."))
		}
	}
	return out
}

func checkExposureMarkers(ex Exchange) []core.Finding {
	lowerURL := strings.ToLower(ex.URL)
	lowerBody := strings.ToLower(ex.RespBody)
	checks := []struct {
		typ string
		hit bool
		rec string
	}{
		{"Directory Listing", strings.Contains(lowerBody, "index of /") && strings.Contains(lowerBody, "<title>index of"), "Disable directory listing on web servers."},
		{"Git Metadata Exposure", strings.Contains(lowerURL, "/.git/") || strings.Contains(lowerBody, "refs/heads"), "Block access to .git paths at the web server layer."},
		{"SVN Metadata Exposure", strings.Contains(lowerURL, "/.svn/") || strings.Contains(lowerBody, "wc.db"), "Block access to .svn paths at the web server layer."},
		{"Swagger/OpenAPI Exposure", strings.Contains(lowerURL, "swagger") || strings.Contains(lowerBody, "openapi"), "Restrict API documentation to trusted networks or authenticated users."},
		{"Spring Boot Actuator Exposure", strings.Contains(lowerURL, "/actuator") || strings.Contains(lowerBody, "_links") && strings.Contains(lowerBody, "actuator"), "Restrict actuator endpoints and expose only required health information."},
	}
	var out []core.Finding
	for _, c := range checks {
		if c.hit {
			out = append(out, finding(ex, c.typ, "Medium", ex.Method+" "+ex.URL, "passive marker observed", c.rec))
		}
	}
	return out
}

func finding(ex Exchange, typ, sev, loc, evidence, rec string) core.Finding {
	return core.Finding{
		Target:         ex.URL,
		Type:           typ,
		Severity:       sev,
		Location:       loc,
		Evidence:       evidence,
		Recommendation: rec,
		Timestamp:      time.Now(),
	}
}
