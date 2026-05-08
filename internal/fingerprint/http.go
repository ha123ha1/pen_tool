package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"scanner/internal/core"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

func ScanHTTP(ctx context.Context, host string, port int, rules []Rule, timeout time.Duration) (core.WebFingerprint, bool) {
	schemes := []string{"http"}
	if port == 443 || port == 8443 {
		schemes = []string{"https", "http"}
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprint(port)))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "AuthorizedSecurityScanner/0.1 (+authorized assessment)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := readBody(resp, 512*1024)
		fp := core.WebFingerprint{
			URL:        url,
			StatusCode: resp.StatusCode,
			Title:      extractTitle(body),
			Server:     resp.Header.Get("Server"),
			PoweredBy:  resp.Header.Get("X-Powered-By"),
		}
		headerBlob := strings.ToLower(fmt.Sprint(resp.Header))
		bodyLower := strings.ToLower(body)
		cookieLower := strings.ToLower(resp.Header.Get("Set-Cookie"))
		for _, r := range rules {
			if matchRule(r, headerBlob, bodyLower, cookieLower) {
				fp.Technologies = append(fp.Technologies, r.Name)
				fp.Evidence = append(fp.Evidence, evidenceFor(r))
			}
		}
		return fp, true
	}
	return core.WebFingerprint{}, false
}

func readBody(resp *http.Response, limit int64) (string, error) {
	defer resp.Body.Close()
	var b strings.Builder
	_, err := io.Copy(&b, ioLimitReader(resp.Body, limit))
	return b.String(), err
}

func extractTitle(body string) string {
	m := titleRE.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := strings.Join(strings.Fields(m[1]), " ")
	if len(title) > 200 {
		return title[:200]
	}
	return title
}

func matchRule(r Rule, headers, body, cookie string) bool {
	if r.Header != "" && strings.Contains(headers, strings.ToLower(r.Header)) {
		return true
	}
	if r.Body != "" && strings.Contains(body, strings.ToLower(r.Body)) {
		return true
	}
	if r.Cookie != "" && strings.Contains(cookie, strings.ToLower(r.Cookie)) {
		return true
	}
	return false
}

func evidenceFor(r Rule) string {
	switch {
	case r.Header != "":
		return "header contains " + r.Header
	case r.Body != "":
		return "body contains " + r.Body
	case r.Cookie != "":
		return "cookie contains " + r.Cookie
	default:
		return "fingerprint rule matched"
	}
}
