package passive

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scanner/internal/core"
	"scanner/internal/rate"
)

type ActiveOptions struct {
	Enabled       bool
	Timeout       time.Duration
	MaxPerRequest int
	UserAgent     string
}

func SafeActiveProbes(ctx context.Context, ex Exchange, opts ActiveOptions, limiter *rate.Limiter) []core.Finding {
	if !opts.Enabled || ex.Method != http.MethodGet || opts.MaxPerRequest <= 0 {
		return nil
	}
	u, err := url.Parse(ex.URL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	params := u.Query()
	var out []core.Finding
	count := 0
	for name := range params {
		if count >= opts.MaxPerRequest {
			break
		}
		out = append(out, probeReflectedMarker(ctx, ex, opts, limiter, name)...)
		count++
		if count >= opts.MaxPerRequest {
			break
		}
		out = append(out, probeSQLError(ctx, ex, opts, limiter, name)...)
		count++
		if count >= opts.MaxPerRequest {
			break
		}
		if looksRedirectParam(name) {
			out = append(out, probeOpenRedirect(ctx, ex, opts, limiter, name)...)
			count++
		}
	}
	return out
}

func probeReflectedMarker(ctx context.Context, ex Exchange, opts ActiveOptions, limiter *rate.Limiter, param string) []core.Finding {
	const marker = "scanner-safe-reflect-marker"
	body, status, ok := sendMutatedGET(ctx, ex, opts, limiter, param, marker)
	if !ok || status >= 500 {
		return nil
	}
	if strings.Contains(body, marker) {
		return []core.Finding{finding(ex, "Reflected Input", "Info", "GET parameter "+param, "safe marker reflected in response", "HTML-encode reflected values and validate input by context.")}
	}
	return nil
}

func probeSQLError(ctx context.Context, ex Exchange, opts ActiveOptions, limiter *rate.Limiter, param string) []core.Finding {
	body, status, ok := sendMutatedGET(ctx, ex, opts, limiter, param, "'")
	if !ok || status >= 500 {
		return nil
	}
	if sqlError(body) {
		return []core.Finding{finding(ex, "Possible SQL Injection", "High", "GET parameter "+param, "database error pattern after single quote probe", "Use parameterized queries and avoid returning database errors to users.")}
	}
	return nil
}

func probeOpenRedirect(ctx context.Context, ex Exchange, opts ActiveOptions, limiter *rate.Limiter, param string) []core.Finding {
	_, status, ok, loc := sendMutatedGETWithLocation(ctx, ex, opts, limiter, param, "https://example.com/")
	if !ok {
		return nil
	}
	if status >= 300 && status < 400 && strings.HasPrefix(loc, "https://example.com/") {
		return []core.Finding{finding(ex, "Possible Open Redirect", "Medium", "GET parameter "+param, "redirect location follows safe external marker", "Allow only relative redirects or validate destinations against an allowlist.")}
	}
	return nil
}

func sendMutatedGET(ctx context.Context, ex Exchange, opts ActiveOptions, limiter *rate.Limiter, param, value string) (string, int, bool) {
	body, status, ok, _ := sendMutatedGETWithLocation(ctx, ex, opts, limiter, param, value)
	return body, status, ok
}

func sendMutatedGETWithLocation(ctx context.Context, ex Exchange, opts ActiveOptions, limiter *rate.Limiter, param, value string) (string, int, bool, string) {
	u, err := url.Parse(ex.URL)
	if err != nil {
		return "", 0, false, ""
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	if limiter != nil {
		limiter.Wait(ctx)
	}
	client := &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", 0, false, ""
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "AuthorizedSecurityScanner/0.1 passive-safe-probe"
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, false, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return string(b), resp.StatusCode, true, resp.Header.Get("Location")
}

func sqlError(body string) bool {
	lower := strings.ToLower(body)
	needles := []string{"sql syntax", "mysql", "postgresql", "sqlite error", "ora-", "odbc", "sqlstate", "syntax error at or near"}
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func looksRedirectParam(name string) bool {
	n := strings.ToLower(name)
	return n == "url" || n == "redirect" || n == "redirect_uri" || n == "return" || n == "next" || n == "target" || n == "continue"
}

func ProbeSummary() string {
	return fmt.Sprintf("safe GET probes: reflected marker, single-quote SQL error signal, allowlisted open redirect marker")
}
