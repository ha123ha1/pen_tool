package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"scanner/internal/core"
	"scanner/internal/logger"
	"scanner/internal/output"
	"scanner/internal/passive"
	"scanner/internal/rate"
)

type Config struct {
	Version             string
	Listen              string
	AllowHosts          []string
	OutputFile          string
	OutputFormat        string
	Authorization       string
	Timeout             time.Duration
	RateLimit           int
	EnableActiveProbes  bool
	MaxActivePerRequest int
	MaxBodyBytes        int64
	DecryptHTTPS        bool
	GenerateCA          bool
	CACertPath          string
	CAKeyPath           string
	Logger              *logger.Logger
}

type Server struct {
	cfg      Config
	client   *http.Client
	analyzer passive.Analyzer
	limiter  *rate.Limiter
	ca       *CertificateAuthority
	mu       sync.Mutex
	report   core.Report
}

func Run(ctx context.Context, cfg Config) (core.Report, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8088"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1024 * 1024
	}
	if len(cfg.AllowHosts) == 0 {
		return core.Report{}, errors.New("passive proxy requires --proxy-allow-hosts to avoid scanning unintended hosts")
	}
	var ca *CertificateAuthority
	if cfg.DecryptHTTPS {
		if cfg.GenerateCA {
			if err := GenerateCAFiles(cfg.CACertPath, cfg.CAKeyPath); err != nil {
				return core.Report{}, err
			}
			if cfg.Logger != nil {
				cfg.Logger.Warn("generated local CA certificate: %s; import it into your browser/system trust store for HTTPS decryption", cfg.CACertPath)
			}
		}
		loaded, err := LoadCA(cfg.CACertPath, cfg.CAKeyPath)
		if err != nil {
			return core.Report{}, err
		}
		ca = loaded
	}
	s := &Server{
		cfg:      cfg,
		analyzer: passive.NewAnalyzer(),
		limiter:  rate.New(cfg.RateLimit),
		ca:       ca,
		report: core.Report{
			ToolVersion:   cfg.Version,
			Authorization: cfg.Authorization,
			StartedAt:     time.Now(),
			ScanLevel:     "passive",
		},
	}
	defer s.limiter.Stop()
	s.client = &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: s}
	errc := make(chan error, 1)
	go func() {
		if cfg.Logger != nil {
			cfg.Logger.Info("passive proxy listening on http://%s", cfg.Listen)
		}
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	case err := <-errc:
		if err != nil {
			return s.snapshot(), err
		}
	}
	report := s.snapshot()
	report.FinishedAt = time.Now()
	if err := output.Write(report, output.OutputOptions{File: cfg.OutputFile, Format: cfg.OutputFormat}); err != nil {
		return report, err
	}
	return report, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := absoluteURL(r)
	if targetURL == nil {
		http.Error(w, "proxy requires an absolute URL or Host header", http.StatusBadRequest)
		return
	}
	if !s.allowed(targetURL.Hostname()) {
		http.Error(w, "host is not in proxy allowlist", http.StatusForbidden)
		return
	}
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes))
		_ = r.Body.Close()
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), strings.NewReader(string(reqBody)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	outReq.Header = cloneHeader(r.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")
	if outReq.Header.Get("User-Agent") == "" {
		outReq.Header.Set("User-Agent", "AuthorizedSecurityScanner/0.1 passive-proxy")
	}
	if s.limiter != nil {
		s.limiter.Wait(r.Context())
	}
	resp, err := s.client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBodyBytes))
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	ex := passive.Exchange{
		Method:      r.Method,
		URL:         targetURL.String(),
		Host:        targetURL.Hostname(),
		StatusCode:  resp.StatusCode,
		ReqHeaders:  redactHeaders(r.Header),
		RespHeaders: redactHeaders(resp.Header),
		ReqBody:     safeBodySummary(reqBody),
		RespBody:    string(respBody),
	}
	findings := s.analyzer.Analyze(ex)
	findings = append(findings, passive.SafeActiveProbes(r.Context(), ex, passive.ActiveOptions{
		Enabled:       s.cfg.EnableActiveProbes,
		Timeout:       s.cfg.Timeout,
		MaxPerRequest: s.cfg.MaxActivePerRequest,
		UserAgent:     "AuthorizedSecurityScanner/0.1 passive-safe-probe",
	}, s.limiter)...)
	s.record(core.HTTPTransaction{
		Method:         r.Method,
		URL:            targetURL.String(),
		Host:           targetURL.Hostname(),
		StatusCode:     resp.StatusCode,
		RequestBytes:   int64(len(reqBody)),
		ResponseBytes:  int64(len(respBody)),
		RequestSummary: requestSummary(r, reqBody),
		ResponseTitle:  extractTitle(string(respBody)),
		Timestamp:      time.Now(),
	}, findings)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	if !s.allowed(host) {
		http.Error(w, "host is not in proxy allowlist", http.StatusForbidden)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if s.cfg.DecryptHTTPS {
		s.handleMITM(clientConn, host)
		return
	}
	upstream, err := net.DialTimeout("tcp", r.Host, s.cfg.Timeout)
	if err != nil {
		_ = clientConn.Close()
		return
	}
	go tunnel(upstream, clientConn)
	go tunnel(clientConn, upstream)
}

func (s *Server) handleMITM(clientConn net.Conn, host string) {
	defer clientConn.Close()
	leaf, err := s.ca.Leaf(host)
	if err != nil {
		return
	}
	cert, err := tls.X509KeyPair(leaf.certPEM, leaf.keyPEM)
	if err != nil {
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		s.handleInterceptedHTTPS(tlsConn, req, host)
	}
}

func (s *Server) handleInterceptedHTTPS(client io.Writer, r *http.Request, host string) {
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes))
		_ = r.Body.Close()
	}
	targetURL := &url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	if r.URL.RawPath != "" {
		targetURL.RawPath = r.URL.RawPath
	}
	outReq, err := http.NewRequestWithContext(context.Background(), r.Method, targetURL.String(), strings.NewReader(string(reqBody)))
	if err != nil {
		writeGatewayError(client, err)
		return
	}
	outReq.Header = cloneHeader(r.Header)
	outReq.Header.Del("Proxy-Connection")
	if outReq.Header.Get("User-Agent") == "" {
		outReq.Header.Set("User-Agent", "AuthorizedSecurityScanner/0.1 passive-mitm")
	}
	if s.limiter != nil {
		s.limiter.Wait(context.Background())
	}
	resp, err := s.client.Do(outReq)
	if err != nil {
		writeGatewayError(client, err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBodyBytes))
	resp.Body = io.NopCloser(strings.NewReader(string(respBody)))
	resp.ContentLength = int64(len(respBody))
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", fmt.Sprint(len(respBody)))
	_ = resp.Write(client)

	ex := passive.Exchange{
		Method:      r.Method,
		URL:         targetURL.String(),
		Host:        host,
		StatusCode:  resp.StatusCode,
		ReqHeaders:  redactHeaders(r.Header),
		RespHeaders: redactHeaders(resp.Header),
		ReqBody:     safeBodySummary(reqBody),
		RespBody:    string(respBody),
	}
	findings := s.analyzer.Analyze(ex)
	findings = append(findings, passive.SafeActiveProbes(context.Background(), ex, passive.ActiveOptions{
		Enabled:       s.cfg.EnableActiveProbes,
		Timeout:       s.cfg.Timeout,
		MaxPerRequest: s.cfg.MaxActivePerRequest,
		UserAgent:     "AuthorizedSecurityScanner/0.1 passive-safe-probe",
	}, s.limiter)...)
	s.record(core.HTTPTransaction{
		Method:         r.Method,
		URL:            targetURL.String(),
		Host:           host,
		StatusCode:     resp.StatusCode,
		RequestBytes:   int64(len(reqBody)),
		ResponseBytes:  int64(len(respBody)),
		RequestSummary: requestSummary(r, reqBody),
		ResponseTitle:  extractTitle(string(respBody)),
		Timestamp:      time.Now(),
	}, findings)
}

func (s *Server) allowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, item := range s.cfg.AllowHosts {
		rule := strings.ToLower(strings.TrimSpace(item))
		if rule == "" {
			continue
		}
		if host == rule {
			return true
		}
		if strings.HasPrefix(rule, "*.") && strings.HasSuffix(host, strings.TrimPrefix(rule, "*")) {
			return true
		}
		if strings.HasPrefix(rule, ".") && strings.HasSuffix(host, rule) {
			return true
		}
	}
	return false
}

func (s *Server) record(flow core.HTTPTransaction, findings []core.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.report.HTTPFlows = append(s.report.HTTPFlows, flow)
	s.report.Findings = append(s.report.Findings, findings...)
}

func (s *Server) snapshot() core.Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := s.report
	cp.HTTPFlows = append([]core.HTTPTransaction(nil), s.report.HTTPFlows...)
	cp.Findings = append([]core.Finding(nil), s.report.Findings...)
	return cp
}

func absoluteURL(r *http.Request) *url.URL {
	if r.URL != nil && r.URL.IsAbs() {
		return r.URL
	}
	if r.Host == "" || r.URL == nil {
		return nil
	}
	u := *r.URL
	u.Scheme = "http"
	u.Host = r.Host
	return &u
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, values := range h {
		out[k] = append([]string(nil), values...)
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func redactHeaders(h http.Header) http.Header {
	out := cloneHeader(h)
	for _, key := range []string{"Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization"} {
		if out.Get(key) != "" {
			out.Set(key, "<redacted>")
		}
	}
	return out
}

func safeBodySummary(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	s := string(body)
	if len(s) > 512 {
		s = s[:512]
	}
	return redactInlineSecrets(s)
}

func requestSummary(r *http.Request, body []byte) string {
	return fmt.Sprintf("%s %s body=%d %s", r.Method, r.URL.RequestURI(), len(body), safeBodySummary(body))
}

func redactInlineSecrets(s string) string {
	parts := []string{"password=", "passwd=", "pwd=", "token=", "access_token=", "secret=", "api_key="}
	lower := strings.ToLower(s)
	for _, p := range parts {
		idx := strings.Index(lower, p)
		if idx >= 0 {
			end := strings.IndexAny(s[idx+len(p):], "& \r\n\t")
			if end < 0 {
				end = len(s) - idx - len(p)
			}
			s = s[:idx+len(p)] + "<redacted>" + s[idx+len(p)+end:]
			lower = strings.ToLower(s)
		}
	}
	return s
}

func tunnel(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func writeGatewayError(w io.Writer, err error) {
	resp := &http.Response{
		StatusCode:    http.StatusBadGateway,
		Status:        "502 Bad Gateway",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(err.Error())),
		ContentLength: int64(len(err.Error())),
	}
	_ = resp.Write(w)
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	gt := strings.Index(lower[start:], ">")
	if gt < 0 {
		return ""
	}
	from := start + gt + 1
	end := strings.Index(lower[from:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.Join(strings.Fields(body[from:from+end]), " ")
	if len(title) > 200 {
		return title[:200]
	}
	return title
}
