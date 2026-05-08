package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"scanner/internal/core"
)

func Detect(ctx context.Context, target core.Target, port int, timeout time.Duration) core.PortResult {
	result := core.PortResult{Port: port, Transport: "tcp", Protocol: protocolByPort(port), Service: guessByPort(port), Confidence: 0.45}
	result.Product = productByService(result.Service)
	result.Tags = tagsForService(result.Service)
	result.Evidence = append(result.Evidence, "port heuristic: "+result.Service)
	if isSOCKSPort(port) {
		if socks := probeSOCKS5(ctx, target.Host, port, timeout); socks != nil {
			result.Protocol = "socks5"
			result.Service = "socks5"
			result.Product = "SOCKS5 Proxy"
			result.Banner = socks.Banner
			result.Tags = mergeStrings(result.Tags, []string{"proxy", "tunnel"})
			result.Evidence = append(result.Evidence, socks.Evidence...)
			result.Confidence = 0.95
			result.Fingerprint = fingerprintID(result)
			return result
		}
	}
	if isHTTPPort(port) {
		if fp, ok := ProbeHTTP(ctx, target.Host, port, timeout); ok {
			result.Protocol = fp.Scheme
			result.Service = fp.Service
			result.Product = productFromHTTP(fp, result.Product)
			result.Version = versionFromServer(fp.Banner)
			result.Banner = fp.Banner
			result.HTTPStatus = fp.StatusCode
			result.HTTPTitle = fp.Title
			result.HTTPServer = fp.Banner
			result.TLS = fp.Scheme == "https"
			result.Tags = mergeStrings(result.Tags, []string{"web"})
			result.Evidence = append(result.Evidence, fmt.Sprintf("http status: %d", fp.StatusCode))
			if fp.Title != "" {
				result.Evidence = append(result.Evidence, "title: "+fp.Title)
			}
			if fp.Banner != "" {
				result.Evidence = append(result.Evidence, "server: "+fp.Banner)
			}
			result.Confidence = 0.9
			result.Fingerprint = fingerprintID(result)
			if cert := probeTLSCert(ctx, target.Host, port, timeout); cert != nil {
				result.TLS = true
				result.TLSCN = cert.Subject.CommonName
				result.TLSSANs = cert.DNSNames
			}
			return result
		}
	}
	if shouldProbeTLS(port) {
		if cert := probeTLSCert(ctx, target.Host, port, timeout); cert != nil {
			result.TLS = true
			result.TLSCN = cert.Subject.CommonName
			result.TLSSANs = cert.DNSNames
			result.Evidence = append(result.Evidence, "tls certificate observed")
			result.Confidence = maxConfidence(result.Confidence, 0.7)
		}
	}
	banner := grabBanner(ctx, target.Host, port, timeout)
	if banner != "" {
		result.Banner = sanitizeBanner(banner)
		result.Service = matchBanner(result.Service, banner)
		result.Protocol = protocolByService(result.Service, result.Protocol)
		result.Product = productByService(result.Service)
		result.Version = versionFromBanner(result.Service, banner)
		result.Tags = mergeStrings(result.Tags, tagsForService(result.Service))
		result.Evidence = append(result.Evidence, "banner matched")
		result.Confidence = maxConfidence(result.Confidence, 0.8)
	}
	result.Fingerprint = fingerprintID(result)
	return result
}

type HTTPProbe struct {
	URL        string
	Scheme     string
	Service    string
	Banner     string
	StatusCode int
	Title      string
	Resp       *http.Response
	Body       string
}

func ProbeHTTP(ctx context.Context, host string, port int, timeout time.Duration) (HTTPProbe, bool) {
	schemes := []string{"http"}
	if isLikelyHTTPSPort(port) {
		schemes = []string{"https", "http"}
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprint(port)))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "AuthorizedSecurityScanner/0.1")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := readLimited(resp, 256*1024)
		service := "http"
		if scheme == "https" {
			service = "https"
		}
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "tomcat") {
			service = "tomcat"
		}
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "rabbitmq") || strings.Contains(strings.ToLower(body), "rabbitmq management") {
			service = "rabbitmq-management"
		}
		if port == 9200 || strings.Contains(strings.ToLower(body), "cluster_name") && strings.Contains(strings.ToLower(body), "elasticsearch") {
			service = "elasticsearch"
		}
		if strings.Contains(strings.ToLower(body), "frp") || strings.Contains(strings.ToLower(body), "frps") {
			service = "frp-dashboard"
		}
		return HTTPProbe{URL: url, Scheme: scheme, Service: service, Banner: resp.Header.Get("Server"), StatusCode: resp.StatusCode, Title: extractTitle(body), Resp: resp, Body: body}, true
	}
	return HTTPProbe{}, false
}

func readLimited(resp *http.Response, limit int64) (string, error) {
	defer resp.Body.Close()
	reader := ioLimitReader(resp.Body, limit)
	var b strings.Builder
	_, err := io.Copy(&b, reader)
	return b.String(), err
}

func grabBanner(ctx context.Context, host string, port int, timeout time.Duration) string {
	var d net.Dialer
	d.Timeout = timeout
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	switch port {
	case 21, 22, 25, 110, 143:
	default:
		_, _ = conn.Write([]byte("\r\n"))
	}
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return line
}

func guessByPort(port int) string {
	switch port {
	case 20:
		return "ftp-data"
	case 21:
		return "ftp"
	case 2121:
		return "ftp-alt"
	case 22:
		return "ssh"
	case 2222:
		return "ssh-alt"
	case 23:
		return "telnet"
	case 25, 465, 587:
		return "smtp"
	case 80, 81, 3000, 5000, 7001, 7002, 8000, 8080, 8081, 8082, 8088, 8090, 8099, 8888, 9000, 9080, 10000, 18080:
		return "http"
	case 443, 8443, 9443:
		return "https"
	case 445:
		return "smb"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 33060:
		return "mysqlx"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5433:
		return "postgresql-alt"
	case 4369:
		return "epmd"
	case 5671:
		return "rabbitmq-amqps"
	case 5672:
		return "rabbitmq"
	case 15671:
		return "rabbitmq-management-https"
	case 15672:
		return "rabbitmq-management"
	case 25672:
		return "rabbitmq-clustering"
	case 6379:
		return "redis"
	case 6380:
		return "redis-tls"
	case 8005:
		return "tomcat-shutdown"
	case 8009:
		return "tomcat-ajp"
	case 9200, 9300:
		return "elasticsearch"
	case 9092:
		return "kafka"
	case 9093, 9094:
		return "kafka-tls"
	case 1080, 1081, 1086, 1088, 9050, 9150:
		return "socks"
	case 3128:
		return "http-proxy"
	case 6000:
		return "frp-proxy"
	case 7400, 7500:
		return "frp-dashboard"
	case 11211:
		return "memcached"
	case 27017:
		return "mongodb"
	default:
		return "unknown"
	}
}

func protocolByPort(port int) string {
	switch port {
	case 20, 21, 2121:
		return "ftp"
	case 22, 2222:
		return "ssh"
	case 80, 81, 3000, 3128, 5000, 5601, 7001, 7002, 7400, 7500, 8000, 8080, 8081, 8082, 8088, 8090, 8099, 8888, 9000, 9080, 9200, 10000, 15672, 18080:
		return "http"
	case 443, 8443, 9443, 15671:
		return "https"
	case 3306, 33060:
		return "mysql"
	case 5432, 5433:
		return "postgresql"
	case 6379:
		return "redis"
	case 6380:
		return "rediss"
	case 5671:
		return "amqps"
	case 5672:
		return "amqp"
	case 9300:
		return "es-transport"
	case 9092:
		return "kafka"
	case 9093, 9094:
		return "kafka-tls"
	case 1080, 1081, 1086, 1088, 9050, 9150:
		return "socks"
	case 6000:
		return "frp"
	default:
		return "tcp"
	}
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 81, 443, 3000, 3128, 5000, 5601, 7001, 7002, 7400, 7500, 8000, 8080, 8081, 8082, 8088, 8090, 8099, 8443, 8888, 9000, 9080, 9200, 9443, 10000, 15671, 15672, 18080:
		return true
	default:
		return false
	}
}

func isLikelyHTTPSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 15671:
		return true
	default:
		return false
	}
}

func matchBanner(current, banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "ssh"):
		return "ssh"
	case strings.Contains(b, "ftp"):
		return "ftp"
	case strings.Contains(b, "socks"):
		return "socks"
	case strings.Contains(b, "frp") || strings.Contains(b, "frps"):
		return "frp"
	case strings.Contains(b, "redis"):
		return "redis"
	case strings.Contains(b, "mysql"):
		return "mysql"
	case strings.Contains(b, "postgres"):
		return "postgresql"
	case strings.Contains(b, "rabbitmq"):
		return "rabbitmq"
	case strings.Contains(b, "kafka"):
		return "kafka"
	default:
		return current
	}
}

func protocolByService(service, fallback string) string {
	switch service {
	case "ftp", "ftp-alt", "ftp-data":
		return "ftp"
	case "ssh", "ssh-alt":
		return "ssh"
	case "mysql", "mysqlx":
		return "mysql"
	case "postgresql", "postgresql-alt":
		return "postgresql"
	case "redis", "redis-tls":
		return "redis"
	case "rabbitmq", "rabbitmq-amqps":
		return "amqp"
	case "kafka", "kafka-tls":
		return "kafka"
	case "socks", "socks5":
		return "socks"
	case "http-proxy":
		return "http-proxy"
	case "frp", "frp-proxy", "frp-dashboard":
		return "frp"
	case "elasticsearch":
		return "http"
	case "http", "https", "tomcat", "rabbitmq-management":
		return service
	default:
		return fallback
	}
}

func sanitizeBanner(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 500 {
		return s[:500]
	}
	return strings.TrimSpace(s)
}

func shouldProbeTLS(port int) bool {
	switch port {
	case 443, 465, 563, 587, 636, 993, 995, 8443, 9443, 5671, 6380, 9093, 9094, 15671:
		return true
	default:
		return false
	}
}

func isSOCKSPort(port int) bool {
	switch port {
	case 1080, 1081, 1086, 1088, 9050, 9150:
		return true
	default:
		return false
	}
}

type socksProbeResult struct {
	Banner   string
	Evidence []string
}

func probeSOCKS5(ctx context.Context, host string, port int, timeout time.Duration) *socksProbeResult {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil
	}
	if resp[0] != 0x05 {
		return nil
	}
	method := "no-auth"
	if resp[1] == 0xff {
		method = "no-acceptable-method"
	}
	return &socksProbeResult{
		Banner:   fmt.Sprintf("SOCKS5 greeting response method=%s", method),
		Evidence: []string{"socks5 greeting accepted"},
	}
}

func probeTLSCert(ctx context.Context, host string, port int, timeout time.Duration) *x509.Certificate {
	_ = ctx
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, fmt.Sprint(port)), &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return nil
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
}

func productByService(service string) string {
	switch service {
	case "ssh", "ssh-alt":
		return "OpenSSH/SSH"
	case "ftp", "ftp-alt", "ftp-data":
		return "FTP Server"
	case "mysql", "mysqlx":
		return "MySQL"
	case "postgresql", "postgresql-alt":
		return "PostgreSQL"
	case "redis", "redis-tls":
		return "Redis"
	case "rabbitmq", "rabbitmq-amqps", "rabbitmq-management", "rabbitmq-management-https", "rabbitmq-clustering":
		return "RabbitMQ"
	case "elasticsearch":
		return "Elasticsearch"
	case "kafka", "kafka-tls":
		return "Kafka"
	case "socks", "socks5":
		return "SOCKS Proxy"
	case "http-proxy":
		return "HTTP Proxy"
	case "frp", "frp-proxy", "frp-dashboard":
		return "frp"
	case "tomcat", "tomcat-ajp", "tomcat-shutdown":
		return "Apache Tomcat"
	case "http", "https":
		return "Web Server"
	default:
		return ""
	}
}

func productFromHTTP(fp HTTPProbe, fallback string) string {
	lower := strings.ToLower(fp.Banner + "\n" + fp.Body)
	switch {
	case strings.Contains(lower, "tomcat"):
		return "Apache Tomcat"
	case strings.Contains(lower, "nginx"):
		return "Nginx"
	case strings.Contains(lower, "apache"):
		return "Apache HTTP Server"
	case strings.Contains(lower, "microsoft-iis"):
		return "Microsoft IIS"
	case strings.Contains(lower, "rabbitmq management"):
		return "RabbitMQ Management"
	case strings.Contains(lower, "kibana"):
		return "Kibana"
	case strings.Contains(lower, "elasticsearch"):
		return "Elasticsearch"
	case strings.Contains(lower, "frp") || strings.Contains(lower, "frps"):
		return "frp"
	default:
		return fallback
	}
}

func tagsForService(service string) []string {
	switch service {
	case "mysql", "mysqlx", "postgresql", "postgresql-alt", "redis", "redis-tls", "mongodb", "elasticsearch":
		return []string{"database", "data-service"}
	case "rabbitmq", "rabbitmq-amqps", "rabbitmq-management", "rabbitmq-management-https", "rabbitmq-clustering", "kafka", "kafka-tls":
		return []string{"message-queue", "middleware"}
	case "socks", "socks5", "http-proxy":
		return []string{"proxy", "tunnel"}
	case "frp", "frp-proxy", "frp-dashboard":
		return []string{"tunnel", "proxy", "frp"}
	case "ssh", "ssh-alt", "rdp", "smb":
		return []string{"remote-access"}
	case "ftp", "ftp-alt", "ftp-data":
		return []string{"file-transfer"}
	case "http", "https", "tomcat":
		return []string{"web"}
	case "tomcat-ajp", "tomcat-shutdown":
		return []string{"app-server", "tomcat"}
	default:
		return nil
	}
}

var serverVersionRE = regexp.MustCompile(`(?i)(apache|nginx|microsoft-iis|tomcat|openssh|mysql|redis|rabbitmq|kafka|postgresql|frp|frps|vsftpd|proftpd|filezilla)[/\s-]*([0-9][0-9A-Za-z._-]*)?`)

func versionFromServer(server string) string {
	return versionFromBanner("", server)
}

func versionFromBanner(service, banner string) string {
	if service == "ssh" && strings.HasPrefix(strings.ToUpper(banner), "SSH-") {
		parts := strings.Fields(banner)
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], "SSH-")
		}
	}
	m := serverVersionRE.FindStringSubmatch(banner)
	if len(m) >= 3 {
		return strings.TrimSpace(m[2])
	}
	return ""
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

func mergeStrings(sets ...[]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, set := range sets {
		for _, item := range set {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

func maxConfidence(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func fingerprintID(r core.PortResult) string {
	parts := []string{r.Transport, r.Protocol, r.Service, r.Product, r.Version}
	return strings.Trim(strings.Join(parts, "/"), "/")
}
