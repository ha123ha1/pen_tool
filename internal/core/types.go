package core

import (
	"time"
)

type Target struct {
	Raw    string `json:"raw"`
	Host   string `json:"host"`
	URL    string `json:"url,omitempty"`
	Scheme string `json:"scheme,omitempty"`
}

type PortResult struct {
	Port        int      `json:"port"`
	Transport   string   `json:"transport"`
	Protocol    string   `json:"protocol,omitempty"`
	Service     string   `json:"service,omitempty"`
	Product     string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	Banner      string   `json:"banner,omitempty"`
	TLS         bool     `json:"tls,omitempty"`
	TLSCN       string   `json:"tls_cn,omitempty"`
	TLSSANs     []string `json:"tls_sans,omitempty"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	HTTPTitle   string   `json:"http_title,omitempty"`
	HTTPServer  string   `json:"http_server,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

type WebFingerprint struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	PoweredBy    string   `json:"x_powered_by,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
}

type Finding struct {
	Target         string    `json:"target"`
	Type           string    `json:"type"`
	Severity       string    `json:"severity"`
	Location       string    `json:"location"`
	Evidence       string    `json:"evidence"`
	Recommendation string    `json:"recommendation"`
	Timestamp      time.Time `json:"timestamp"`
}

type HTTPTransaction struct {
	Method         string    `json:"method"`
	URL            string    `json:"url"`
	Host           string    `json:"host"`
	StatusCode     int       `json:"status_code"`
	RequestBytes   int64     `json:"request_bytes"`
	ResponseBytes  int64     `json:"response_bytes"`
	RequestSummary string    `json:"request_summary,omitempty"`
	ResponseTitle  string    `json:"response_title,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

type HostResult struct {
	Target       Target           `json:"target"`
	OpenPorts    []PortResult     `json:"open_ports"`
	Assets       []AssetService   `json:"assets,omitempty"`
	Fingerprints []WebFingerprint `json:"web_fingerprints,omitempty"`
}

type AssetService struct {
	Target      string    `json:"target"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Transport   string    `json:"transport"`
	Protocol    string    `json:"protocol,omitempty"`
	Service     string    `json:"service,omitempty"`
	Product     string    `json:"product,omitempty"`
	Version     string    `json:"version,omitempty"`
	URL         string    `json:"url,omitempty"`
	Title       string    `json:"title,omitempty"`
	Banner      string    `json:"banner,omitempty"`
	TLS         bool      `json:"tls,omitempty"`
	TLSCN       string    `json:"tls_cn,omitempty"`
	TLSSANs     []string  `json:"tls_sans,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Confidence  float64   `json:"confidence,omitempty"`
	Evidence    []string  `json:"evidence,omitempty"`
	ObservedAt  time.Time `json:"observed_at"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

type Report struct {
	ToolVersion   string            `json:"tool_version"`
	Authorization string            `json:"authorization"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	ScanLevel     string            `json:"scan_level"`
	Hosts         []HostResult      `json:"hosts"`
	Assets        []AssetService    `json:"assets,omitempty"`
	HTTPFlows     []HTTPTransaction `json:"http_flows,omitempty"`
	Findings      []Finding         `json:"findings"`
}
