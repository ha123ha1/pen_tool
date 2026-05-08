package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"scanner/internal/core"
)

type OutputOptions struct {
	File   string
	Format string
}

func Write(report core.Report, opts OutputOptions) error {
	if opts.File == "" {
		opts.File = "reports/report.json"
	}
	if opts.Format == "" {
		opts.Format = strings.TrimPrefix(filepath.Ext(opts.File), ".")
	}
	if err := os.MkdirAll(filepath.Dir(opts.File), 0755); err != nil && filepath.Dir(opts.File) != "." {
		return err
	}
	switch strings.ToLower(opts.Format) {
	case "json":
		return writeJSON(report, opts.File)
	case "html":
		return writeHTML(report, opts.File)
	case "csv":
		return writeCSV(report, opts.File)
	default:
		return fmt.Errorf("unsupported output format %q", opts.Format)
	}
}

func writeJSON(report core.Report, file string) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, b, 0644)
}

func writeHTML(report core.Report, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	return reportTemplate.Execute(f, report)
}

func writeCSV(report core.Report, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"target", "host", "port", "transport", "protocol", "service", "product", "version", "url", "title", "tls", "tags", "confidence", "banner"})
	for _, a := range report.Assets {
		_ = w.Write([]string{a.Target, a.Host, fmt.Sprint(a.Port), a.Transport, a.Protocol, a.Service, a.Product, a.Version, a.URL, a.Title, fmt.Sprint(a.TLS), strings.Join(a.Tags, "|"), fmt.Sprintf("%.2f", a.Confidence), a.Banner})
	}
	for _, f := range report.Findings {
		_ = w.Write([]string{f.Target, "", "", "", "", f.Type, "", "", "", "", "", "", "", f.Evidence})
	}
	return w.Error()
}

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Authorized Security Scan Report</title>
<style>body{font-family:Arial,sans-serif;margin:32px;color:#1f2937}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #d1d5db;padding:8px;text-align:left}th{background:#eef2f7}.badge{display:inline-block;padding:2px 6px;border-radius:4px;background:#e0f2fe;margin:2px}</style></head>
<body><h1>Authorized Security Scan Report</h1>
<p><strong>Version:</strong> {{.ToolVersion}} | <strong>Scan Level:</strong> {{.ScanLevel}}</p>
<p><strong>Authorization:</strong> {{.Authorization}}</p>
<p><strong>Time:</strong> {{.StartedAt}} - {{.FinishedAt}}</p>
{{if .Assets}}<h2>Asset Mapping</h2><table><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th>Title</th><th>TLS</th><th>Tags</th><th>Confidence</th></tr>{{range .Assets}}<tr><td>{{.Host}}</td><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Service}}</td><td>{{.Product}}</td><td>{{.Version}}</td><td>{{.Title}}</td><td>{{.TLS}}</td><td>{{range .Tags}}<span class="badge">{{.}}</span>{{end}}</td><td>{{printf "%.2f" .Confidence}}</td></tr>{{end}}</table>{{end}}
{{range .Hosts}}<h2>{{.Target.Raw}}</h2>
<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Banner</th></tr>{{range .OpenPorts}}<tr><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Service}}</td><td>{{.Product}}</td><td>{{.Banner}}</td></tr>{{end}}</table>
{{if .Fingerprints}}<h3>Web Fingerprints</h3><table><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technologies</th></tr>{{range .Fingerprints}}<tr><td>{{.URL}}</td><td>{{.StatusCode}}</td><td>{{.Title}}</td><td>{{.Server}}</td><td>{{range .Technologies}}<span class="badge">{{.}}</span>{{end}}</td></tr>{{end}}</table>{{end}}
{{end}}
{{if .HTTPFlows}}<h2>Passive HTTP Flows</h2><table><tr><th>Method</th><th>URL</th><th>Status</th><th>Bytes</th><th>Title</th></tr>{{range .HTTPFlows}}<tr><td>{{.Method}}</td><td>{{.URL}}</td><td>{{.StatusCode}}</td><td>{{.RequestBytes}} / {{.ResponseBytes}}</td><td>{{.ResponseTitle}}</td></tr>{{end}}</table>{{end}}
{{if .Findings}}<h2>Findings</h2><table><tr><th>Severity</th><th>Type</th><th>Target</th><th>Location</th><th>Evidence</th><th>Recommendation</th></tr>{{range .Findings}}<tr><td>{{.Severity}}</td><td>{{.Type}}</td><td>{{.Target}}</td><td>{{.Location}}</td><td>{{.Evidence}}</td><td>{{.Recommendation}}</td></tr>{{end}}</table>{{end}}
</body></html>`))
