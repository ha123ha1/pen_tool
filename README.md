# Scanner

Scanner is a cross-platform authorized security assessment tool written in Go. The current MVP implements target parsing, TCP connect port scanning, service detection, HTTP fingerprinting, passive proxy scanning, HTTPS interception for authorized traffic, vulnerability intelligence updates, and JSON / HTML / CSV reporting.

This project is intended only for legally authorized penetration testing, enterprise asset self-assessment, and security evaluation. Risky capabilities must be explicitly enabled, and the default operating model is non-destructive validation.

## Legal Use And Safety Boundaries

Use this tool only against targets where you have explicit authorization. The CLI requires `--authorized`; otherwise, scanning will not start.

Current safety boundaries:

- No persistence, stealth, log bypass, malicious payload delivery, or data theft.
- Vulnerability checks are designed to verify possible existence only. They must not write web shells, execute system commands, read sensitive files, or damage data.
- Brute-force capabilities are disabled by default and require `--enable-bruteforce`, rate limits, attempt caps, target allowlists, and password masking.
- Passive proxy mode requires `--proxy-allow-hosts` to avoid intercepting or probing unauthorized targets.
- Vulnerability intelligence updates collect metadata and references only. They do not automatically download, compile, run, or import public EXP code.

## Project Layout

- `cmd/scanner`: CLI entry point.
- `internal/utils`: target input parsing.
- `internal/portscan`: high-concurrency TCP connect port scanning.
- `internal/service`: banner grabbing, service detection, protocol fingerprinting, and asset mapping.
- `internal/core`: shared data structures for assets, ports, fingerprints, findings, and reports.
- `internal/fingerprint`: YAML-based HTTP fingerprint matching.
- `internal/scheduler`: scan orchestration, concurrency control, and rate limiting.
- `internal/output`: JSON, HTML, and CSV report writers.
- `internal/passive`: passive findings and bounded safe active probes.
- `internal/proxy`: allowlisted HTTP/HTTPS passive proxy scanner.
- `internal/intel`: vulnerability intelligence collection and safe POC candidate queue.
- `internal/poc`: non-destructive POC plugin interfaces.
- `internal/brute`: brute-force safety policy and credential masking helpers.
- `fingerprints`: extensible fingerprint rules.
- `docs`: architecture, plugin development, and vulnerability intelligence documentation.

Additional docs:

- [Architecture](docs/architecture.md)
- [Plugin Development](docs/plugin-development.md)
- [Vulnerability Intelligence Workflow](docs/vulnerability-intelligence.md)

## Build

```bash
go build -o scanner ./cmd/scanner
```

Windows:

```powershell
go build -o scanner.exe ./cmd/scanner
```

## Basic Usage

```bash
scanner -t 192.168.1.1 --authorized
scanner -t 192.168.1.0/24 --authorized
scanner -t 192.168.1.1 -p 22,80,443,3306 --authorized
scanner -t 192.168.1.0/24 --service-ports web,tomcat,ssh,mysql,postgresql,redis,rabbitmq,elasticsearch,kafka --authorized
scanner -u https://example.com --webscan --authorized
scanner -f targets.txt --authorized
```

Write an HTML report:

```bash
scanner -t 192.168.1.1 --authorized --format html --output reports/result.html
```

Use a config file:

```bash
scanner -t 192.168.1.1 --config config.example.yaml --authorized
```

## Implemented Capabilities

- Single IP, CIDR, domain, URL, file input, and mixed target parsing.
- Exclusion list support via `--exclude`.
- Default common ports, custom ports, port ranges, and full-port scanning.
- Service-oriented port groups for Web, Tomcat, SSH, FTP, MySQL, PostgreSQL, Redis, RabbitMQ, Elasticsearch, Kafka, SOCKS, FRP, HTTP Proxy, and more.
- TCP connect scanning with bounded concurrency and timeout control.
- Service detection based on port heuristics, banners, HTTP responses, TLS certificates, and lightweight protocol handshakes.
- Asset-mapping style service profiles: protocol, application, product, version, TLS certificate data, title, tags, confidence, and evidence.
- HTTP title, Server header, X-Powered-By, Cookie, and body keyword fingerprinting.
- JSON, HTML, and CSV reports.
- Passive HTTP proxy scanning.
- HTTPS interception with a generated local CA for authorized targets.
- Passive findings and bounded safe active probes.
- NVD / CISA KEV vulnerability intelligence updates.
- Unit tests for target parsing, port parsing, fingerprint rules, reporting, brute-force policy, passive scanning, proxy behavior, certificate generation, and service detection.

## Passive Proxy Scanning

Start the passive HTTP proxy:

```bash
scanner --passive-proxy --proxy-listen 127.0.0.1:8088 --proxy-allow-hosts example.com,*.example.org --authorized --output reports/passive.html --format html
```

Then configure your browser or test client to use:

```text
127.0.0.1:8088
```

The passive proxy records request/response summaries for authorized targets and performs non-destructive checks for:

- Missing security response headers.
- Cookies missing `HttpOnly`, `Secure`, or `SameSite`.
- Sensitive token / key format exposure.
- Private IP disclosure.
- Debug information and stack traces.
- Directory listing.
- Git / SVN metadata exposure.
- Swagger / OpenAPI exposure.
- Spring Boot actuator exposure.

### Safe Active Probes

Active probes are disabled by default. Enable them explicitly:

```bash
scanner --passive-proxy --proxy-allow-hosts example.com --proxy-active-probes --proxy-max-active-per-request 4 --authorized
```

Current safe active probes include:

- Reflected marker checks.
- SQL error signal checks using a single quote probe.
- Open redirect checks using `https://example.com/` as a safe external marker.

These probes are request-limited and do not execute commands, read files, or write data.

## HTTPS Interception

By default, HTTPS `CONNECT` traffic is tunneled and not decrypted.

To decrypt HTTPS traffic during authorized testing, enable it explicitly:

```bash
scanner --passive-proxy --proxy-https-decrypt --proxy-generate-ca --proxy-allow-hosts example.com --authorized --output reports/passive-https.html --format html
```

On first run, the scanner generates:

- `certs/scanner-ca.pem`: import this certificate into your browser or OS trust store.
- `certs/scanner-ca-key.pem`: private key used by the proxy to sign temporary leaf certificates. Keep it private.

You can also provide your own CA pair:

```bash
scanner --passive-proxy --proxy-https-decrypt --proxy-ca-cert certs/my-ca.pem --proxy-ca-key certs/my-ca-key.pem --proxy-allow-hosts example.com --authorized
```

Note: a public CA certificate alone, such as Burp's `cacert.der`, is not enough to dynamically sign per-host certificates. HTTPS interception requires the matching CA private key.

## Vulnerability Intelligence

Vulnerabilities change continuously. Scanner provides an intelligence update mode that collects structured vulnerability metadata and produces a manually reviewed safe POC candidate queue.

```bash
scanner --intel-update --intel-sources nvd,kev --intel-days 7 --authorized --intel-output data/vuln-intel.json
```

Currently supported sources:

- NVD CVE API: CVE, CVSS, CWE, references, and related metadata.
- CISA KEV: known exploited vulnerabilities catalog.

Designed future sources:

- GitHub Advisory Database.
- GitHub repositories, issues, and releases.
- Vendor security advisories.
- Blogs, RSS feeds, and archived articles.

Safety policy:

- Collect vulnerability metadata and references only.
- Do not automatically download EXP code.
- Do not automatically execute EXP code.
- Do not directly convert public EXP code into scanner plugins.
- All POCs must be manually rewritten as non-destructive `safe_check=true` checks.

## Report Formats

Supported formats:

- `json`
- `html`
- `csv`

Examples:

```bash
scanner -t 192.168.1.1 --authorized --format json --output reports/result.json
scanner -t 192.168.1.1 --authorized --format html --output reports/result.html
scanner -t 192.168.1.1 --authorized --format csv --output reports/result.csv
```

## Service Port Groups

Use `--service-ports` to scan focused service groups. This is lighter than a full-port scan and more precise than the default common-port set.

```bash
scanner -t 192.168.1.0/24 --service-ports mysql,redis,kafka --authorized
scanner -t 192.168.1.0/24 --service-ports web,tomcat,rabbitmq,elasticsearch --authorized
scanner -t 192.168.1.0/24 --service-ports ftp,socks,frp,proxy --authorized
scanner -t 192.168.1.1 -p 22,2222 --service-ports postsql,mysql --authorized
```

Built-in service groups:

- `web`: `80,81,443,3000,5000,5601,7001,7002,7400,7500,8000,8080,8081,8082,8088,8090,8099,8443,8888,9000,9080,9443,10000,18080`
- `tomcat`: `8005,8009,8080,8081,8082,8443`
- `ssh`: `22,2222`
- `ftp`: `20,21,2121`
- `mysql`: `3306,33060`
- `postgresql` / `postgres` / `postsql`: `5432,5433`
- `redis`: `6379,6380`
- `rabbitmq`: `4369,5671,5672,15671,15672,25672`
- `elasticsearch` / `es`: `9200,9300`
- `kafka`: `9092,9093,9094`
- `socks`: `1080,1081,1086,1088,9050,9150`
- `frp`: `6000,7000,7001,7400,7500`
- `proxy`: `3128,8000,8080,8081,8088,8888`

`-p` and `--service-ports` can be combined. The final port list is automatically deduplicated and sorted.

## Asset Mapping Output

Reports include an asset service profile in the top-level `assets` field and per-host profiles in `hosts[].assets`.

Fields include:

- `host` / `port` / `transport`
- `protocol`: for example `http`, `https`, `ssh`, `ftp`, `mysql`, `postgresql`, `redis`, `amqp`, `kafka`, `socks5`, `frp`
- `service`: specific service names such as `rabbitmq-management`, `elasticsearch`, `tomcat-ajp`, `frp-dashboard`
- `product` / `version`
- `url` / `title`
- `tls` / `tls_cn` / `tls_sans`
- `tags`: for example `web`, `database`, `message-queue`, `middleware`, `remote-access`, `file-transfer`, `proxy`, `tunnel`
- `confidence`
- `evidence`: port heuristic, banner, HTTP status, Server header, TLS certificate, SOCKS5 greeting, and other identification signals

Example:

```bash
scanner -t 192.168.1.1 --service-ports web,mysql,redis,rabbitmq,elasticsearch,kafka --authorized --format json --output reports/assets.json
```

This output can be used for enterprise asset inventory, exposure statistics, protocol distribution analysis, middleware review, and vulnerability intelligence matching.

## Configuration

See [config.example.yaml](config.example.yaml):

```yaml
scan:
  concurrency: 200
  port_concurrency: 1000
  web_concurrency: 50
  timeout: 3s
  retries: 1
  rate_limit: 100
  safe_mode: true
```

Use it with:

```bash
scanner -t 192.168.1.1 --config config.example.yaml --authorized
```

## Tests

```bash
go test ./...
```

## Cross-Platform Builds

Windows:

```bash
GOOS=windows GOARCH=amd64 go build -o dist/scanner-windows-amd64.exe ./cmd/scanner
```

Linux:

```bash
GOOS=linux GOARCH=amd64 go build -o dist/scanner-linux-amd64 ./cmd/scanner
```

macOS Intel:

```bash
GOOS=darwin GOARCH=amd64 go build -o dist/scanner-darwin-amd64 ./cmd/scanner
```

macOS Apple Silicon:

```bash
GOOS=darwin GOARCH=arm64 go build -o dist/scanner-darwin-arm64 ./cmd/scanner
```

## Roadmap

- URL crawler.
- More passive scanning rules.
- Broader safe Web vulnerability checks.
- Non-destructive POC plugin framework and built-in safe POCs.
- Explicitly authorized brute-force module.
- Resume support, caching, and a stronger scheduler.
- GitHub Advisory, vendor advisory, RSS, and archived article intelligence adapters.
- Web UI and asset management.

