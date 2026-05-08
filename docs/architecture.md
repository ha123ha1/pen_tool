# Architecture

This project is an authorized, non-destructive security assessment scanner inspired by modular tools such as fscan, nuclei, xray, and EZ. It is designed for enterprise self-assessment and explicitly requires authorization confirmation before running.

## Overall Design

The scanner is organized as staged pipelines:

1. Target parsing expands IP, CIDR, host, URL, file, and exclusion inputs into normalized targets.
2. TCP connect scanning discovers open ports with bounded concurrency.
3. Service detection uses port heuristics, banner grabbing, and lightweight HTTP probing.
4. HTTP fingerprinting extracts title, headers, cookies, body markers, and YAML-based rules.
5. Output writers produce JSON, HTML, and CSV reports with authorization metadata.
6. Passive proxy mode observes allowlisted HTTP traffic, records request/response summaries, runs passive checks, and can optionally send bounded safe active probes derived from observed GET parameters.

Later phases can add crawler, passive scan, web vulnerability checks, POC plugins, brute-force modules, resume state, and distributed workers behind the same `core` result types.

## Module Interfaces

- `internal/utils`: target parsing and file input helpers.
- `internal/portscan`: port expression parsing and TCP connect scanner.
- `internal/service`: banner and HTTP service probes.
- `internal/fingerprint`: YAML rule loader and HTTP fingerprint matcher.
- `internal/scheduler`: staged worker orchestration and global rate limiter use.
- `internal/output`: report writers.
- `internal/config`: CLI-compatible YAML configuration.
- `internal/logger`: leveled audit-friendly logging.
- `internal/poc`: future non-destructive POC plugin contracts.
- `internal/brute`: future brute-force safety policy and credential masking helpers.
- `internal/passive`: passive response analysis and safe active probe generation.
- `internal/proxy`: allowlisted HTTP proxy scanner with CONNECT tunneling.

## Safety Model

The CLI refuses to scan unless `--authorized` is supplied. Destructive checks, persistence, stealth, log bypass, payload delivery, data theft, and command execution are not implemented. Brute-force modules are placeholders for later phases and must remain disabled unless `--enable-bruteforce` is explicitly supplied with rate limits and max attempts.

Passive proxy mode requires `--proxy-allow-hosts`. HTTP traffic can be inspected and safely probed. HTTPS `CONNECT` traffic is tunneled by default. When `--proxy-https-decrypt` is explicitly enabled, the proxy uses a local CA private key to dynamically sign allowlisted host certificates. `--proxy-generate-ca` creates a local CA pair for this purpose; the public certificate must be trusted by the test browser, and the private key must be protected.
