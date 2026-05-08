package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"scanner/internal/brute"
	"scanner/internal/config"
	"scanner/internal/core"
	"scanner/internal/fingerprint"
	"scanner/internal/intel"
	"scanner/internal/logger"
	"scanner/internal/output"
	"scanner/internal/portscan"
	"scanner/internal/proxy"
	"scanner/internal/scheduler"
	"scanner/internal/utils"
)

const version = "0.1.0-mvp"

func main() {
	var opts config.Options
	var targets, targetFile, urlTarget, exclude, ports, servicePortGroups, outputFile, outputFormat, cfgFile, bruteAllowlist string
	var proxyListen, proxyAllowHosts, proxyCACert, proxyCAKey string
	var intelSources, intelOutput string
	var authorized, webscan, fullPorts, passiveProxy, proxyActiveProbes, proxyHTTPSDecrypt, proxyGenerateCA, intelUpdate bool
	var proxyDuration time.Duration
	var proxyMaxActive, intelDays int

	flag.StringVar(&targets, "t", "", "target IP, CIDR, host, URL, or comma-separated targets")
	flag.StringVar(&targetFile, "f", "", "file containing targets, one per line")
	flag.StringVar(&urlTarget, "u", "", "URL target")
	flag.StringVar(&exclude, "exclude", "", "comma-separated targets to exclude")
	flag.StringVar(&ports, "p", "", "ports such as 22,80,443 or 1-1024")
	flag.StringVar(&servicePortGroups, "service-ports", "", "service port groups, such as web,tomcat,ssh,mysql,postgresql,redis,rabbitmq,elasticsearch,kafka")
	flag.BoolVar(&fullPorts, "full-ports", false, "scan TCP ports 1-65535")
	flag.IntVar(&opts.Concurrency, "concurrency", 200, "global concurrency")
	flag.IntVar(&opts.PortConcurrency, "port-concurrency", 1000, "port scan concurrency")
	flag.IntVar(&opts.WebConcurrency, "web-concurrency", 50, "web concurrency")
	flag.DurationVar(&opts.Timeout, "timeout", 3*time.Second, "network timeout")
	flag.IntVar(&opts.Retries, "retries", 1, "retry count for lightweight probes")
	flag.IntVar(&opts.RateLimit, "rate-limit", 100, "global requests per second; 0 disables limiter")
	flag.StringVar(&opts.ScanLevel, "scan-level", "safe", "safe, normal, aggressive, custom")
	flag.BoolVar(&opts.SafeMode, "safe-mode", true, "keep destructive checks disabled")
	flag.BoolVar(&webscan, "webscan", false, "enable HTTP fingerprint checks")
	flag.BoolVar(&passiveProxy, "passive-proxy", false, "run authorized passive HTTP proxy scanner")
	flag.StringVar(&proxyListen, "proxy-listen", "127.0.0.1:8088", "passive proxy listen address")
	flag.StringVar(&proxyAllowHosts, "proxy-allow-hosts", "", "comma-separated passive proxy host allowlist; supports *.example.com")
	flag.BoolVar(&proxyActiveProbes, "proxy-active-probes", false, "enable safe non-destructive active probes from observed GET requests")
	flag.BoolVar(&proxyHTTPSDecrypt, "proxy-https-decrypt", false, "decrypt allowlisted HTTPS traffic using a local MITM CA")
	flag.BoolVar(&proxyGenerateCA, "proxy-generate-ca", false, "generate a local CA certificate/key for HTTPS decryption if missing")
	flag.StringVar(&proxyCACert, "proxy-ca-cert", "certs/scanner-ca.pem", "CA certificate path for HTTPS decryption; DER or PEM")
	flag.StringVar(&proxyCAKey, "proxy-ca-key", "certs/scanner-ca-key.pem", "CA private key path for HTTPS decryption; PEM or DER")
	flag.DurationVar(&proxyDuration, "proxy-duration", 0, "passive proxy run duration; 0 runs until Ctrl+C")
	flag.IntVar(&proxyMaxActive, "proxy-max-active-per-request", 4, "maximum safe active probes generated from each observed request")
	flag.BoolVar(&opts.EnablePOC, "poc", false, "enable non-destructive POC checks placeholder")
	flag.BoolVar(&intelUpdate, "intel-update", false, "update vulnerability intelligence cache from trusted metadata sources")
	flag.StringVar(&intelSources, "intel-sources", "nvd,kev", "comma-separated intel sources: nvd,kev")
	flag.IntVar(&intelDays, "intel-days", 7, "NVD publication lookback days for intel update")
	flag.StringVar(&intelOutput, "intel-output", "data/vuln-intel.json", "vulnerability intelligence output file")
	flag.BoolVar(&opts.EnableBruteforce, "enable-bruteforce", false, "enable rate-limited brute force modules; disabled by default")
	flag.IntVar(&opts.MaxAttemptsPerService, "max-attempts-per-service", 20, "maximum brute force attempts per service")
	flag.StringVar(&bruteAllowlist, "bruteforce-allowlist", "", "comma-separated whitelist required when --enable-bruteforce is used")
	flag.BoolVar(&authorized, "authorized", false, "confirm you are authorized to scan these targets")
	flag.StringVar(&outputFile, "output", "reports/report.json", "report output file")
	flag.StringVar(&outputFormat, "format", "json", "json or html")
	flag.StringVar(&cfgFile, "config", "", "optional YAML config file")
	flag.Parse()

	log := logger.New(os.Stderr, logger.InfoLevel)
	if err := run(log, opts, cfgFile, authorized, webscan, fullPorts, passiveProxy, proxyActiveProbes, proxyHTTPSDecrypt, proxyGenerateCA, intelUpdate, targets, targetFile, urlTarget, exclude, ports, servicePortGroups, outputFile, outputFormat, bruteAllowlist, proxyListen, proxyAllowHosts, proxyCACert, proxyCAKey, intelSources, intelOutput, proxyDuration, proxyMaxActive, intelDays); err != nil {
		log.Error("%v", err)
		os.Exit(1)
	}
}

func run(log *logger.Logger, opts config.Options, cfgFile string, authorized, webscan, fullPorts, passiveProxyMode, proxyActiveProbes, proxyHTTPSDecrypt, proxyGenerateCA, intelUpdateMode bool, targets, targetFile, urlTarget, exclude, ports, servicePortGroups, outputFile, outputFormat, bruteAllowlist, proxyListen, proxyAllowHosts, proxyCACert, proxyCAKey, intelSources, intelOutput string, proxyDuration time.Duration, proxyMaxActive, intelDays int) error {
	if cfgFile != "" {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		opts = cfg.MergeOptions(opts)
	}
	if !authorized {
		return errors.New("authorization confirmation is required: rerun with --authorized after confirming you have explicit permission")
	}
	if opts.EnableBruteforce {
		policy := brute.Policy{
			Enabled:               true,
			MaxAttemptsPerService: opts.MaxAttemptsPerService,
			RateLimit:             opts.RateLimit,
			StopOnSuccess:         true,
			MaskPassword:          true,
			AllowedTargets:        splitCSV(bruteAllowlist),
		}
		if err := policy.Validate(); err != nil {
			return err
		}
		log.Warn("bruteforce modules are enabled; rate limits, max attempts, masking, and lockout protection must remain active")
	}
	if opts.ScanLevel == "" {
		opts.ScanLevel = "safe"
	}
	if intelUpdateMode {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		bundle, err := intel.Update(ctx, intel.Options{Sources: splitCSV(intelSources), Days: intelDays, Output: intelOutput})
		if err != nil {
			return err
		}
		log.Info("intel update complete: records=%d candidates=%d output=%s", len(bundle.Records), len(bundle.Candidates), intelOutput)
		return nil
	}
	if passiveProxyMode {
		return runPassiveProxy(log, opts, proxyListen, proxyAllowHosts, outputFile, outputFormat, proxyCACert, proxyCAKey, proxyDuration, proxyActiveProbes, proxyHTTPSDecrypt, proxyGenerateCA, proxyMaxActive)
	}

	rawTargets, err := collectTargets(targets, targetFile, urlTarget)
	if err != nil {
		return err
	}
	excluded, err := utils.ParseExcludeList(exclude)
	if err != nil {
		return err
	}
	parsedTargets, err := utils.ParseTargets(rawTargets, excluded)
	if err != nil {
		return err
	}
	if len(parsedTargets) == 0 {
		return errors.New("no targets to scan")
	}

	scanPorts, err := selectPorts(ports, servicePortGroups, fullPorts)
	if err != nil {
		return err
	}
	rules, err := fingerprint.LoadRules("fingerprints/web_fingerprints.yaml")
	if err != nil {
		log.Warn("fingerprint rules unavailable: %v", err)
	}

	cfg := scheduler.ScanConfig{
		Version:      version,
		Options:      opts,
		Targets:      parsedTargets,
		Ports:        scanPorts,
		EnableWeb:    webscan || urlTarget != "",
		Fingerprints: rules,
		Logger:       log,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	report, err := scheduler.Run(ctx, cfg)
	if err != nil {
		return err
	}
	report.Authorization = "User confirmed authorized assessment with --authorized"
	if err := output.Write(report, output.OutputOptions{File: outputFile, Format: outputFormat}); err != nil {
		return err
	}
	log.Info("scan complete: %s findings=%d open_ports=%d", outputFile, len(report.Findings), countPorts(report.Hosts))
	return nil
}

func runPassiveProxy(log *logger.Logger, opts config.Options, listen, allowHosts, outputFile, outputFormat, caCert, caKey string, duration time.Duration, active, decryptHTTPS, generateCA bool, maxActive int) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	report, err := proxy.Run(ctx, proxy.Config{
		Version:             version,
		Listen:              listen,
		AllowHosts:          splitCSV(allowHosts),
		OutputFile:          outputFile,
		OutputFormat:        outputFormat,
		Authorization:       "User confirmed authorized passive proxy assessment with --authorized",
		Timeout:             opts.Timeout,
		RateLimit:           opts.RateLimit,
		EnableActiveProbes:  active,
		MaxActivePerRequest: maxActive,
		MaxBodyBytes:        1024 * 1024,
		DecryptHTTPS:        decryptHTTPS,
		GenerateCA:          generateCA,
		CACertPath:          caCert,
		CAKeyPath:           caKey,
		Logger:              log,
	})
	if err != nil {
		return err
	}
	log.Info("passive proxy stopped: flows=%d findings=%d report=%s", len(report.HTTPFlows), len(report.Findings), outputFile)
	return nil
}

func splitCSV(expr string) []string {
	var out []string
	for _, item := range strings.Split(expr, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func collectTargets(targets, targetFile, urlTarget string) ([]string, error) {
	var raw []string
	if targets != "" && !strings.Contains(targets, ",") {
		if st, err := os.Stat(targets); err == nil && !st.IsDir() {
			lines, err := utils.ReadLines(targets)
			if err != nil {
				return nil, err
			}
			raw = append(raw, lines...)
		} else {
			raw = append(raw, targets)
		}
	} else {
		for _, item := range strings.Split(targets, ",") {
			if strings.TrimSpace(item) != "" {
				raw = append(raw, item)
			}
		}
	}
	if urlTarget != "" {
		raw = append(raw, urlTarget)
	}
	if targetFile != "" {
		lines, err := utils.ReadLines(targetFile)
		if err != nil {
			return nil, err
		}
		raw = append(raw, lines...)
	}
	return raw, nil
}

func selectPorts(portExpr, serviceExpr string, full bool) ([]int, error) {
	if full {
		return portscan.RangePorts(1, 65535), nil
	}
	if portExpr == "" && serviceExpr == "" {
		return portscan.DefaultPorts(), nil
	}
	var sets [][]int
	if portExpr != "" {
		ports, err := portscan.ParsePorts(portExpr)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ports)
	}
	if serviceExpr != "" {
		ports, err := portscan.ParseServicePorts(serviceExpr)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ports)
	}
	return portscan.MergePorts(sets...), nil
}

func countPorts(hosts []core.HostResult) int {
	n := 0
	for _, h := range hosts {
		n += len(h.OpenPorts)
	}
	return n
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Authorized security assessment scanner %s\n\n", version)
		fmt.Fprintln(flag.CommandLine.Output(), "Examples:")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanner -t 192.168.1.1 --authorized")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanner -t 192.168.1.0/24 -p 22,80,443 --authorized")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanner -t 192.168.1.0/24 --service-ports web,tomcat,ssh,mysql,postgresql,redis,rabbitmq,elasticsearch,kafka --authorized")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanner -u https://example.com --webscan --authorized --format html --output reports/report.html")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanner --passive-proxy --proxy-allow-hosts example.com --authorized --output reports/passive.html --format html")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanner --passive-proxy --proxy-https-decrypt --proxy-generate-ca --proxy-allow-hosts example.com --authorized")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanner --intel-update --intel-sources nvd,kev --authorized")
		fmt.Fprintln(flag.CommandLine.Output())
		flag.PrintDefaults()
	}
}
