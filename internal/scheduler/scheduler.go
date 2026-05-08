package scheduler

import (
	"context"
	"strconv"
	"sync"
	"time"

	"scanner/internal/config"
	"scanner/internal/core"
	"scanner/internal/fingerprint"
	"scanner/internal/logger"
	"scanner/internal/portscan"
	"scanner/internal/rate"
	"scanner/internal/service"
)

type ScanConfig struct {
	Version      string
	Options      config.Options
	Targets      []core.Target
	Ports        []int
	EnableWeb    bool
	Fingerprints []fingerprint.Rule
	Logger       *logger.Logger
}

func Run(ctx context.Context, cfg ScanConfig) (core.Report, error) {
	start := time.Now()
	report := core.Report{
		ToolVersion: cfg.Version,
		StartedAt:   start,
		ScanLevel:   cfg.Options.ScanLevel,
	}
	limiter := rate.New(cfg.Options.RateLimit)
	defer limiter.Stop()

	results := make(chan core.HostResult)
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, cfg.Options.Concurrency))
	for _, target := range cfg.Targets {
		t := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			hostCtx, cancel := context.WithTimeout(ctx, cfg.Options.Timeout*time.Duration(max(1, len(cfg.Ports))))
			defer cancel()
			results <- scanHost(hostCtx, cfg, limiter, t)
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	for r := range results {
		report.Hosts = append(report.Hosts, r)
		report.Assets = append(report.Assets, r.Assets...)
	}
	report.FinishedAt = time.Now()
	return report, ctx.Err()
}

func scanHost(ctx context.Context, cfg ScanConfig, limiter *rate.Limiter, target core.Target) core.HostResult {
	if cfg.Logger != nil {
		cfg.Logger.Info("scanning %s", target.Raw)
	}
	open, _ := portscan.Scan(ctx, target.Host, cfg.Ports, cfg.Options.PortConcurrency, cfg.Options.Timeout)
	result := core.HostResult{Target: target}
	for _, op := range open {
		limiter.Wait(ctx)
		pr := service.Detect(ctx, target, op.Port, cfg.Options.Timeout)
		result.OpenPorts = append(result.OpenPorts, pr)
		result.Assets = append(result.Assets, assetFromPort(target, pr))
		if cfg.EnableWeb && (pr.Service == "http" || pr.Service == "https" || pr.Service == "tomcat" || pr.Port == 9200) {
			limiter.Wait(ctx)
			if fp, ok := fingerprint.ScanHTTP(ctx, target.Host, op.Port, cfg.Fingerprints, cfg.Options.Timeout); ok {
				result.Fingerprints = append(result.Fingerprints, fp)
			}
		}
	}
	return result
}

func assetFromPort(target core.Target, pr core.PortResult) core.AssetService {
	url := ""
	if pr.Protocol == "http" || pr.Protocol == "https" {
		url = pr.Protocol + "://" + target.Host
		if (pr.Protocol == "http" && pr.Port != 80) || (pr.Protocol == "https" && pr.Port != 443) {
			url += ":" + itoa(pr.Port)
		}
	}
	return core.AssetService{
		Target:      target.Raw,
		Host:        target.Host,
		Port:        pr.Port,
		Transport:   pr.Transport,
		Protocol:    pr.Protocol,
		Service:     pr.Service,
		Product:     pr.Product,
		Version:     pr.Version,
		URL:         url,
		Title:       pr.HTTPTitle,
		Banner:      pr.Banner,
		TLS:         pr.TLS,
		TLSCN:       pr.TLSCN,
		TLSSANs:     pr.TLSSANs,
		Tags:        pr.Tags,
		Confidence:  pr.Confidence,
		Evidence:    pr.Evidence,
		ObservedAt:  time.Now(),
		Fingerprint: pr.Fingerprint,
	}
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
