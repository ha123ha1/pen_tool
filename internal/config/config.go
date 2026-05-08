package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	Concurrency           int
	PortConcurrency       int
	WebConcurrency        int
	Timeout               time.Duration
	Retries               int
	RateLimit             int
	ScanLevel             string
	SafeMode              bool
	EnablePOC             bool
	EnableBruteforce      bool
	MaxAttemptsPerService int
}

type Config struct {
	Options Options
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	cfg := Config{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if section == "scan" {
			applyScan(&cfg.Options, key, val)
		}
		if section == "modules" && key == "brute_force" {
			cfg.Options.EnableBruteforce = parseBool(val)
		}
		if section == "bruteforce" && key == "max_attempts_per_service" {
			cfg.Options.MaxAttemptsPerService = parseInt(val)
		}
	}
	return cfg, sc.Err()
}

func (c Config) MergeOptions(cli Options) Options {
	o := c.Options
	if cli.Concurrency != 0 {
		o.Concurrency = cli.Concurrency
	}
	if cli.PortConcurrency != 0 {
		o.PortConcurrency = cli.PortConcurrency
	}
	if cli.WebConcurrency != 0 {
		o.WebConcurrency = cli.WebConcurrency
	}
	if cli.Timeout != 0 {
		o.Timeout = cli.Timeout
	}
	if cli.Retries != 0 {
		o.Retries = cli.Retries
	}
	if cli.RateLimit != 0 {
		o.RateLimit = cli.RateLimit
	}
	if cli.ScanLevel != "" {
		o.ScanLevel = cli.ScanLevel
	}
	o.SafeMode = cli.SafeMode
	o.EnablePOC = cli.EnablePOC
	o.EnableBruteforce = cli.EnableBruteforce || o.EnableBruteforce
	if cli.MaxAttemptsPerService != 0 {
		o.MaxAttemptsPerService = cli.MaxAttemptsPerService
	}
	return o
}

func applyScan(o *Options, key, val string) {
	switch key {
	case "concurrency":
		o.Concurrency = parseInt(val)
	case "port_concurrency":
		o.PortConcurrency = parseInt(val)
	case "web_concurrency":
		o.WebConcurrency = parseInt(val)
	case "timeout":
		if d, err := time.ParseDuration(val); err == nil {
			o.Timeout = d
		}
	case "retries":
		o.Retries = parseInt(val)
	case "rate_limit":
		o.RateLimit = parseInt(val)
	case "safe_mode":
		o.SafeMode = parseBool(val)
	}
}

func parseInt(v string) int {
	n, _ := strconv.Atoi(v)
	return n
}

func parseBool(v string) bool {
	return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
}
