package utils

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	"scanner/internal/core"
)

func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func ParseExcludeList(expr string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for _, item := range strings.Split(expr, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out[item] = struct{}{}
		if ip := net.ParseIP(item); ip != nil {
			out[ip.String()] = struct{}{}
		}
	}
	return out, nil
}

func ParseTargets(raw []string, exclude map[string]struct{}) ([]core.Target, error) {
	seen := map[string]core.Target{}
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		targets, err := expandTarget(item)
		if err != nil {
			return nil, err
		}
		for _, t := range targets {
			if _, skip := exclude[t.Raw]; skip {
				continue
			}
			if _, skip := exclude[t.Host]; skip {
				continue
			}
			seen[t.Host+"|"+t.URL] = t
		}
	}
	out := make([]core.Target, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Raw < out[j].Raw })
	return out, nil
}

func expandTarget(item string) ([]core.Target, error) {
	if strings.Contains(item, "://") {
		u, err := url.Parse(item)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("invalid URL target %q", item)
		}
		return []core.Target{{Raw: item, Host: u.Hostname(), URL: item, Scheme: u.Scheme}}, nil
	}
	if strings.Contains(item, "/") {
		ip, ipnet, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", item)
		}
		if ip.To4() != nil {
			ip = ip.To4()
		}
		var targets []core.Target
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ip = nextIP(ip) {
			cpy := append(net.IP(nil), ip...)
			if isNetworkOrBroadcast(cpy, ipnet) {
				continue
			}
			targets = append(targets, core.Target{Raw: cpy.String(), Host: cpy.String()})
		}
		return targets, nil
	}
	host := strings.TrimSpace(item)
	if host == "" {
		return nil, nil
	}
	return []core.Target{{Raw: item, Host: host}}, nil
}

func nextIP(ip net.IP) net.IP {
	ip = append(net.IP(nil), ip...)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip
}

func isNetworkOrBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	if ip.To4() != nil {
		ip = ip.To4()
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones >= 31 {
		return false
	}
	base := ip.Mask(ipnet.Mask)
	if ip.Equal(base) {
		return true
	}
	bcast := append(net.IP(nil), base...)
	for i := range bcast {
		bcast[i] |= ^ipnet.Mask[i]
	}
	return ip.Equal(bcast)
}
