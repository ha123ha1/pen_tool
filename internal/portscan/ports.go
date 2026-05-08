package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

func DefaultPorts() []int {
	return mergePorts(
		ServicePorts("base"),
		ServicePorts("web"),
		ServicePorts("tomcat"),
		ServicePorts("ssh"),
		ServicePorts("ftp"),
		ServicePorts("mysql"),
		ServicePorts("postgresql"),
		ServicePorts("redis"),
		ServicePorts("rabbitmq"),
		ServicePorts("elasticsearch"),
		ServicePorts("kafka"),
		ServicePorts("socks"),
		ServicePorts("frp"),
		ServicePorts("proxy"),
	)
}

func ServicePorts(name string) []int {
	switch normalizeServiceName(name) {
	case "base":
		return []int{21, 23, 25, 53, 88, 110, 135, 139, 143, 389, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3389, 5900, 5984, 11211, 27017}
	case "ssh":
		return []int{22, 2222}
	case "ftp":
		return []int{20, 21, 2121}
	case "web":
		return []int{80, 81, 443, 3000, 5000, 5601, 7001, 7002, 7400, 7500, 8000, 8080, 8081, 8082, 8088, 8090, 8099, 8443, 8888, 9000, 9080, 9443, 10000, 18080}
	case "tomcat":
		return []int{8005, 8009, 8080, 8081, 8082, 8443}
	case "mysql":
		return []int{3306, 33060}
	case "postgresql":
		return []int{5432, 5433}
	case "redis":
		return []int{6379, 6380}
	case "rabbitmq":
		return []int{4369, 5671, 5672, 15671, 15672, 25672}
	case "elasticsearch":
		return []int{9200, 9300}
	case "kafka":
		return []int{9092, 9093, 9094}
	case "socks":
		return []int{1080, 1081, 1086, 1088, 9050, 9150}
	case "frp":
		return []int{6000, 7000, 7001, 7400, 7500}
	case "proxy":
		return []int{3128, 8000, 8080, 8081, 8088, 8888}
	default:
		return nil
	}
}

func ParseServicePorts(expr string) ([]int, error) {
	var sets [][]int
	for _, part := range strings.Split(expr, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		ports := ServicePorts(name)
		if len(ports) == 0 {
			return nil, fmt.Errorf("unknown service port group %q", name)
		}
		sets = append(sets, ports)
	}
	return mergePorts(sets...), nil
}

func KnownServiceGroups() []string {
	return []string{"base", "web", "tomcat", "ssh", "ftp", "mysql", "postgresql", "redis", "rabbitmq", "elasticsearch", "kafka", "socks", "frp", "proxy"}
}

func RangePorts(start, end int) []int {
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

func ParsePorts(expr string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := start; p <= end; p++ {
				seen[p] = struct{}{}
			}
			continue
		}
		p, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		seen[p] = struct{}{}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func MergePorts(sets ...[]int) []int {
	return mergePorts(sets...)
}

func mergePorts(sets ...[]int) []int {
	seen := map[int]struct{}{}
	for _, set := range sets {
		for _, p := range set {
			if p >= 1 && p <= 65535 {
				seen[p] = struct{}{}
			}
		}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

func normalizeServiceName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "pg", "pgsql", "postgres", "postgresql", "postsql":
		return "postgresql"
	case "es", "elastic", "elasticsearch":
		return "elasticsearch"
	case "mq", "amqp", "rabbit", "rabbitmq":
		return "rabbitmq"
	case "socks5", "socks4", "socks":
		return "socks"
	case "frps", "frpc", "frp":
		return "frp"
	case "http-proxy", "httpproxy", "proxy":
		return "proxy"
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}
