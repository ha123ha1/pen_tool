package fingerprint

import (
	"bufio"
	"os"
	"strings"
)

type Rule struct {
	Name     string
	Header   string
	Body     string
	Cookie   string
	Path     string
	Severity string
}

func LoadRules(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rules []Rule
	var current *Rule
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "- name:") {
			if current != nil {
				rules = append(rules, *current)
			}
			current = &Rule{Name: cleanValue(strings.TrimPrefix(line, "- name:"))}
			continue
		}
		if current == nil {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), cleanValue(parts[1])
		switch key {
		case "header":
			current.Header = val
		case "body":
			current.Body = val
		case "cookie":
			current.Cookie = val
		case "path":
			current.Path = val
		case "severity":
			current.Severity = val
		}
	}
	if current != nil {
		rules = append(rules, *current)
	}
	return rules, sc.Err()
}

func cleanValue(v string) string {
	return strings.Trim(strings.TrimSpace(v), `"'`)
}
