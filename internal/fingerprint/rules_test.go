package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte("- name: TestApp\n  header: TestServer\n  body: hello\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name != "TestApp" || rules[0].Header != "TestServer" {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}
