package poc

import (
	"context"

	"scanner/internal/core"
)

type Metadata struct {
	Name       string   `json:"name"`
	CVE        string   `json:"cve,omitempty"`
	Product    string   `json:"product"`
	Severity   string   `json:"severity"`
	Author     string   `json:"author,omitempty"`
	References []string `json:"references,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	SafeCheck  bool     `json:"safe_check"`
}

type Plugin interface {
	Metadata() Metadata
	MatchFingerprint(target core.Target, fingerprints []core.WebFingerprint) bool
	Check(ctx context.Context, target core.Target) (core.Finding, bool, error)
}

func ValidateMetadata(meta Metadata) bool {
	return meta.Name != "" && meta.Product != "" && meta.Severity != "" && meta.SafeCheck
}
