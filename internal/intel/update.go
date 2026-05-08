package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func Update(ctx context.Context, opts Options) (Bundle, error) {
	if opts.Days <= 0 {
		opts.Days = 7
	}
	if len(opts.Sources) == 0 {
		opts.Sources = []string{"nvd", "kev"}
	}
	var records []Record
	for _, source := range opts.Sources {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case "", "none":
			continue
		case "nvd":
			got, err := FetchNVD(ctx, opts.Days)
			if err != nil {
				return Bundle{}, err
			}
			records = append(records, got...)
		case "kev", "cisa-kev":
			got, err := FetchCISAKEV(ctx)
			if err != nil {
				return Bundle{}, err
			}
			records = append(records, got...)
		default:
			return Bundle{}, fmt.Errorf("unsupported intel source %q", source)
		}
	}
	records = dedupe(records)
	bundle := Bundle{GeneratedAt: time.Now(), Records: records, Candidates: candidates(records)}
	if opts.Output != "" {
		if err := WriteBundle(bundle, opts.Output); err != nil {
			return Bundle{}, err
		}
	}
	return bundle, nil
}

func WriteBundle(bundle Bundle, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func httpJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "AuthorizedSecurityScanner/0.1 intel-updater")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func dedupe(records []Record) []Record {
	seen := map[string]Record{}
	for _, r := range records {
		key := strings.ToUpper(r.ID)
		if key == "" {
			key = r.Source + ":" + r.Title
		}
		if old, ok := seen[key]; ok {
			old.References = unique(append(old.References, r.References...))
			old.Products = unique(append(old.Products, r.Products...))
			old.ExploitObserved = old.ExploitObserved || r.ExploitObserved
			if old.Severity == "" {
				old.Severity = r.Severity
			}
			seen[key] = old
			continue
		}
		r.ReviewStatus = "needs-human-review"
		r.SafePOCStatus = "not-generated"
		r.CollectedAt = time.Now()
		seen[key] = r
	}
	out := make([]Record, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExploitObserved != out[j].ExploitObserved {
			return out[i].ExploitObserved
		}
		return out[i].PublishedAt.After(out[j].PublishedAt)
	})
	return out
}

func candidates(records []Record) []POCCandidate {
	var out []POCCandidate
	for _, r := range records {
		if r.ID == "" {
			continue
		}
		product := ""
		if len(r.Products) > 0 {
			product = r.Products[0]
		}
		out = append(out, POCCandidate{
			ID:            r.ID,
			Product:       product,
			Severity:      r.Severity,
			References:    r.References,
			SafeCheckOnly: true,
			Status:        "manual-safe-check-required",
			Guidance:      "Create only a non-destructive existence check. Do not import exploit code, execute commands, read files, write shells, bypass logs, or exfiltrate data.",
		})
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
