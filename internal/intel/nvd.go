package intel

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
			Metrics map[string][]struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func FetchNVD(ctx context.Context, days int) ([]Record, error) {
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -days)
	q := url.Values{}
	q.Set("pubStartDate", start.Format("2006-01-02T15:04:05.000Z"))
	q.Set("pubEndDate", end.Format("2006-01-02T15:04:05.000Z"))
	q.Set("resultsPerPage", "100")
	q.Set("noRejected", "")
	endpoint := "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q.Encode()
	var resp nvdResponse
	if err := httpJSON(ctx, endpoint, &resp); err != nil {
		return nil, err
	}
	var out []Record
	for _, item := range resp.Vulnerabilities {
		c := item.CVE
		rec := Record{
			ID:          c.ID,
			Source:      "nvd",
			Title:       c.ID,
			Description: nvdDescription(c.Descriptions),
			CWE:         nvdCWE(c.Weaknesses),
			References:  nvdRefs(c.References),
			PublishedAt: parseNVDTime(c.Published),
			UpdatedAt:   parseNVDTime(c.LastModified),
		}
		rec.CVSS, rec.Severity = nvdSeverity(c.Metrics)
		rec.ExploitObserved = hasExploitTaggedReference(c.References)
		rec.Products = inferProducts(rec.Description)
		out = append(out, rec)
	}
	return out, nil
}

func nvdDescription(items []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range items {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(items) > 0 {
		return items[0].Value
	}
	return ""
}

func nvdCWE(items []struct {
	Description []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
}) []string {
	var out []string
	for _, w := range items {
		for _, d := range w.Description {
			if d.Value != "" && d.Value != "NVD-CWE-noinfo" {
				out = append(out, d.Value)
			}
		}
	}
	return unique(out)
}

func nvdRefs(items []struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}) []string {
	var out []string
	for _, r := range items {
		out = append(out, r.URL)
	}
	return unique(out)
}

func hasExploitTaggedReference(items []struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}) bool {
	for _, r := range items {
		for _, tag := range r.Tags {
			if strings.EqualFold(tag, "Exploit") {
				return true
			}
		}
	}
	return false
}

func nvdSeverity(metrics map[string][]struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}) (float64, string) {
	for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		if values := metrics[key]; len(values) > 0 {
			return values[0].CVSSData.BaseScore, values[0].CVSSData.BaseSeverity
		}
	}
	return 0, ""
}

func parseNVDTime(v string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

func inferProducts(desc string) []string {
	words := strings.Fields(desc)
	if len(words) > 8 {
		words = words[:8]
	}
	product := strings.Trim(strings.Join(words, " "), "., ")
	if product == "" {
		return nil
	}
	return []string{fmt.Sprintf("inferred: %s", product)}
}
