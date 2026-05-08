package intel

import (
	"context"
	"time"
)

type kevResponse struct {
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}

func FetchCISAKEV(ctx context.Context) ([]Record, error) {
	var resp kevResponse
	err := httpJSON(ctx, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", &resp)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, v := range resp.Vulnerabilities {
		out = append(out, Record{
			ID:              v.CVEID,
			Source:          "cisa-kev",
			Title:           v.VulnerabilityName,
			Description:     v.ShortDescription,
			Products:        unique([]string{v.VendorProject + " " + v.Product}),
			References:      unique([]string{v.Notes}),
			ExploitObserved: true,
			PublishedAt:     parseKEVDate(v.DateAdded),
			Notes:           []string{v.RequiredAction, "Known ransomware campaign use: " + v.KnownRansomwareCampaignUse},
		})
	}
	return out, nil
}

func parseKEVDate(v string) time.Time {
	t, _ := time.Parse("2006-01-02", v)
	return t
}
