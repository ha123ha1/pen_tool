package intel

import "time"

type Record struct {
	ID              string    `json:"id"`
	Source          string    `json:"source"`
	Title           string    `json:"title"`
	Description     string    `json:"description,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	CVSS            float64   `json:"cvss,omitempty"`
	CWE             []string  `json:"cwe,omitempty"`
	Products        []string  `json:"products,omitempty"`
	References      []string  `json:"references,omitempty"`
	ExploitObserved bool      `json:"exploit_observed,omitempty"`
	PublishedAt     time.Time `json:"published_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
	CollectedAt     time.Time `json:"collected_at"`
	ReviewStatus    string    `json:"review_status"`
	SafePOCStatus   string    `json:"safe_poc_status"`
	Notes           []string  `json:"notes,omitempty"`
}

type Bundle struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Records     []Record       `json:"records"`
	Candidates  []POCCandidate `json:"poc_candidates"`
}

type POCCandidate struct {
	ID            string   `json:"id"`
	Product       string   `json:"product,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	References    []string `json:"references,omitempty"`
	SafeCheckOnly bool     `json:"safe_check_only"`
	Status        string   `json:"status"`
	Guidance      string   `json:"guidance"`
}

type Options struct {
	Sources []string
	Days    int
	Output  string
}
