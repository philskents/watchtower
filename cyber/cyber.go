// Package cyber fetches structured threat intelligence: CISA's Known
// Exploited Vulnerabilities catalog, FIRST EPSS exploit-probability scores,
// and the SANS Internet Storm Center Infocon level. None need an API key.
package cyber

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	kevURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL    = "https://api.first.org/data/v1/epss"
	infoconURL = "https://isc.sans.edu/api/infocon?json"

	// EPSS accepts a comma-separated CVE list; keep each request well under its URL limits
	epssBatch = 100
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

// KEVEntry is one vulnerability from the CISA KEV catalog
type KEVEntry struct {
	CVE         string
	Vendor      string
	Product     string
	Name        string
	Description string
	DateAdded   time.Time
	DueDate     time.Time
	Ransomware  bool    // CISA knows of ransomware campaigns using it
	EPSS        float64 // probability of exploitation in the next 30 days, 0–1; -1 if unknown
	Percentile  float64 // EPSS percentile, 0–1; -1 if unknown
}

// URL links to the NVD entry for the CVE
func (e KEVEntry) URL() string {
	return "https://nvd.nist.gov/vuln/detail/" + e.CVE
}

// Intel is a snapshot of structured threat intelligence
type Intel struct {
	Infocon     string     // green, yellow, orange or red; "" if unavailable
	KEV         []KEVEntry // entries added within the requested window, newest first
	KEVTotal    int        // size of the whole catalog
	CatalogDate time.Time  // when CISA last released the catalog
	FetchedAt   time.Time
}

// FetchIntel fetches KEV entries added within window, enriched with EPSS
// scores, plus the Infocon level. KEV is required; EPSS and Infocon are
// best-effort and leave their fields unset on failure.
func FetchIntel(ctx context.Context, window time.Duration) (*Intel, error) {
	var catalog kevCatalog
	if err := getJSON(ctx, kevURL, &catalog); err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	entries := catalog.recent(time.Now().Add(-window))

	if scores, err := fetchEPSS(ctx, cveIDs(entries)); err == nil {
		for i := range entries {
			if s, ok := scores[entries[i].CVE]; ok {
				entries[i].EPSS, entries[i].Percentile = s.epss, s.percentile
			}
		}
	}

	var infocon struct {
		Status string `json:"status"`
	}
	if err := getJSON(ctx, infoconURL, &infocon); err != nil {
		infocon.Status = ""
	}

	released, _ := time.Parse(time.RFC3339, catalog.DateReleased)
	return &Intel{
		Infocon:     strings.ToLower(infocon.Status),
		KEV:         entries,
		KEVTotal:    catalog.Count,
		CatalogDate: released,
		FetchedAt:   time.Now(),
	}, nil
}

// ─── KEV ──────────────────────────────────────────────────────────────────────

type kevCatalog struct {
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		ShortDescription           string `json:"shortDescription"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// recent returns entries added on or after cutoff, newest first
func (c kevCatalog) recent(cutoff time.Time) []KEVEntry {
	cutoffDay := cutoff.Format(time.DateOnly)
	var out []KEVEntry
	for _, v := range c.Vulnerabilities {
		// dateAdded is a plain YYYY-MM-DD, so compare as strings to avoid timezone edges
		if v.DateAdded < cutoffDay {
			continue
		}
		added, _ := time.Parse(time.DateOnly, v.DateAdded)
		due, _ := time.Parse(time.DateOnly, v.DueDate)
		out = append(out, KEVEntry{
			CVE:         v.CVEID,
			Vendor:      v.VendorProject,
			Product:     v.Product,
			Name:        v.VulnerabilityName,
			Description: v.ShortDescription,
			DateAdded:   added,
			DueDate:     due,
			Ransomware:  v.KnownRansomwareCampaignUse == "Known",
			EPSS:        -1,
			Percentile:  -1,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].DateAdded.Equal(out[j].DateAdded) {
			return out[i].DateAdded.After(out[j].DateAdded)
		}
		return out[i].CVE > out[j].CVE
	})
	return out
}

func cveIDs(entries []KEVEntry) []string {
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.CVE
	}
	return ids
}

// ─── EPSS ─────────────────────────────────────────────────────────────────────

type epssScore struct{ epss, percentile float64 }

func fetchEPSS(ctx context.Context, cves []string) (map[string]epssScore, error) {
	scores := make(map[string]epssScore, len(cves))
	for start := 0; start < len(cves); start += epssBatch {
		end := min(start+epssBatch, len(cves))
		var resp struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		url := epssURL + "?cve=" + strings.Join(cves[start:end], ",")
		if err := getJSON(ctx, url, &resp); err != nil {
			return nil, fmt.Errorf("epss: %w", err)
		}
		for _, d := range resp.Data {
			e, err1 := strconv.ParseFloat(d.EPSS, 64)
			p, err2 := strconv.ParseFloat(d.Percentile, 64)
			if err1 == nil && err2 == nil {
				scores[d.CVE] = epssScore{e, p}
			}
		}
	}
	return scores, nil
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "watchtower/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
