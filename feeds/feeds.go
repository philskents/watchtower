package feeds

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mmcdole/gofeed"
)

// ThreatLevel represents news item severity
type ThreatLevel int

const (
	ThreatInfo ThreatLevel = iota
	ThreatLow
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatCritical:
		return "CRITICAL"
	case ThreatHigh:
		return "HIGH"
	case ThreatMedium:
		return "MEDIUM"
	case ThreatLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// NewsItem represents a single news article
type NewsItem struct {
	Title       string
	Source      string
	Published   time.Time
	URL         string
	ThreatLevel ThreatLevel
	Category    string
	IsLocal     bool
}

// GlobalFeeds are world news RSS sources
var GlobalFeeds = []struct {
	Name string
	URL  string
}{
	{"Reuters", "https://feeds.reuters.com/reuters/topNews"},
	{"BBC World", "http://feeds.bbci.co.uk/news/world/rss.xml"},
	{"AP News", "https://rsshub.app/apnews/topics/apf-topnews"},
	{"Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"},
	{"The Guardian", "https://www.theguardian.com/world/rss"},
	{"Defense News", "https://www.defensenews.com/arc/outboundfeeds/rss/"},
	{"Politico", "https://rss.politico.com/politics-news.xml"},
	{"Foreign Policy", "https://foreignpolicy.com/feed/"},
}

// CyberFeeds are cybersecurity news and advisory RSS sources
var CyberFeeds = []struct {
	Name string
	URL  string
}{
	{"BleepingComputer", "https://www.bleepingcomputer.com/feed/"},
	{"The Hacker News", "https://feeds.feedburner.com/TheHackersNews"},
	{"Krebs on Security", "https://krebsonsecurity.com/feed/"},
	{"The Record", "https://therecord.media/feed"},
	{"SecurityWeek", "https://www.securityweek.com/feed/"},
	{"Dark Reading", "https://www.darkreading.com/rss.xml"},
	{"SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"},
	{"CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
}

// LocalFeedURLs generates geo-targeted RSS feeds based on city/country
func LocalFeedURLs(city, country string) []struct{ Name, URL string } {
	return []struct{ Name, URL string }{
		{"Google News Local", fmt.Sprintf("https://news.google.com/rss/search?q=%s+news&hl=en&gl=%s&ceid=%s:en",
			strings.ReplaceAll(city, " ", "+"), country, country)},
		{"Google News Country", fmt.Sprintf("https://news.google.com/rss/headlines/section/geo/%s",
			strings.ReplaceAll(city, " ", "%20"))},
	}
}

// keyword threat classifier
type keywordTier struct {
	level    ThreatLevel
	category string
	words    []string
}

var threatKeywords = []keywordTier{
	{ThreatCritical, "conflict", []string{
		"nuclear", "missile strike", "war declared", "invasion", "airstrike kills",
		"coup", "assassination", "mass casualty", "chemical weapon", "dirty bomb",
		"martial law", "genocide",
	}},
	{ThreatHigh, "security", []string{
		"attack", "bombing", "explosion", "shooting", "killed", "hostage",
		"terrorist", "conflict", "offensive", "troops deployed", "sanctions",
		"ceasefire", "escalation", "warship", "military exercises",
	}},
	{ThreatHigh, "disaster", []string{
		"earthquake", "tsunami", "hurricane", "typhoon", "flood kills",
		"wildfire", "eruption", "catastrophic",
	}},
	{ThreatMedium, "politics", []string{
		"election", "protest", "crisis", "emergency", "shutdown",
		"impeachment", "indicted", "arrested", "detained", "expelled",
		"diplomatic", "summit", "agreement",
	}},
	{ThreatMedium, "economy", []string{
		"recession", "crash", "collapse", "default", "bankrupt",
		"inflation", "unemployment spike", "rate hike", "supply chain",
	}},
	{ThreatMedium, "cyber", []string{
		"hack", "breach", "ransomware", "cyberattack", "data leak",
		"malware", "phishing campaign", "zero-day",
	}},
	{ThreatLow, "general", []string{
		"trade deal", "policy", "reform", "budget", "statement",
		"meeting", "conference", "report",
	}},
}

// classifier assigns a threat level and category to a headline
type classifier func(title string) (ThreatLevel, string)

// cyberKeywords are matched on word boundaries so short terms like "rce"
// and "apt" don't fire inside "force" or "capture"
var cyberKeywords = compileTiers([]keywordTier{
	{ThreatCritical, "exploited", []string{
		"exploited", "actively exploiting", "under active attack", "exploitation",
		"zero-day", "zero-days", "0-day", "emergency directive", "emergency patch",
		"supply chain attack", "wormable",
	}},
	{ThreatHigh, "ransomware", []string{
		"ransomware", "extortion",
	}},
	{ThreatHigh, "breach", []string{
		"breach", "data leak", "stolen data", "leaked", "compromised", "hacked",
		"stole", "stolen", "theft", "implant",
	}},
	{ThreatHigh, "attack", []string{
		"cyberattack", "cyberattacks", "cyber attack", "systems offline", "outage",
		"hackers", "hacker", "hack",
	}},
	{ThreatHigh, "vuln", []string{
		"remote code execution", "code execution", "rce", "critical vulnerability",
		"critical flaw", "max severity", "maximum severity", "cvss 10", "cvss 10.0",
		"unauthenticated", "authentication bypass", "auth bypass", "backdoor",
	}},
	{ThreatHigh, "actor", []string{
		"apt", "state-sponsored", "nation-state", "botnet", "espionage",
	}},
	{ThreatMedium, "malware", []string{
		"malware", "phishing", "trojan", "infostealer", "stealer", "spyware",
		"loader", "rat", "exploit kit", "clickfix", "malvertising", "ddos",
		"credential-stealing", "planted",
		"worm", "scam", "fraud",
	}},
	{ThreatMedium, "vuln", []string{
		"vulnerability", "vulnerabilities", "flaw", "flaws", "cve", "patch",
		"patches", "patched", "bug", "bugs", "exploit", "exploits",
		"security update", "security updates", "advisory",
	}},
	{ThreatLow, "policy", []string{
		"arrest", "arrested", "arrests", "sentenced", "charged", "indicted", "pleads guilty",
		"extradited", "sanctions", "regulation", "fined", "takedown",
	}},
})

var criticalRe = regexp.MustCompile(`(?i)\bcritical\b`)

type compiledTier struct {
	level    ThreatLevel
	category string
	re       *regexp.Regexp
}

func compileTiers(tiers []keywordTier) []compiledTier {
	out := make([]compiledTier, len(tiers))
	for i, t := range tiers {
		alts := make([]string, len(t.words))
		for j, w := range t.words {
			alts[j] = regexp.QuoteMeta(w)
		}
		out[i] = compiledTier{t.level, t.category,
			regexp.MustCompile(`(?i)\b(?:` + strings.Join(alts, "|") + `)\b`)}
	}
	return out
}

func classifyCyber(title string) (ThreatLevel, string) {
	for _, tier := range cyberKeywords {
		if tier.re.MatchString(title) {
			// "Critical SonicWall Vulnerability": the vendor's severity rating
			// rarely sits next to the vulnerability word, so check it separately
			if tier.category == "vuln" && tier.level < ThreatHigh && criticalRe.MatchString(title) {
				return ThreatHigh, "vuln"
			}
			return tier.level, tier.category
		}
	}
	return ThreatInfo, "general"
}

var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// CVEs returns the CVE IDs mentioned in s, upper-cased and de-duplicated
func CVEs(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range cveRe.FindAllString(s, -1) {
		id = strings.ToUpper(id)
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func classifyThreat(title string) (ThreatLevel, string) {
	lower := strings.ToLower(title)
	for _, tier := range threatKeywords {
		for _, kw := range tier.words {
			if strings.Contains(lower, kw) {
				return tier.level, tier.category
			}
		}
	}
	return ThreatInfo, "general"
}

// FetchGlobalNews fetches and classifies global news items
func FetchGlobalNews(ctx context.Context) ([]NewsItem, error) {
	return fetchFeeds(ctx, GlobalFeeds, false, classifyThreat, 24*time.Hour)
}

// FetchLocalNews fetches geo-targeted news items
func FetchLocalNews(ctx context.Context, city, country string) ([]NewsItem, error) {
	return fetchFeeds(ctx, LocalFeedURLs(city, country), true, classifyThreat, 24*time.Hour)
}

// FetchCyberNews fetches cybersecurity news, classified for cyber severity.
// Security outlets publish less often than world news, so look back 72h.
func FetchCyberNews(ctx context.Context) ([]NewsItem, error) {
	items, err := fetchFeeds(ctx, CyberFeeds, false, classifyCyber, 72*time.Hour)
	if err != nil {
		return nil, err
	}
	// The same CVE is usually covered by several outlets; keep the first
	// (highest severity, newest) story for each
	seenCVE := map[string]bool{}
	var out []NewsItem
	for _, item := range items {
		ids := CVEs(item.Title)
		dup := false
		for _, id := range ids {
			if seenCVE[id] {
				dup = true
			}
			seenCVE[id] = true
		}
		if !dup {
			out = append(out, item)
		}
	}
	return out, nil
}

func fetchFeeds(ctx context.Context, sources []struct{ Name, URL string }, isLocal bool, classify classifier, maxAge time.Duration) ([]NewsItem, error) {
	fp := gofeed.NewParser()
	fp.UserAgent = "watchtower/1.0 (Go RSS reader)"

	var (
		mu    sync.Mutex
		items []NewsItem
		wg    sync.WaitGroup
	)

	for _, src := range sources {
		wg.Add(1)
		go func(name, url string) {
			defer wg.Done()

			fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			feed, err := fp.ParseURLWithContext(url, fetchCtx)
			if err != nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()

			cutoff := time.Now().Add(-maxAge)
			for _, entry := range feed.Items {
				if entry.Title == "" {
					continue
				}
				// Some feeds double-escape titles (e.g. "M&amp;A")
				entry.Title = html.UnescapeString(entry.Title)
				pub := time.Now()
				if entry.PublishedParsed != nil {
					pub = *entry.PublishedParsed
				} else if entry.UpdatedParsed != nil {
					pub = *entry.UpdatedParsed
				}
				if pub.Before(cutoff) {
					continue
				}
				level, cat := classify(entry.Title)
				link := ""
				if entry.Link != "" {
					link = entry.Link
				}
				items = append(items, NewsItem{
					Title:       entry.Title,
					Source:      name,
					Published:   pub,
					URL:         link,
					ThreatLevel: level,
					Category:    cat,
					IsLocal:     isLocal,
				})
			}
		}(src.Name, src.URL)
	}

	wg.Wait()

	// Sort: critical first, then by time
	sort.Slice(items, func(i, j int) bool {
		if items[i].ThreatLevel != items[j].ThreatLevel {
			return items[i].ThreatLevel > items[j].ThreatLevel
		}
		return items[i].Published.After(items[j].Published)
	})

	// Deduplicate similar titles
	seen := make(map[string]bool)
	var deduped []NewsItem
	for _, item := range items {
		key := strings.ToLower(item.Title[:min(40, len(item.Title))])
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, item)
		}
	}

	return deduped, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
