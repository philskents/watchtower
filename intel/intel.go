package intel

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"watchtower/cyber"
	"watchtower/feeds"
	"watchtower/weather"
)

type Provider string

const (
	ProviderGroq     Provider = "groq"
	ProviderOpenAI   Provider = "openai"
	ProviderDeepSeek Provider = "deepseek"
	ProviderGemini   Provider = "gemini"
	ProviderClaude   Provider = "claude"
	ProviderLocal    Provider = "local"
)

var providerDefaults = map[Provider]struct {
	endpoint     string
	defaultModel string
	authHeader   string
	authPrefix   string
}{
	ProviderGroq: {
		endpoint:     "https://api.groq.com/openai/v1/chat/completions",
		defaultModel: "llama-3.1-8b-instant",
		authHeader:   "Authorization",
		authPrefix:   "Bearer ",
	},
	ProviderOpenAI: {
		endpoint:     "https://api.openai.com/v1/chat/completions",
		defaultModel: "gpt-4o-mini",
		authHeader:   "Authorization",
		authPrefix:   "Bearer ",
	},
	ProviderDeepSeek: {
		endpoint:     "https://api.deepseek.com/v1/chat/completions",
		defaultModel: "deepseek-chat",
		authHeader:   "Authorization",
		authPrefix:   "Bearer ",
	},
	ProviderGemini: {
		endpoint:     "https://generativelanguage.googleapis.com/v1beta/models",
		defaultModel: "gemini-1.5-flash",
		authHeader:   "X-Goog-Api-Key",
		authPrefix:   "",
	},
	ProviderClaude: {
		endpoint:     "https://api.anthropic.com/v1/messages",
		defaultModel: "claude-3-haiku-20240307",
		authHeader:   "x-api-key",
		authPrefix:   "",
	},
	ProviderLocal: {
		endpoint:     "http://localhost:11434/v1/chat/completions",
		defaultModel: "llama3",
		authHeader:   "Authorization",
		authPrefix:   "Bearer ",
	},
}

type LLMConfig struct {
	Provider Provider
	APIKey   string
	Model    string
}

func (c LLMConfig) Endpoint() string {
	p := providerDefaults[c.Provider]
	if c.Model == "" {
		return p.endpoint
	}
	if c.Provider == ProviderGemini {
		return p.endpoint + "/" + c.Model + ":generateContent"
	}
	return p.endpoint
}

func (c LLMConfig) ModelName() string {
	if c.Model != "" {
		return c.Model
	}
	return providerDefaults[c.Provider].defaultModel
}

func (c LLMConfig) AuthHeader() string {
	return providerDefaults[c.Provider].authHeader
}

func (c LLMConfig) AuthValue() string {
	p := providerDefaults[c.Provider]
	return p.authPrefix + c.APIKey
}

// CountryRisk holds a risk score for one country
type CountryRisk struct {
	Country string
	Score   int    // 0–100
	Reason  string // one short phrase
}

// Brief holds an AI-generated intelligence summary
type Brief struct {
	Summary      string
	KeyThreats   []string
	CountryRisks []CountryRisk
	GeneratedAt  time.Time
	Model        string
}

// LocalBrief holds an AI-generated summary of local news and weather
type LocalBrief struct {
	Summary     string
	GeneratedAt time.Time
	Model       string
}

// CyberBrief holds an AI-generated summary of the cyber threat picture
type CyberBrief struct {
	Summary     string
	Priorities  []string // things to act on, most urgent first
	GeneratedAt time.Time
	Model       string
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// GenerateBrief calls the configured LLM to synthesize a brief, summary, and country risk scores
func GenerateBrief(ctx context.Context, cfg LLMConfig, items []feeds.NewsItem) (*Brief, error) {
	if cfg.APIKey == "" {
		return &Brief{
			Summary:     "No LLM_API_KEY set. Add it to ~/.config/watchtower/config.yaml to enable AI briefings.",
			GeneratedAt: time.Now(),
			Model:       "none",
		}, nil
	}

	if len(items) == 0 {
		return &Brief{
			Summary:     "No news items available to summarize.",
			GeneratedAt: time.Now(),
		}, nil
	}

	// Build headline list (top 40 by severity)
	limit := 40
	if len(items) < limit {
		limit = len(items)
	}
	var sb strings.Builder
	for i, item := range items[:limit] {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s (%s)\n",
			i+1, item.ThreatLevel.String(), item.Title, item.Source))
	}

	prompt := fmt.Sprintf(`You are a geopolitical intelligence analyst. Analyze these recent headlines and respond in EXACTLY this format with no extra text:

SUMMARY:
<3-4 sentences covering the most critical global developments right now>

THREATS:
• <threat 1, one line>
• <threat 2, one line>
• <threat 3, one line>
• <threat 4, one line>
• <threat 5, one line>

COUNTRY_RISKS:
<CountryName>|<score 0-100>|<one short reason phrase>
<CountryName>|<score 0-100>|<one short reason phrase>
<CountryName>|<score 0-100>|<one short reason phrase>
<CountryName>|<score 0-100>|<one short reason phrase>
<CountryName>|<score 0-100>|<one short reason phrase>
<CountryName>|<score 0-100>|<one short reason phrase>
<CountryName>|<score 0-100>|<one short reason phrase>
<CountryName>|<score 0-100>|<one short reason phrase>

Rules:
- SUMMARY: factual, analyst-toned, no fluff, max 3 sentences
- THREATS: exactly 5 bullets, one line each, most severe first
- COUNTRY_RISKS: exactly 8 countries most prominent in the news, score reflects current instability/risk (100=active war, 0=stable), pipe-separated, short reason (3-5 words max)
- No markdown, no extra formatting, no preamble

HEADLINES:
%s`, sb.String())

	text, model, err := complete(ctx, cfg, "You are a geopolitical intelligence analyst.", prompt, 700)
	if err != nil {
		return nil, err
	}
	summary, threats, risks := parseBriefResponse(text)
	return &Brief{
		Summary:      summary,
		KeyThreats:   threats,
		CountryRisks: risks,
		GeneratedAt:  time.Now(),
		Model:        model,
	}, nil
}

// GenerateLocalBrief calls the configured LLM to synthesize a local news and weather summary
func GenerateLocalBrief(ctx context.Context, cfg LLMConfig, city string, items []feeds.NewsItem, cond *weather.Conditions, forecast []weather.DayForecast) (*LocalBrief, error) {
	if cfg.APIKey == "" {
		return &LocalBrief{
			Summary:     "No LLM_API_KEY set. Add it to ~/.config/watchtower/config.yaml to enable AI briefings.",
			GeneratedAt: time.Now(),
			Model:       "none",
		}, nil
	}

	var sb strings.Builder

	// Build local news headline list (top 20)
	sb.WriteString("LOCAL NEWS HEADLINES:\n")
	limit := 20
	if len(items) > limit {
		items = items[:limit]
	}
	for i, item := range items {
		sb.WriteString(fmt.Sprintf("%d. %s (%s)\n", i+1, item.Title, item.Source))
	}

	// Add current weather
	sb.WriteString("\nCURRENT WEATHER:\n")
	if cond != nil {
		sb.WriteString(fmt.Sprintf("Location: %s\n", cond.City))
		sb.WriteString(fmt.Sprintf("Temperature: %.1f°C (feels like %.1f°C)\n", cond.TempC, cond.FeelsLikeC))
		sb.WriteString(fmt.Sprintf("Conditions: %s %s\n", cond.Icon, cond.Description))
		sb.WriteString(fmt.Sprintf("Humidity: %d%%, Wind: %.0f km/h, UV: %.0f\n", cond.Humidity, cond.WindSpeedKmh, cond.UVIndex))
	}

	// Add forecast
	sb.WriteString("\nFORECAST (next 5 days):\n")
	for i, f := range forecast {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("- %s: %s %s, High: %.0f°C, Low: %.0f°C, Rain: %.1fmm\n",
			f.Date.Format("Mon Jan 02"), f.Icon, f.Desc, f.MaxTempC, f.MinTempC, f.RainMM))
	}

	prompt := fmt.Sprintf(`You are a local news and weather analyst. Summarize this information for %s in 2-3 sentences.
Focus on:
1. Any notable local news stories
2. Current weather conditions and any weather concerns for the coming days
3. Short summary of the news stories

Respond in this exact format with no extra text:

SUMMARY:
<2-3 sentence summary>

Rules:
- Keep it concise and practical
- No markdown formatting
- Lead with the most important information
- Never send back the 'DATA' as is, always explain

DATA:
%s`, city, sb.String())

	text, model, err := complete(ctx, cfg, "You are a local news and weather analyst.", prompt, 300)
	if err != nil {
		return nil, err
	}
	return &LocalBrief{
		Summary:     parseLocalBriefResponse(text),
		GeneratedAt: time.Now(),
		Model:       model,
	}, nil
}

// GenerateCyberBrief calls the configured LLM to summarize the cyber threat
// picture from KEV, EPSS, Infocon and headlines. watchlist names products the
// reader runs so the brief can call them out.
func GenerateCyberBrief(ctx context.Context, cfg LLMConfig, in *cyber.Intel, items []feeds.NewsItem, watchlist []string) (*CyberBrief, error) {
	if cfg.APIKey == "" {
		return &CyberBrief{
			Summary:     "No LLM_API_KEY set. Add it to ~/.config/watchtower/config.yaml to enable AI briefings.",
			GeneratedAt: time.Now(),
			Model:       "none",
		}, nil
	}

	var sb strings.Builder
	// Without today's date the model can't tell a past patch deadline from an upcoming one
	sb.WriteString("TODAY: " + time.Now().Format("Mon Jan 02 2006") + "\n\n")
	if in != nil {
		infocon := in.Infocon
		if infocon == "" {
			infocon = "unknown"
		}
		sb.WriteString("SANS INFOCON: " + infocon + "\n\n")

		sb.WriteString("CISA KNOWN EXPLOITED VULNERABILITIES, RECENTLY ADDED:\n")
		if len(in.KEV) == 0 {
			sb.WriteString("(none)\n")
		}
		for _, e := range in.KEV {
			epss := "unknown"
			if e.EPSS >= 0 {
				epss = fmt.Sprintf("%.1f%%", e.EPSS*100)
			}
			ransom := ""
			if e.Ransomware {
				ransom = ", used by ransomware"
			}
			sb.WriteString(fmt.Sprintf("- %s %s %s: %s (added %s, EPSS %s%s, federal patch deadline %s)\n",
				e.CVE, e.Vendor, e.Product, e.Name, e.DateAdded.Format("Jan 02"),
				epss, ransom, e.DueDate.Format("Jan 02")))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("HEADLINES:\n")
	if len(items) > 40 {
		items = items[:40]
	}
	for i, item := range items {
		tag := item.ThreatLevel.String()
		if item.Category != "" {
			tag += "/" + item.Category
		}
		sb.WriteString(fmt.Sprintf("%d. [%s] %s (%s)\n", i+1, tag, item.Title, item.Source))
	}

	reader := ""
	if len(watchlist) > 0 {
		reader = "\nThe reader runs: " + strings.Join(watchlist, ", ") +
			". Call out anything affecting these first, by name.\n"
	}

	prompt := fmt.Sprintf(`You are a cyber threat intelligence analyst. Using the data below, respond in EXACTLY this format with no extra text:

SUMMARY:
<3 sentences on the most important cyber threat developments right now>

PRIORITIES:
• <action 1, one line>
• <action 2, one line>
• <action 3, one line>
• <action 4, one line>
• <action 5, one line>

Rules:
- SUMMARY: factual, analyst-toned, no fluff, max 3 sentences
- PRIORITIES: exactly 5 concrete things a defender should do or check, most urgent first, one line each, cite the CVE ID when one applies
- Weigh active exploitation, ransomware use and high EPSS above everything else
- A patch deadline before TODAY is overdue; say so
- No markdown, no extra formatting, no preamble
%s
DATA:
%s`, reader, sb.String())

	text, model, err := complete(ctx, cfg, "You are a cyber threat intelligence analyst.", prompt, 600)
	if err != nil {
		return nil, err
	}
	summary, priorities := parseCyberBriefResponse(text)
	return &CyberBrief{
		Summary:     summary,
		Priorities:  priorities,
		GeneratedAt: time.Now(),
		Model:       model,
	}, nil
}

func parseCyberBriefResponse(content string) (string, []string) {
	sections := parseSections(content, "SUMMARY", "PRIORITIES")
	summary := strings.Join(strings.Fields(sections["SUMMARY"]), " ")
	if summary == "" && len(sections) == 0 {
		// The model ignored the format; show what it said rather than nothing
		summary = strings.TrimSpace(content)
	}
	return summary, parseBullets(sections["PRIORITIES"])
}

func parseLocalBriefResponse(content string) string {
	lines := strings.Split(content, "\n")
	inSummary := false
	var summaryLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SUMMARY:") {
			inSummary = true
			continue
		}
		if inSummary && trimmed != "" {
			summaryLines = append(summaryLines, trimmed)
		}
	}

	if len(summaryLines) > 0 {
		return strings.Join(summaryLines, " ")
	}
	return strings.TrimSpace(content)
}

func parseBriefResponse(content string) (string, []string, []CountryRisk) {
	sections := parseSections(content, "SUMMARY", "THREATS", "COUNTRY_RISKS")
	summary := sections["SUMMARY"]
	threats := parseBullets(sections["THREATS"])

	// Parse COUNTRY_RISKS  format: Country|score|reason
	var risks []CountryRisk
	for _, line := range strings.Split(sections["COUNTRY_RISKS"], "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		country := strings.TrimSpace(parts[0])
		score, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || country == "" {
			continue
		}
		reason := ""
		if len(parts) == 3 {
			reason = strings.TrimSpace(parts[2])
		}
		risks = append(risks, CountryRisk{
			Country: country,
			Score:   clamp(score, 0, 100),
			Reason:  reason,
		})
	}

	return summary, threats, risks
}

// parseSections splits an LLM reply into sections that start with a line
// "HEADER:", returning each section's trimmed body keyed by header
func parseSections(content string, headers ...string) map[string]string {
	isHeader := make(map[string]bool, len(headers))
	for _, h := range headers {
		isHeader[h+":"] = true
	}

	sections := map[string]string{}
	current := ""
	var buf strings.Builder
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if isHeader[trimmed] {
			if current != "" {
				sections[current] = strings.TrimSpace(buf.String())
			}
			current = strings.TrimSuffix(trimmed, ":")
			buf.Reset()
			continue
		}
		if current != "" {
			buf.WriteString(line + "\n")
		}
	}
	if current != "" {
		sections[current] = strings.TrimSpace(buf.String())
	}
	return sections
}

// parseBullets returns the non-empty lines of s with any •, - or * prefix removed
func parseBullets(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "•")
		line = strings.TrimPrefix(line, "-")
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
