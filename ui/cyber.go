package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// kevWindow is how far back the Known Exploited Vulnerabilities table looks
const kevWindow = 14 * 24 * time.Hour

// maxKEVRows caps the KEV table so the article list stays near the top
const maxKEVRows = 15

// renderCyberContent renders the Cyber tab and returns (content, headerLineCount).
// The header holds the Infocon level and recent KEV entries; the selectable
// article list follows it.
func (m Model) renderCyberContent() (string, int) {
	innerW := m.width - 6 // account for pane borders/padding
	if innerW < 40 {
		innerW = 40
	}

	var hdr strings.Builder
	hdr.WriteString(m.renderThreatIntelPanel(innerW))
	hdr.WriteString(StyleDivider.Render(strings.Repeat("─", innerW)) + "\n\n")

	var sb strings.Builder
	if errMsg, ok := m.errors["cyberNews"]; ok {
		hdr.WriteString(StyleError.Render("⚠ Error: "+errMsg) + "\n\n")
	}
	if m.cyberNews == nil {
		hdr.WriteString("  " + m.spinner.View() + " Fetching cyber news...\n")
		return hdr.String(), strings.Count(hdr.String(), "\n")
	}
	if len(m.cyberNews) == 0 {
		hdr.WriteString("  No cyber news in the last 72h. Press r to refresh.\n")
		return hdr.String(), strings.Count(hdr.String(), "\n")
	}
	hdr.WriteString(StyleSectionHeader.Render(
		fmt.Sprintf(" ARTICLES  (%d)  ·  j/k navigate  ·  enter to open in browser", len(m.cyberNews))) + "\n\n")

	sb.WriteString(hdr.String())
	hdrLines := strings.Count(hdr.String(), "\n")

	// Titles get their own line, indented by 2
	titleW := maxInt(innerW-4, 20)
	for i, item := range m.cyberNews {
		if i >= 200 {
			break
		}
		badge := threatStyle(item.ThreatLevel).Render(fmt.Sprintf(" %-8s", item.ThreatLevel.String()))
		source := StyleSource.Render(item.Source)
		category := StyleMuted.Render(item.Category)
		age := StyleAge.Render(formatAge(item.Published))
		urlIndicator := ""
		if item.URL != "" {
			urlIndicator = StyleMuted.Render("  ↗")
		}
		line1 := fmt.Sprintf("%s %s  %s  %s%s", badge, source, category, age, urlIndicator)
		title := truncate(item.Title, titleW)

		if i == m.sel[TabCyber].idx {
			sb.WriteString(StyleSelectedRow.Render(line1) + "\n")
			sb.WriteString(StyleSelectedRow.Render("  "+StyleSelectedTitle.Render(title)) + "\n\n")
		} else {
			sb.WriteString(line1 + "\n  " + StyleNewsTitle.Render(title) + "\n\n")
		}
	}
	return sb.String(), hdrLines
}

// renderThreatIntelPanel renders the Infocon level and the table of
// vulnerabilities CISA added to KEV within kevWindow
func (m Model) renderThreatIntelPanel(w int) string {
	var sb strings.Builder
	sb.WriteString(StyleBriefTitle.Render("🛡️  THREAT INTEL"))

	in := m.cyberIntel
	if in == nil {
		if errMsg, ok := m.errors["cyberIntel"]; ok {
			sb.WriteString("\n\n" + StyleError.Render("⚠ "+errMsg) + "\n\n")
		} else {
			sb.WriteString("\n\n  " + m.spinner.View() + " Fetching CISA KEV, EPSS and Infocon...\n\n")
		}
		return sb.String()
	}

	sb.WriteString("   " + infoconBadge(in.Infocon))
	meta := fmt.Sprintf("   KEV catalog %d entries", in.KEVTotal)
	if !in.CatalogDate.IsZero() {
		meta += " · released " + in.CatalogDate.Local().Format("Jan 02 15:04")
	}
	sb.WriteString(StyleBriefMeta.Render(meta) + "\n\n")

	sb.WriteString(StyleSubSectionHeader.Render(
		fmt.Sprintf(" KNOWN EXPLOITED · ADDED LAST %d DAYS  (%d)", int(kevWindow.Hours()/24), len(in.KEV))) + "\n")
	if len(in.KEV) == 0 {
		sb.WriteString(StyleMuted.Render("  None added in this window.") + "\n\n")
		return sb.String()
	}

	const (
		addedW = 6  // "Oct 08"
		cveW   = 16 // "CVE-2026-104286"
		epssW  = 6  // " 99.5%"
		dueW   = 6  // "Oct 27"
		flagW  = 6  // "RANSOM"
	)
	// Keep the table compact on wide terminals so EPSS and DUE stay near the product
	productW := minInt(maxInt(w-2-addedW-cveW-epssW-dueW-flagW-6, 12), 40)
	sb.WriteString(StyleTableHeader.Render(fmt.Sprintf("  %-*s %-*s %s %*s %-*s %s",
		addedW, "ADDED", cveW, "CVE", padRight("VENDOR / PRODUCT", productW),
		epssW, "EPSS", dueW, "DUE", "")) + "\n")

	today := time.Now().Truncate(24 * time.Hour)
	for i, e := range in.KEV {
		if i >= maxKEVRows {
			sb.WriteString(StyleMuted.Render(fmt.Sprintf("  … and %d more", len(in.KEV)-maxKEVRows)) + "\n")
			break
		}
		product := padRight(truncate(e.Vendor+" "+e.Product, productW), productW)

		epss := StyleMuted.Render(fmt.Sprintf("%*s", epssW, "—"))
		if e.EPSS >= 0 {
			epss = epssStyle(e.EPSS).Render(fmt.Sprintf("%*.1f%%", epssW-1, e.EPSS*100))
		}

		due := e.DueDate.Format("Jan 02")
		switch {
		case e.DueDate.IsZero():
			due = StyleMuted.Render(fmt.Sprintf("%-*s", dueW, "—"))
		case e.DueDate.Before(today.Add(3 * 24 * time.Hour)):
			due = StyleNegative.Render(due) // federal deadline imminent or passed
		default:
			due = StyleMuted.Render(due)
		}

		flag := ""
		if e.Ransomware {
			flag = StyleCritical.Render("RANSOM")
		}

		sb.WriteString(fmt.Sprintf("  %s %s %s %s %s %s\n",
			StyleAge.Render(e.DateAdded.Format("Jan 02")),
			StyleSymbol.Render(fmt.Sprintf("%-*s", cveW, e.CVE)),
			product, epss, due, flag))
	}
	sb.WriteString("\n")
	return sb.String()
}

// infoconBadge renders the SANS ISC Infocon level as a colored badge
func infoconBadge(level string) string {
	label := " INFOCON " + strings.ToUpper(level) + " "
	switch level {
	case "green":
		return StyleLowThreat.Render(label)
	case "yellow":
		return StyleMediumThreat.Render(label)
	case "orange":
		return StyleHighThreat.Render(label)
	case "red":
		return StyleCritical.Render(label)
	}
	return StyleInfoThreat.Render(" INFOCON N/A ")
}

// epssStyle colors an EPSS probability: likely exploitation stands out
func epssStyle(p float64) lipgloss.Style {
	switch {
	case p >= 0.5:
		return StyleNegative
	case p >= 0.1:
		return StyleWarning
	}
	return StyleMuted
}
