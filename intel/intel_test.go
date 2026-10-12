package intel

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseBriefResponse(t *testing.T) {
	reply := `SUMMARY:
Fighting continues in the east.
Markets are steady.

THREATS:
• Escalation along the border
- Shipping disruption in the strait
* Cyberattacks on utilities

COUNTRY_RISKS:
Ukraine|92|active war
Taiwan|60|military drills
Nowhere|abc|bad score
Sudan|140|civil war
`
	summary, threats, risks := parseBriefResponse(reply)

	if want := "Fighting continues in the east.\nMarkets are steady."; summary != want {
		t.Errorf("summary = %q, want %q", summary, want)
	}
	wantThreats := []string{
		"Escalation along the border",
		"Shipping disruption in the strait",
		"Cyberattacks on utilities",
	}
	if !reflect.DeepEqual(threats, wantThreats) {
		t.Errorf("threats = %q, want %q", threats, wantThreats)
	}
	wantRisks := []CountryRisk{
		{"Ukraine", 92, "active war"},
		{"Taiwan", 60, "military drills"},
		{"Sudan", 100, "civil war"},
	}
	if !reflect.DeepEqual(risks, wantRisks) {
		t.Errorf("risks = %+v, want %+v", risks, wantRisks)
	}
}

func TestParseSectionsIgnoresPreamble(t *testing.T) {
	got := parseSections("Sure, here it is:\nSUMMARY:\nA.\nOTHER:\nB.", "SUMMARY", "OTHER")
	want := map[string]string{"SUMMARY": "A.", "OTHER": "B."}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSections = %q, want %q", got, want)
	}
}

func TestErrorMessage(t *testing.T) {
	cases := map[string]string{
		`{"error":{"message":"Invalid  key\n given","type":"auth"}}`: "Invalid key given",
		`<html>Bad Gateway</html>`:                                   "<html>Bad Gateway</html>",
		``:                                                           "",
	}
	for body, want := range cases {
		if got := errorMessage(strings.NewReader(body)); got != want {
			t.Errorf("errorMessage(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestParseCyberBriefResponse(t *testing.T) {
	reply := `SUMMARY:
Attackers are exploiting a Fortinet flaw.
Ransomware crews are active.

PRIORITIES:
• Patch CVE-2026-1234 on FortiGate
- Check Exchange logs
* Rotate VPN credentials
`
	summary, priorities := parseCyberBriefResponse(reply)
	if want := "Attackers are exploiting a Fortinet flaw. Ransomware crews are active."; summary != want {
		t.Errorf("summary = %q, want %q", summary, want)
	}
	want := []string{"Patch CVE-2026-1234 on FortiGate", "Check Exchange logs", "Rotate VPN credentials"}
	if !reflect.DeepEqual(priorities, want) {
		t.Errorf("priorities = %q, want %q", priorities, want)
	}

	if summary, _ := parseCyberBriefResponse("Just prose."); summary != "Just prose." {
		t.Errorf("unformatted reply summary = %q", summary)
	}
}
