package feeds

import (
	"reflect"
	"testing"
)

func TestClassifyCyber(t *testing.T) {
	cases := []struct {
		title string
		level ThreatLevel
		cat   string
	}{
		{"Fortinet warns of FortiOS zero-day exploited in attacks", ThreatCritical, "exploited"},
		{"CISA orders agencies to patch actively exploited Ivanti flaw", ThreatCritical, "exploited"},
		{"Akira ransomware hits US hospital chain", ThreatHigh, "ransomware"},
		{"Critical RCE in Apache Struts", ThreatHigh, "vuln"},
		{"Chinese APT targets telecoms", ThreatHigh, "actor"},
		{"New infostealer spreads via fake CAPTCHA pages", ThreatMedium, "malware"},
		{"Microsoft fixes 60 flaws in Patch Tuesday", ThreatMedium, "vuln"},
		{"Scattered Spider member sentenced to 10 years", ThreatLow, "policy"},
		{"Critical SonicWall Vulnerability Exploited Days After Disclosure", ThreatCritical, "exploited"},
		{"Retail giant takes systems offline after cyberattack", ThreatHigh, "attack"},
		{"GitLab warns of max severity code execution vulnerability", ThreatHigh, "vuln"},
		{"Critical SonicWall SMA 1000 flaw patched", ThreatHigh, "vuln"},
		{"Mastermind of laundering network pleads guilty", ThreatLow, "policy"},
		{"Campaign That Stole Over 628,000 Records", ThreatHigh, "breach"},
		{"Japan confirms arrest of Russian Qilin operative", ThreatLow, "policy"},
		// short keywords must not match inside other words
		{"Police force adapts to capture source code thieves", ThreatInfo, "general"},
		{"Interview: the state of security careers", ThreatInfo, "general"},
	}
	for _, c := range cases {
		level, cat := classifyCyber(c.title)
		if level != c.level || cat != c.cat {
			t.Errorf("classifyCyber(%q) = %v/%s, want %v/%s", c.title, level, cat, c.level, c.cat)
		}
	}
}

func TestCVEs(t *testing.T) {
	got := CVEs("Patch cve-2026-1234 and CVE-2026-12345 now (CVE-2026-1234 again)")
	want := []string{"CVE-2026-1234", "CVE-2026-12345"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CVEs = %v, want %v", got, want)
	}
}
