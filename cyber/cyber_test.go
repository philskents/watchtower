package cyber

import (
	"encoding/json"
	"testing"
	"time"
)

const sampleCatalog = `{"dateReleased":"2026-10-08T20:09:18.9833Z","count":3,"vulnerabilities":[
 {"cveID":"CVE-2026-0001","vendorProject":"Old","product":"A","dateAdded":"2026-09-01","dueDate":"2026-09-22","knownRansomwareCampaignUse":"Unknown"},
 {"cveID":"CVE-2026-0002","vendorProject":"Fortinet","product":"FortiOS","dateAdded":"2026-10-06","dueDate":"2026-10-27","knownRansomwareCampaignUse":"Known"},
 {"cveID":"CVE-2026-0003","vendorProject":"Ivanti","product":"EPMM","dateAdded":"2026-10-08","dueDate":"2026-10-11","knownRansomwareCampaignUse":"Unknown"}]}`

func TestRecent(t *testing.T) {
	var c kevCatalog
	if err := json.Unmarshal([]byte(sampleCatalog), &c); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Date(2026, 9, 28, 15, 0, 0, 0, time.Local)
	got := c.recent(cutoff)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].CVE != "CVE-2026-0003" || got[1].CVE != "CVE-2026-0002" {
		t.Errorf("order = %s, %s; want newest first", got[0].CVE, got[1].CVE)
	}
	if !got[1].Ransomware || got[0].Ransomware {
		t.Errorf("ransomware flags = %v, %v; want false, true", got[0].Ransomware, got[1].Ransomware)
	}
	if got[0].EPSS != -1 {
		t.Errorf("EPSS should default to -1 (unknown), got %v", got[0].EPSS)
	}
}
