package cyber

import "testing"

func TestWatchlistMatch(t *testing.T) {
	w := NewWatchlist([]string{"SAP", "Palo Alto", " ", ".NET", "C++"})
	cases := map[string]string{
		"Critical sap NetWeaver flaw exploited": "SAP",
		"Sapphire ransomware hits hospitals":    "",
		"Palo Alto  Networks PAN-OS zero-day":   "Palo Alto",
		"Microsoft .NET denial of service":      ".NET",
		"Bug in C++ standard library":           "C++",
		"Microsoft Windows SMB vulnerability":   "",
		"palo altogether a different story":     "",
	}
	for text, want := range cases {
		if got := w.Match(text); got != want {
			t.Errorf("Match(%q) = %q, want %q", text, got, want)
		}
	}
	if w.Len() != 4 {
		t.Errorf("Len() = %d, want 4 (blank term dropped)", w.Len())
	}
}

func TestEmptyWatchlist(t *testing.T) {
	var nilList *Watchlist
	for _, w := range []*Watchlist{nilList, NewWatchlist(nil)} {
		if got := w.Match("SAP Palo Alto Fortinet"); got != "" {
			t.Errorf("empty watchlist matched %q", got)
		}
		if w.Len() != 0 {
			t.Errorf("empty watchlist Len() = %d", w.Len())
		}
	}
}
