package cyber

import (
	"regexp"
	"strings"
	"unicode"
)

// Watchlist matches text against vendors and products the user runs
type Watchlist struct {
	terms []string
	res   []*regexp.Regexp
}

// NewWatchlist compiles terms into case-insensitive whole-word matchers.
// Blank terms are ignored; a nil or empty Watchlist matches nothing.
func NewWatchlist(terms []string) *Watchlist {
	w := &Watchlist{}
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		w.terms = append(w.terms, t)
		w.res = append(w.res, regexp.MustCompile(`(?i)`+termPattern(t)))
	}
	return w
}

// termPattern quotes t, lets its spaces match any whitespace, and anchors it
// at word boundaries. An end that isn't a word character (".NET", "C++")
// gets no anchor there, since \b would never match beside it.
func termPattern(t string) string {
	words := strings.Fields(t)
	for i, w := range words {
		words[i] = regexp.QuoteMeta(w)
	}
	p := strings.Join(words, `\s+`)
	r := []rune(t)
	if isWordRune(r[0]) {
		p = `\b` + p
	}
	if isWordRune(r[len(r)-1]) {
		p += `\b`
	}
	return p
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// Match returns the first watchlist term found in text, or "" if none is
func (w *Watchlist) Match(text string) string {
	if w == nil {
		return ""
	}
	for i, re := range w.res {
		if re.MatchString(text) {
			return w.terms[i]
		}
	}
	return ""
}

// Len reports how many terms the watchlist holds
func (w *Watchlist) Len() int {
	if w == nil {
		return 0
	}
	return len(w.terms)
}
