package intel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// cachedBrief is the on-disk representation — identical to Brief but
// with JSON tags so the time.Time round-trips correctly.
type cachedBrief struct {
	Summary      string        `json:"summary"`
	KeyThreats   []string      `json:"key_threats"`
	CountryRisks []CountryRisk `json:"country_risks"`
	GeneratedAt  time.Time     `json:"generated_at"`
	Model        string        `json:"model"`
}

const (
	briefCacheFile      = "brief.json"
	localBriefCacheFile = "local_brief.json"
	cyberBriefCacheFile = "cyber_brief.json"
)

func cachePath(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".cache", "watchtower")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// readCache decodes the named cache file into v. It reports false (and no
// error) when the file is missing or corrupted, so callers treat both as a miss.
func readCache(name string, v interface{}) (bool, error) {
	path, err := cachePath(name)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, nil
	}
	return true, nil
}

// writeCache writes v to the named cache file, silently ignoring errors
// (a cache write failure should never crash the app).
func writeCache(name string, v interface{}) {
	path, err := cachePath(name)
	if err != nil {
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	// Write atomically via a temp file then rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// clearCache deletes the named cache file
func clearCache(name string) error {
	path, err := cachePath(name)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// expired reports whether a cache entry generated at t is older than maxAge
func expired(t time.Time, maxAge time.Duration) bool {
	return maxAge > 0 && time.Since(t) > maxAge
}

// LoadCachedBrief reads the cached brief from disk.
// Returns nil (no error) if the file doesn't exist or is older than maxAge.
func LoadCachedBrief(maxAge time.Duration) (*Brief, error) {
	var cb cachedBrief
	ok, err := readCache(briefCacheFile, &cb)
	if !ok || expired(cb.GeneratedAt, maxAge) {
		return nil, err
	}
	return &Brief{
		Summary:      cb.Summary,
		KeyThreats:   cb.KeyThreats,
		CountryRisks: cb.CountryRisks,
		GeneratedAt:  cb.GeneratedAt,
		Model:        cb.Model,
	}, nil
}

// SaveCachedBrief writes the brief to disk
func SaveCachedBrief(b *Brief) {
	if b == nil {
		return
	}
	writeCache(briefCacheFile, cachedBrief{
		Summary:      b.Summary,
		KeyThreats:   b.KeyThreats,
		CountryRisks: b.CountryRisks,
		GeneratedAt:  b.GeneratedAt,
		Model:        b.Model,
	})
}

// ClearBriefCache deletes the cached brief file.
func ClearBriefCache() error {
	return clearCache(briefCacheFile)
}

// ─── Local Brief Caching ─────────────────────────────────────────────────────

// cachedLocalBrief is the on-disk representation for local brief
type cachedLocalBrief struct {
	Summary     string    `json:"summary"`
	GeneratedAt time.Time `json:"generated_at"`
	Model       string    `json:"model"`
}

// LoadCachedLocalBrief reads the cached local brief from disk.
func LoadCachedLocalBrief(maxAge time.Duration) (*LocalBrief, error) {
	var cb cachedLocalBrief
	ok, err := readCache(localBriefCacheFile, &cb)
	if !ok || expired(cb.GeneratedAt, maxAge) {
		return nil, err
	}
	return &LocalBrief{
		Summary:     cb.Summary,
		GeneratedAt: cb.GeneratedAt,
		Model:       cb.Model,
	}, nil
}

// SaveCachedLocalBrief writes the local brief to disk
func SaveCachedLocalBrief(b *LocalBrief) {
	if b == nil {
		return
	}
	writeCache(localBriefCacheFile, cachedLocalBrief{
		Summary:     b.Summary,
		GeneratedAt: b.GeneratedAt,
		Model:       b.Model,
	})
}

// ClearLocalBriefCache deletes the cached local brief file.
func ClearLocalBriefCache() error {
	return clearCache(localBriefCacheFile)
}

// ─── Cyber Brief Caching ─────────────────────────────────────────────────────

// cachedCyberBrief is the on-disk representation for the cyber brief
type cachedCyberBrief struct {
	Summary     string    `json:"summary"`
	Priorities  []string  `json:"priorities"`
	GeneratedAt time.Time `json:"generated_at"`
	Model       string    `json:"model"`
}

// LoadCachedCyberBrief reads the cached cyber brief from disk.
func LoadCachedCyberBrief(maxAge time.Duration) (*CyberBrief, error) {
	var cb cachedCyberBrief
	ok, err := readCache(cyberBriefCacheFile, &cb)
	if !ok || expired(cb.GeneratedAt, maxAge) {
		return nil, err
	}
	return &CyberBrief{
		Summary:     cb.Summary,
		Priorities:  cb.Priorities,
		GeneratedAt: cb.GeneratedAt,
		Model:       cb.Model,
	}, nil
}

// SaveCachedCyberBrief writes the cyber brief to disk
func SaveCachedCyberBrief(b *CyberBrief) {
	if b == nil {
		return
	}
	writeCache(cyberBriefCacheFile, cachedCyberBrief{
		Summary:     b.Summary,
		Priorities:  b.Priorities,
		GeneratedAt: b.GeneratedAt,
		Model:       b.Model,
	})
}
