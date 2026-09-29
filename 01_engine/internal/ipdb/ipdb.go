// Package ipdb downloads, verifies and swaps the local IP bases the engine
// reads. A download replaces the current file only after it passed every
// check; the previous file is kept as .prev.
package ipdb

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Source is one downloadable base.
type Source struct {
	Name       string // key in the manifest
	File       string // file name in the bases folder
	URL        func(now time.Time, tok Token) string
	NeedsToken bool
	PrevMonth  bool          // on HTTP 404, try the previous month (monthly files)
	MinAge     time.Duration // do not fetch again sooner: the source's own update pace and API limits
	Gzip       bool
	MaxBytes   int64                        // download cap (CWE-409)
	MaxRaw     int64                        // decompressed cap (CWE-409)
	MinRows    int                          // sanity floor for a complete file
	Validate   func(io.Reader) (int, error) // parses the whole file, returns rows
}

// Entry records the file in use for one source.
type Entry struct {
	File   string    `json:"file"`
	URL    string    `json:"url"` // token redacted
	Date   time.Time `json:"date"`
	SHA256 string    `json:"sha256"`
	Rows   int       `json:"rows"`
}

// Manifest maps source names to the files in use.
type Manifest map[string]Entry

const manifestFile = "manifest.json"

// shrinkFloor rejects a file with fewer than half the rows of the one in use:
// valid but truncated upstream data must not replace good data.
const shrinkFloor = 0.5

// NewClient returns an HTTP client with a deadline that only follows HTTPS
// redirects (net/http follows up to 10 and allows https->http by default).
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a non-https URL refused")
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// UserAgent identifies the tool to the servers it downloads from.
var UserAgent = "tracertip (+https://github.com/RBN8080/tracertIP)"

// ErrFresh means the file in use is younger than the source's MinAge.
var ErrFresh = errors.New("fresh")

// Due reports whether src should be fetched now, and the entry in use.
func Due(dir string, src Source, now time.Time) (bool, Entry, error) {
	m, err := ReadManifest(dir)
	if err != nil {
		return false, Entry{}, err
	}
	e, ok := m[src.Name]
	return !ok || now.Sub(e.Date) >= src.MinAge, e, nil
}

// ReadManifest reads dir/manifest.json; a missing file is an empty manifest.
func ReadManifest(dir string) (Manifest, error) {
	m := Manifest{}
	b, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	return m, json.Unmarshal(b, &m)
}

// Update downloads src into dir, verifies it and swaps it in.
func Update(ctx context.Context, c *http.Client, dir string, src Source, tok Token, now time.Time) (Entry, error) {
	if src.NeedsToken && tok.Empty() {
		return Entry{}, ErrNoToken
	}
	man, err := ReadManifest(dir)
	if err != nil {
		return Entry{}, err
	}
	u := src.URL(now, tok)
	tmp, sum, err := download(ctx, c, dir, u, src.MaxBytes)
	if errors.Is(err, errNotFound) && src.PrevMonth {
		u = src.URL(now.AddDate(0, 0, -now.Day()), tok) // last day of the previous month
		tmp, sum, err = download(ctx, c, dir, u, src.MaxBytes)
	}
	if err != nil {
		return Entry{}, fmt.Errorf("%s: %s", src.Name, tok.redact(err.Error()))
	}
	defer os.Remove(tmp) // no-op after a successful rename
	rows, err := validate(tmp, src)
	if err != nil {
		return Entry{}, fmt.Errorf("%s: rejected: %w", src.Name, err)
	}
	if rows < src.MinRows {
		return Entry{}, fmt.Errorf("%s: rejected: %d rows, want at least %d", src.Name, rows, src.MinRows)
	}
	if prev, ok := man[src.Name]; ok && float64(rows) < shrinkFloor*float64(prev.Rows) {
		return Entry{}, fmt.Errorf("%s: rejected: %d rows, the file in use has %d", src.Name, rows, prev.Rows)
	}
	cur := filepath.Join(dir, src.File)
	if _, err := os.Stat(cur); err == nil {
		if err := os.Rename(cur, cur+".prev"); err != nil {
			return Entry{}, err
		}
	}
	if err := os.Rename(tmp, cur); err != nil {
		return Entry{}, err
	}
	e := Entry{File: src.File, URL: redactURL(u, tok), Date: now.UTC(), SHA256: sum, Rows: rows}
	man[src.Name] = e
	return e, writeManifest(dir, man)
}

func download(ctx context.Context, c *http.Client, dir, u string, max int64) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", "", errNotFound
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		after := resp.Header.Get("Retry-After") // RFC 9110 10.2.3: seconds or a date
		if after == "" {
			after = "unknown"
		}
		return "", "", fmt.Errorf("rate limited by the server (HTTP 429); retry after %s", after)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("larger than %d bytes", max)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", "", err
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

func validate(path string, src Source) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var r io.Reader = f
	if src.Gzip {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		r = gz
	}
	lr := &capped{r: r, left: src.MaxRaw}
	rows, err := src.Validate(lr)
	if err != nil {
		return rows, err
	}
	if _, err := io.Copy(io.Discard, lr); err != nil { // trailing data must still fit
		return rows, err
	}
	return rows, nil
}

// capped fails once more than left bytes are read (decompression bombs).
type capped struct {
	r    io.Reader
	left int64
}

var (
	errTooBig   = errors.New("decompressed data exceeds the cap")
	errNotFound = errors.New("HTTP 404")
)

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, _ := c.r.Read(one[:]); n > 0 {
			return 0, errTooBig
		}
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

func writeManifest(dir string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".manifest-*")
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, manifestFile))
}

func redactURL(u string, tok Token) string {
	p, err := url.Parse(u)
	if err != nil {
		return tok.redact(u)
	}
	q := p.Query()
	if q.Has("token") {
		q.Set("token", "redacted")
		p.RawQuery = q.Encode()
	}
	return tok.redact(p.String())
}
