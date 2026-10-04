package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
)

// Only declared IP addresses, at most five: it measures paths, it does not
// scan (00_IDEA 1.bis).
func TestReadTargetsFrontier(t *testing.T) {
	for _, tc := range []struct {
		name, body, err string
		n               int
	}{
		{"addresses and comments", "# far ones\n192.0.2.1\n2001:db8::1  # v6\n\n", "", 2},
		{"a name", "example.org\n", "not an IP address", 0},
		{"a range", "192.0.2.0/24\n", "not an IP address", 0},
		{"twice", "192.0.2.1\n192.0.2.1\n", "listed twice", 0},
		{"loopback", "127.0.0.1\n", "cannot be a target", 0},
		{"six", "192.0.2.1\n192.0.2.2\n192.0.2.3\n192.0.2.4\n192.0.2.5\n192.0.2.6\n", "the frontier allows 5", 0},
		{"empty", "# nothing\n", "no targets", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.txt")
			os.WriteFile(path, []byte(tc.body), 0o644)
			got, err := readTargets(path)
			switch {
			case tc.err == "" && err != nil:
				t.Fatal(err)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Fatalf("err = %v, want %q", err, tc.err)
			case len(got) != tc.n:
				t.Errorf("got %v, want %d targets", got, tc.n)
			}
		})
	}
}

// serve probes every target, writes one file per target and logs the health
// of each one.
func TestServeRuns(t *testing.T) {
	defer func(o func(netip.Addr) (probe.Conn, error), d probe.Config) { open, probe.Defaults = o, d }(open, probe.Defaults)
	probe.Defaults.TTLMax, probe.Defaults.Timeout = 3, 30*time.Millisecond
	probe.Defaults.RoundInterval, probe.Defaults.Spacing = 40*time.Millisecond, time.Millisecond
	open = func(a netip.Addr) (probe.Conn, error) {
		return &fakePath{target: a, mode: "up", replies: make(chan []byte, 64)}, nil
	}
	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	os.WriteFile(list, []byte("192.0.2.1\n192.0.2.2\n"), 0o644)
	state := filepath.Join(dir, "live")
	cfg := filepath.Join(dir, "config.json")
	os.WriteFile(cfg, []byte("{}"), 0o644)
	var out, errs bytes.Buffer
	code := run([]string{"serve", "-targets", list, "-state", state, "-status", "100ms", "-for", "450ms",
		"-config", cfg}, &out, &errs)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if !strings.Contains(out.String(), "tracertip serve: 2 targets") {
		t.Errorf("start line: %q", out.String())
	}
	day := time.Now().UTC().Format(time.DateOnly)
	for _, a := range []string{"192.0.2.1", "192.0.2.2"} {
		b, err := os.ReadFile(filepath.Join(state, live.TargetDir(netip.MustParseAddr(a)), day+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(b), `{"v":1,"type":"start"`) || !strings.Contains(string(b), `"type":"probe"`) {
			t.Errorf("%s history starts %.80q", a, b)
		}
		if !strings.Contains(errs.String(), "target="+a) {
			t.Errorf("no health line for %s in %q", a, errs.String())
		}
	}
}
