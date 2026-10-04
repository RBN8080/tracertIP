package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/output"
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
	if !strings.Contains(out.String(), "tracertip serve: 2 of at most 5 targets") {
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

// syncBuffer lets a test read what serve prints while it runs.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The terminal says where the live API is; the API answers, the stream
// carries rounds, and an address outside the LAN is refused.
func TestServeLiveAPI(t *testing.T) {
	defer func(o func(netip.Addr) (probe.Conn, error), d probe.Config) { open, probe.Defaults = o, d }(open, probe.Defaults)
	probe.Defaults.TTLMax, probe.Defaults.Timeout = 3, 30*time.Millisecond
	probe.Defaults.RoundInterval, probe.Defaults.Spacing = 40*time.Millisecond, time.Millisecond
	open = func(a netip.Addr) (probe.Conn, error) {
		return &fakePath{target: a, mode: "up", replies: make(chan []byte, 64)}, nil
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	os.WriteFile(cfg, []byte("{}"), 0o644)
	args := []string{"serve", "-state", filepath.Join(dir, "live"), "-config", cfg, "-for", "3s"}

	var errs bytes.Buffer
	if code := run(append(args, "-listen", "0.0.0.0:0"), io.Discard, &errs); code != exitUsage || !strings.Contains(errs.String(), "LAN only") {
		t.Errorf("listen on all interfaces: exit %d, %q", code, errs.String())
	}

	var out syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(append(args, "-listen", "127.0.0.1:0"), &out, io.Discard) }()
	var base string
	for deadline := time.Now().Add(2 * time.Second); base == "" && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, rest, ok := strings.Cut(out.String(), "live view on "); ok {
			base, _, _ = strings.Cut(rest, " ")
			base += "v1/"
		}
	}
	if base == "" {
		t.Fatalf("no API address printed: %q", out.String())
	}
	if !strings.Contains(out.String(), "0 of at most 5 targets") {
		t.Errorf("start line: %q", out.String())
	}
	add, err := http.Post(base+"targets", "application/json", strings.NewReader(`{"target":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	add.Body.Close()
	if add.StatusCode != http.StatusCreated {
		t.Fatalf("adding a target: %d", add.StatusCode)
	}
	resp, err := http.Get(base + "stream")
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	got := false
	for sc.Scan() {
		if strings.Contains(sc.Text(), `"type":"round"`) && strings.Contains(sc.Text(), "192.0.2.1") {
			got = true
			break
		}
	}
	resp.Body.Close()
	if !got {
		t.Error("no round of 192.0.2.1 on the stream")
	}
	r, err := http.Get(base + "targets")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), `"target":"192.0.2.1"`) {
		t.Errorf("targets: %s", b)
	}
	if code := <-done; code != exitOK {
		t.Errorf("serve exit %d", code)
	}
}

// The API judges recent rounds like trace: one record per TTL up to the
// target, and in public form the home router keeps only its TTL and RTT.
func TestHopJudgeFromRounds(t *testing.T) {
	tgt := netip.MustParseAddr("192.0.2.9")
	home := netip.MustParsePrefix("192.168.0.0/16").Addr().Next()
	var rounds []live.Round
	for n := range 3 {
		rounds = append(rounds, live.Round{Target: tgt, N: n, Samples: []live.Sample{
			{TTL: 1, From: home, RTTms: 0.5, Status: "reply"}, {TTL: 2, RTTms: -1, Status: "no_reply"},
			{TTL: 3, From: tgt, RTTms: 50 + float64(n), Status: "reply"}}})
	}
	j := &hopJudge{opts: enrich.Options{Dir: t.TempDir(), NoDNS: true, NoIPmap: true, NoCity: true}, known: map[netip.Addr]enrich.Info{}}
	for _, public := range []bool{false, true} {
		got, err := j.hops(context.Background(), tgt, rounds, public)
		if err != nil {
			t.Fatal(err)
		}
		recs := got.([]output.HopRecord)
		// Documentation addresses are special-purpose, so public form hides the target too.
		if len(recs) != 3 || !public && recs[2].Addr != tgt.String() || recs[2].MinRTT != 50 || recs[1].MinRTT >= 0 || recs[1].Sent != 3 {
			t.Fatalf("public=%t records %+v", public, recs)
		}
		if public && (!recs[0].Home || recs[0].Addr != "") || !public && recs[0].Addr != home.String() {
			t.Errorf("public=%t home hop %+v", public, recs[0])
		}
	}
}
