package live

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
	"github.com/rbn8080/tracertip/01_engine/internal/route"
)

func TestRingKeepsNewest(t *testing.T) {
	g := NewRing(3)
	if got := g.Last(5); len(got) != 0 {
		t.Fatalf("empty ring gave %d rounds", len(got))
	}
	for n := range 5 {
		g.Add(Round{N: n})
	}
	var got []int
	for _, r := range g.Last(10) {
		got = append(got, r.N)
	}
	if want := []int{2, 3, 4}; !slices.Equal(got, want) {
		t.Errorf("Last(10) = %v, want %v", got, want)
	}
	if r := g.Last(1); len(r) != 1 || r[0].N != 4 {
		t.Errorf("Last(1) = %+v", r)
	}
}

// A late reply is not an RTT, and a probe without a reply is a gap, never 0.
func TestSummarize(t *testing.T) {
	at := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	r := Summarize(netip.MustParseAddr("192.0.2.9"), 7, []model.Probe{
		{TTL: 1, SendWall: at, Status: model.StatusReply, Replies: []model.Reply{{From: "192.0.2.1", RTTNS: 2e6}}},
		{TTL: 2, Status: model.StatusNoReply, Replies: []model.Reply{{From: "192.0.2.2", RTTNS: 3e9, Late: true}}},
		{TTL: 3, Status: model.StatusSendError},
	})
	if r.N != 7 || !r.Start.Equal(at) || len(r.Samples) != 3 {
		t.Fatalf("round %+v", r)
	}
	if s := r.Samples[0]; s.RTTms != 2 || s.From != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("reply sample %+v", s)
	}
	for _, s := range r.Samples[1:] {
		if s.RTTms >= 0 || s.From.IsValid() {
			t.Errorf("gap sample %+v: want no address and a negative RTT", s)
		}
	}
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		r = zr
	}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Each day has its own file opened by the header; a closed day is gzipped,
// and the oldest days go once the history passes its cap.
func TestStoreDaysCompressionAndCap(t *testing.T) {
	dir := t.TempDir()
	a := netip.MustParseAddr("2001:db8::1")
	day1 := time.Date(2026, 10, 1, 23, 59, 0, 0, time.UTC)
	s, err := OpenStore(dir, 1<<30, day1)
	if err != nil {
		t.Fatal(err)
	}
	header := func() any { return map[string]string{"type": "start"} }
	for i, at := range []time.Time{day1, day1.Add(2 * time.Minute), day1.Add(24*time.Hour + 2*time.Minute)} {
		if err := s.Write(a, at, header, map[string]int{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	td := filepath.Join(dir, TargetDir(a))
	for _, f := range []string{"2026-10-01.jsonl.gz", "2026-10-02.jsonl.gz", "2026-10-03.jsonl"} {
		if got := lines(t, filepath.Join(td, f)); len(got) != 2 || !strings.Contains(got[0], "start") {
			t.Errorf("%s = %v, want the header and one record", f, got)
		}
	}
	if _, err := os.Stat(filepath.Join(td, "2026-10-01.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("day 1 left uncompressed: %v", err)
	}

	// Reopened on day 4 with a cap smaller than everything: the closed days
	// are compressed, then the oldest go first and today's file stays.
	s, err = OpenStore(dir, 1, day1.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(a, day1.Add(72*time.Hour), header, map[string]int{"n": 9}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(td, "*"))
	if len(left) != 1 || filepath.Base(left[0]) != "2026-10-04.jsonl" {
		t.Errorf("after the cap: %v, want only today's file", left)
	}
}

// fakeNet answers every probe from the target at once, unless down.
type fakeNet struct {
	target  netip.Addr
	down    *atomic.Bool
	replies chan []byte
}

func (f *fakeNet) Send(dst netip.Addr, ttl int, icmp []byte) error {
	if f.down.Load() {
		return errors.New("network is unreachable")
	}
	pkt := make([]byte, 20, 20+len(icmp))
	pkt[0], pkt[8], pkt[9] = 0x45, 57, 1
	src := f.target.As4()
	copy(pkt[12:], src[:])
	pkt = append(pkt, icmp...)
	pkt[20] = 0 // Echo Reply
	f.replies <- pkt
	return nil
}

func (f *fakeNet) Recv(buf []byte, deadline time.Time) (int, probe.Meta, error) {
	select {
	case b := <-f.replies:
		return copy(buf, b), probe.Meta{}, nil
	case <-time.After(time.Until(deadline)):
		return 0, probe.Meta{}, os.ErrDeadlineExceeded
	}
}

func (f *fakeNet) Close() error { return nil }

func testConfig(t *testing.T, down *atomic.Bool, opened *atomic.Int32) Config {
	t.Helper()
	s, err := OpenStore(t.TempDir(), DefaultCap, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	pc := probe.Defaults
	pc.TTLMax, pc.Timeout, pc.RoundInterval, pc.Spacing = 3, 30*time.Millisecond, 40*time.Millisecond, time.Millisecond
	return Config{
		Probe: pc, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Open: func(a netip.Addr) (probe.Conn, error) {
			opened.Add(1)
			return &fakeNet{target: a, down: down, replies: make(chan []byte, 64)}, nil
		},
		Source: func(netip.Addr) (netip.Addr, error) { return netip.Addr{}, errors.New("unused for IPv4") },
		Header: func(a netip.Addr, pc probe.Config) any {
			return model.Start{V: model.SchemaVersion, Type: model.TypeStart, Target: a.String()}
		},
	}
}

// A monitor counts what it sent and what came back, keeps the rounds in its
// ring, and writes a session header followed by every probe.
func TestMonitorMeasures(t *testing.T) {
	var down atomic.Bool
	var opened atomic.Int32
	cfg := testConfig(t, &down, &opened)
	var mu sync.Mutex
	var seen []int
	cfg.OnRound = func(r Round) {
		mu.Lock()
		seen = append(seen, r.N)
		mu.Unlock()
	}
	a := netip.MustParseAddr("192.0.2.9")
	m := NewMonitor(a, cfg, 0x1234, 0x5678)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if err := m.Run(ctx); err != nil {
		t.Fatal(err)
	}
	h := m.Health()
	if h.State != StateMeasuring || h.Rounds < 3 || h.Replied == 0 || h.SendErrors != 0 || h.Sessions != 1 {
		t.Errorf("health %+v", h)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, n := range seen {
		if n != i {
			t.Fatalf("rounds seen %v, want 0, 1, 2…", seen)
		}
	}
	if got := len(m.Ring.Last(RingRounds)); int64(got) != h.Rounds {
		t.Errorf("ring holds %d rounds, health counts %d", got, h.Rounds)
	}
	cfg.Store.Close()
	recs := lines(t, filepath.Join(cfg.Store.dir, TargetDir(a), time.Now().UTC().Format(time.DateOnly)+".jsonl"))
	var first model.Start
	if err := json.Unmarshal([]byte(recs[0]), &first); err != nil || first.Type != model.TypeStart {
		t.Fatalf("first record %q, want the session header", recs[0])
	}
	probes := 0
	for _, l := range recs[1:] {
		if strings.Contains(l, `"type":"probe"`) {
			probes++
		}
	}
	if int64(probes) != h.Probes {
		t.Errorf("%d probes on disk, health counts %d", probes, h.Probes)
	}
}

// When the node cannot send, the monitor says so instead of blaming the
// target, ends the session and starts a new one once the network is back.
func TestMonitorRecoversFromNodeOutage(t *testing.T) {
	defer func(w time.Duration) { restartWait = w }(restartWait)
	restartWait = 50 * time.Millisecond
	var down atomic.Bool
	var opened atomic.Int32
	down.Store(true)
	cfg := testConfig(t, &down, &opened)
	m := NewMonitor(netip.MustParseAddr("192.0.2.9"), cfg, 1, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for m.Health().State != StateDark && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h := m.Health(); h.State != StateDark || h.Replied != 0 {
		t.Fatalf("during the outage: %+v", h)
	}
	down.Store(false)
	for (m.Health().Replied == 0 || opened.Load() < 2) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if h := m.Health(); h.State != StateMeasuring || h.Replied == 0 || h.Sessions < 2 {
		t.Errorf("after the outage: %+v", h)
	}
}

// The analyzer asks the bases once per new address, turns a change of
// transit into a provisional and a confirmed event, and writes them to
// memory and to the target's history.
func TestAnalyzerEvents(t *testing.T) {
	var down atomic.Bool
	var opened atomic.Int32
	cfg := testConfig(t, &down, &opened)
	tgt := netip.MustParseAddr("192.0.2.99")
	m := NewMonitor(tgt, cfg, 1, 2)
	hopA, hopB := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	asns := map[netip.Addr]int{hopA: 64500, hopB: 64501, tgt: 64510}
	var asked atomic.Int32
	resolve := func(_ context.Context, addrs []netip.Addr) (map[netip.Addr]int, error) {
		asked.Add(int32(len(addrs)))
		out := map[netip.Addr]int{}
		for _, a := range addrs {
			out[a] = asns[a]
		}
		return out, nil
	}
	log := route.NewLog(10)
	a := NewAnalyzer(m, resolve, log, cfg.Store, cfg.Log)
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for n, hop := range []netip.Addr{hopA, hopA, hopA, hopB, hopB, hopB} {
		a.Feed(Round{Target: tgt, N: n, Start: at.Add(time.Duration(n) * 2 * time.Second), Samples: []Sample{
			{TTL: 1, From: hop, RTTms: 1}, {TTL: 2, From: tgt, RTTms: 50}}})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(log.Last(10)) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	evs := log.Last(10)
	if len(evs) != 2 || evs[0].State != model.StateProvisional || evs[1].State != model.StateConfirmed {
		t.Fatalf("events %+v", evs)
	}
	if got := asked.Load(); got != 3 {
		t.Errorf("resolver asked for %d addresses, want 3 (each once)", got)
	}
	if p := a.Path(); !slices.Equal(p, []int{64501, 64510}) {
		t.Errorf("path %v", p)
	}
	cfg.Store.Close()
	b, _ := os.ReadFile(filepath.Join(cfg.Store.dir, TargetDir(tgt), time.Now().UTC().Format(time.DateOnly)+".jsonl"))
	if n := strings.Count(string(b), `"type":"event"`); n != 2 || !strings.HasPrefix(string(b), `{"v":1,"type":"start"`) {
		t.Errorf("history %q", b)
	}
}

// A record that arrives late for a day already closed goes to the open day:
// rewriting the closed day's file would replace its compressed copy.
func TestStoreNeverReopensAClosedDay(t *testing.T) {
	dir := t.TempDir()
	a := netip.MustParseAddr("192.0.2.1")
	d2 := time.Date(2026, 10, 2, 0, 0, 1, 0, time.UTC)
	s, err := OpenStore(dir, DefaultCap, d2)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{d2.Add(-2 * time.Second), d2, d2.Add(-time.Second)} {
		if err := s.Write(a, at, nil, map[string]string{"at": at.Format(time.TimeOnly)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	td := filepath.Join(dir, TargetDir(a))
	if got := lines(t, filepath.Join(td, "2026-10-01.jsonl.gz")); len(got) != 1 {
		t.Errorf("closed day = %v, want only its own record", got)
	}
	if got := lines(t, filepath.Join(td, "2026-10-02.jsonl")); len(got) != 2 {
		t.Errorf("open day = %v, want its record and the late one", got)
	}
}

func TestWindowPerTTL(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	var rounds []Round
	for i := range 60 {
		hop2 := Sample{TTL: 2, RTTms: -1}
		if i%4 != 0 {
			hop2 = Sample{TTL: 2, From: b, RTTms: 30 + float64(i%5)}
		}
		rounds = append(rounds, Round{N: i, Samples: []Sample{{TTL: 1, From: a, RTTms: 0.5}, hop2}})
	}
	w := Window(rounds)
	if len(w) != 2 || w[0].TTL != 1 || w[0].Addr != "192.0.2.1" || w[0].Addrs != 1 || *w[0].LossPct != 0 {
		t.Fatalf("hop 1: %+v", w)
	}
	h := w[1]
	if h.Sent != 60 || h.Replied != 45 || *h.LossPct != 25 || h.MaxBurst != 1 || h.Addr != "192.0.2.2" {
		t.Errorf("hop 2: %+v", h)
	}
	if h.P95MS != nil || h.P50MS == nil || *h.MinMS != 30 {
		t.Errorf("hop 2 percentiles: p50 %v p95 %v min %v; want a median, no p95 from 45 RTTs, min 30", h.P50MS, h.P95MS, *h.MinMS)
	}
}

// Targets come and go while the fleet runs; the frontier holds; the list and
// an audit line survive; a restart picks the saved list up.
func TestFleet(t *testing.T) {
	var down atomic.Bool
	var opened atomic.Int32
	mcfg := testConfig(t, &down, &opened)
	state := t.TempDir()
	var rounds atomic.Int32
	var changes [][]netip.Addr
	var mu sync.Mutex
	newFleet := func() (*Fleet, []netip.Addr) {
		f, saved, err := NewFleet(FleetConfig{Monitor: mcfg, Store: mcfg.Store, Log: mcfg.Log, State: state,
			Events: route.NewLog(10),
			Resolve: func(_ context.Context, addrs []netip.Addr) (map[netip.Addr]int, error) {
				return map[netip.Addr]int{}, nil
			},
			OnRound: func(Round) { rounds.Add(1) },
			OnChange: func(l []netip.Addr) {
				mu.Lock()
				changes = append(changes, l)
				mu.Unlock()
			},
			Fail: func(err error) { t.Errorf("fleet failed: %v", err) },
		})
		if err != nil {
			t.Fatal(err)
		}
		return f, saved
	}
	f, saved := newFleet()
	if saved != nil {
		t.Fatalf("nothing saved yet, got %v", saved)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := f.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	addrs := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}
	for _, s := range addrs {
		if err := f.Add(netip.MustParseAddr(s), "192.0.2.200"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Add(netip.MustParseAddr("192.0.2.6"), "x"); !errors.Is(err, ErrFull) {
		t.Errorf("sixth target: %v, want ErrFull", err)
	}
	if err := f.Add(netip.MustParseAddr("192.0.2.1"), "x"); !errors.Is(err, ErrExists) {
		t.Errorf("twice: %v, want ErrExists", err)
	}
	if err := f.Add(netip.MustParseAddr("::1"), "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("loopback: %v, want ErrInvalid", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for rounds.Load() < 10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rounds.Load() < 10 {
		t.Fatalf("only %d rounds from five targets", rounds.Load())
	}
	if err := f.Remove(netip.MustParseAddr("192.0.2.3"), "192.0.2.200"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(netip.MustParseAddr("192.0.2.3"), "x"); !errors.Is(err, ErrUnknown) {
		t.Errorf("remove twice: %v, want ErrUnknown", err)
	}
	if got := len(f.Members()); got != 4 {
		t.Errorf("%d members after a removal, want 4", got)
	}
	cancel()
	f.Wait()
	mu.Lock()
	if n := len(changes); n != 6 || len(changes[n-1]) != 4 {
		t.Errorf("changes seen: %v", changes)
	}
	mu.Unlock()
	log, _ := os.ReadFile(filepath.Join(state, "targets-log.jsonl"))
	if strings.Count(string(log), `"action":"add"`) != 5 || strings.Count(string(log), `"action":"remove"`) != 1 ||
		!strings.Contains(string(log), `"by":"192.0.2.200"`) {
		t.Errorf("audit log:\n%s", log)
	}

	_, saved = newFleet()
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.4"), netip.MustParseAddr("192.0.2.5")}
	if !slices.Equal(saved, want) {
		t.Errorf("saved list %v, want %v", saved, want)
	}
}
