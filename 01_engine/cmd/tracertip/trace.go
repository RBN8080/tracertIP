package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
	"github.com/rbn8080/tracertip/01_engine/internal/judge"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/output"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
)

// open is swapped in tests.
var open = probe.Open

// session is what judging a set of probes needs.
type session struct {
	target netip.Addr
	cfg    config
	opts   enrich.Options
	public bool
	known  map[netip.Addr]enrich.Info // watch mode enriches each address once
	// The target's city comes from the slowest base; it is read while probing.
	city     chan cityResult
	cityDone bool
	dbCity   *enrich.City
}

type cityResult struct {
	c   *enrich.City
	err error
}

func (s *session) startCity() {
	s.city = make(chan cityResult, 1)
	go func() {
		c, err := enrich.DBCity(s.opts.Dir, s.target)
		s.city <- cityResult{c, err}
	}()
}

// targetCity returns the target's city once known; wait blocks until then.
func (s *session) targetCity(wait bool) (*enrich.City, error) {
	if s.cityDone {
		return s.dbCity, nil
	}
	var r cityResult
	if wait {
		r = <-s.city
	} else {
		select {
		case r = <-s.city:
		default:
			return nil, nil
		}
	}
	s.cityDone, s.dbCity = true, r.c
	return r.c, r.err
}

func runTrace(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "write JSON Lines records (schema v1) instead of a table")
	public := fs.Bool("public", false, "hide the home side and raw probes, for sharing")
	rounds := fs.Int("rounds", probe.Defaults.Rounds, "rounds of probes (1-100)")
	ttlMax := fs.Int("ttl-max", probe.Defaults.TTLMax, "highest TTL (1-40, frontier)")
	watch := fs.Bool("watch", false, "keep probing and update every round, until stopped")
	window := fs.Int("window", 30, "watch: rounds each update summarises (1-300)")
	limit := fs.Duration("for", 0, "watch: stop after this long (0 = until stopped)")
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (origin, access ISP)")
	dir := fs.String("dir", "", "folder with the bases (default: config, then the user cache)")
	resolver := fs.String("resolver", "", "DNS server for names, host:port (default: config, then system)")
	noDNS := fs.Bool("no-dns", false, "do not look up names")
	noIPmap := fs.Bool("no-ipmap", false, "do not ask RIPE IPmap for router cities")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip trace [flags] <ip>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	target, err := netip.ParseAddr(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "tracertip: %q is not an IP address\n", fs.Arg(0))
		return exitUsage
	}
	if *rounds < 1 || *rounds > 100 || *ttlMax < 1 || *ttlMax > probe.Defaults.TTLMax || *window < 1 || *window > 300 || *limit < 0 {
		fmt.Fprintln(stderr, "tracertip: rounds must be 1-100, ttl-max 1-40, window 1-300 and for not negative")
		return exitUsage
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := loadConfig(*cfgPath, explicit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	s := &session{cfg: cfg, opts: enrichOptions(cfg, *dir, *resolver, *noDNS, *noIPmap), public: *public,
		known: map[netip.Addr]enrich.Info{}}
	s.opts.NoCity = true

	pc := probe.Defaults
	pc.Rounds, pc.TTLMax = *rounds, *ttlMax
	if *watch {
		pc.Rounds = 0
	}
	pc.ICMPID, pc.FlowID = random16(), random16()
	target = target.Unmap()
	pc.Target, s.target = target, target
	s.startCity()
	if target.Is6() {
		if pc.Source, err = probe.SourceFor(target); err != nil {
			fmt.Fprintln(stderr, "tracertip: no IPv6 route:", err)
			return exitFail
		}
	}

	conn, err := open(target)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *limit)
		defer cancel()
	}
	if cfg.Origin == nil {
		fmt.Fprintln(stderr, "tracertip: no origin in the configuration: locations are not judged")
	}

	term := isTerminal(stdout)
	stdout = &lockedWriter{w: stdout} // watch writes probes and updates from two goroutines
	enc := json.NewEncoder(stdout)
	begin := time.Now()
	if *jsonOut {
		if err := enc.Encode(startRecord(begin, target, pc, s.opts.Dir)); err != nil {
			fmt.Fprintln(stderr, "tracertip:", err)
			return exitFail
		}
	}
	raw := func(p model.Probe) error {
		if *jsonOut && !*public { // raw probes quote the node's own address
			return enc.Encode(p)
		}
		return nil
	}
	var sum probe.Summary
	var recs []output.HopRecord
	if *watch {
		sum, err = s.watch(ctx, conn, pc, *window, raw, func(recs []output.HopRecord, round int) error {
			if *jsonOut {
				return output.WriteJSON(stdout, recs)
			}
			if term {
				fmt.Fprint(stdout, "\033[H\033[2J") // redraw in place
			}
			fmt.Fprintf(stdout, "tracertip watch %s  round %d  %s  (last %d rounds; Ctrl-C stops)\n",
				target, round, time.Now().UTC().Format("15:04:05Z"), *window)
			output.WriteTable(stdout, recs)
			return nil
		})
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			err = nil // stopping is how a watch ends
		}
	} else {
		sum, recs, err = s.once(ctx, conn, pc, raw)
	}
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	end := model.End{
		V: model.SchemaVersion, Type: model.TypeEnd, Time: time.Now().UTC(), Reached: sum.Reached,
		Hops: sum.TargetTTL, Probes: sum.Probes, NoReply: sum.NoReply, DurationMS: time.Since(begin).Milliseconds(),
	}
	if *jsonOut {
		if err := output.WriteJSON(stdout, recs); err != nil {
			return exitFail
		}
		if err := enc.Encode(end); err != nil {
			return exitFail
		}
		return exitOK
	}
	output.WriteTable(stdout, recs)
	fmt.Fprintf(stdout, "reached=%t probes=%d no_reply=%d %.1f s\n", end.Reached, end.Probes, end.NoReply, float64(end.DurationMS)/1000)
	return exitOK
}

// once probes pc.Rounds rounds and judges the hops; raw sees every probe.
func (s *session) once(ctx context.Context, conn probe.Conn, pc probe.Config, raw func(model.Probe) error) (probe.Summary, []output.HopRecord, error) {
	var probes []model.Probe
	sum, err := probe.Trace(ctx, conn, pc, func(p model.Probe) error {
		probes = append(probes, p)
		return raw(p)
	})
	if err != nil {
		return sum, nil, err
	}
	recs, err := s.judge(ctx, probes, true)
	return sum, recs, err
}

// judge turns probes into hop records, enriching addresses not seen before;
// wait: block until the target's city is known.
func (s *session) judge(ctx context.Context, probes []model.Probe, wait bool) ([]output.HopRecord, error) {
	hops := judge.Hops(probes, s.target)
	var fresh []netip.Addr
	for _, h := range hops {
		for _, a := range h.Addrs {
			if _, ok := s.known[a]; !ok && !slices.Contains(fresh, a) {
				fresh = append(fresh, a)
			}
		}
	}
	if len(fresh) > 0 {
		info, err := enrich.Enrich(ctx, fresh, s.opts)
		if err != nil {
			return nil, err
		}
		for a, inf := range info {
			s.known[a] = inf
		}
	}
	city, err := s.targetCity(wait)
	if err != nil {
		return nil, err
	}
	if inf, ok := s.known[s.target]; ok && city != nil && inf.DBCity == nil {
		inf.DBCity = city
		s.known[s.target] = inf
	}
	return output.Records(hops, judge.Judge(hops, s.known, s.cfg.Origin), s.known, s.cfg.AccessASN, s.public), nil
}

// watch probes until ctx ends. After each round it judges the last window
// rounds in its own goroutine, so a slow enrichment never delays the probes;
// updates that pile up are merged into one.
func (s *session) watch(ctx context.Context, conn probe.Conn, pc probe.Config, window int,
	raw func(model.Probe) error, show func([]output.HopRecord, int) error) (probe.Summary, error) {
	var (
		mu     sync.Mutex
		probes []model.Probe
		done   = -1 // last complete round
	)
	ready := make(chan struct{}, 1)
	failed := make(chan error, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() {
		var prev []output.HopRecord
		for range ready {
			mu.Lock()
			snap, round := slices.Clone(probes), done
			mu.Unlock()
			recs, err := s.judge(ctx, snap, false)
			if err == nil {
				output.MarkChanges(prev, recs)
				for i := range recs {
					recs[i].Round = &round
				}
				err = show(recs, round)
				prev = recs
			}
			if err != nil && ctx.Err() == nil {
				failed <- err
				cancel()
				return
			}
		}
	})
	sum, err := probe.Trace(ctx, conn, pc, func(p model.Probe) error {
		mu.Lock()
		if p.Round > done+1 { // the first probe of a new round: the one before is complete
			done = p.Round - 1
			select {
			case ready <- struct{}{}:
			default:
			}
		}
		probes = append(probes, p)
		probes = slices.DeleteFunc(probes, func(q model.Probe) bool { return q.Round <= p.Round-window })
		mu.Unlock()
		return raw(p)
	})
	close(ready)
	wg.Wait()
	select {
	case e := <-failed:
		return sum, e
	default:
		return sum, err
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func startRecord(t time.Time, target netip.Addr, pc probe.Config, bases string) model.Start {
	s := model.Start{
		V: model.SchemaVersion, Type: model.TypeStart, Tool: "tracertip", Version: version(),
		Time: t.UTC(), Target: target.String(), Method: method(target),
		Params: model.Params{
			TTLMax: pc.TTLMax, TimeoutMS: int(pc.Timeout.Milliseconds()),
			RoundIntervalMS: int(pc.RoundInterval.Milliseconds()), ProbeSpacingMS: int(pc.Spacing.Milliseconds()),
			Rounds: pc.Rounds, ICMPID: int(pc.ICMPID), FlowID: int(pc.FlowID),
		},
	}
	if m, err := ipdb.ReadManifest(bases); err == nil {
		for name, e := range m {
			s.Bases = append(s.Bases, model.Base{Name: name, Date: e.Date, SHA256: e.SHA256, Rows: e.Rows})
		}
		slices.SortFunc(s.Bases, func(a, b model.Base) int { return compare(a.Name, b.Name) })
	}
	return s
}

// method names the probe: ICMP or ICMPv6 Echo, Paris style.
func method(t netip.Addr) string {
	if t.Is6() {
		return "icmpv6-paris"
	}
	return "icmp-paris"
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func first(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func random16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil || binary.BigEndian.Uint16(b[:]) == 0 {
		return 0x7472 // "tr": fixed fallback, never zero
	}
	return binary.BigEndian.Uint16(b[:])
}
