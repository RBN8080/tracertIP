package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/api"
	"github.com/rbn8080/tracertip/01_engine/internal/batch"
	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
	"github.com/rbn8080/tracertip/01_engine/internal/route"
)

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	list := fs.String("targets", "", "file with the first targets, one IP per line (used only while no list is saved)")
	dir := fs.String("state", "", "folder for the history and the saved target list")
	capGB := fs.Float64("cap-gb", float64(live.DefaultCap)/(1<<30), "disk the history may use, in GiB")
	every := fs.Duration("status", time.Minute, "how often to log the health")
	limit := fs.Duration("for", 0, "stop after this long (0 = until stopped)")
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (origin, access ISP, resolver, bases)")
	bases := fs.String("dir", "", "folder with the bases (default: config, then the user cache)")
	listen := fs.String("listen", "", "serve the live view and API on this loopback or private address:port (default: none)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip serve -state <dir> [-listen <addr:port>] [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" || *capGB <= 0 || *every <= 0 || *limit < 0 {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	if *listen != "" {
		if err := api.CheckListen(*listen); err != nil {
			fmt.Fprintln(stderr, "tracertip:", err)
			return exitUsage
		}
	}
	var seed []netip.Addr
	if *list != "" {
		var err error
		if seed, err = readTargets(*list); err != nil {
			fmt.Fprintln(stderr, "tracertip:", err)
			return exitUsage
		}
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := loadConfig(*cfgPath, explicit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	basesDir := enrichOptions(cfg, *bases, "", true, true).Dir

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *limit)
		defer cancel()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu       sync.Mutex
		failures []error
	)
	fail := func(err error) {
		mu.Lock()
		failures = append(failures, err)
		mu.Unlock()
		cancel()
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))
	store, err := live.OpenStore(*dir, int64(*capGB*(1<<30)), time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	asns := newASNCache(asnResolver(basesDir))
	events := route.NewLog(eventLogSize)
	var srv *api.Server // set before the fleet starts; read-only afterwards
	fleet, saved, err := live.NewFleet(live.FleetConfig{
		Monitor: live.Config{Probe: probe.Defaults, Open: open, Source: probe.SourceFor, Store: store, Log: log,
			Header: func(a netip.Addr, pc probe.Config) any { return startRecord(time.Now(), a, pc, basesDir) }},
		Resolve: asns.Resolve, Events: events, Store: store, Log: log, State: *dir, Fail: fail,
		OnRound: func(r live.Round) {
			if srv != nil {
				srv.PublishRound(r)
			}
		},
		OnChange: func(l []netip.Addr) {
			if srv != nil {
				srv.PublishTargets(l)
			}
		},
	})
	if err != nil {
		store.Close()
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	if saved == nil { // no list saved yet: the seed file, if any
		saved = seed
	}

	var hs *http.Server
	var ln net.Listener
	if *listen != "" {
		j := &hopJudge{cfg: cfg, opts: enrichOptions(cfg, *bases, "", false, false), known: map[netip.Addr]enrich.Info{}}
		j.opts.NoCity = true
		srv = api.New(api.Config{
			Fleet: fleetView{fleet}, Events: events, Hops: j.hops, Home: asns.home(cfg.AccessASN), AccessASN: cfg.AccessASN,
			Hub: api.NewHub(),
			Node: func() api.Node {
				t, free := batch.Health(*dir)
				return api.Node{Version: version(), ClockSynced: batch.ClockSynced(), TempC: t, DiskFreeMB: free, RSSMB: batch.RSSMB()}
			},
		})
		events.OnAdd(srv.PublishEvents)
		if ln, err = net.Listen("tcp", *listen); err != nil {
			store.Close()
			fmt.Fprintln(stderr, "tracertip:", err)
			return exitFail
		}
		hs = srv.HTTPServer(*listen)
	}
	if err := fleet.Start(ctx, saved); err != nil {
		cancel()
		fleet.Wait()
		store.Close()
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	fmt.Fprintf(stdout, "tracertip serve: %d of at most %d targets, one round every %s each; history in %s (cap %.1f GiB); Ctrl-C stops\n",
		len(fleet.Members()), live.MaxTargets, probe.Defaults.RoundInterval, *dir, *capGB)

	var wg sync.WaitGroup
	if hs != nil {
		fmt.Fprintf(stdout, "tracertip serve: live view on http://%s/ (LAN only; type an IP address to trace it)\n", ln.Addr())
		wg.Go(func() { srv.Run(ctx) })
		wg.Go(func() {
			if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				fail(err)
			}
		})
	}
	t := time.NewTicker(*every)
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-t.C:
			logHealth(log, fleet, *dir)
		}
	}
	t.Stop()
	if hs != nil {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		hs.Shutdown(sctx)
		scancel()
	}
	wg.Wait()
	fleet.Wait()
	if err := store.Close(); err != nil {
		fail(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(failures) > 0 {
		fmt.Fprintln(stderr, "tracertip:", errors.Join(failures...))
		return exitFail
	}
	return exitOK
}

// fleetView shows the fleet to the API.
type fleetView struct{ f *live.Fleet }

func (v fleetView) Targets() []api.Target {
	var out []api.Target
	for _, m := range v.f.Members() {
		out = append(out, api.Target{Monitor: m.Monitor, Path: m.Analyzer.Path})
	}
	return out
}

func (v fleetView) Get(a netip.Addr) (api.Target, bool) {
	m, ok := v.f.Get(a)
	if !ok {
		return api.Target{}, false
	}
	return api.Target{Monitor: m.Monitor, Path: m.Analyzer.Path}, true
}

func (v fleetView) Add(a netip.Addr, by string) error    { return v.f.Add(a, by) }
func (v fleetView) Remove(a netip.Addr, by string) error { return v.f.Remove(a, by) }

// eventLogSize is how many route events memory keeps for every target: at
// the rehearsal's 74 records a day for 122 paths, weeks of them.
const eventLogSize = 1000

// asnResolver looks addresses up in the local AS bases only (no DNS, no
// IPmap): IPtoASN, the source the hop records name first.
func asnResolver(dir string) live.Resolver {
	return func(ctx context.Context, addrs []netip.Addr) (map[netip.Addr]int, error) {
		info, err := enrich.Enrich(ctx, addrs, enrich.Options{Dir: dir, NoDNS: true, NoIPmap: true, NoCity: true})
		if err != nil {
			return nil, err
		}
		out := map[netip.Addr]int{}
		for a, inf := range info {
			for _, x := range inf.AS {
				if x.Source == "iptoasn" {
					out[a] = x.ASN
					break
				}
			}
		}
		return out, nil
	}
}

func logHealth(log *slog.Logger, fleet *live.Fleet, dir string) {
	tempC, freeMB := batch.Health(dir)
	members := fleet.Members()
	log.Info("node", "clock_synced", batch.ClockSynced(), "temp_c", tempC, "disk_free_mb", freeMB, "rss_mb", batch.RSSMB(),
		"targets", len(members))
	for _, m := range members {
		h := m.Monitor.Health()
		log.Info("target", "target", h.Target, "state", h.State, "rounds", h.Rounds, "replied", h.Replied,
			"no_reply", h.NoReply, "send_errors", h.SendErrors, "sessions", h.Sessions,
			"lag_ms", fmt.Sprintf("%.0f", h.LagMS), "max_lag_ms", fmt.Sprintf("%.0f", h.MaxLagMS),
			"path", m.Analyzer.Path(), "unanalyzed", m.Analyzer.Dropped(), "err", h.Error)
	}
}

// readTargets reads a seed list: IP addresses only, no names or ranges, at
// most live.MaxTargets (00_IDEA 1.bis: it measures paths, it does not scan).
func readTargets(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		a, err := netip.ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %q is not an IP address", path, n, line)
		}
		a = a.Unmap()
		if live.CheckTarget(a) != nil {
			return nil, fmt.Errorf("%s:%d: %s cannot be a target", path, n, a)
		}
		if slices.Contains(out, a) {
			return nil, fmt.Errorf("%s:%d: %s is listed twice", path, n, a)
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	switch {
	case len(out) == 0:
		return nil, fmt.Errorf("%s: no targets", path)
	case len(out) > live.MaxTargets:
		return nil, fmt.Errorf("%s: %d targets; the frontier allows %d at once", path, len(out), live.MaxTargets)
	}
	return out, nil
}
