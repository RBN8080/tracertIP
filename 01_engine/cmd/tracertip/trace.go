package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"slices"
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

func runTrace(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "write JSON Lines records (schema v1) instead of a table")
	public := fs.Bool("public", false, "hide the home side and raw probes, for sharing")
	rounds := fs.Int("rounds", probe.Defaults.Rounds, "rounds of probes (1-100)")
	ttlMax := fs.Int("ttl-max", probe.Defaults.TTLMax, "highest TTL (1-40, frontier)")
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (origin, access ISP)")
	dir := fs.String("dir", "", "folder with the bases (default: config, then the user cache)")
	resolver := fs.String("resolver", "", "DNS server for names, host:port (default: config, then system)")
	noDNS := fs.Bool("no-dns", false, "do not look up names")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip trace [flags] <ipv4>")
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
	if err != nil || !target.Is4() {
		fmt.Fprintf(stderr, "tracertip: %q is not an IPv4 address\n", fs.Arg(0))
		return exitUsage
	}
	if *rounds < 1 || *rounds > 100 || *ttlMax < 1 || *ttlMax > probe.Defaults.TTLMax {
		fmt.Fprintln(stderr, "tracertip: rounds must be 1-100 and ttl-max 1-40")
		return exitUsage
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := loadConfig(*cfgPath, explicit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	bases := first(*dir, cfg.Bases, defaultBasesDir())

	pc := probe.Defaults
	pc.Target, pc.Rounds, pc.TTLMax = target, *rounds, *ttlMax
	pc.ICMPID, pc.FlowID = random16(), random16()

	conn, err := open()
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	enc := json.NewEncoder(stdout)
	begin := time.Now()
	if *jsonOut {
		if err := enc.Encode(startRecord(begin, target, pc, bases)); err != nil {
			fmt.Fprintln(stderr, "tracertip:", err)
			return exitFail
		}
	}
	var probes []model.Probe
	sum, err := probe.Trace(ctx, conn, pc, func(p model.Probe) error {
		probes = append(probes, p)
		if *jsonOut && !*public { // raw probes quote the node's own address
			return enc.Encode(p)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}

	hops := judge.Hops(probes, target)
	var addrs []netip.Addr
	for _, h := range hops {
		for _, a := range h.Addrs {
			if !slices.Contains(addrs, a) {
				addrs = append(addrs, a)
			}
		}
	}
	info, err := enrich.Enrich(ctx, addrs, enrich.Options{Dir: bases, Resolver: first(*resolver, cfg.Resolver), NoDNS: *noDNS})
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	if cfg.Origin == nil {
		fmt.Fprintln(stderr, "tracertip: no origin in the configuration: locations are not judged")
	}
	recs := output.Records(hops, judge.Judge(hops, info, cfg.Origin), info, cfg.AccessASN, *public)
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

func startRecord(t time.Time, target netip.Addr, pc probe.Config, bases string) model.Start {
	s := model.Start{
		V: model.SchemaVersion, Type: model.TypeStart, Tool: "tracertip", Version: version(),
		Time: t.UTC(), Target: target.String(), Method: "icmp-paris",
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
