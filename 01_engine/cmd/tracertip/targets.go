package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
	"github.com/rbn8080/tracertip/01_engine/internal/judge"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
	"github.com/rbn8080/tracertip/01_engine/internal/targets"
)

// targetList is the validator's output, kept with the study.
type targetList struct {
	V         int              `json:"v"`
	Generated time.Time        `json:"generated"`
	Tool      string           `json:"tool"`
	Seed      string           `json:"seed"`
	Anchors   anchorSource     `json:"anchors"`
	Rules     targets.Options  `json:"rules"`
	Probed    bool             `json:"probed"`
	Targets   []targets.Target `json:"targets"`
	Rejected  []targets.Target `json:"rejected"`
}

type anchorSource struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
}

func runTargets(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("targets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	anchorsFile := fs.String("anchors", "", "saved anchor list (default: download it and save a dated copy next to -out)")
	exclude := fs.String("exclude", "", "file with addresses already measured, to leave out")
	fixed := fs.String("fixed", "", "comma-separated addresses to add by hand (checked, not anchors)")
	seed := fs.String("seed", time.Now().UTC().Format("2006-01-02"), "seed of the reproducible order")
	perContinent := fs.Int("per-continent", 10, "study targets per continent")
	reserve := fs.Int("reserve", 5, "reserve targets per continent")
	noProbe := fs.Bool("no-probe", false, "skip reachability and physics (they need CAP_NET_RAW)")
	out := fs.String("out", "", "output file (JSON)")
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (origin)")
	dir := fs.String("dir", "", "folder with the bases (default: config, then the user cache)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip targets -out <file> [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *out == "" || *perContinent < 1 || *reserve < 0 {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := loadConfig(*cfgPath, explicit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	if !*noProbe && cfg.Origin == nil {
		fmt.Fprintln(stderr, "tracertip: the physics check needs the origin in the configuration (or use -no-probe)")
		return exitUsage
	}
	bases := first(*dir, cfg.Bases, defaultBasesDir())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ua := "tracertip/" + version() + " (+https://github.com/RBN8080/tracertIP)"
	client := ipdb.NewClient(2 * time.Minute)

	anchors, src, err := loadAnchors(ctx, client, ua, *anchorsFile, *out)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	continent, err := continents(filepath.Join(bases, "airports.csv"))
	if err != nil {
		fmt.Fprintln(stderr, "tracertip: continents from OurAirports:", err)
		return exitFail
	}
	skip, err := readAddrs(*exclude)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}

	public := func(a netip.Addr) bool { c, _ := enrich.Classify(a); return c == enrich.ClassPublic }
	var cands []targets.Target
	var addrs []netip.Addr
	refused := map[string]int{}
	for _, a := range anchors {
		cont := continent[a.Country]
		if ok, why := targets.Eligible(a, cont, public, skip); !ok {
			refused[why]++
			continue
		}
		cands = append(cands, targets.Target{Anchor: a, Continent: cont})
		addrs = append(addrs, a.IPv4, a.IPv6)
	}
	var extra []netip.Addr
	for _, s := range strings.FieldsFunc(*fixed, func(r rune) bool { return r == ',' }) {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			fmt.Fprintf(stderr, "tracertip: %q is not an IP address\n", s)
			return exitUsage
		}
		extra = append(extra, a.Unmap())
	}
	info, err := enrich.Enrich(ctx, append(slices.Clone(addrs), extra...),
		enrich.Options{Dir: bases, NoDNS: true, NoIPmap: true, NoCity: true})
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}

	v := &validator{ctx: ctx, client: client, ua: ua, info: info, origin: cfg.Origin, probe: !*noProbe, log: stderr}
	o := targets.Options{Continents: []string{"AF", "AS", "EU", "NA", "OC", "SA"},
		PerContinent: *perContinent, Reserve: *reserve, Seed: *seed}
	chosen, rejected := targets.Select(cands, o, v.anchor)
	for _, a := range extra {
		t := targets.Target{Role: targets.RoleFixed}
		if a.Is4() {
			t.IPv4 = a
		} else {
			t.IPv6 = a
		}
		v.fixed(&t, a)
		chosen = append(chosen, t)
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "tracertip: interrupted; nothing written")
		return exitFail
	}

	list := targetList{V: 1, Generated: time.Now().UTC(), Tool: "tracertip " + version(), Seed: *seed,
		Anchors: src, Rules: o, Probed: !*noProbe, Targets: chosen, Rejected: rejected}
	b, err := json.MarshalIndent(list, "", " ")
	if err == nil {
		err = ipdb.WriteAtomic(*out, append(b, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	summarize(stdout, list, refused, o)
	return exitOK
}

// validator runs the costly checks, cheapest first, and stops at the first
// failure.
type validator struct {
	ctx    context.Context
	client *http.Client
	ua     string
	info   map[netip.Addr]enrich.Info
	origin *judge.Coord
	probe  bool
	log    io.Writer
}

func (v *validator) anchor(t *targets.Target) bool {
	for _, f := range []struct {
		addr netip.Addr
		as   int
		fam  string
	}{{t.IPv4, t.ASv4, "v4"}, {t.IPv6, t.ASv6, "v6"}} {
		if !v.census(t, f.addr, f.fam) || !v.originAS(t, f.addr, f.as, f.fam) || !v.bgp(t, f.addr, f.as, f.fam) {
			return false
		}
	}
	if !v.probe {
		return true
	}
	for _, f := range []struct {
		addr netip.Addr
		fam  string
	}{{t.IPv4, "v4"}, {t.IPv6, "v6"}} {
		rtt, ok := v.reach(t, f.addr, f.fam)
		if !ok {
			return false
		}
		// Physics (Katz-Bassett et al., IMC 2006): an answer faster than light
		// in fiber from the declared place came from somewhere closer: a
		// proxy, an anycast site or a wrong location.
		need := judge.MinRTTms(judge.DistanceKm(*v.origin, judge.Coord{Lat: t.Lat, Lon: t.Lon}))
		if !add(t, "physics-"+f.fam, rtt >= need, "%.1f ms measured, fiber minimum %.1f ms to %s, %s", rtt, need, t.City, t.Country) {
			return false
		}
	}
	return true
}

func (v *validator) fixed(t *targets.Target, a netip.Addr) {
	fam := "v4"
	if a.Is6() {
		fam = "v6"
	}
	if !v.census(t, a, fam) {
		return
	}
	as := 0
	if inf := v.info[a]; len(inf.AS) > 0 {
		as = inf.AS[0].ASN
	}
	if !v.bgp(t, a, as, fam) || !v.probe {
		return
	}
	v.reach(t, a, fam)
}

func add(t *targets.Target, name string, ok bool, format string, args ...any) bool {
	t.Add(name, ok, format, args...)
	return ok
}

func (v *validator) census(t *targets.Target, a netip.Addr, fam string) bool {
	if c := v.info[a].Anycast; c != nil {
		return add(t, "anycast-census-"+fam, false, "listed: %s", c.Prefix)
	}
	return add(t, "anycast-census-"+fam, true, "")
}

func (v *validator) originAS(t *targets.Target, a netip.Addr, declared int, fam string) bool {
	for _, as := range v.info[a].AS {
		if as.Source == "iptoasn" {
			return add(t, "origin-as-"+fam, as.ASN == declared, "IPtoASN AS%d, declared AS%d", as.ASN, declared)
		}
	}
	return add(t, "origin-as-"+fam, false, "not in IPtoASN")
}

// bgp: the prefix is announced by one AS only, the expected one (RIPEstat).
func (v *validator) bgp(t *targets.Target, a netip.Addr, declared int, fam string) bool {
	r, err := targets.PrefixOverview(v.ctx, v.client, a, v.ua)
	if err != nil {
		return add(t, "bgp-"+fam, false, "RIPEstat: %v", err)
	}
	ok := r.Announced && len(r.Origins) == 1 && (declared == 0 || r.Origins[0] == declared)
	return add(t, "bgp-"+fam, ok, "%s announced=%t origins=%v", r.Prefix, r.Announced, r.Origins)
}

// reach traces a few rounds, one target at a time (frontier 1.bis), and
// returns the target's lowest RTT.
func (v *validator) reach(t *targets.Target, a netip.Addr, fam string) (float64, bool) {
	pc := probe.Defaults
	pc.Rounds, pc.Target, pc.ICMPID, pc.FlowID = 3, a, random16(), random16()
	var err error
	if a.Is6() {
		if pc.Source, err = probe.SourceFor(a); err != nil {
			return 0, add(t, "reach-"+fam, false, "no IPv6 route: %v", err)
		}
	}
	conn, err := open(a)
	if err != nil {
		return 0, add(t, "reach-"+fam, false, "%v", err)
	}
	defer conn.Close()
	fmt.Fprintf(v.log, "probing %s (%s, %s)\n", a, t.Country, fam)
	var probes []model.Probe
	if _, err := probe.Trace(v.ctx, conn, pc, func(p model.Probe) error { probes = append(probes, p); return nil }); err != nil {
		return 0, add(t, "reach-"+fam, false, "%v", err)
	}
	hops := judge.Hops(probes, a)
	if len(hops) == 0 || !hops[len(hops)-1].Target {
		return 0, add(t, "reach-"+fam, false, "no echo reply in %d rounds", pc.Rounds)
	}
	h := hops[len(hops)-1]
	return h.MinRTT, add(t, "reach-"+fam, true, "%d hops, %.1f ms", h.TTL, h.MinRTT)
}

// loadAnchors reads a saved list or downloads it and keeps a dated copy.
func loadAnchors(ctx context.Context, c *http.Client, ua, file, out string) ([]targets.Anchor, anchorSource, error) {
	var raw []byte
	src := anchorSource{Source: file}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, src, err
		}
		raw = b
	} else {
		var err error
		if _, raw, err = targets.FetchAnchors(ctx, c, ua); err != nil {
			return nil, src, err
		}
		src.Source = filepath.Join(filepath.Dir(out), "anchors-"+time.Now().UTC().Format("2006-01-02T1504Z")+".json")
		if err := ipdb.WriteAtomic(src.Source, raw, 0o644); err != nil {
			return nil, src, err
		}
	}
	a, err := targets.ReadAnchors(strings.NewReader(string(raw)))
	sum := sha256.Sum256(raw)
	src.SHA256, src.Count = hex.EncodeToString(sum[:]), len(a)
	return a, src, err
}

// continents maps each country to the continent most of its airports are
// on (OurAirports, public domain).
func continents(airports string) (map[string]string, error) {
	f, err := os.Open(airports)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	votes := map[string]map[string]int{}
	if _, err := ipdb.ReadAirports(f, func(a ipdb.Airport) error {
		if votes[a.Country] == nil {
			votes[a.Country] = map[string]int{}
		}
		votes[a.Country][a.Continent]++
		return nil
	}); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for cc, v := range votes {
		best := ""
		for cont, n := range v {
			if best == "" || n > v[best] || n == v[best] && cont < best {
				best = cont
			}
		}
		out[cc] = best
	}
	return out, nil
}

func readAddrs(path string) (map[netip.Addr]bool, error) {
	out := map[netip.Addr]bool{}
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		for _, w := range strings.Fields(line) {
			a, err := netip.ParseAddr(w)
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not an IP address", path, w)
			}
			out[a.Unmap()] = true
		}
	}
	return out, sc.Err()
}

func summarize(w io.Writer, l targetList, refused map[string]int, o targets.Options) {
	fmt.Fprintf(w, "anchors: %d (sha256 %s), seed %q\n", l.Anchors.Count, l.Anchors.SHA256[:16], l.Seed)
	var why []string
	for k, n := range refused {
		why = append(why, fmt.Sprintf("%s %d", k, n))
	}
	slices.Sort(why)
	fmt.Fprintf(w, "left out before checks: %s\n", strings.Join(why, ", "))
	for _, cont := range o.Continents {
		study, res := 0, 0
		for _, t := range l.Targets {
			if t.Continent == cont {
				if t.Role == targets.RoleStudy {
					study++
				} else {
					res++
				}
			}
		}
		fmt.Fprintf(w, "%s: %d study, %d reserve\n", cont, study, res)
	}
	fmt.Fprintf(w, "rejected by checks: %d\n", len(l.Rejected))
	for _, t := range l.Targets {
		if t.Role == targets.RoleReserve {
			continue
		}
		status := "ok"
		if !t.Passed() {
			status = "FAILED"
		}
		fmt.Fprintf(w, "%-7s %-2s %-2s %-18s %-15s %-39s %s\n", t.Role, t.Continent, t.Country, trimTo(t.City, 18), addrOr(t.IPv4), addrOr(t.IPv6), status)
	}
}

func addrOr(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}

func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
