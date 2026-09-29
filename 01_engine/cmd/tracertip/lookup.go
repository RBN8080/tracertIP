package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
)

func runLookup(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultBasesDir(), "folder with the bases (update-db)")
	hints := fs.String("hints", "", "hint table (default: <dir>/geohints.tsv)")
	resolver := fs.String("resolver", "", "DNS server for names, host:port (default: system)")
	noDNS := fs.Bool("no-dns", false, "do not look up names")
	jsonOut := fs.Bool("json", false, "write one JSON object per address")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip lookup [flags] <ipv4>... (or - to read them from stdin)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	words := fs.Args()
	if len(words) == 1 && words[0] == "-" {
		words = nil
		sc := bufio.NewScanner(stdin)
		for sc.Scan() {
			words = append(words, strings.Fields(sc.Text())...)
		}
	}
	var addrs []netip.Addr
	for _, w := range words {
		a, err := netip.ParseAddr(w)
		if err != nil || !a.Is4() {
			fmt.Fprintf(stderr, "tracertip: %q is not an IPv4 address\n", w)
			return exitUsage
		}
		addrs = append(addrs, a)
	}
	info, err := enrich.Enrich(context.Background(), addrs,
		enrich.Options{Dir: *dir, Hints: *hints, Resolver: *resolver, NoDNS: *noDNS})
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	enc := json.NewEncoder(stdout)
	for _, a := range addrs {
		inf := info[a]
		if *jsonOut {
			if err := enc.Encode(inf); err != nil {
				return exitFail
			}
			continue
		}
		fmt.Fprintf(stdout, "%-16s %-8s %s\n", inf.Addr, inf.Class, describe(inf))
	}
	return exitOK
}

// describe summarises the answers: AS by source, name, name hints, DB city.
func describe(inf enrich.Info) string {
	var parts []string
	if inf.RFC != "" {
		parts = append(parts, inf.RFC)
	}
	for _, as := range inf.AS {
		label := fmt.Sprintf("AS%d", as.ASN)
		if as.ASN == 0 {
			label = "not routed"
		}
		parts = append(parts, fmt.Sprintf("%s %s [%s]", label, as.Name, as.Source))
	}
	if len(inf.AS) == 0 && inf.Class == enrich.ClassPublic {
		parts = append(parts, "AS?")
	}
	if inf.Name != "" {
		parts = append(parts, inf.Name)
	}
	for _, p := range inf.Places {
		parts = append(parts, fmt.Sprintf("hint %s=%s, %s [%s]", p.Token, p.City, p.Country, p.Source))
	}
	if c := inf.DBCity; c != nil {
		parts = append(parts, fmt.Sprintf("db %s, %s", c.City, c.Country))
	}
	return strings.Join(parts, " | ")
}
