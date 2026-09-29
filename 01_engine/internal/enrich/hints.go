package enrich

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

// Place is a location read from a router's name. It is an inference: the
// judge keeps it only if physics allows it (Luckie et al., CoNEXT 2021;
// Gharaibeh et al., IMC 2017).
type Place struct {
	Token   string  `json:"token"`
	IATA    string  `json:"iata"`
	City    string  `json:"city"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Source  string  `json:"source"` // "iata" or "table"
}

// Hints resolves hostname tokens to places: IATA codes from OurAirports and a
// local table for operator codes without public coordinates (for example
// CLLI-style "lsanca"). The table maps a token to an IATA code of the metro.
type Hints struct {
	airports map[string]ipdb.Airport
	table    map[string]string
}

// LoadHints reads airports.csv and an optional table ("token<TAB>iata<TAB>source").
func LoadHints(airports, table string) (*Hints, error) {
	h := &Hints{airports: map[string]ipdb.Airport{}, table: map[string]string{}}
	f, err := os.Open(airports)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := ipdb.ReadAirports(f, func(a ipdb.Airport) error { h.airports[a.IATA] = a; return nil }); err != nil {
		return nil, fmt.Errorf("%s: %w", airports, err)
	}
	if table == "" {
		return h, nil
	}
	t, err := os.Open(table)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	defer t.Close()
	return h, h.readTable(t, table)
}

func (h *Hints) readTable(r io.Reader, name string) error {
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 || f[2] == "" {
			return fmt.Errorf("%s:%d: want token, IATA code and source", name, n)
		}
		iata := strings.ToLower(f[1])
		if _, ok := h.airports[iata]; !ok {
			return fmt.Errorf("%s:%d: unknown IATA code %q", name, n, f[1])
		}
		h.table[strings.ToLower(f[0])] = iata
	}
	return sc.Err()
}

// orgSuffixes are second-level labels under a country code (aarnet.net.au).
var orgSuffixes = map[string]bool{"com": true, "net": true, "org": true, "edu": true, "gov": true, "ac": true, "co": true}

// For returns the places a hostname points to. Labels of the registered
// domain are skipped (they name the operator, not a place); when the name
// carries two-letter country labels, only places in those countries remain.
func (h *Hints) For(host string) []Place {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(host), "."), ".")
	n := len(labels)
	countries := map[string]bool{}
	if n > 0 && len(labels[n-1]) == 2 {
		countries[labels[n-1]] = true
	}
	cut := 2
	if n >= 3 && orgSuffixes[labels[n-2]] {
		cut = 3
	}
	if n <= cut {
		return nil
	}
	hostLabels := labels[:n-cut]
	for _, l := range hostLabels {
		if len(l) == 2 && isLetters(l) {
			countries[l] = true
		}
	}
	var out []Place
	seen := map[string]bool{}
	for _, l := range hostLabels {
		for _, piece := range strings.FieldsFunc(l, func(r rune) bool { return r == '-' || r == '_' }) {
			tok := strings.TrimRightFunc(piece, unicode.IsDigit)
			if tok == "" || !isLetters(tok) {
				continue
			}
			iata, src := h.table[tok], "table"
			if iata == "" && len(tok) == 3 {
				iata, src = tok, "iata"
			}
			a, ok := h.airports[iata]
			if !ok || seen[iata] {
				continue
			}
			if len(countries) > 0 && !countries[strings.ToLower(a.Country)] {
				continue
			}
			seen[iata] = true
			out = append(out, Place{Token: tok, IATA: iata, City: a.City, Country: a.Country, Lat: a.Lat, Lon: a.Lon, Source: src})
		}
	}
	return out
}

func isLetters(s string) bool {
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return s != ""
}
