// Package output writes judged hops as a table or as JSON Lines records, and
// hides the home side for public output (00_IDEA 5.ter).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/judge"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// TypeHop is the derived per-hop record (schema v1).
const TypeHop = "hop"

// HopRecord is one judged hop with what the bases said about its address.
type HopRecord struct {
	V    int    `json:"v"`
	Type string `json:"type"`
	judge.Verdict
	Sent    int          `json:"sent"`
	Replied int          `json:"replied"`
	Home    bool         `json:"home,omitempty"`  // hidden in public output
	Round   *int         `json:"round,omitempty"` // watch mode: last round in the window
	Info    *enrich.Info `json:"info,omitempty"`
}

// FlagRouteChange marks a hop whose address changed since the last update.
const FlagRouteChange = "route-change"

// Records builds the hop records. With public set, the home side (every hop
// before the first transit hop, and any private or CGNAT hop) keeps only its
// TTL and RTT; accessASN is the home ISP's AS. Distances from the origin are
// dropped too: three located hops would give the origin away.
func Records(hops []judge.Hop, v []judge.Verdict, info map[netip.Addr]enrich.Info, accessASN int, public bool) []HopRecord {
	home := HomeSide(hops, info, accessASN)
	out := make([]HopRecord, len(hops))
	for i, h := range hops {
		r := HopRecord{V: model.SchemaVersion, Type: TypeHop, Verdict: v[i], Sent: h.Sent, Replied: h.Replied}
		if len(h.Addrs) > 0 {
			inf := info[h.Addrs[0]]
			r.Info = &inf
		}
		switch {
		case public && home[i]:
			r = HopRecord{V: r.V, Type: r.Type, Verdict: judge.Verdict{TTL: h.TTL, MinRTT: h.MinRTT, MaxKm: v[i].MaxKm},
				Sent: h.Sent, Replied: h.Replied, Home: true}
		case public:
			r.Candidates = slices.Clone(r.Candidates)
			for j := range r.Candidates {
				r.Candidates[j].Km, r.Candidates[j].NeedMs = 0, 0
			}
			if l := r.Location; l != nil {
				c := *l
				c.Km, c.NeedMs = 0, 0
				r.Location = &c
			}
		}
		out[i] = r
	}
	return out
}

// MarkChanges flags the hops whose first address differs from prev's.
func MarkChanges(prev, cur []HopRecord) {
	for i := range cur {
		if i < len(prev) && prev[i].Addr != "" && cur[i].Addr != "" && prev[i].Addr != cur[i].Addr {
			cur[i].Flags = append(slices.Clone(cur[i].Flags), FlagRouteChange)
		}
	}
}

// HomeSide marks the hops of the home and the access ISP.
func HomeSide(hops []judge.Hop, info map[netip.Addr]enrich.Info, accessASN int) []bool {
	home := make([]bool, len(hops))
	inHome := true
	for i, h := range hops {
		if len(h.Addrs) == 0 {
			home[i] = inHome
			continue
		}
		inf := info[h.Addrs[0]]
		local := inf.Class != enrich.ClassPublic
		access := len(inf.AS) > 0 && inf.AS[0].ASN == accessASN && accessASN != 0
		if inHome && !local && !access {
			inHome = false
		}
		home[i] = inHome || local
	}
	return home
}

// WriteJSON writes the records as JSON Lines.
func WriteJSON(w io.Writer, recs []HopRecord) error {
	enc := json.NewEncoder(w)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// WriteTable writes one line per hop; '*' is a gap, never 0 ms. The km column
// is the distance from the origin when the hop is located, else the most
// physics allows ("<"); +km is the jump from the previous located hop.
func WriteTable(w io.Writer, recs []HopRecord) {
	if len(recs) == 0 {
		return
	}
	width := len("[home]")
	for _, r := range recs {
		width = max(width, len(r.Addr)) // IPv6 addresses are up to 39 characters
	}
	fmt.Fprintf(w, "%2s  %-*s %8s %7s %7s  %-26s %s\n", "", width, "address", "rtt", "km", "+km", "network", "location")
	for _, r := range recs {
		switch {
		case r.Home:
			fmt.Fprintf(w, "%2d  %-*s %8s\n", r.TTL, width, "[home]", rtt(r.MinRTT))
			continue
		case r.Addr == "":
			fmt.Fprintf(w, "%2d  *\n", r.TTL)
			continue
		}
		fmt.Fprintf(w, "%2d  %-*s %8s %7s %7s  %-26s %-28s %s\n", r.TTL, width, r.Addr, rtt(r.MinRTT), km(r), jump(r),
			network(r), where(r), strings.Join(r.Flags, " "))
		switch s := r.Segment; {
		case s == nil || s.GainMs < segmentNoteMs:
		case s.NeedMs < localMs:
			fmt.Fprintf(w, "    ^ from TTL %d: +%.1f ms within %.0f km: not distance (detour, queueing or return path)\n",
				s.FromTTL, s.GainMs, s.Km)
		default:
			fmt.Fprintf(w, "    ^ from TTL %d: +%.1f ms over %.0f km, fiber minimum %.1f ms, efficiency %.2f (indicative)\n",
				s.FromTTL, s.GainMs, s.Km, s.NeedMs, s.Efficiency)
		}
	}
}

// segmentNoteMs: segments that add less than this are not worth a line.
const segmentNoteMs = 20

// localMs: under 1 ms of fiber (about 100 km), distance explains none of the gain.
const localMs = 1

func rtt(ms float64) string {
	if ms < 0 {
		return "*"
	}
	return fmt.Sprintf("%.1f ms", ms)
}

func network(r HopRecord) string {
	inf := r.Info
	switch {
	case inf == nil:
		return ""
	case inf.Class != enrich.ClassPublic:
		return inf.Class
	case inf.IXP != nil && inf.IXP.MemberASN != 0:
		return fmt.Sprintf("IXP %s (AS%d)", trim(inf.IXP.Name, 12), inf.IXP.MemberASN)
	case inf.IXP != nil:
		return "IXP " + trim(inf.IXP.Name, 20)
	case len(inf.AS) == 0:
		return "AS?"
	case inf.AS[0].ASN == 0:
		return "unrouted"
	}
	return fmt.Sprintf("AS%d %s", inf.AS[0].ASN, trim(inf.AS[0].Name, 16))
}

func km(r HopRecord) string {
	switch {
	case r.Location != nil && r.Location.Km > 0:
		return fmt.Sprintf("%.0f", r.Location.Km)
	case r.MaxKm > 0:
		return fmt.Sprintf("<%.0f", r.MaxKm)
	}
	return ""
}

func jump(r HopRecord) string {
	if r.Segment == nil {
		return ""
	}
	return fmt.Sprintf("+%.0f", r.Segment.Km)
}

func where(r HopRecord) string {
	l := r.Location
	if l == nil {
		return ""
	}
	src, city := l.Source, l.City
	if strings.HasPrefix(src, "ipmap:") && src != "ipmap:rtt" { // rtt: a RIPE Atlas probe within 1 ms
		src = "ipmap"
	}
	if l.Weak {
		city += "?"
	}
	return trim(fmt.Sprintf("%s, %s [%s]", city, l.Country, src), 28)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
