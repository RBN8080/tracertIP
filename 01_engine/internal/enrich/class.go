// Package enrich tells, for each address on a path, its class, its AS and
// where it may be, always with the source of each answer. It never invents an
// AS: an unknown stays unknown (bdrmap, IMC 2016; MAP-IT, IMC 2016).
package enrich

import "net/netip"

// Address classes. Special-purpose ranges come from the IANA IPv4
// Special-Purpose Address Registry (RFC 6890) and carry no AS.
const (
	ClassPublic   = "public"
	ClassPrivate  = "private"       // RFC 1918
	ClassCGNAT    = "cgnat"         // RFC 6598
	ClassLoopback = "loopback"      // RFC 1122
	ClassLink     = "link-local"    // RFC 3927
	ClassDoc      = "documentation" // RFC 5737
	ClassBench    = "benchmark"     // RFC 2544
	ClassSpecial  = "special"       // other IANA special-purpose ranges
)

var special = []struct {
	p     netip.Prefix
	class string
	rfc   string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), ClassSpecial, "RFC 791"},
	{netip.MustParsePrefix("10.0.0.0/8"), ClassPrivate, "RFC 1918"},
	{netip.MustParsePrefix("100.64.0.0/10"), ClassCGNAT, "RFC 6598"},
	{netip.MustParsePrefix("127.0.0.0/8"), ClassLoopback, "RFC 1122"},
	{netip.MustParsePrefix("169.254.0.0/16"), ClassLink, "RFC 3927"},
	{netip.MustParsePrefix("172.16.0.0/12"), ClassPrivate, "RFC 1918"},
	{netip.MustParsePrefix("192.0.0.0/24"), ClassSpecial, "RFC 6890"},
	{netip.MustParsePrefix("192.0.2.0/24"), ClassDoc, "RFC 5737"},
	{netip.MustParsePrefix("192.88.99.0/24"), ClassSpecial, "RFC 7526"},
	{netip.MustParsePrefix("192.168.0.0/16"), ClassPrivate, "RFC 1918"},
	{netip.MustParsePrefix("198.18.0.0/15"), ClassBench, "RFC 2544"},
	{netip.MustParsePrefix("198.51.100.0/24"), ClassDoc, "RFC 5737"},
	{netip.MustParsePrefix("203.0.113.0/24"), ClassDoc, "RFC 5737"},
	{netip.MustParsePrefix("224.0.0.0/4"), ClassSpecial, "RFC 5771"},
	{netip.MustParsePrefix("240.0.0.0/4"), ClassSpecial, "RFC 1112"},
}

// Classify returns the class of an IPv4 address and the RFC behind it.
func Classify(a netip.Addr) (class, rfc string) {
	for _, s := range special {
		if s.p.Contains(a) {
			return s.class, s.rfc
		}
	}
	return ClassPublic, ""
}
