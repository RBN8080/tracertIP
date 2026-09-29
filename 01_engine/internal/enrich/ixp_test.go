package enrich

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestLookupIXPs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("peeringdb-ixpfx.json", `{"data":[{"protocol":"IPv4","prefix":"203.0.113.0/24","ixlan_id":7},
		{"protocol":"IPv6","prefix":"2001:db8::/64","ixlan_id":7}],"meta":{}}`)
	write("peeringdb-netixlan.json", `{"data":[{"ixlan_id":7,"name":"Example IX","asn":64500,"ipaddr4":"203.0.113.10"},
		{"ixlan_id":7,"name":"Example IX","asn":64501,"ipaddr4":null}],"meta":{}}`)

	member, other, outside := netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.99"), netip.MustParseAddr("192.0.2.1")
	got, err := lookupIXPs(dir, []netip.Addr{member, other, outside})
	if err != nil {
		t.Fatal(err)
	}
	if x := got[member]; x == nil || x.Name != "Example IX" || x.MemberASN != 64500 {
		t.Errorf("member: %+v", x)
	}
	if x := got[other]; x == nil || x.MemberASN != 0 {
		t.Errorf("unlisted address on the LAN: %+v, want member unknown", x)
	}
	if got[outside] != nil {
		t.Errorf("address outside every IXP labelled %+v", got[outside])
	}
	if got, err := lookupIXPs(t.TempDir(), []netip.Addr{member}); err != nil || len(got) != 0 {
		t.Errorf("no PeeringDB files: %v, %v", got, err)
	}
}
