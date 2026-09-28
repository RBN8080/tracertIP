package probe

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// Paris: every probe of a flow keeps type, code, id and checksum, and still
// verifies, whatever its sequence.
func TestEchoRequestConstantFlow(t *testing.T) {
	const id, flow = 0x1234, 0xbeef
	for round := 0; round < 3*maxRoundSeq; round += 37 {
		for ttl := 1; ttl <= 40; ttl++ {
			seq := seqFor(round, ttl)
			b := echoRequest(id, seq, flow)
			if got := binary.BigEndian.Uint16(b[2:]); got != flow {
				t.Fatalf("seq %d: checksum %#x, want %#x", seq, got, flow)
			}
			if !checksumOK(b) {
				t.Fatalf("seq %d: checksum does not verify", seq)
			}
			if b[0] != icmpEcho || b[1] != 0 || binary.BigEndian.Uint16(b[4:]) != id || binary.BigEndian.Uint16(b[6:]) != seq {
				t.Fatalf("seq %d: bad header % x", seq, b[:8])
			}
		}
	}
}

func TestSeqRoundTrip(t *testing.T) {
	for _, tc := range []struct{ round, ttl int }{{0, 1}, {5, 40}, {1023, 63}, {1024, 7}} {
		r, ttl := splitSeq(seqFor(tc.round, tc.ttl))
		if r != tc.round%maxRoundSeq || ttl != tc.ttl {
			t.Errorf("%v: got round %d ttl %d", tc, r, ttl)
		}
	}
}

func TestParseReply(t *testing.T) {
	router := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.7")
	probe := echoRequest(0x1234, seqFor(2, 5), 0xbeef)

	te, err := parseReply(ipv4(router, 250, 99, timeExceeded(target, probe)))
	if err != nil {
		t.Fatal(err)
	}
	if te.from != router || te.dst != target || te.id != 0x1234 || te.seq != seqFor(2, 5) ||
		te.icmpType != icmpTimeExceed || te.ipTTL != 250 || te.ipID != 99 || te.qTTL != 1 {
		t.Errorf("time exceeded parsed as %+v", te)
	}

	er, err := parseReply(ipv4(target, 57, 3, echoReply(probe)))
	if err != nil {
		t.Fatal(err)
	}
	if er.from != target || er.dst != target || er.id != 0x1234 || er.seq != seqFor(2, 5) || er.icmpType != icmpEchoReply {
		t.Errorf("echo reply parsed as %+v", er)
	}

	for name, pkt := range map[string][]byte{
		"empty":  nil,
		"ipv6":   append([]byte{0x60}, make([]byte, 40)...),
		"tcp":    func() []byte { p := ipv4(router, 64, 1, make([]byte, 8)); p[9] = 6; return p }(),
		"echo":   ipv4(router, 64, 1, probe),
		"short":  ipv4(router, 64, 1, []byte{11, 0}),
		"quoted": ipv4(router, 64, 1, append([]byte{11, 0, 0, 0, 0, 0, 0, 0}, 0x45)),
	} {
		if _, err := parseReply(pkt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Parsers of network input must never panic (go.dev/doc/security/fuzz).
func FuzzParseReply(f *testing.F) {
	router := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.7")
	probe := echoRequest(1, 1, 1)
	f.Add(ipv4(router, 250, 1, timeExceeded(target, probe)))
	f.Add(ipv4(target, 57, 1, echoReply(probe)))
	f.Add([]byte{0x45})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseReply(b)
		if err == nil && len(r.icmp) > len(b) {
			t.Fatal("ICMP longer than the packet")
		}
	})
}

// Test helpers: whole IPv4 packets as a raw socket delivers them.

func ipv4(src netip.Addr, ttl, id int, payload []byte) []byte {
	b := make([]byte, 20, 20+len(payload))
	b[0], b[8], b[9] = 0x45, byte(ttl), protoICMP
	binary.BigEndian.PutUint16(b[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(b[4:], uint16(id))
	s := src.As4()
	copy(b[12:], s[:])
	return append(b, payload...)
}

func timeExceeded(dst netip.Addr, probe []byte) []byte {
	q := make([]byte, 20)
	q[0], q[8], q[9] = 0x45, 1, protoICMP
	binary.BigEndian.PutUint16(q[4:], 4242)
	d := dst.As4()
	copy(q[16:], d[:])
	m := append([]byte{icmpTimeExceed, 0, 0, 0, 0, 0, 0, 0}, q...)
	return append(m, probe[:8]...)
}

func echoReply(probe []byte) []byte {
	m := append([]byte(nil), probe...)
	m[0] = icmpEchoReply
	return m
}
