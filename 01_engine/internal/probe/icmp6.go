package probe

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ICMPv6 types handled by the probe (RFC 4443).
const (
	icmp6Unreachable = 1
	icmp6TimeExceed  = 3
	icmp6Echo        = 128
	icmp6EchoReply   = 129
	protoICMPv6      = 58
	ipv6Header       = 40
)

// echoRequest6 builds a Paris-style ICMPv6 Echo. The ICMPv6 checksum covers a
// pseudo-header with both addresses (RFC 8200 8.1; RFC 4443 2.3), so the
// balance word includes them. The kernel computes the checksum of raw ICMPv6
// sockets itself; with the balance word it lands on the chosen constant.
func echoRequest6(src, dst netip.Addr, id, seq, checksum uint16) []byte {
	b := make([]byte, echoHeader+payloadLen)
	b[0] = icmp6Echo
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	for i := echoHeader + 2; i < len(b); i++ {
		b[i] = byte(i)
	}
	s := fold(sum16(pseudo6(src, dst, len(b))) + sum16(b))
	w := fold(uint32(^checksum) + (^s & 0xffff))
	binary.BigEndian.PutUint16(b[echoHeader:], uint16(w))
	binary.BigEndian.PutUint16(b[2:], checksum)
	return b
}

// checksum6OK reports whether an ICMPv6 message verifies with its pseudo-header.
func checksum6OK(src, dst netip.Addr, icmp []byte) bool {
	return fold(sum16(pseudo6(src, dst, len(icmp)))+sum16(icmp)) == 0xffff
}

func pseudo6(src, dst netip.Addr, n int) []byte {
	p := make([]byte, 40)
	s, d := src.As16(), dst.As16()
	copy(p[0:], s[:])
	copy(p[16:], d[:])
	binary.BigEndian.PutUint32(p[32:], uint32(n))
	p[39] = protoICMPv6
	return p
}

func fold(s uint32) uint32 {
	for s > 0xffff {
		s = s&0xffff + s>>16
	}
	return s
}

// parseReply6 reads an ICMPv6 message (the kernel strips the IPv6 header).
// Time Exceeded and Destination Unreachable quote the probe's IPv6 header and
// its first bytes (RFC 4443 3.1, 3.3).
func parseReply6(icmp []byte, m Meta) (reply, error) {
	r := reply{from: m.From, ipTTL: m.HopLimit, ipLen: len(icmp) + ipv6Header, icmp: icmp}
	if len(icmp) < echoHeader {
		return r, errors.New("short ICMPv6 message")
	}
	r.icmpType, r.icmpCode = int(icmp[0]), int(icmp[1])
	switch r.icmpType {
	case icmp6EchoReply:
		r.echo = true
		r.id = binary.BigEndian.Uint16(icmp[4:])
		r.seq = binary.BigEndian.Uint16(icmp[6:])
		r.dst = r.from
		return r, nil
	case icmp6TimeExceed, icmp6Unreachable:
		q := icmp[echoHeader:]
		if len(q) < ipv6Header+echoHeader || q[0]>>4 != 6 || q[6] != protoICMPv6 || q[ipv6Header] != icmp6Echo {
			return r, errNotOurs
		}
		r.dst = netip.AddrFrom16([16]byte(q[24:40]))
		r.qTTL = int(q[7])
		r.qLen = len(q)
		r.id = binary.BigEndian.Uint16(q[ipv6Header+4:])
		r.seq = binary.BigEndian.Uint16(q[ipv6Header+6:])
		return r, nil
	}
	return r, errNotOurs
}
