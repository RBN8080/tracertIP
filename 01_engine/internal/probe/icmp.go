package probe

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ICMP types handled by the probe (RFC 792).
const (
	icmpEchoReply   = 0
	icmpUnreachable = 3
	icmpEcho        = 8
	icmpTimeExceed  = 11
)

const (
	protoICMP   = 1
	echoHeader  = 8  // type, code, checksum, identifier, sequence
	payloadLen  = 32 // 2-byte Paris balance word + fixed pattern
	ttlBits     = 6  // seq = round<<ttlBits | ttl; TTL max 40 < 64
	ttlMask     = 1<<ttlBits - 1
	maxRoundSeq = 1 << (16 - ttlBits)
)

// seqFor packs round and TTL into the ICMP sequence number.
func seqFor(round, ttl int) uint16 {
	return uint16((round%maxRoundSeq)<<ttlBits | ttl&ttlMask)
}

// splitSeq is the inverse of seqFor (round modulo maxRoundSeq).
func splitSeq(seq uint16) (round, ttl int) {
	return int(seq >> ttlBits), int(seq & ttlMask)
}

// sum16 is the one's complement sum of b as big-endian 16-bit words.
func sum16(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s&0xffff + s>>16
	}
	return s
}

// echoRequest builds a Paris-style ICMP Echo: type, code, identifier and
// checksum stay constant across probes (the flow a load balancer hashes);
// only the sequence varies, and the first payload word compensates it
// (Augustin et al., IMC 2006; paris-traceroute ICMPProbe.cc).
func echoRequest(id, seq, checksum uint16) []byte {
	b := make([]byte, echoHeader+payloadLen)
	b[0] = icmpEcho
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	for i := echoHeader + 2; i < len(b); i++ {
		b[i] = byte(i)
	}
	// With the checksum field and the balance word at zero, the sum is s.
	// The balance word w must make s+w equal ^checksum (one's complement).
	s := sum16(b)
	w := uint32(^checksum) + (^s & 0xffff)
	for w > 0xffff {
		w = w&0xffff + w>>16
	}
	binary.BigEndian.PutUint16(b[echoHeader:], uint16(w))
	binary.BigEndian.PutUint16(b[2:], checksum)
	return b
}

// checksumOK reports whether an ICMP message verifies (RFC 792).
func checksumOK(icmp []byte) bool {
	return sum16(icmp) == 0xffff
}

// reply is one ICMP message parsed from a whole IPv4 packet.
type reply struct {
	from     netip.Addr
	ipTTL    int
	ipID     int
	ipLen    int
	icmpType int
	icmpCode int
	echo     bool   // an Echo Reply (ICMP 0, ICMPv6 129): the target answered
	id       uint16 // identifier of the probe it answers
	seq      uint16 // sequence of the probe it answers
	dst      netip.Addr
	qTTL     int // TTL in the quoted header (Time Exceeded, Unreachable)
	qIPID    int
	qLen     int
	icmp     []byte // the whole ICMP message
}

var errNotOurs = errors.New("not a reply to an echo probe")

// parseReply reads a whole IPv4 packet carrying ICMP. Only Echo Reply, Time
// Exceeded and Destination Unreachable are accepted; for the last two the
// quoted header and the first 8 bytes of the probe identify it (RFC 792,
// RFC 1812 4.3.2.3).
func parseReply(pkt []byte) (reply, error) {
	var r reply
	ihl, err := ipv4Header(pkt)
	if err != nil {
		return r, err
	}
	if pkt[9] != protoICMP {
		return r, errNotOurs
	}
	r.from = netip.AddrFrom4([4]byte(pkt[12:16]))
	r.ipTTL = int(pkt[8])
	r.ipID = int(binary.BigEndian.Uint16(pkt[4:]))
	r.ipLen = len(pkt)
	icmp := pkt[ihl:]
	if len(icmp) < echoHeader {
		return r, errors.New("short ICMP message")
	}
	r.icmp = icmp
	r.icmpType, r.icmpCode = int(icmp[0]), int(icmp[1])
	switch r.icmpType {
	case icmpEchoReply:
		r.echo = true
		r.id = binary.BigEndian.Uint16(icmp[4:])
		r.seq = binary.BigEndian.Uint16(icmp[6:])
		r.dst = r.from
		return r, nil
	case icmpTimeExceed, icmpUnreachable:
		q := icmp[echoHeader:]
		qihl, err := ipv4Header(q)
		if err != nil {
			return r, err
		}
		if q[9] != protoICMP || len(q) < qihl+echoHeader || q[qihl] != icmpEcho {
			return r, errNotOurs
		}
		r.dst = netip.AddrFrom4([4]byte(q[16:20]))
		r.qTTL = int(q[8])
		r.qIPID = int(binary.BigEndian.Uint16(q[4:]))
		r.qLen = len(q)
		r.id = binary.BigEndian.Uint16(q[qihl+4:])
		r.seq = binary.BigEndian.Uint16(q[qihl+6:])
		return r, nil
	}
	return r, errNotOurs
}

// ipv4Header validates an IPv4 header and returns its length in bytes.
func ipv4Header(b []byte) (int, error) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return 0, errors.New("not an IPv4 packet")
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return 0, errors.New("bad IPv4 header length")
	}
	return ihl, nil
}
