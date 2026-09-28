// Package model defines the versioned records the engine writes as JSON Lines.
//
// Probe records are the raw, durable truth; everything else is derived and
// can be recomputed from them. Adding a field keeps SchemaVersion; renaming or
// removing one bumps it. Readers must ignore unknown fields.
package model

import "time"

// SchemaVersion is the "v" of every record (see schema/trace.v1.schema.json).
const SchemaVersion = 1

// Record types.
const (
	TypeStart = "start"
	TypeProbe = "probe"
	TypeEnd   = "end"
)

// Probe status values. A probe without a reply is a gap, never a 0 ms RTT.
const (
	StatusReply     = "reply"
	StatusNoReply   = "no_reply"
	StatusSendError = "send_error"
)

// Start opens a trace.
type Start struct {
	V       int       `json:"v"`
	Type    string    `json:"type"`
	Tool    string    `json:"tool"`
	Version string    `json:"version"`
	Time    time.Time `json:"time"`
	Target  string    `json:"target"`
	Method  string    `json:"method"`
	Params  Params    `json:"params"`
	Bases   []Base    `json:"bases,omitempty"`
}

// Params are the probing parameters in effect (1.bis frontier).
type Params struct {
	TTLMax          int `json:"ttl_max"`
	TimeoutMS       int `json:"timeout_ms"`
	RoundIntervalMS int `json:"round_interval_ms"`
	ProbeSpacingMS  int `json:"probe_spacing_ms"`
	Rounds          int `json:"rounds"`
	ICMPID          int `json:"icmp_id"`
	FlowID          int `json:"flow_id"`
}

// Base identifies a local IP database used for enrichment.
type Base struct {
	Name   string    `json:"name"`
	Date   time.Time `json:"date"`
	SHA256 string    `json:"sha256"`
	Rows   int       `json:"rows"`
}

// Probe is one ICMP Echo sent with a given TTL, and every reply it drew.
type Probe struct {
	V          int       `json:"v"`
	Type       string    `json:"type"`
	Round      int       `json:"round"`
	TTL        int       `json:"ttl"`
	ICMPID     int       `json:"icmp_id"`
	Seq        int       `json:"seq"`
	FlowID     int       `json:"flow_id"`
	SendWall   time.Time `json:"t_send_wall"`
	SendMonoNS int64     `json:"t_send_mono_ns"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	Replies    []Reply   `json:"replies,omitempty"`
}

// Reply is one ICMP message matched to a probe. Q* fields come from the IP
// header quoted inside Time Exceeded and Destination Unreachable messages.
type Reply struct {
	RecvWall time.Time `json:"t_recv_wall"`
	RTTNS    int64     `json:"rtt_ns"`
	Late     bool      `json:"late,omitempty"`
	From     string    `json:"from"`
	ICMPType int       `json:"icmp_type"`
	ICMPCode int       `json:"icmp_code"`
	IPTTL    int       `json:"ip_ttl"`
	IPID     int       `json:"ip_id"`
	IPLen    int       `json:"ip_len"`
	QTTL     int       `json:"q_ttl,omitempty"`
	QIPID    int       `json:"q_ip_id,omitempty"`
	QLen     int       `json:"q_len,omitempty"`
	Raw      []byte    `json:"raw"`
}

// End closes a trace.
type End struct {
	V          int       `json:"v"`
	Type       string    `json:"type"`
	Time       time.Time `json:"time"`
	Reached    bool      `json:"reached"`
	Hops       int       `json:"hops"`
	Probes     int       `json:"probes"`
	NoReply    int       `json:"no_reply"`
	DurationMS int64     `json:"duration_ms"`
}
