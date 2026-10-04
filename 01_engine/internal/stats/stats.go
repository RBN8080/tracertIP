// Package stats summarises RTT samples over a window: percentiles from a
// histogram, never averaged (Tene, "How NOT to Measure Latency"; 00_IDEA 4,
// A1), loss and bursts (RFC 7680) and jitter (RFC 3550 6.4.1). A percentile
// that the samples cannot support is absent, never 0 (P5).
package stats

import "math"

// Histogram buckets: logarithmic, each 1 % wider than the one before, from
// 10 µs to 100 s; any value is reported within 1 % of itself. 1 621 buckets
// (about 6 KB) hold any window in fixed memory and merge exactly.
const (
	histMinMS   = 0.01
	histMaxMS   = 100_000
	histRelErr  = 0.01
	histBuckets = 1621 // ceil(ln(histMaxMS/histMinMS) / ln(1+histRelErr)) + 1
)

var logStep = math.Log1p(histRelErr)

// Histogram counts RTTs in milliseconds.
type Histogram struct {
	counts   [histBuckets]uint32
	n        uint64
	min, max float64
}

func bucket(ms float64) int {
	if ms <= histMinMS {
		return 0
	}
	return min(histBuckets-1, int(math.Log(ms/histMinMS)/logStep)+1)
}

// upper is the largest value bucket i holds.
func upper(i int) float64 { return histMinMS * math.Exp(float64(i)*logStep) }

// Add counts one RTT; a negative one (no reply) is not an RTT.
func (h *Histogram) Add(ms float64) {
	if ms < 0 || math.IsNaN(ms) {
		return
	}
	if h.n == 0 || ms < h.min {
		h.min = ms
	}
	if h.n == 0 || ms > h.max {
		h.max = ms
	}
	h.counts[bucket(ms)]++
	h.n++
}

// Merge adds o's counts: the percentiles of the union, exactly as if every
// sample had been added here.
func (h *Histogram) Merge(o *Histogram) {
	if o.n == 0 {
		return
	}
	if h.n == 0 || o.min < h.min {
		h.min = o.min
	}
	if h.n == 0 || o.max > h.max {
		h.max = o.max
	}
	for i, c := range o.counts {
		h.counts[i] += c
	}
	h.n += o.n
}

// Count is how many RTTs the histogram holds.
func (h *Histogram) Count() uint64 { return h.n }

// Quantile is the nearest-rank q-quantile (0 < q ≤ 1), within 1 %, kept
// inside the observed range. It is absent when the samples are too few to
// support it (MinSamples).
func (h *Histogram) Quantile(q float64) (float64, bool) {
	if h.n == 0 || q <= 0 || q > 1 || h.n < MinSamples(q) {
		return 0, false
	}
	rank := uint64(math.Ceil(q * float64(h.n)))
	var seen uint64
	for i, c := range h.counts {
		seen += uint64(c)
		if seen >= rank {
			return math.Min(math.Max(upper(i), h.min), h.max), true
		}
	}
	return h.max, true
}

// Confidence is how sure a percentile from the window's maximum must be.
const Confidence = 0.95

// MinSamples is the fewest samples whose maximum exceeds the true
// q-quantile with probability Confidence: n ≥ ln(1−γ)/ln(q) (Wilks, Ann.
// Math. Statist., 1941). The median needs 5, p95 needs 59, p99 needs 299.
func MinSamples(q float64) uint64 {
	if q >= 1 {
		return math.MaxUint64
	}
	return uint64(math.Ceil(math.Log(1-Confidence) / math.Log(q)))
}

// Summary describes a window of probes in time order.
type Summary struct {
	Sent     int      `json:"sent"`
	Replied  int      `json:"replied"`
	LossPct  *float64 `json:"loss_pct,omitempty"`
	MaxBurst int      `json:"max_burst"` // longest run of probes without a reply (RFC 7680 3.4)
	MinMS    *float64 `json:"min_ms,omitempty"`
	P50MS    *float64 `json:"p50_ms,omitempty"`
	P95MS    *float64 `json:"p95_ms,omitempty"`
	P99MS    *float64 `json:"p99_ms,omitempty"`
	MaxMS    *float64 `json:"max_ms,omitempty"`
	// JitterMS is RFC 3550's smoothed estimator over consecutive RTTs: a
	// round trip stands in for the one-way transit RTP compares.
	JitterMS *float64 `json:"jitter_ms,omitempty"`
}

// Summarize takes RTTs in time order; a negative one is a probe without a
// reply.
func Summarize(rtts []float64) Summary {
	var s Summary
	var h Histogram
	burst, jitter, prev := 0, 0.0, -1.0
	pairs := 0
	for _, r := range rtts {
		s.Sent++
		if r < 0 {
			burst++
			s.MaxBurst = max(s.MaxBurst, burst)
			continue
		}
		burst = 0
		s.Replied++
		h.Add(r)
		if prev >= 0 {
			jitter += (math.Abs(r-prev) - jitter) / 16
			pairs++
		}
		prev = r
	}
	if s.Sent > 0 {
		s.LossPct = new(100 * float64(s.Sent-s.Replied) / float64(s.Sent))
	}
	if h.n > 0 {
		s.MinMS, s.MaxMS = new(h.min), new(h.max)
	}
	for q, dst := range map[float64]**float64{0.5: &s.P50MS, 0.95: &s.P95MS, 0.99: &s.P99MS} {
		if v, ok := h.Quantile(q); ok {
			*dst = new(v)
		}
	}
	if pairs > 0 {
		s.JitterMS = new(jitter)
	}
	return s
}
