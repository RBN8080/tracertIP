package api

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/route"
)

// Window bounds, in rounds.
const (
	DefaultRounds = 30               // one minute, the window of trace -watch
	MaxEvents     = 1000             // what the event log keeps
	healthEvery   = 10 * time.Second // health on the stream
	requestWait   = 10 * time.Second // judging may wait for names and IPmap
)

// The live view is built into the binary (00_IDEA 5: go:embed): HTML,
// CSS and JavaScript of our own, drawing on Canvas, nothing from elsewhere.
//
//go:embed ui
var embedded embed.FS

var uiFiles, _ = fs.Sub(embedded, "ui")

// Target is one monitored target as the server sees it.
type Target struct {
	Monitor *live.Monitor
	Path    func() []int // the established AS path
}

// Node is the measuring host's own health.
type Node struct {
	Version     string  `json:"version"`
	ClockSynced bool    `json:"clock_synced"`
	TempC       float64 `json:"temp_c,omitempty"`
	DiskFreeMB  int64   `json:"disk_free_mb,omitempty"`
}

// Config wires the server to the running engine.
type Config struct {
	Targets []Target
	Events  *route.Log
	Node    func() Node
	// Hops judges a target's rounds as the trace command would.
	Hops func(ctx context.Context, target netip.Addr, rounds []live.Round, public bool) (any, error)
	// Home says whether an address is on the home side: special-purpose or
	// the access ISP's. Unknown addresses must count as home (fail-safe).
	Home      func(netip.Addr) bool
	AccessASN int
	Hub       *Hub
}

// Server serves Config over HTTP.
type Server struct {
	cfg     Config
	targets map[netip.Addr]Target
}

// New builds the server; Publish and Run feed its stream.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg, targets: map[netip.Addr]Target{}}
	for _, t := range cfg.Targets {
		s.targets[t.Monitor.Target] = t
	}
	return s
}

// CheckListen refuses addresses reachable from outside the LAN: only an
// explicit loopback or private address (RFC 1918, RFC 4193) will do. The
// node has a global IPv6 address, so "all interfaces" is never allowed.
func CheckListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("listen: %q is not an IP address", host)
	}
	if !ip.IsLoopback() && !ip.IsPrivate() {
		return fmt.Errorf("listen: %s is not a loopback or private address: the API is for the LAN only", ip)
	}
	return nil
}

// Handler routes /v1. Every route is GET; anything else is 405.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	quick := func(h http.HandlerFunc) http.Handler {
		return http.TimeoutHandler(s.guard(h), requestWait, "timeout\n")
	}
	mux.Handle("GET /v1/health", quick(s.health))
	mux.Handle("GET /v1/targets", quick(s.targetList))
	mux.Handle("GET /v1/targets/{addr}/window", quick(s.window))
	mux.Handle("GET /v1/targets/{addr}/rounds", quick(s.rounds))
	mux.Handle("GET /v1/targets/{addr}/hops", quick(s.hops))
	mux.Handle("GET /v1/events", quick(s.events))
	mux.Handle("GET /v1/stream", s.guard(s.stream)) // long-lived: no timeout handler, it would break flushing
	mux.Handle("GET /", http.FileServerFS(uiFiles))
	return headers(mux)
}

// HTTPServer bounds what a client may hold (Nygard: timeouts on all I/O).
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
}

func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Cache-Control", "no-store")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'")
		h.ServeHTTP(w, r)
	})
}

func public(r *http.Request) bool { return r.URL.Query().Get("public") == "1" }

// errNoAccessASN: without the access ISP's AS the server cannot tell its
// routers apart, so a public view would show them. It is refused instead
// of degraded (P5).
const errNoAccessASN = "public view needs access_asn in the configuration"

// guard refuses a public request the server cannot honour.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if public(r) && s.cfg.AccessASN == 0 {
			fail(w, http.StatusServiceUnavailable, errNoAccessASN)
			return
		}
		h(w, r)
	}
}

// list keeps an empty answer a JSON array, never null.
func list[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	http.Error(w, msg, code)
}

// intParam reads a bounded integer query parameter.
func intParam(r *http.Request, name string, def, lo, hi int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be %d-%d", name, lo, hi)
	}
	return n, nil
}

func (s *Server) target(w http.ResponseWriter, r *http.Request) (Target, bool) {
	a, err := netip.ParseAddr(r.PathValue("addr"))
	t, ok := s.targets[a.Unmap()]
	if err != nil || !ok {
		fail(w, http.StatusNotFound, "not a monitored target")
		return Target{}, false
	}
	return t, true
}

// path drops the access ISP's AS in public form (5.ter).
func (s *Server) path(p []int, pub bool) []int {
	if !pub || s.cfg.AccessASN == 0 {
		return p
	}
	return slices.DeleteFunc(slices.Clone(p), func(a int) bool { return a == s.cfg.AccessASN })
}

func (s *Server) addr(a netip.Addr, pub bool) string {
	if !a.IsValid() || pub && s.cfg.Home(a) {
		return ""
	}
	return a.String()
}

type healthView struct {
	Node    Node          `json:"node"`
	Targets []live.Health `json:"targets"`
}

func (s *Server) healthNow() healthView {
	v := healthView{Node: s.cfg.Node(), Targets: []live.Health{}}
	for _, t := range s.cfg.Targets {
		v.Targets = append(v.Targets, t.Monitor.Health())
	}
	return v
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.healthNow()) }

type targetView struct {
	Target string          `json:"target"`
	State  string          `json:"state"`
	Path   []int           `json:"path"`
	Last   *live.HopWindow `json:"last,omitempty"` // the target over the last minute
}

func (s *Server) targetList(w http.ResponseWriter, r *http.Request) {
	pub := public(r)
	var out []targetView
	for _, t := range s.cfg.Targets {
		v := targetView{Target: t.Monitor.Target.String(), State: t.Monitor.Health().State, Path: list(s.path(t.Path(), pub))}
		for _, h := range live.Window(t.Monitor.Ring.Last(DefaultRounds)) {
			if h.Addr == v.Target { // the first TTL that reaches it: its distance
				v.Last = &h
				break
			}
		}
		out = append(out, v)
	}
	writeJSON(w, list(out))
}

func (s *Server) window(w http.ResponseWriter, r *http.Request) {
	t, ok := s.target(w, r)
	if !ok {
		return
	}
	n, err := intParam(r, "rounds", DefaultRounds, 1, live.RingRounds)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	win := live.Window(t.Monitor.Ring.Last(n))
	pub := public(r)
	for i := range win {
		if a, err := netip.ParseAddr(win[i].Addr); err == nil {
			win[i].Addr = s.addr(a, pub)
		}
	}
	writeJSON(w, list(win))
}

// roundView is a round as the stream and /rounds send it.
type roundView struct {
	Type   string      `json:"type"` // "round"
	Target string      `json:"target"`
	N      int         `json:"n"`
	Start  time.Time   `json:"start"`
	Hops   []hopSample `json:"hops"`
}

type hopSample struct {
	TTL   int      `json:"ttl"`
	Addr  string   `json:"addr,omitempty"`
	RTTms *float64 `json:"rtt_ms,omitempty"` // absent: no reply, never 0
}

func (s *Server) roundView(r live.Round, pub bool) roundView {
	v := roundView{Type: "round", Target: r.Target.String(), N: r.N, Start: r.Start.UTC(), Hops: make([]hopSample, len(r.Samples))}
	for i, x := range r.Samples {
		v.Hops[i] = hopSample{TTL: x.TTL, Addr: s.addr(x.From, pub)}
		if x.RTTms >= 0 {
			v.Hops[i].RTTms = new(x.RTTms)
		}
	}
	return v
}

func (s *Server) rounds(w http.ResponseWriter, r *http.Request) {
	t, ok := s.target(w, r)
	if !ok {
		return
	}
	n, err := intParam(r, "n", DefaultRounds, 1, live.RingRounds)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	pub := public(r)
	var out []roundView
	for _, x := range t.Monitor.Ring.Last(n) {
		out = append(out, s.roundView(x, pub))
	}
	writeJSON(w, list(out))
}

func (s *Server) hops(w http.ResponseWriter, r *http.Request) {
	t, ok := s.target(w, r)
	if !ok {
		return
	}
	n, err := intParam(r, "rounds", DefaultRounds, 1, live.RingRounds)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	recs, err := s.cfg.Hops(r.Context(), t.Monitor.Target, t.Monitor.Ring.Last(n), public(r))
	if err != nil {
		fail(w, http.StatusInternalServerError, "judging failed")
		return
	}
	writeJSON(w, recs)
}

func (s *Server) eventView(e model.Event, pub bool) model.Event {
	e.Before, e.After = s.path(e.Before, pub), s.path(e.After, pub)
	return e
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	n, err := intParam(r, "n", 100, 1, MaxEvents)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	pub := public(r)
	evs := s.cfg.Events.Last(n)
	for i := range evs {
		evs[i] = s.eventView(evs[i], pub)
	}
	writeJSON(w, list(evs))
}

// sse frames one message: "event: <kind>" and one line of JSON.
func sse(kind string, v any) []byte {
	b, _ := json.Marshal(v)
	return append(append([]byte("event: "+kind+"\ndata: "), b...), '\n', '\n')
}

// PublishRound sends a finished round to the stream. It never blocks.
func (s *Server) PublishRound(r live.Round) {
	s.cfg.Hub.Publish(sse("round", s.roundView(r, false)), sse("round", s.roundView(r, true)))
}

// PublishEvents sends route events to the stream.
func (s *Server) PublishEvents(evs []model.Event) {
	for _, e := range evs {
		s.cfg.Hub.Publish(sse("event", s.eventView(e, false)), sse("event", s.eventView(e, true)))
	}
}

// Run sends the health to the stream every healthEvery until ctx ends.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(healthEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h := sse("health", s.healthNow())
			s.cfg.Hub.Publish(h, h)
		}
	}
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	ch, cancel, ok := s.cfg.Hub.Subscribe(public(r))
	if !ok {
		fail(w, http.StatusServiceUnavailable, "too many live viewers")
		return
	}
	defer cancel()
	rc.SetReadDeadline(time.Time{}) // the server's read timeout would end a live stream
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(sse("health", s.healthNow()))
	rc.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, open := <-ch:
			if !open {
				return // fell behind: the browser reconnects by itself
			}
			if _, err := w.Write(msg); err != nil {
				return
			}
			rc.Flush()
		}
	}
}
