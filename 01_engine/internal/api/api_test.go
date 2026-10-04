package api

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/route"
)

// first is a prefix's first host: test addresses come from CIDR notation,
// so no home-like host address enters the public repository (5.ter).
func first(prefix string) netip.Addr { return netip.MustParsePrefix(prefix).Addr().Next() }

func TestCheckListen(t *testing.T) {
	lan := netip.AddrPortFrom(first("192.168.0.0/16"), 8080).String()
	for addr, ok := range map[string]bool{
		lan: true, "127.0.0.1:8080": true, "[fd00::1]:8080": true,
		"0.0.0.0:8080": false, "[::]:8080": false, "8.8.8.8:8080": false, "[2001:db8::1]:8080": false,
		"node.lan:8080": false, first("192.168.0.0/16").String(): false,
	} {
		if err := CheckListen(addr); (err == nil) != ok {
			t.Errorf("CheckListen(%q) = %v, want ok=%t", addr, err, ok)
		}
	}
}

// The addresses of the home side, the access ISP and its AS must never
// reach public output (00_IDEA 5.ter).
var (
	homeRouter = first("192.168.0.0/16")
	cgnat      = first("100.64.0.0/10")
	ispRouter  = netip.MustParseAddr("198.51.100.7")
	transit    = netip.MustParseAddr("203.0.113.9")
	tgt        = netip.MustParseAddr("192.0.2.99")
)

const accessASN = 64496

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	m := live.NewMonitor(tgt, live.Config{}, 1, 2)
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for n := range 40 {
		m.Ring.Add(live.Round{Target: tgt, N: n, Start: at.Add(time.Duration(n) * 2 * time.Second), Samples: []live.Sample{
			{TTL: 1, From: homeRouter, RTTms: 0.5}, {TTL: 2, From: cgnat, RTTms: 2}, {TTL: 3, From: ispRouter, RTTms: 4},
			{TTL: 4, From: transit, RTTms: 35}, {TTL: 5, RTTms: -1}, {TTL: 6, From: tgt, RTTms: 97},
		}})
	}
	asn := map[netip.Addr]int{ispRouter: accessASN, transit: 64500, tgt: 64510}
	events := route.NewLog(10)
	events.Add(model.Event{Type: model.TypeEvent, State: model.StateConfirmed, Target: tgt.String(),
		Before: []int{accessASN, 64500, 64510}, After: []int{accessASN, 64501, 64510}})
	s := New(Config{
		Targets: []Target{{Monitor: m, Path: func() []int { return []int{accessASN, 64500, 64510} }}},
		Events:  events, AccessASN: accessASN, Hub: NewHub(),
		Node: func() Node { return Node{Version: "test", ClockSynced: true} },
		Home: func(a netip.Addr) bool {
			n, ok := asn[a]
			return a.IsPrivate() || cgnatNet.Contains(a) || !ok || n == accessASN
		},
		Hops: func(_ context.Context, _ netip.Addr, rounds []live.Round, public bool) (any, error) {
			return map[string]any{"rounds": len(rounds), "public": public}, nil
		},
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

var cgnatNet = netip.MustParsePrefix("100.64.0.0/10")

func get(t *testing.T, url string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestRoutes(t *testing.T) {
	_, ts := testServer(t)
	for path, code := range map[string]int{
		"/v1/health": 200, "/v1/targets": 200, "/v1/events": 200, "/v1/targets/192.0.2.99/window": 200,
		"/v1/targets/192.0.2.99/rounds?n=5": 200, "/v1/targets/192.0.2.99/hops": 200,
		"/v1/targets/192.0.2.1/window": 404, "/v1/targets/x/window": 404,
		"/v1/targets/192.0.2.99/window?rounds=0": 400, "/v1/targets/192.0.2.99/window?rounds=1801": 400,
		"/v1/events?n=abc": 400, "/v1/nothing": 404,
	} {
		if got, body, _ := get(t, ts.URL+path); got != code {
			t.Errorf("GET %s = %d %q, want %d", path, got, body, code)
		}
	}
	resp, err := http.Post(ts.URL+"/v1/targets", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /v1/targets = %d, want 405: the API is read-only", resp.StatusCode)
	}
	_, _, h := get(t, ts.URL+"/v1/health")
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Security-Policy") == "" || h.Get("Cache-Control") != "no-store" {
		t.Errorf("security headers missing: %v", h)
	}
}

func TestPublicHidesHomeSide(t *testing.T) {
	_, ts := testServer(t)
	secrets := []string{homeRouter.String(), cgnat.String(), ispRouter.String(), "64496"}
	for _, path := range []string{"/v1/targets", "/v1/targets/192.0.2.99/window", "/v1/targets/192.0.2.99/rounds", "/v1/events"} {
		_, full, _ := get(t, ts.URL+path)
		_, pub, _ := get(t, ts.URL+path+"?public=1")
		for _, s := range secrets {
			if strings.Contains(pub, s) {
				t.Errorf("%s?public=1 shows %s: %s", path, s, pub)
			}
		}
		if !strings.Contains(pub, transit.String()) && path != "/v1/targets" && path != "/v1/events" {
			t.Errorf("%s?public=1 hides the transit hop too: %s", path, pub)
		}
		if !strings.Contains(full, "64496") && !strings.Contains(full, ispRouter.String()) {
			t.Errorf("%s without public hides the home side: %s", path, full)
		}
	}
	if _, body, _ := get(t, ts.URL+"/v1/targets/192.0.2.99/hops?public=1"); !strings.Contains(body, `"public":true`) {
		t.Errorf("hops did not ask the judge for public records: %s", body)
	}
}

// A round reaches a live viewer well within the 2 s of the exit criterion,
// in the form the viewer asked for; viewers beyond MaxStreams are refused.
func TestStream(t *testing.T) {
	s, ts := testServer(t)
	resp, err := http.Get(ts.URL + "/v1/stream?public=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	sent := time.Now()
	s.PublishRound(s.targets[tgt].Monitor.Ring.Last(1)[0])
	deadline := time.After(2 * time.Second)
	for {
		select {
		case l := <-lines:
			if !strings.HasPrefix(l, "data: ") || !strings.Contains(l, `"type":"round"`) {
				continue
			}
			if d := time.Since(sent); d > 2*time.Second {
				t.Errorf("round took %s", d)
			}
			for _, secret := range []string{homeRouter.String(), cgnat.String(), ispRouter.String()} {
				if strings.Contains(l, secret) {
					t.Errorf("public stream shows %s: %s", secret, l)
				}
			}
			goto viewers
		case <-deadline:
			t.Fatal("no round on the stream within 2 s")
		}
	}
viewers:
	var open []*http.Response
	defer func() {
		for _, r := range open {
			r.Body.Close()
		}
	}()
	for range MaxStreams - 1 {
		r, err := http.Get(ts.URL + "/v1/stream")
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, r)
	}
	r, err := http.Get(ts.URL + "/v1/stream")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("viewer %d got %d, want 503", MaxStreams+1, r.StatusCode)
	}
}

// The live view comes from the binary, with its own scripts only.
func TestUIServed(t *testing.T) {
	_, ts := testServer(t)
	code, body, h := get(t, ts.URL+"/")
	if code != 200 || !strings.Contains(body, `<script src="app.js"`) || strings.Contains(body, "<script>") {
		t.Errorf("GET / = %d: %.200s", code, body)
	}
	if h.Get("Content-Security-Policy") != "default-src 'self'" {
		t.Errorf("CSP %q", h.Get("Content-Security-Policy"))
	}
	for _, f := range []string{"/app.js", "/app.css"} {
		if code, body, _ := get(t, ts.URL+f); code != 200 || len(body) < 100 {
			t.Errorf("GET %s = %d (%d bytes)", f, code, len(body))
		}
	}
	if code, _, _ := get(t, ts.URL+"/../go.mod"); code == 200 {
		t.Error("files outside the view are served")
	}
}

// Empty answers are JSON arrays, and without the access ISP's AS a public
// view is refused rather than shown with the ISP's routers in it.
func TestEmptyAndRefusedPublic(t *testing.T) {
	m := live.NewMonitor(tgt, live.Config{}, 1, 2)
	s := New(Config{Targets: []Target{{Monitor: m, Path: func() []int { return nil }}}, Events: route.NewLog(5), Hub: NewHub(),
		Node: func() Node { return Node{} }, Home: func(netip.Addr) bool { return true }})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	for path, want := range map[string]string{"/v1/events": "[]", "/v1/targets/192.0.2.99/rounds": "[]", "/v1/targets/192.0.2.99/window": "[]"} {
		if _, body, _ := get(t, ts.URL+path); strings.TrimSpace(body) != want {
			t.Errorf("%s = %q, want %s", path, body, want)
		}
	}
	if _, body, _ := get(t, ts.URL+"/v1/targets"); !strings.Contains(body, `"path":[]`) {
		t.Errorf("targets before any path: %s", body)
	}
	for _, path := range []string{"/v1/targets?public=1", "/v1/stream?public=1", "/v1/events?public=1"} {
		if code, body, _ := get(t, ts.URL+path); code != http.StatusServiceUnavailable || !strings.Contains(body, "access_asn") {
			t.Errorf("%s = %d %q, want 503 naming access_asn", path, code, body)
		}
	}
}
