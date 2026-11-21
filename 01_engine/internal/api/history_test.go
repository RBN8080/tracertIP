package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

func TestHistoryAndCaptures(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 10, 4, 23, 59, 58, 0, time.UTC)
	store, err := live.OpenStore(dir, live.DefaultCap, at)
	if err != nil {
		t.Fatal(err)
	}
	header := func() any { return model.Start{Type: model.TypeStart, Time: at, Target: tgt.String()} }
	oldProbe := model.Probe{Type: model.TypeProbe, Round: 4, TTL: 1, SendWall: at, Status: model.StatusReply,
		Replies: []model.Reply{{From: homeRouter.String(), RTTNS: 1000000, Raw: []byte("raw fixture packet")}}}
	endProbe := model.Probe{Type: model.TypeProbe, Round: 4, TTL: 2, SendWall: at.Add(40 * time.Millisecond), Status: model.StatusReply,
		Replies: []model.Reply{{From: tgt.String(), RTTNS: 20000000}}}
	unsent := model.Probe{Type: model.TypeProbe, Round: 5, TTL: 1, SendWall: at.Add(4 * time.Second), Status: model.StatusSendError}
	change := model.Event{Type: model.TypeEvent, State: model.StateConfirmed, Time: at.Add(2 * time.Second), ID: at.UnixNano(), Target: tgt.String(),
		Before: []int{accessASN, 64500}, After: []int{accessASN, 64510}}
	if err := store.Write(tgt, at, header, oldProbe); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(tgt, at.Add(3*time.Second), header, endProbe, unsent, change); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// A crash can leave an incomplete line in an older, uncompressed day.
	plain := filepath.Join(dir, live.TargetDir(tgt), at.Add(3*time.Second).Format(time.DateOnly)+".jsonl")
	f, err := os.OpenFile(plain, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{\"type\":\"probe\","); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = live.OpenStore(dir, live.DefaultCap, at.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	base, _ := testServer(t)
	cfg := base.cfg
	cfg.Store, cfg.NodeName = store, "measurement-fixture"
	cfg.Fleet = newFakeFleet() // the recorded target was removed from live monitoring
	ts := httptest.NewServer(New(cfg).Handler())
	t.Cleanup(ts.Close)

	status, body, _ := get(t, ts.URL+"/v1/history/targets")
	if status != http.StatusOK || !strings.Contains(body, tgt.String()) {
		t.Fatalf("historical target absent: %d %s", status, body)
	}
	from, to := at.Add(-time.Second), at.Add(5*time.Second)
	params := url.Values{"target": {tgt.String()}, "from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
	status, body, _ = get(t, ts.URL+"/v1/history?"+params.Encode())
	var data historyView
	if err := json.Unmarshal([]byte(body), &data); status != http.StatusOK || err != nil || len(data.Rounds) != 2 || len(data.Events) != 1 {
		t.Fatalf("history: %d %s (%v)", status, body, err)
	}
	if len(data.Rounds[0].Hops) != 2 || data.Rounds[1].Hops[0].Status != model.StatusSendError || data.Node != cfg.NodeName {
		t.Fatalf("wrong rounds or metadata: %s", body)
	}
	if !data.Events[0].ObservedAt.Equal(at) || data.Events[0].Time.Equal(at) {
		t.Fatalf("wrong timestamps for route change: %+v", data.Events[0])
	}
	params.Set("from", at.Add(-2*time.Hour).Format(time.RFC3339Nano))
	if status, _, _ := get(t, ts.URL+"/v1/history?"+params.Encode()); status != http.StatusBadRequest {
		t.Fatalf("long interval returned %d", status)
	}

	request := func(note string) string {
		b, err := json.Marshal(map[string]any{"target": tgt.String(), "from": from, "to": to, "note": note})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	create := func(suffix, note string) captureInfo {
		t.Helper()
		code, body := send(t, "POST", ts.URL+"/v1/captures"+suffix, "application/json", ts.URL, request(note))
		var info captureInfo
		if err := json.Unmarshal([]byte(body), &info); code != http.StatusCreated || err != nil || !captureID.MatchString(info.ID) {
			t.Fatalf("create capture: %d %s (%v)", code, body, err)
		}
		return info
	}
	if code, _ := send(t, "POST", ts.URL+"/v1/captures", "application/json", "http://example.org", request("")); code != http.StatusForbidden {
		t.Fatalf("cross-origin save returned %d", code)
	}
	if code, _ := send(t, "POST", ts.URL+"/v1/captures?public=1", "application/json", ts.URL, request("nota privada")); code != http.StatusBadRequest {
		t.Fatalf("public capture accepted a note: %d", code)
	}
	private := create("", "Nota de medición")
	pub := create("?public=1", "")
	if !pub.Public || pub.Node != "" || private.Note == "" {
		t.Fatalf("capture metadata: private=%+v public=%+v", private, pub)
	}
	if code, _, _ := get(t, ts.URL+"/v1/captures/"+private.ID+"/export/jsonl?public=1"); code != http.StatusNotFound {
		t.Fatalf("public export exposed private capture: %d", code)
	}
	if code, body, _ := get(t, ts.URL+"/v1/captures?public=1"); code != http.StatusOK ||
		strings.Contains(body, private.ID) || !strings.Contains(body, pub.ID) {
		t.Fatalf("public capture list: %d %s", code, body)
	}

	// A restart with a smaller cap rotates old days but leaves saved snapshots.
	rotated, err := live.OpenStore(dir, 1, at.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Close()
	if targets, err := rotated.HistoryTargets(); err != nil || len(targets) != 0 {
		t.Fatalf("raw days did not rotate: %v, %v", targets, err)
	}
	for format, prefix := range map[string]string{"pdf": "%PDF-", "csv": "record_type,target", "jsonl": "{"} {
		ep := ts.URL + "/v1/captures/" + pub.ID + "/export/" + format + "?public=1"
		code, body, headers := get(t, ep)
		if code != http.StatusOK || !strings.HasPrefix(body, prefix) || !strings.Contains(headers.Get("Content-Disposition"), "."+format) {
			t.Fatalf("%s: %d (%d bytes, header %v)", format, code, len(body), headers)
		}
		if strings.Contains(body, homeRouter.String()) || strings.Contains(body, cfg.NodeName) || strings.Contains(body, "AS64496") {
			t.Fatalf("%s public output shows a private identifier", format)
		}
	}
	code, body, _ := get(t, ts.URL+"/v1/captures/"+private.ID+"/export/jsonl")
	if code != http.StatusOK || !strings.Contains(body, "Nota de medición") || !strings.Contains(body, homeRouter.String()) || strings.Contains(body, "raw fixture packet") {
		t.Fatalf("private JSONL export: %d %s", code, body)
	}
}
