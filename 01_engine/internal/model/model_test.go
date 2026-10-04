package model

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The JSON Schema must list exactly the fields the Go types write.
func TestSchemaMatchesTypes(t *testing.T) {
	b, err := os.ReadFile("../../schema/trace.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for def, typ := range map[string]any{
		"start": Start{}, "params": Params{}, "base": Base{},
		"probe": Probe{}, "reply": Reply{}, "end": End{}, "event": Event{},
	} {
		want := keys(s.Defs[def].Properties)
		got := jsonNames(reflect.TypeOf(typ))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: Go fields %v, schema properties %v", def, got, want)
		}
	}
}

func TestProbeRoundTrip(t *testing.T) {
	in := Probe{
		V: SchemaVersion, Type: TypeProbe, Round: 2, TTL: 7, ICMPID: 4660, Seq: 135, FlowID: 51966,
		SendWall: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), SendMonoNS: 123,
		Status:  StatusReply,
		Replies: []Reply{{From: "192.0.2.1", ICMPType: 11, IPTTL: 250, QTTL: 1, Raw: []byte{11, 0, 1, 2}}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Probe
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip changed the record:\n in %+v\nout %+v", in, out)
	}
}

// An RTT that was not measured is absent, never 0 (P5).
func TestEventUnmeasuredRTT(t *testing.T) {
	rtt := 97.4
	for _, tc := range []struct {
		name   string
		before *float64
		want   string
	}{
		{"measured", &rtt, `"rtt_before_ms":97.4`},
		{"not measured", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(Event{V: SchemaVersion, Type: TypeEvent, Kind: EventRouteChange, State: StateProvisional,
				Before: []int{64500, 64501}, After: []int{64500, 64502}, RTTBeforeMS: tc.before})
			if err != nil {
				t.Fatal(err)
			}
			has := strings.Contains(string(b), "rtt_before_ms")
			if tc.want == "" && has || tc.want != "" && !strings.Contains(string(b), tc.want) {
				t.Errorf("got %s", b)
			}
			if strings.Contains(string(b), "rtt_after_ms") {
				t.Errorf("unmeasured rtt_after_ms written: %s", b)
			}
		})
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonNames(t reflect.Type) []string {
	var out []string
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
