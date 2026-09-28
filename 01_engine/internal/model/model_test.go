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
		"probe": Probe{}, "reply": Reply{}, "end": End{},
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
