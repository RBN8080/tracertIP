package ipdb

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic data only: documentation ranges (RFC 5737) and ASNs (RFC 5398).
const tsv = "192.0.2.0\t192.0.2.255\t64496\tZZ\tEXAMPLE-A\n" +
	"198.51.100.0\t198.51.100.255\t0\tNone\tNot routed\n" +
	"2001:db8::\t2001:db8::ffff\t64497\tZZ\tEXAMPLE-V6\n" +
	"203.0.113.0\t203.0.113.255\t64498\tZZ\tEXAMPLE-B\n"

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	io.WriteString(w, s)
	w.Close()
	return b.Bytes()
}

func testSource(u string) Source {
	s := Sources()[0] // iptoasn
	s.URL = fixed(u)
	s.MinRows = 1
	return s
}

func server(t *testing.T, body func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(body))
	t.Cleanup(srv.Close)
	c := srv.Client()
	c.CheckRedirect = NewClient(time.Minute).CheckRedirect
	return srv, c
}

func TestReaders(t *testing.T) {
	var got []ASNRange
	n, err := ReadIPtoASN(strings.NewReader(tsv), func(r ASNRange) error { got = append(got, r); return nil })
	if err != nil || n != 4 || got[1].ASN != 0 || got[2].Name != "EXAMPLE-V6" || got[3].Name != "EXAMPLE-B" {
		t.Errorf("iptoasn: %d rows, %v, %+v", n, err, got)
	}
	for name, bad := range map[string]string{
		"asn":   "192.0.2.0\t192.0.2.255\tAS1\tZZ\tX\n",
		"range": "192.0.2.9\t192.0.2.1\t1\tZZ\tX\n",
		"cols":  "192.0.2.0\t192.0.2.255\t1\n",
	} {
		if _, err := ReadIPtoASN(strings.NewReader(bad), func(ASNRange) error { return nil }); err == nil {
			t.Errorf("iptoasn %s: accepted", name)
		}
	}

	city := "192.0.2.0,192.0.2.255,NA,ZZ,Region,Town,19.43,-99.13\n"
	var c []CityRange
	if n, err := ReadDBIPCity(strings.NewReader(city), func(r CityRange) error { c = append(c, r); return nil }); err != nil || n != 1 || c[0].City != "Town" {
		t.Errorf("dbip-city: %d, %v, %+v", n, err, c)
	}
	if _, err := ReadDBIPCity(strings.NewReader(strings.Replace(city, "19.43", "99.9", 1)), func(CityRange) error { return nil }); err == nil {
		t.Error("dbip-city: latitude 99.9 accepted")
	}

	ipinfo := "network,country,country_code,continent,continent_code,asn,as_name,as_domain\n" +
		"192.0.2.0/24,X,ZZ,Y,YY,AS64496,EXAMPLE,example.com\n192.0.2.7,X,ZZ,Y,YY,AS64497,E2,e.com\n" +
		"198.51.100.0/24,X,ZZ,Y,YY,,,\n"
	var p []ASNRange
	if n, err := ReadIPinfoLite(strings.NewReader(ipinfo), func(r ASNRange) error { p = append(p, r); return nil }); err != nil || n != 2 ||
		p[0].Hi.String() != "192.0.2.255" || p[1].Lo != p[1].Hi {
		t.Errorf("ipinfo: %d, %v, %+v", n, err, p)
	}

	air := `"id","ident","type","name","latitude_deg","longitude_deg","elevation_ft","continent","iso_country","iso_region","municipality","scheduled_service","icao_code","iata_code"` + "\n" +
		`1,"X","large_airport","Test Intl",33.94,-118.40,1,"NA","US","US-CA","Testville","yes","KXXX","TST"` + "\n" +
		`2,"Y","heliport","No Code",1,1,1,"NA","US","US-CA","Nowhere","no",,` + "\n"
	var a []Airport
	if n, err := ReadAirports(strings.NewReader(air), func(r Airport) error { a = append(a, r); return nil }); err != nil || n != 1 || a[0].IATA != "tst" {
		t.Errorf("airports: %d, %v, %+v", n, err, a)
	}
}

func FuzzReadIPtoASN(f *testing.F) {
	f.Add(tsv)
	f.Fuzz(func(t *testing.T, s string) {
		ReadIPtoASN(strings.NewReader(s), func(r ASNRange) error {
			if r.Hi.Less(r.Lo) || r.Lo.Is4() != r.Hi.Is4() {
				t.Fatalf("bad range accepted: %+v", r)
			}
			return nil
		})
	})
}

func TestUpdate(t *testing.T) {
	body := gz(tsv)
	srv, c := server(t, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	dir := t.TempDir()
	src := testSource(srv.URL + "/ip2asn-v4.tsv.gz")
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

	e, err := Update(context.Background(), c, dir, src, Token{}, now)
	if err != nil || e.Rows != 4 || len(e.SHA256) != 64 {
		t.Fatalf("first update: %+v, %v", e, err)
	}
	good, _ := os.ReadFile(filepath.Join(dir, src.File))

	for name, bad := range map[string][]byte{
		"truncated gzip": body[:len(body)/2],
		"not gzip":       []byte(tsv),
		"malformed row":  gz(tsv + "x\ty\n"),
		"shrunk":         gz("192.0.2.0\t192.0.2.255\t64496\tZZ\tEXAMPLE-A\n"),
	} {
		body = bad
		if _, err := Update(context.Background(), c, dir, src, Token{}, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if cur, _ := os.ReadFile(filepath.Join(dir, src.File)); !bytes.Equal(cur, good) {
			t.Errorf("%s: replaced the good file", name)
		}
	}

	body = gz(tsv + "203.0.114.0\t203.0.114.255\t64499\tZZ\tEXAMPLE-C\n")
	if e, err := Update(context.Background(), c, dir, src, Token{}, now); err != nil || e.Rows != 5 {
		t.Fatalf("second good update: %+v, %v", e, err)
	}
	if prev, _ := os.ReadFile(filepath.Join(dir, src.File+".prev")); !bytes.Equal(prev, good) {
		t.Error("the previous file was not kept as .prev")
	}
	if m, _ := ReadManifest(dir); m["iptoasn"].Rows != 5 {
		t.Errorf("manifest %+v", m)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".download-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestUpdateCaps(t *testing.T) {
	body := gz(tsv)
	srv, c := server(t, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	src := testSource(srv.URL)
	src.MaxBytes = int64(len(body) - 1)
	if _, err := Update(context.Background(), c, t.TempDir(), src, Token{}, time.Now()); err == nil {
		t.Error("download over MaxBytes accepted")
	}
	src = testSource(srv.URL)
	src.MaxRaw = int64(len(tsv) - 1)
	if _, err := Update(context.Background(), c, t.TempDir(), src, Token{}, time.Now()); err == nil {
		t.Error("decompressed data over MaxRaw accepted")
	}
}

func TestPrevMonthFallback(t *testing.T) {
	srv, c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "2026-09") {
			http.NotFound(w, r)
			return
		}
		w.Write(gz(tsv))
	})
	src := testSource("")
	src.PrevMonth = true
	src.URL = func(now time.Time, _ Token) string { return srv.URL + "/db-" + now.Format("2006-01") }
	e, err := Update(context.Background(), c, t.TempDir(), src, Token{}, time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC))
	if err != nil || !strings.HasSuffix(e.URL, "2026-09") {
		t.Errorf("fallback: %+v, %v", e, err)
	}
}

func TestRedirectToHTTPRefused(t *testing.T) {
	srv, c := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/x", http.StatusFound)
	})
	if _, err := Update(context.Background(), c, t.TempDir(), testSource(srv.URL), Token{}, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "non-https") {
		t.Errorf("err = %v, want a refused redirect", err)
	}
}

// The token must not appear in errors, the manifest, fmt or slog output.
func TestTokenNeverPrinted(t *testing.T) {
	const secret = "s3cr3t-token-value"
	tok := Token{secret}
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "token", tok)
	out := fmt.Sprint(tok) + fmt.Sprintf("%v %+v %#v %s", tok, tok, tok, tok) + logs.String()

	fail := true
	srv, c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "nope "+r.URL.RawQuery, http.StatusForbidden)
			return
		}
		w.Write(gz(tsv))
	})
	src := testSource("")
	src.NeedsToken = true
	src.URL = func(_ time.Time, t Token) string { return srv.URL + "/db?token=" + t.reveal() }
	dir := t.TempDir()
	if _, err := Update(context.Background(), c, dir, src, tok, time.Now()); err != nil {
		out += err.Error()
	}
	fail = false
	if _, err := Update(context.Background(), c, dir, src, tok, time.Now()); err != nil {
		t.Fatal(err)
	}
	m, _ := os.ReadFile(filepath.Join(dir, manifestFile))
	out += string(m)
	if strings.Contains(out, secret) {
		t.Errorf("token leaked: %s", out)
	}
	if _, err := Update(context.Background(), c, dir, src, Token{}, time.Now()); err != ErrNoToken {
		t.Errorf("no token: err = %v, want ErrNoToken", err)
	}
}

func TestLoadToken(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	os.WriteFile(p, []byte("abc123\n"), 0o600)
	if tok, err := LoadToken(TokenOptions{File: p}); err != nil || tok.reveal() != "abc123" {
		t.Errorf("file: %v", err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if tok, err := LoadToken(TokenOptions{Credential: "tok"}); err != nil || tok.reveal() != "abc123" {
		t.Errorf("credential: %v", err)
	}
	if _, err := LoadToken(TokenOptions{Credential: "missing"}); err != ErrNoToken {
		t.Errorf("missing credential: %v", err)
	}
	if os.Getenv("OS") != "Windows_NT" {
		os.Chmod(p, 0o644)
		if _, err := LoadToken(TokenOptions{File: p}); err == nil {
			t.Error("world-readable token file accepted")
		}
	}
}

func TestAPIEtiquette(t *testing.T) {
	var ua string
	limited := true
	srv, c := server(t, func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		if limited {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write(gz(tsv))
	})
	dir := t.TempDir()
	src := testSource(srv.URL)
	src.MinAge = time.Hour
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	if _, err := Update(context.Background(), c, dir, src, Token{}, now); err == nil || !strings.Contains(err.Error(), "retry after 3600") {
		t.Errorf("429: err = %v, want the Retry-After value", err)
	}
	if !strings.HasPrefix(ua, "tracertip") {
		t.Errorf("User-Agent %q", ua)
	}
	limited = false
	if _, err := Update(context.Background(), c, dir, src, Token{}, now); err != nil {
		t.Fatal(err)
	}
	if due, _, _ := Due(dir, src, now.Add(30*time.Minute)); due {
		t.Error("due again before MinAge")
	}
	if due, _, _ := Due(dir, src, now.Add(2*time.Hour)); !due {
		t.Error("not due after MinAge")
	}
}

func TestReadAnycastCensus(t *testing.T) {
	csv := "prefix,number_of_sites,backing_prefix\n192.0.2.0/24,62,192.0.2.0/24\n2001:db8::/48,5,2001:db8::/48\n"
	var got []AnycastPrefix
	n, err := ReadAnycastCensus(strings.NewReader(csv), func(p AnycastPrefix) error { got = append(got, p); return nil })
	if err != nil || n != 2 || got[0].Sites != 62 || got[1].Prefix.String() != "2001:db8::/48" {
		t.Errorf("%d, %v, %+v", n, err, got)
	}
}

// census is a LACeS export: one prefix the latency method confirms, one only
// the anycast-based method sees, one unicast.
const census = "prefix,AB_ICMPv4,AB_TCPv4,AB_DNSv4,GCD_ICMPv4,GCD_TCPv4,partial,locations,backing_prefix,ASN\n" +
	`192.0.2.0/24,31,31,31,73,29,False,"[{""id"": ""1"", ""city"": ""X"", ""lat"": 1.5}]",192.0.2.0/24,64496` + "\n" +
	`198.51.100.0/24,5,0,0,1,1,False,"[]",198.51.100.0/23,64497` + "\n" +
	`203.0.113.0/24,0,0,0,1,0,False,"[]",203.0.113.0/24,64498` + "\n"

const censusKept = "prefix,number_of_sites,backing_prefix\n192.0.2.0/24,73,192.0.2.0/24\n"

func TestConvertAnycastCensus(t *testing.T) {
	var b strings.Builder
	if n, err := ConvertAnycastCensus(strings.NewReader(census), &b); err != nil || n != 1 || b.String() != censusKept {
		t.Errorf("IPv4: %d, %v, %q", n, err, b.String())
	}
	v6 := "prefix,AB_ICMPv6,AB_TCPv6,AB_DNSv6,GCD_ICMPv6,GCD_TCPv6,locations,backing_prefix,ASN\n" +
		`2001:db8::/48,3,0,3,2,5,"[]",2001:db8::/32,64496` + "\n"
	b.Reset()
	if n, err := ConvertAnycastCensus(strings.NewReader(v6), &b); err != nil || n != 1 ||
		b.String() != "prefix,number_of_sites,backing_prefix\n2001:db8::/48,5,2001:db8::/32\n" {
		t.Errorf("IPv6: %d, %v, %q", n, err, b.String())
	}
	for name, bad := range map[string]string{
		"short form":  censusKept,
		"bad count":   strings.Replace(census, ",73,", ",x,", 1),
		"short row":   census + "192.0.2.0/24,1\n",
		"no prefixes": "AB_ICMPv4,GCD_ICMPv4\n1,1\n",
	} {
		if _, err := ConvertAnycastCensus(strings.NewReader(bad), io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The census server sends its .csv.gz as Content-Encoding gzip, which net/http
// unpacks; a plain gzip body must work too. The manifest describes the file kept.
func TestUpdateCensus(t *testing.T) {
	encoded, body := true, gz(census)
	srv, c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if encoded {
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Write(body)
	})
	var src Source
	for _, s := range Sources() {
		if s.Name == "laces-anycast" {
			src = s
		}
	}
	src.URL = fixed(srv.URL + "/IPv4-latest.csv.gz")
	src.MinRows = 1
	for _, encoded = range []bool{true, false} {
		dir := t.TempDir()
		e, err := Update(context.Background(), c, dir, src, Token{}, time.Now())
		kept, _ := os.ReadFile(filepath.Join(dir, src.File))
		sum := sha256.Sum256(kept)
		if err != nil || e.Rows != 1 || string(kept) != censusKept || e.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("Content-Encoding %v: %+v, %v, %q", encoded, e, err, kept)
		}
		if left, _ := filepath.Glob(filepath.Join(dir, ".download-*")); len(left) != 0 {
			t.Errorf("Content-Encoding %v: temporary files left: %v", encoded, left)
		}
		if encoded {
			continue
		}
		body = gz(censusKept) // an export in another form never replaces the file in use
		if _, err := Update(context.Background(), c, dir, src, Token{}, time.Now()); err == nil {
			t.Error("short form accepted as an export")
		}
		if cur, _ := os.ReadFile(filepath.Join(dir, src.File)); string(cur) != censusKept {
			t.Error("a rejected export replaced the file in use")
		}
	}
}
