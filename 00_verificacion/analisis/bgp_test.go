package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCruzarBGP(t *testing.T) {
	t0 := time.Date(2026, 1, 5, 0, 0, 5, 0, time.UTC)
	en := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	cs := []cambio{
		{Antes: en(0), Despues: en(15)},  // evento a los 10 min: si
		{Antes: en(15), Despues: en(30)}, // evento justo en Antes: no cuenta
		{Antes: en(30), Despues: en(45)}, // evento durante la traza del cambio: si
		{Antes: en(45), Despues: en(60)}, // pasa del fin de los datos
	}
	ev := []eventoBGP{{en(10), "A"}, {en(15), "W"}, {en(45).Add(20 * time.Second), "A"}}
	cruzarBGP(cs, ev, en(50))
	for i, quiero := range []string{"si", "no", "si", "sin datos"} {
		if cs[i].BGP != quiero {
			t.Errorf("cambio %d: %q; quiero %q", i, cs[i].BGP, quiero)
		}
	}
}

// RIPEstat de mentira: cuenta las consultas y, en bgp-updates, la primera
// respuesta no cubre toda la ventana (como pasa con el retraso de RIS).
func TestRIPEstatCache(t *testing.T) {
	desde := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	hasta := desde.Add(duracionVentana)
	var mu sync.Mutex
	pedidos := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		pedidos[r.URL.Path]++
		q := r.URL.Query()
		if q.Get("sourceapp") != appRIPEstat {
			t.Errorf("%s sin sourceapp", r.URL)
		}
		switch {
		case r.URL.Path == "/prefix-overview/data.json":
			fmt.Fprint(w, `{"status":"ok","data":{"resource":"192.0.2.0/24","announced":true,"asns":[{"asn":64500,"holder":"X"}]}}`)
		case r.URL.Path == "/bgp-updates/data.json" && q.Get("resource") == "192.0.2.0/24":
			if q.Get("starttime") != "2026-01-05T00:00:00" || q.Get("endtime") != "2026-01-07T00:00:00" {
				t.Errorf("ventana mal pedida: %s", r.URL.RawQuery)
			}
			fin := "2026-01-06T20:00:00"
			if pedidos[r.URL.Path] > 1 {
				fin = "2026-01-06T23:59:58"
			}
			fmt.Fprintf(w, `{"status":"ok","data":{"query_endtime":%q,"updates":[{"type":"A","timestamp":"2026-01-05T10:00:00"},{"type":"W","timestamp":"2026-01-05T11:00:00"}]}}`, fin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	r := nuevoRIPEstat(t.TempDir())
	r.base, r.pausa = srv.URL+"/", 0
	for range 2 {
		pref, origen, err := r.prefijo("192.0.2.10")
		if err != nil || pref != "192.0.2.0/24" || len(origen) != 1 || origen[0] != 64500 {
			t.Fatalf("prefijo = %q, %v, %v", pref, origen, err)
		}
	}
	finQuiero := []string{"2026-01-06T20:00:00", "2026-01-06T23:59:58", "2026-01-06T23:59:58"}
	for i, fq := range finQuiero {
		ev, fin, err := r.actualizaciones("192.0.2.0/24", desde, hasta)
		if err != nil || len(ev) != 2 || fin.Format(formatoRIS) != fq {
			t.Fatalf("vuelta %d: %d eventos, fin %v, %v; quiero fin %s", i, len(ev), fin, err, fq)
		}
	}
	mu.Lock()
	if pedidos["/prefix-overview/data.json"] != 1 || pedidos["/bgp-updates/data.json"] != 2 {
		t.Errorf("pedidos %v; quiero 1 de prefix-overview (cache) y 2 de bgp-updates (la incompleta se repite)", pedidos)
	}
	mu.Unlock()
	if _, _, err := r.actualizaciones("198.51.100.0/24", desde, hasta.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("un HTTP distinto de 200 deberia fallar: %v", err)
	}
}
