package main

// Pruebas de tabla del paso 0.5 (instruccion, 12.2). Solo hay valores de
// documentacion: IPv4 de RFC 5737 y ASN de RFC 5398 (64496-64511). Las IP
// privadas y de CGNAT se arman en tiempo de ejecucion, para que no queden
// escritas en el repositorio publico.

import (
	"net/netip"
	"testing"
	"time"
)

func ip4(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }

func tabla(pares map[string]int) tablaASN {
	t := tablaASN{}
	for h, n := range pares {
		t[netip.MustParseAddr(h)] = infoASN{ASN: n, Fuente: "IPinfo"}
	}
	return t
}

func TestPercentil(t *testing.T) {
	serie := func(n int) []float64 {
		s := make([]float64, n)
		for i := range s {
			s[i] = float64(i + 1)
		}
		return s
	}
	casos := []struct {
		nombre string
		s      []float64
		p      int
		quiero float64
		ok     bool
	}{
		{"vacia", nil, 50, 0, false},
		{"un valor", []float64{7}, 95, 7, true},
		{"p50 de 4", serie(4), 50, 2, true},
		{"p50 de 5", serie(5), 50, 3, true},
		{"p95 de 20", serie(20), 95, 19, true},
		{"p95 de 192", serie(192), 95, 183, true},
		{"p7 de 100: en coma flotante daria 8", serie(100), 7, 7, true},
		{"p100", serie(10), 100, 10, true},
	}
	for _, c := range casos {
		v, ok := percentil(c.s, c.p)
		if v != c.quiero || ok != c.ok {
			t.Errorf("%s: percentil = %v, %v; quiero %v, %v", c.nombre, v, ok, c.quiero, c.ok)
		}
	}
}

func TestClasificar(t *testing.T) {
	casos := map[string]clase{
		mudo:                    claseMudo,
		ip4(10, 1, 2, 3):        clasePrivada,
		ip4(172, 16, 0, 1):      clasePrivada,
		ip4(172, 31, 255, 254):  clasePrivada,
		"172.32.0.1":            clasePublica,
		ip4(192, 168, 1, 1):     clasePrivada,
		ip4(100, 64, 0, 1):      claseCGNAT,
		ip4(100, 127, 255, 254): claseCGNAT,
		"100.128.0.1":           clasePublica,
		ip4(169, 254, 1, 1):     claseEnlaceLocal,
		"203.0.113.9":           clasePublica,
		"2001:db8::1":           claseInvalida,
		"no-es-ip":              claseInvalida,
	}
	for h, quiero := range casos {
		if c := clasificar(h); c != quiero {
			t.Errorf("clasificar(%q) = %d; quiero %d", h, c, quiero)
		}
	}
}

func saltos(hosts ...string) []salto {
	s := make([]salto, len(hosts))
	for i, h := range hosts {
		s[i] = salto{Count: i + 1, Host: h, Snt: 10}
		if h == mudo {
			s[i].Loss = 100
		}
	}
	return s
}

func TestLadoCasaYHuellaASN(t *testing.T) {
	asn := tabla(map[string]int{
		"203.0.113.1": 64500, "203.0.113.2": 64500, // ISP de acceso
		"198.51.100.1": 64501, "198.51.100.2": 64501,
		"192.0.2.1": 64502,
	})
	const acceso = 64500
	casos := []struct {
		nombre      string
		s           []salto
		casa        int
		huella      string
		desconocido int
	}{
		{"casa, CGNAT, mudo e ISP; privada en el transito; AS? y repetidos",
			saltos(ip4(192, 168, 1, 1), ip4(100, 64, 0, 1), mudo, "203.0.113.1", "203.0.113.2", mudo,
				"198.51.100.1", ip4(10, 0, 0, 5), "198.51.100.2", "192.0.2.99", "192.0.2.1"),
			5, "AS64501 AS? AS64502", 1},
		{"sin lado de la casa", saltos("198.51.100.1", "192.0.2.1"), 0, "AS64501 AS64502", 0},
		{"todo es casa", saltos(ip4(192, 168, 1, 1), "203.0.113.1"), 2, "", 0},
		{"el ASN de acceso despues del transito no es casa",
			saltos("203.0.113.1", "198.51.100.1", "203.0.113.2"), 1, "AS64501 AS64500", 0},
	}
	for _, c := range casos {
		casa := ladoCasa(c.s, asn, acceso)
		h, d := huellaASN(c.s, casa, asn)
		if casa != c.casa || h != c.huella || d != c.desconocido {
			t.Errorf("%s: casa %d, huella %q, AS? %d; quiero %d, %q, %d", c.nombre, casa, h, d, c.casa, c.huella, c.desconocido)
		}
	}
}

func TestEstadisticasYCambios(t *testing.T) {
	asn := tabla(map[string]int{
		"203.0.113.1": 64500, "198.51.100.1": 64501,
		"203.0.113.130": 64503, "203.0.113.131": 64503, "192.0.2.1": 64502,
	})
	t0 := time.Date(2026, 1, 5, 0, 0, 5, 0, time.UTC)
	hacer := func(k int, avg float64, hosts ...string) traza {
		s := saltos(hosts...)
		s[len(s)-1].Avg, s[len(s)-1].Best, s[len(s)-1].Wrst = avg, avg-1, avg+1
		tk := t0.Add(time.Duration(k) * periodoCorrida)
		return traza{T: tk, TDestino: tk, Destino: "192.0.2.1", Saltos: s}
	}
	casa := ip4(192, 168, 1, 1)
	trs := []traza{
		hacer(0, 10, casa, "203.0.113.1", "198.51.100.1", "192.0.2.1"),
		hacer(1, 12, casa, "203.0.113.1", "198.51.100.1", "192.0.2.1"),
		hacer(2, 99, casa, "203.0.113.1", "203.0.113.130", mudo), // no valida: no llega
		hacer(3, 11, casa, "203.0.113.1", "203.0.113.130", "192.0.2.1"),
		hacer(4, 13, casa, "203.0.113.1", "203.0.113.131", "192.0.2.1"), // otra IP, mismo ASN
	}
	e := estadisticas(destino{"192.0.2.1", grupoAborto}, trs, asn, 64500, 192)
	if e.Obtenidas != 5 || e.Validas != 4 {
		t.Fatalf("obtenidas %d, validas %d; quiero 5 y 4", e.Obtenidas, e.Validas)
	}
	if len(e.Cambios) != 1 || e.CambiosIP != 2 {
		t.Fatalf("cambios ASN %d, IP %d; quiero 1 y 2", len(e.Cambios), e.CambiosIP)
	}
	c := e.Cambios[0]
	if c.De != "AS64501 AS64502" || c.A != "AS64503 AS64502" || !c.Antes.Equal(trs[1].TDestino) || !c.Despues.Equal(trs[3].TDestino) {
		t.Errorf("cambio = %+v", c)
	}
	if e.P50 != 11 || e.P95 != 13 || e.BestMin != 9 || e.WrstMax != 14 {
		t.Errorf("p50 %v, p95 %v, best %v, wrst %v; quiero 11, 13, 9, 14", e.P50, e.P95, e.BestMin, e.WrstMax)
	}
	if e.RutaDominante != "AS64501 AS64502" || e.Prevalencia != 0.5 {
		t.Errorf("dominante %q (%v); quiero la menor en empate, 0.5", e.RutaDominante, e.Prevalencia)
	}
}

func TestPosibleArtefacto(t *testing.T) {
	casos := []struct {
		de, a          string
		mudosDe, mudoA int
		quiero         bool
	}{
		{"AS1 AS2 AS3", "AS1 AS3", 0, 1, true},  // se callo el unico salto de AS2
		{"AS1 AS3", "AS1 AS2 AS3", 1, 0, true},  // y volvio a contestar
		{"AS1 AS2 AS3", "AS1 AS3", 1, 1, false}, // mismos mudos: ruta nueva
		{"AS1 AS2", "AS1 AS4", 0, 5, false},     // sustitucion
		{"AS1 AS2 AS3", "AS3 AS1", 0, 2, false}, // no es subsecuencia
	}
	for _, c := range casos {
		if r := posibleArtefacto(c.de, c.a, c.mudosDe, c.mudoA); r != c.quiero {
			t.Errorf("posibleArtefacto(%q, %q, %d, %d) = %v", c.de, c.a, c.mudosDe, c.mudoA, r)
		}
	}
}

func TestResumirSalud(t *testing.T) {
	t0 := time.Date(2026, 1, 5, 0, 0, 5, 0, time.UTC)
	f := func(v float64) *float64 { return &v }
	m := func(min int, temp *float64, thr string, sub *float64, ntp string) muestraSalud {
		return muestraSalud{t0.Add(time.Duration(min) * time.Minute), temp, thr, sub, ntp}
	}
	ms := []muestraSalud{
		m(0, f(70000), "0x0", f(0), "-583us"),
		m(5, f(76000), "0x0", f(0), "-2.564ms"),
		m(10, f(76000), "0x50005", nil, "NA"),
		m(15, f(76000), "NA", f(1), "+1.2s"),
		m(20, f(76000), "0x50000", f(0), "-1ms"), // la racha sigue: un solo episodio
		m(25, nil, "0x0", f(0), "-1ms"),
		m(30, f(76000), "0x0", f(0), "-1ms"),
		m(35, f(76000), "0x0", f(0), "-1ms"),
		m(60, f(76000), "0x0", f(0), "-1ms"), // hueco de 25 min: corta la racha
	}
	r := resumirSalud(ms)
	if r.Episodios != 1 || r.TempMaxMC != 76000 || r.SinTemp != 1 {
		t.Errorf("episodios %d, max %v, sin dato %d; quiero 1, 76000, 1", r.Episodios, r.TempMaxMC, r.SinTemp)
	}
	if r.ThrActivo != 1 || r.ThrNuevo != 2 || r.ThrNA != 1 || r.BitsNuevos != 0x50000 {
		t.Errorf("throttled activo %d, nuevo %d, NA %d, bits %x", r.ThrActivo, r.ThrNuevo, r.ThrNA, r.BitsNuevos)
	}
	if r.Subtension != 1 || r.SubtensionNA != 1 || r.NTPMaxMs != 1200 || r.NTPNA != 1 {
		t.Errorf("subtension %d/%d, NTP %v ms (NA %d)", r.Subtension, r.SubtensionNA, r.NTPMaxMs, r.NTPNA)
	}
	// Un bit de "ya ocurrio" presente desde la primera muestra no es nuevo.
	if r := resumirSalud([]muestraSalud{m(0, f(1), "0x50000", f(0), "0ms"), m(5, f(1), "0x50000", f(0), "0ms")}); r.ThrNuevo != 0 {
		t.Errorf("throttled nuevo = %d con el bit ya en la primera muestra", r.ThrNuevo)
	}
}

func TestNTPMs(t *testing.T) {
	casos := map[string]float64{"-583us": -0.583, "-2.564ms": -2.564, "+1.2s": 1200, "0ms": 0, "7µs": 0.007}
	for s, quiero := range casos {
		if v, ok := ntpMs(s); !ok || v != quiero {
			t.Errorf("ntpMs(%q) = %v, %v; quiero %v", s, v, ok, quiero)
		}
	}
	for _, s := range []string{"NA", "", "12", "ms"} {
		if _, ok := ntpMs(s); ok {
			t.Errorf("ntpMs(%q) deberia fallar", s)
		}
	}
}
