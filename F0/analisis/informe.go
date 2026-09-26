package main

// RESULTADOS_F0.md: el informe del paso 0.5, en el orden de la instruccion,
// 12.3. Todas las horas en UTC.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

func fechaHora(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func pct(n, de int) string {
	if de == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f %%", 100*float64(n)/float64(de))
}

func ms(v float64, hay bool) string {
	if !hay {
		return "—"
	}
	return fmt.Sprintf("%.1f", v)
}

func enteros(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = "AS" + strconv.Itoa(x)
	}
	return strings.Join(s, ", ")
}

func (v veredicto) consecuencia() string {
	switch {
	case !v.evaluable():
		return "No evaluable: sin trazas válidas de " + strings.Join(v.Faltan, ", ")
	case v.Aborto:
		return "Aborto parcial: se construye solo la F1 y la F2 se archiva"
	}
	return "F1 y después F2"
}

func (v veredicto) enfriamiento() string {
	if v.Enfriamiento {
		return "Revisar el enfriamiento es requisito antes de F2"
	}
	return "Nada que revisar"
}

func (inf *informe) resumen() string {
	v, c := inf.Veredicto, inf.Cob
	esperadas := c.Ranuras * len(inf.Destinos)
	return fmt.Sprintf("Cobertura: %d de %d trazas (%s)\n"+
		"Originales: %d cambios ASN (%d posibles artefactos); p95-p50 maximo %.1f ms (%s)\n"+
		"Veredicto propuesto: %s\nEnfriamiento: %s\n",
		c.Trazas-len(c.Ajenos), esperadas, pct(c.Trazas, esperadas),
		v.Cambios, v.Artefactos, v.JitterMax, v.JitterDestino, v.consecuencia(), v.enfriamiento())
}

func (inf *informe) markdown() string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	c, s, v, a := inf.Cob, inf.Salud, inf.Veredicto, inf.ASN
	esperadas := c.Ranuras * len(inf.Destinos)

	p("# tracertIP — Resultados de la Fase 0\n\n")
	p("| Campo | Valor |\n|---|---|\n")
	p("| **Generado** | %s, por `F0/analisis` (paso 0.5) |\n", fechaHora(inf.Generado))
	p("| **Ventana** | %s a %s |\n", fechaHora(c.Inicio), fechaHora(c.Fin))
	p("| **Datos** | `mtr`: %d líneas en %d archivos · salud: %d · vigía: %d · ilegibles: %d |\n",
		c.Mtr.Lineas, c.Mtr.Archivos, c.Salud.Lineas, c.Vigia.Lineas, c.Mtr.Ilegibles+c.Salud.Ilegibles+c.Vigia.Ilegibles)
	p("| **ASN** | `%s` y, si falta, `%s`: %d direcciones por IPinfo, %d por DB-IP, %d sin ASN |\n",
		a.ArchivoIPinfo, a.ArchivoDBIP, a.IPinfo, a.DBIP, a.Desconocidas)
	if inf.BGP {
		p("| **BGP** | RIPE RIS vía RIPEstat; datos hasta %s |\n", fechaHora(inf.FinBGP))
	} else {
		p("| **BGP** | No consultado (`-sin-bgp`) |\n")
	}
	p("\n> ⛔ El veredicto de §6 es una propuesta: lo firma el responsable con estos números en la mano.\n\n")

	p("## 1. Ventana y cobertura\n\n")
	p("- Corridas esperadas por destino: %d (una cada %d min). Trazas: %d de %d (%s).\n",
		c.Ranuras, int(periodoCorrida.Minutes()), c.Trazas-len(c.Ajenos), esperadas, pct(c.Trazas-len(c.Ajenos), esperadas))
	p("- Corridas completas: %d de %d.", c.Completas, c.Ranuras)
	if len(c.Huecos) == 0 {
		p(" Sin huecos.\n")
	} else {
		p(" Huecos (corrida ausente o incompleta; no se rellenan):\n")
		for _, h := range c.Huecos {
			p("  - %s: %d de %d trazas\n", fechaHora(h.Ranura), h.Trazas, len(inf.Destinos))
		}
	}
	p("- Salud: %d muestras (una cada 5 min: se esperan unas %d).\n", s.Muestras, 3*c.Ranuras)
	ok, alertas := 0, []veredictoVigia{}
	for _, x := range inf.Vigia {
		if x.Estado == "ok" {
			ok++
		} else {
			alertas = append(alertas, x)
		}
	}
	p("- Vigía: %d corridas `ok` y %d con alerta.\n", ok, len(alertas))
	for _, x := range alertas {
		p("  - %s: %s\n", fechaHora(x.Corrida), x.Motivos)
	}
	if len(c.Ajenos) > 0 {
		p("- Destinos en los datos que no están en `destinos.conf` (no se analizan): %s.\n", strings.Join(c.Ajenos, ", "))
	}
	p("- Reinicios: el análisis no los ve; van en la bitácora (`journalctl --list-boots`).\n\n")

	p("## 2. Por destino\n\n")
	p("RTT = `Avg` del salto destino en cada traza válida; p50 y p95 por rango más cercano. «No llegó» = trazas no válidas entre las obtenidas. Mudos = saltos `???` entre todos los saltos de las trazas válidas. La ruta es la huella ASN, sin el lado de la casa.\n\n")
	for _, g := range inf.Grupos {
		if g == grupoAborto {
			p("### %s (punto de aborto)\n\n", g)
		} else {
			p("### %s\n\n", g)
		}
		p("| Destino | Válidas | No llegó | p50 ms | p95 ms | p95−p50 | Best mín | Cambios ASN | Cambios IP | Prevalencia | Mudos | Ruta dominante |\n")
		p("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
		for _, e := range inf.Destinos {
			if e.Grupo != g {
				continue
			}
			cambios := strconv.Itoa(len(e.Cambios))
			if n := contarArtefactos(e.Cambios); n > 0 {
				cambios += fmt.Sprintf(" (%d art.)", n)
			}
			p("| %s | %d/%d | %s | %s | %s | %s | %s | %s | %d | %s | %s | `%s` |\n",
				e.IP, e.Validas, e.Esperadas, pct(e.Obtenidas-e.Validas, e.Obtenidas),
				ms(e.P50, e.HayRTT), ms(e.P95, e.HayRTT), ms(e.P95-e.P50, e.HayRTT), ms(e.BestMin, e.HayRTT),
				cambios, e.CambiosIP, pct(int(e.Prevalencia*float64(e.Validas)+0.5), e.Validas), pct(e.Mudos, e.Saltos), e.RutaDominante)
		}
		p("\n")
	}
	conAS := 0
	for _, e := range inf.Destinos {
		conAS += e.ConASDesconocido
	}
	p("Trazas válidas con algún ASN desconocido (`AS?`): %d.\n\n", conAS)

	p("### Cambios de ruta ASN\n\n")
	p("Entre dos trazas válidas consecutivas del mismo destino. «art.» = posible artefacto: la huella con menos ASN viene de la traza con más saltos mudos.\n\n")
	hay := false
	for _, e := range inf.Destinos {
		for _, x := range e.Cambios {
			if !hay {
				p("| Destino | Grupo | Antes → después | De | A | BGP | Nota |\n|---|---|---|---|---|---|---|\n")
				hay = true
			}
			nota := ""
			if x.PosibleArtefacto {
				nota = "art."
			}
			bgp := x.BGP
			if bgp == "" {
				bgp = "—"
			}
			p("| %s | %s | %s → %s | `%s` | `%s` | %s | %s |\n", e.IP, e.Grupo,
				x.Antes.UTC().Format("01-02 15:04"), x.Despues.UTC().Format("01-02 15:04"), x.De, x.A, bgp, nota)
		}
	}
	if !hay {
		p("Ninguno.\n")
	}
	p("\n### ASN que aparecen en las rutas\n\n")
	p("| ASN | Nombre |\n|---|---|\n")
	for _, n := range asnVistos(inf.Destinos) {
		p("| AS%d | %s |\n", n, a.Nombres[n])
	}
	p("\n")

	p("## 2.bis BGP (RIPE RIS, vía RIPEstat)\n\n")
	if !inf.BGP {
		p("No se consultó (`-sin-bgp`).\n\n")
	} else {
		p("RIS publica con retraso: lo posterior al %s queda «sin datos». Coincidir con un evento BGP no prueba la causa del cambio.\n\n", fechaHora(inf.FinBGP))
		p("| Destino | Prefijo | Origen | Anuncios | Retiros | Cambios ASN | Con evento BGP | Sin datos |\n|---|---|---|---|---|---|---|---|\n")
		for _, e := range inf.Destinos {
			si, sin := 0, 0
			for _, x := range e.Cambios {
				switch x.BGP {
				case "si":
					si++
				case "sin datos":
					sin++
				}
			}
			pref := e.Prefijo
			if pref == "" {
				pref = "no anunciado"
			}
			p("| %s | %s | %s | %d | %d | %d | %d | %d |\n", e.IP, pref, enteros(e.Origen), e.Anuncios, e.Retiros, len(e.Cambios), si, sin)
		}
		p("\n")
	}

	p("## 3. Salud del nodo\n\n")
	if s.Muestras == s.SinTemp {
		p("- Temperatura: sin dato en las %d muestras.\n", s.Muestras)
	} else {
		p("- Temperatura máxima: %.1f °C (%s). Episodios calientes (%d o más muestras seguidas sobre %d °C): %d. Sin dato: %d.\n",
			s.TempMaxMC/1000, fechaHora(s.TempMaxT), muestrasCaliente, umbralCalienteMC/1000, s.Episodios, s.SinTemp)
	}
	p("- `throttled` activo: %d muestras. Nuevo durante la ventana: %d", s.ThrActivo, s.ThrNuevo)
	if s.BitsNuevos != 0 {
		p(" (bits 0x%x)", s.BitsNuevos)
	}
	p(". Sin dato: %d.\n", s.ThrNA)
	p("- Subtensión: %d muestras. Sin dato: %d.\n", s.Subtension, s.SubtensionNA)
	if s.NTPNA < s.Muestras {
		p("- Desfase NTP máximo: %.1f ms (%s). Sin dato: %d.\n", s.NTPMaxMs, fechaHora(s.NTPMaxT), s.NTPNA)
	}
	p("- Si la actualización semanal afectó la recolección, está en los huecos de §1.\n\n")

	p("## 4. Espiga Windows (0.1) y capacidades Linux (0.4)\n\nEstán en la bitácora; no se repiten aquí.\n\n")
	p("## 5. Bases de datos (0.3)\n\nPasa a la Fase 1 (instrucción, §10.3).\n\n")

	p("## 6. Veredicto (propuesto)\n\n")
	p("| Condición (12.4) | Medido | Consecuencia |\n|---|---|---|\n")
	p("| 0 cambios ASN en los %d originales y p95−p50 < %.0f ms en todos | %d cambios ASN (%d posibles artefactos); p95−p50 máximo %.1f ms (%s) | **%s** |\n",
		v.Originales, umbralJitterMs, v.Cambios, v.Artefactos, v.JitterMax, v.JitterDestino, v.consecuencia())
	p("| Episodio caliente, `throttled` activo o nuevo | %d episodios; `throttled` activo en %d muestras y nuevo en %d | **%s** |\n",
		s.Episodios, s.ThrActivo, s.ThrNuevo, v.enfriamiento())
	p("| Espiga 0.1 | En la bitácora | — |\n\n")
	p("⛔ **PARADA.** Lo firma el responsable.\n\n")
	p("Valores de 1.bis, con lo medido:\n")
	p("- `TTL_MAXIMO`: el camino más largo midió %d saltos.\n", v.SaltosMax)
	p("- `TIMEOUT_SONDA`: el peor RTT de un destino fue %.1f ms.\n", v.WrstMax)
	p("- `RONDA_POR_DESTINO` y `DESTINOS_SIMULTANEOS`: la F0 midió un destino a la vez; no aporta datos para cambiarlos.\n\n")

	p("## 7. Atribución\n\n")
	p("- «IP Geolocation by DB-IP» (https://db-ip.com), CC BY 4.0.\n- «IPinfo Lite», CC BY-SA 4.0.\n- Datos BGP: RIPE NCC, RIPE RIS, consultados en RIPEstat.\n\n")

	p("## 8. Lo que sigue sin medir\n\n")
	p("- El camino de regreso: un solo punto de vista ve la ida.\n")
	p("- El balanceo por flujo: `mtr` no es Paris y su JSON da una sola IP por salto, así que los cambios de IP lo sobrestiman o lo esconden.\n")
	p("- La causa de cada cambio: coincidir con BGP no la prueba, y RIS no ve la red interna del ISP.\n")
	p("- La cola de latencia por paquete: los percentiles son de trazas de 10 sondas.\n")
	p("- La física y la comparación de bases de IP: Fase 1.\n")
	return b.String()
}

func contarArtefactos(cs []cambio) int {
	n := 0
	for _, c := range cs {
		if c.PosibleArtefacto {
			n++
		}
	}
	return n
}

// asnVistos: los ASN de las rutas dominantes y de los cambios, ordenados.
func asnVistos(est []estadDestino) []int {
	visto := map[int]bool{}
	agregar := func(h string) {
		for t := range strings.FieldsSeq(h) {
			if n, err := strconv.Atoi(strings.TrimPrefix(t, "AS")); err == nil {
				visto[n] = true
			}
		}
	}
	for _, e := range est {
		agregar(e.RutaDominante)
		for _, c := range e.Cambios {
			agregar(c.De)
			agregar(c.A)
		}
	}
	out := make([]int, 0, len(visto))
	for n := range visto {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}
