// tracertIP - F0 - paso 0.5 - analisis de la ventana de 48 h y veredicto.
// Lee lo recolectado y los ajustes de la carpeta privada, consulta BGP en
// RIPEstat (con cache en esa misma carpeta) y escribe RESULTADOS_F0.md.
//
//	go run . -inicio 2026-01-01T00:00:00Z -privado <carpeta privada> -salida <informe.md>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Constantes del analisis (P3): nombre, unidad y razon.
const (
	duracionVentana  = 48 * time.Hour   // 0.2: la ventana dura 48 h
	periodoCorrida   = 15 * time.Minute // timer de recoleccion: *:0/15
	duracionTraza    = 24 * time.Second // medido: 723 s para 30 destinos
	umbralJitterMs   = 5.0              // punto de aborto: p95 - p50 < 5 ms
	umbralCalienteMC = 75000            // umbral de enfriamiento: mas de 75 C
	muestrasCaliente = 3                // 3 muestras seguidas = 15 min (salud cada 5 min)
	maxHuecoSalud    = 10 * time.Minute // mas separadas que esto ya no son "seguidas"
	grupoAborto      = "originales"     // grupo de destinos.conf del punto de aborto
)

func main() {
	inicio := flag.String("inicio", "", "INICIO de la ventana (RFC 3339, UTC)")
	privado := flag.String("privado", "", "carpeta privada del proyecto")
	salida := flag.String("salida", "", "informe a escribir (Markdown)")
	sinBGP := flag.Bool("sin-bgp", false, "no consultar RIPEstat; el informe lo dice")
	flag.Parse()
	if *inicio == "" || *privado == "" || *salida == "" || flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	t0, err := time.Parse(time.RFC3339, *inicio)
	if err != nil {
		fmt.Fprintln(os.Stderr, "-inicio:", err)
		os.Exit(2)
	}
	var bgp fuenteBGP
	if !*sinBGP {
		bgp = nuevoRIPEstat(filepath.Join(*privado, "datos", "bgp"))
	}
	inf, err := analizar(*privado, t0.UTC(), bgp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*salida, []byte(inf.markdown()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	fmt.Print(inf.resumen())
}
