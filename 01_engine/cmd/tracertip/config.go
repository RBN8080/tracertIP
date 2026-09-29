package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/judge"
)

// config holds what varies per installation and must stay out of the code
// (Twelve-Factor III; 00_IDEA 5.ter): the real origin and the access ISP.
type config struct {
	Origin    *judge.Coord `json:"origin"`     // measurement point; nil = physics not evaluable
	AccessASN int          `json:"access_asn"` // home ISP, hidden in public output
	Resolver  string       `json:"resolver"`   // DNS server for names, host:port
	Bases     string       `json:"bases"`      // folder of the bases
}

func defaultConfigPath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "tracertip", "config.json")
}

// loadConfig reads path; a missing default file is an empty config.
func loadConfig(path string, explicit bool) (config, error) {
	var c config
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if o := c.Origin; o != nil && (o.Lat < -90 || o.Lat > 90 || o.Lon < -180 || o.Lon > 180) {
		return c, fmt.Errorf("%s: origin out of range", path)
	}
	return c, nil
}

// enrichOptions joins the flags with the configuration; the IPmap cache is
// per user, so it works whoever owns the bases folder.
func enrichOptions(c config, dir, resolver string, noDNS, noIPmap bool) enrich.Options {
	o := enrich.Options{Dir: first(dir, c.Bases, defaultBasesDir()), Resolver: first(resolver, c.Resolver),
		NoDNS: noDNS, NoIPmap: noIPmap, AccessASN: c.AccessASN}
	if d, err := os.UserCacheDir(); err == nil {
		o.IPmapCache = filepath.Join(d, "tracertip", "ipmap.json")
	}
	return o
}
