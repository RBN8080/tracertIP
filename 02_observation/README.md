# 02 · Observation — study

The engine running untouched on the measurement host for at least 14 days, over 60 validated targets, one run every 30 min. Not production code: it tests the engine and produces the data that calibrates live telemetry.

- **Before:** fixed validity rules and a 24 h rehearsal. The study starts only if the rehearsal passes.
- **During:** a daily review; nothing is patched. Failures are logged, and a failure that invalidates the study means a rerun.

**How it runs:**

- **Targets:** `tracertip targets` picks RIPE Atlas anchors, 10 per continent plus a reserve. It checks each one:
  - active and dual-stack;
  - outside the anycast census;
  - one BGP origin, the declared one;
  - reachable on both families;
  - no faster than light in fiber from its declared place.
- **Runs:** `tracertip study` alternates IPv4 and IPv6 on 30-minute UTC slots and traces one target at a time.
  - Fixed targets also get a 2-round trace every 5 minutes.
  - A target that misses 4 runs in a row, or whose prefix changes origin, is replaced by its continent's reserve. The replacement is logged.
- **Data:** one JSON Lines file per run, synced after every trace, plus:
  - the state;
  - the replacements;
  - the daily BGP answers;
  - the dated IPmap answers.

  The bases are a frozen copy with its SHA-256 list.

```sh
tracertip targets -exclude measured.txt -fixed 192.0.2.1 -out targets.json
sudo sh start.sh targets.json config.json   # undo: sudo sh stop.sh
```

**Feeds `01_engine`:** weeks of real data to calibrate Phase 2.

**Status:** in preparation (targets, runs and service built; validity rules and the rehearsal next).

*Updated: 2026-09-29 10:05 UTC.*
