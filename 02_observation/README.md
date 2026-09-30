# 02 · Observation — study

The engine running untouched on the measurement host for at least 14 days, over 60 validated targets, one run every 30 min. Not production code: it tests the engine and produces the data that calibrates live telemetry.

- **Before:** fixed validity rules and a 24 h rehearsal. The study starts only if the rehearsal passes.
- **During:** a daily review; nothing is patched. Failures are logged, and a failure that invalidates the study means a rerun.

**How it runs:** the engine's own commands do the work. This folder holds only what belongs to the study: the service with its parameters and the start and stop scripts. The target list and the validity rules are kept with the data.

- **Targets:** `tracertip targets` picks RIPE Atlas anchors, 10 per continent plus a reserve. It checks each one:
  - active and dual-stack;
  - outside the anycast census;
  - one BGP origin, the declared one;
  - reachable on both families;
  - no faster than light in fiber from its declared place.
- **Runs:** `tracertip batch` alternates IPv4 and IPv6 on 30-minute UTC slots and traces one target at a time.
  - Fixed targets also get a 2-round trace every 5 minutes.
  - A target that misses 4 runs in a row, or fails the daily routing check 2 days in a row, is replaced by its continent's reserve. The replacement is logged.
  - The node's own outages never count against a target: a trace the node could not make (no route, probes not sent) is `unmeasured`, and misses are ignored in a run where fewer than half of the targets answered.
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

**Watching it** (read-only, from any SSH session to the host):

```sh
watch -n 30 sh status.sh     # service, run in progress, last runs, health
tracertip batch -state /var/lib/tracertip/study -report   # facts per day
```

Do not trace from the host by hand while the study runs: one target at a time is part of the method.

**Status:** 24 h rehearsal running since 2026-09-29 10:30 UTC; the 14 days start only if it passes.

*Updated: 2026-09-29 10:16 UTC.*
