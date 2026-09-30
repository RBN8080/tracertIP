# 01 · Engine — product

The only production code. Given an IP, it traces the path and, hop by hop, reports the network, the city, how far the hop can be and whether physics agrees. When physics disagrees, the hop is a proxy or anycast, or its location is wrong.

Probe → enrich → judge → output (console table and JSON Lines, schema in `schema/`).

- **Probe:** Paris traceroute over ICMP and ICMPv6, so every probe of a trace follows the same path.
- **Enrich:** AS and city from local bases, IXPs, router names, the anycast census and RIPE IPmap.
- **Judge:** each claimed location is checked against the speed of light in fiber, with its source. A guess stays a guess.
- **Targets and batch:** the same rules choose targets and keep them honest, with automatic replacement and a log. Batch mode runs a list for days, and its data survives a power cut. What the host could not measure is recorded as `unmeasured` and never counts against a target.
- **It grows in place:** Phase 2 (live telemetry: a LAN-only API and a web dashboard embedded in the binary) builds on this code. A Java desktop client comes later, on the same API.

**Setup:**

- Copy `config.example.json` to the user's config folder as `tracertip/config.json`.
- Copy `geohints.tsv.example` to the bases folder as `geohints.tsv`.
- Run `tracertip update-db`.
- On a node, use `deploy/install.sh`.

**Status:** Phase 1 closed on 2026-09-29. The first study rehearsal exposed two defects in batch mode, fixed on 2026-09-30; the engine is frozen again while the study runs.

*Updated: 2026-09-30 12:40 UTC.*
