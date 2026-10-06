# 01 · Engine — product

The only production code. Given an IP, it traces the path and, hop by hop, reports the network, the city, how far the hop can be and whether physics agrees. When physics disagrees, the hop is a proxy or anycast, or its location is wrong.

Probe → enrich → judge → output (console table and JSON Lines, schema in `schema/`).

- **Probe:** Paris traceroute over ICMP and ICMPv6, so every probe of a trace follows the same path.
- **Enrich:** AS and city from local bases, IXPs, router names, the anycast census and RIPE IPmap.
- **Judge:** each claimed location is checked against the speed of light in fiber, with its source. A guess stays a guess.
- **Targets and batch:** the same rules choose targets and keep them honest, with automatic replacement and a log. Batch mode runs a list for days, and its data survives a power cut. What the host could not measure is recorded as `unmeasured` and never counts against a target.
- **Live (`serve`, Phase 2):** the same probe, run without end on up to 5 targets, one round every 2 s each, with a constant Paris flow per target.
  - Route changes by AS become events: provisional in the round that sees them, confirmed after 3 rounds.
  - Window statistics come from histograms; a percentile is shown only with enough samples, otherwise `NA`, never 0.
  - A LAN-only API (`/v1`, JSON and server-sent events) and a web view embedded in the binary. Type any IP address there to trace it, or remove it; the list is saved and audited.
  - Public mode (`?public=1`) is applied on the server and hides the home side.
  - History: JSON Lines per target and UTC day, synced every 10 s, compressed when the day closes, under a disk cap (16 GiB by default). It survived a real power cut intact.
  - If the node boots before it has its LAN address, it measures anyway and opens the view once the address comes.

**Setup:**

- Copy `config.example.json` to the user's config folder as `tracertip/config.json`.
- Copy `geohints.tsv.example` to the bases folder as `geohints.tsv`.
- Run `tracertip update-db`.
- On a node, use `deploy/install.sh`.
- For the live view: copy `deploy/live.env.example` to `/etc/tracertip/live.env` with the node's LAN address, install `deploy/tracertip-live.service`, and apply `deploy/nftables.conf` with the LAN range. The terminal and the journal print the address to open.

**Status:** Phase 1 closed on 2026-09-29 and Phase 2 on 2026-10-06. The project is paused; the live service is ready whenever the node is on. A separate desktop client is not planned: the web view covers it.

*Updated: 2026-10-06 01:08 UTC.*
