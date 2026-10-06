# tracertIP

**Live telemetry of the path to an IP.** It shows which networks the traffic crosses, where each hop is, how far it can be, and what physics (the speed of light in fiber) says about it.

> **Status: paused on 2026-10-06, with the live service ready to use.** Phases 1 and 2 are closed. The service starts when the node boots: open its address in a browser on the LAN and type an IP address. A third phase (outside context such as BGP) is not planned. This repository holds only structural material: code, scripts and templates that work on any network.

## Layout

One folder per piece, in order. Only `01_engine/` is production code; `00_` and `02_` are studies that test it. Each folder's `README.md` says what it does and what it feeds.

| Folder | What it is | Status |
|---|---|---|
| `00_verification/` | Study: 48 h of real data and the verdict on whether to build | Closed 2026-09-28 |
| `01_engine/` | Product: traces and judges every hop, once or live | Phase 1 closed 2026-09-29; Phase 2 closed 2026-10-06 |
| `02_observation/` | Study: the engine running untouched for at least 14 days | Rehearsals passed; the 14 days were cancelled on 2026-10-06 |

## The engine (`01_engine/`)

One binary, `tracertip`, for Linux.

| Command | What it does |
|---|---|
| `trace <ip>` | Paris traceroute (ICMP and ICMPv6). For each hop: network (AS), IXP, name, city, distance and the physics check. Add `-json` for records, `-public` to hide the home side, and `-watch` to keep probing and update every round. |
| `lookup <ip>...` | Everything the bases and services say about addresses, without probing |
| `update-db` | Downloads and verifies the local IP bases, each at its source's pace |
| `targets` | Chooses and checks measurement targets: RIPE Atlas anchors, dual-stack, one BGP origin, outside the anycast census, and no faster than light from their declared place |
| `batch` | Traces a target list on fixed UTC slots that alternate IPv4 and IPv6, one target at a time. It replaces failing targets from a reserve, never blames a target for the host's own outages, and writes data that survives a power cut |
| `serve` | Live telemetry: up to 5 targets, one round every 2 s each, without end. A web view built into the binary, on the LAN only: type an IP address to trace it, and see the judged path, a hop-by-time heat map, RTT, route-change events and the instrument's own health. A public mode hides the home side. History is kept per target and day, compressed, under a disk cap |

`01_engine/deploy/` installs the binary with `CAP_NET_RAW` only, a daily, hardened update of the bases, the live service (`tracertip-live.service`) and a host firewall that opens its port to the LAN only.

## Studies

- **`00_verification/`:** closed and kept as it ran. It has the collector (`mtr`), the watchdog, the host firewall, the analysis that produced the verdict, and read-only monitors over SSH.
- **`02_observation/`:** the service that runs `tracertip batch` for the study, its start and stop scripts, and `status.sh`, a one-screen, read-only view of the running study. The study itself was cancelled after its rehearsals: live telemetry keeps continuous history of its targets.

## What it does, and what it does not

- It traces **declared targets only**, one at a time and at a bounded rate. **It does not scan**: no range sweeps, no port lists.
- It uses physics as the judge. A location that violates the speed of light is flagged as impossible, and a guess is shown as a guess, never as a fact.
- It never invents an answer. An unknown AS is `AS?`, an unrouted address says so, and a gap is `*`, never 0 ms.

## Requirements

- A Linux host with `systemd`. It need not be always on: the live service starts at boot, and a missed base update runs then.
- Go 1.27 or later, to build:

  ```sh
  go build -trimpath -o bin/tracertip ./01_engine/cmd/tracertip
  ```

  For the node, add `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`.
- For `00_verification/`: `mtr` 0.96 or later, `jq` and `nftables`; its monitors need `htop`, `nload`, `tcpdump`, `sysstat` and `watch`.

Whatever depends on each installation (origin, access network, resolver, targets) goes in settings files, with an `.example` template.

## Privacy

There is no data from any specific network here. Examples use ranges reserved for documentation (RFC 5737, RFC 3849, RFC 7042 and RFC 2606).

- **Public output:** `-public` hides the home side and every distance from the origin, since three located hops would give the origin away.
- **External services:** the engine never sends the access network's addresses to them.

Every commit goes through a checker, `.githooks/pre-commit`, which:

- looks for private host IPs, MACs, keys, tokens, user paths and e-mail addresses;
- matches the content against private term lists that live outside the repository;
- runs [gitleaks](https://github.com/gitleaks/gitleaks).

If the lists or gitleaks are missing, it blocks the commit.

```sh
git config core.hooksPath .githooks
```

## Third-party data

Not redistributed: each installation downloads or asks for it and accepts its terms.

- [IPtoASN](https://iptoasn.com) — PDDL (public domain)
- [IP Geolocation by DB-IP](https://db-ip.com), ASN and City Lite — CC BY 4.0
- [OurAirports](https://ourairports.com) — public domain
- [PeeringDB](https://www.peeringdb.com) — its acceptable use policy
- [LACeS anycast census](https://github.com/ut-dacs/Anycast-Census) — Hendriks et al., IMC 2025
- RIPE NCC services: [RIPE IPmap](https://ipmap.ripe.net), [RIPEstat](https://stat.ripe.net) and [RIPE Atlas](https://atlas.ripe.net) anchors — RIPE NCC terms
- IPinfo Lite (optional, with its token) — CC BY-SA 4.0

## License

MIT. See `LICENSE`.

---

*Updated: 2026-10-06 01:08 UTC.*
