# tracertIP

**Live telemetry of the path to an IP.** It shows which networks the traffic crosses, where along the path the time goes, and what physics (the speed of light in fiber) says about each hop.

> **Status: Phase 1, building the engine.** Phase 0 closed on 2026-09-28. This repository holds only structural material: code, scripts and templates that work on any network.

## Layout

One folder per piece, in order. Only `01_engine/` is production code; `00_` and `02_` are studies that test it. Each folder's `README.md` says what it does and what it feeds.

| Folder | What it is | Status |
|---|---|---|
| `00_verification/` | Study: 48 h of real data and the verdict on whether to build | Closed 2026-09-28 |
| `01_engine/` | Product: traces and judges every hop; grows into live telemetry | In progress |
| `02_observation/` | Study: the engine running untouched for at least 14 days | In preparation |

## What is here today

`00_verification/node/` holds what runs on the measurement host during Phase 0 (48 h of data before building):

| File | What it does |
|---|---|
| `recolectar.sh` + `.service` + `.timer` | Every 15 min, traces the declared targets in sequence with `mtr --json`, and samples host health every 5 min |
| `vigilar.sh` + `.service` + `.timer` | Checks each run and alerts if access (router and CGNAT) stops answering, if several targets lose packets at once, if a run is incomplete or if the host overheats |
| `nftables.conf` | Host firewall: inbound closed except what is needed |
| `*.example` | Templates for per-network settings (targets, local network) |

`00_verification/analysis/` (Go, standard library only) analyzes that data when the window closes: route changes by network (ASN), latency variation, host health, and a cross-check with the BGP announcements seen by RIPE RIS. It writes a report with the phase verdict. Its tests use made-up data only.

`00_verification/monitor/` opens read-only views of the measurement host over SSH, each in its own window:
- processes;
- a dashboard with temperature, fan, current run and watchdog verdicts;
- throughput;
- traffic that is not the probe;
- sockets per process;
- system warnings;
- the collection log;
- interface errors.

`monitor.ps1` (Windows Terminal) deploys `monitor.sh` to the host if its SHA-256 does not match.

## What it does, and what it does not

- It continuously traces **declared targets only**, one at a time and at a bounded rate. **It does not scan**: no range sweeps, no port lists.
- It gathers in one view the hops and their networks (ASN), the geography, ocean crossings, the route history with its changes, and how many milliseconds each segment adds.
- It uses physics as the judge: a location that violates the speed of light is flagged as impossible.

## Expected requirements

- A Linux host that is always on, with `systemd` and `nftables`.
- Go 1.27 or later, to build: `go build -trimpath -o bin/tracertip ./01_engine/cmd/tracertip` (for the node, add `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`).
- For `00_verification/node/`: `mtr` 0.96 or later, and `jq`.
- For `00_verification/monitor/`: `htop`, `nload`, `tcpdump`, `sysstat` and `watch` on the host; Windows Terminal on the PC.

Whatever depends on each installation (local network, addresses, targets) goes in settings files, with an `.example` template.

## Privacy

There is no data from any specific network here. Examples use ranges reserved for documentation (RFC 5737, RFC 3849, RFC 7042 and RFC 2606).

Every commit goes through a checker, `.githooks/pre-commit`, which:

- looks for private host IPs, MACs, keys, tokens, user paths and e-mail addresses;
- matches the content against private term lists that live outside the repository;
- runs [gitleaks](https://github.com/gitleaks/gitleaks).

If the lists or gitleaks are missing, it blocks the commit.

```sh
git config core.hooksPath .githooks
```

## Third-party data

Not redistributed: each installation downloads it and accepts its terms.

- IPinfo Lite — CC BY-SA 4.0
- [IP Geolocation by DB-IP](https://db-ip.com) — CC BY 4.0
- TeleGeography Submarine Cable Map — CC BY-NC-SA 3.0 (**non-commercial use**)
- Natural Earth — public domain

## License

MIT. See `LICENSE`.

---

*Updated: 2026-09-28 23:40 UTC.*
