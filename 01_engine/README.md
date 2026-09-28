# 01 · Engine — product

The only production code. Given an IP, it traces the path and, hop by hop, reports the network, the location and whether physics agrees. When physics disagrees, the hop is a proxy or anycast.

Probe → enrich → judge → output (console table and JSON).

- **Target validation lives in the judge:** the same rules pick the targets and keep them honest: no proxies, true location, and automatic replacement with a log.
- **It grows in place:** a one-shot CLI first (Phase 1), then live telemetry (Phase 2): continuous mode, route changes as events, a LAN-only API and a web dashboard embedded in the binary. A Java desktop client comes later, on the same API.
- Built and tuned with the real data from `00_verification`.

**Status:** next. Only planned engine work goes here.

*Updated: 2026-09-28 18:54 UTC.*
