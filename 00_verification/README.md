# 00 · Verification (Phase 0) — study

Checks whether the product is worth building: 48 h of real traces with `mtr` to 30 targets, their analysis and a verdict. Not production code.

- `node/`: collection, watchdog and firewall of the measurement host.
- `analysis/`: analyzes the 48 h and writes the report with the verdict.
- `monitor/`: read-only live views of the host.

**Feeds `01_engine`:** real data to build and tune it.

**Status:** frozen when the window closes, on 2026-09-28. Its code and comments stay in Spanish, exactly as they ran on the node.

*Updated: 2026-09-28 19:02 UTC.*
