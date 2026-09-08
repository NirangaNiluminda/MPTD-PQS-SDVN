#!/usr/bin/env python3
"""Snapshot the live Fabric ledger to JSON, for demo-day reliability.

Run standalone (not part of the FastAPI app's request path): querying every
surface can take a while under load, and re-querying live on every page load
couples the demo to Fabric being reachable at presentation time. This repo's
whole design philosophy is replay-first (see DEMO_UI_PLAN_2026-08-14.md) —
the ledger panel gets the same treatment.

Usage:
    cd demo_ui/backend && python3 scripts/snapshot_ledger.py
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from parsers import ledger  # noqa: E402

OUT = Path(__file__).resolve().parent.parent.parent / "captures" / "ledger_snapshot.json"


def main():
    print(f"Querying {len(ledger.SNAPSHOT_QUERIES)} chaincode functions via {ledger.SOCKET_PATH} ...")
    t0 = time.time()
    snapshot = ledger.build_snapshot()
    elapsed = time.time() - t0

    for key, val in snapshot.items():
        n = len(val) if isinstance(val, list) else "ERROR" if isinstance(val, dict) and "_error" in val else "?"
        print(f"  {key:18} {n}")

    payload = {"captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "data": snapshot}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"\nWrote {OUT} in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
