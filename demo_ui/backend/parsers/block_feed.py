"""Real block-commit events, read from a Fabric peer CONTAINER's own docker
log — not the ns-3 process's stdout, which has no distinct block-creation
line of its own (see ledger.py's module docstring: that logging lives in
the separate peer/orderer containers). One peer is enough: every peer on
mptdchannel converges to the same chain, so peer1's own "Committed block"
lines are a faithful live feed of block creation.

`docker logs --tail N <container>` was measured at ~10ms for N=400 against
this network (2026-08-30) — cheap enough to poll every ~1s from an SSE
generator, matching the same tail-and-sleep pattern app.py already uses for
live run logs (runs_stream). No `--since` timestamp parsing: a fixed-size
tail plus dedup-by-block-number is simpler and just as correct, since
consecutive polls comfortably overlap at this log volume.
"""

import re
import subprocess

PEER_CONTAINER = "peer1.rsu.example.com"
CHANNEL = "mptdchannel"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")
_BLOCK_RE = re.compile(
    r"\[(?P<channel>[\w.-]+)\] Committed block \[(?P<block>\d+)\] with (?P<txs>\d+) transaction\(s\) "
    r"in (?P<ms>[\d.]+)ms.*?commitHash=\[(?P<hash>[0-9a-fA-F]+)\]"
)


def _parse_line(raw: str) -> dict | None:
    line = _ANSI_RE.sub("", raw)
    m = _BLOCK_RE.search(line)
    if not m:
        return None
    ts_m = _TS_RE.match(line)
    return {
        "block": int(m.group("block")),
        "channel": m.group("channel"),
        "tx_count": int(m.group("txs")),
        "commit_ms": float(m.group("ms")),
        "hash": m.group("hash")[:16],
        "log_ts": ts_m.group(1) if ts_m else None,
    }


def fetch_recent(container: str = PEER_CONTAINER, tail: int = 400) -> list[dict]:
    """Block-commit events found in the last `tail` lines of the container's
    log, oldest first. Returns [] (not fabricated data) if docker itself is
    unreachable or the container is gone."""
    try:
        out = subprocess.run(
            ["docker", "logs", "--tail", str(tail), container],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        raise BlockFeedError(f"docker logs failed: {e}") from e
    events = []
    for line in out.stdout.splitlines() + out.stderr.splitlines():
        ev = _parse_line(line)
        if ev is not None:
            events.append(ev)
    events.sort(key=lambda e: e["block"])
    return events


def chain_height(container: str = PEER_CONTAINER, channel: str = CHANNEL) -> dict | None:
    """One real `peer channel getinfo` call — height plus the current block
    hash, straight from the peer. None (not a guess) if it fails."""
    try:
        out = subprocess.run(
            ["docker", "exec", container, "peer", "channel", "getinfo", "-c", channel],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    m = re.search(r"Blockchain info: (\{.*\})", out.stdout + out.stderr)
    if not m:
        return None
    import json

    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


class BlockFeedError(Exception):
    pass
