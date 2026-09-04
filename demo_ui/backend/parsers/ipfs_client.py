"""Thin client for the real local IPFS daemon's HTTP API — stdlib only, no
new dependency. Used for an on-demand "pin real data, get a real CID" demo
that is deliberately independent of the simulator: the simulator only talks
to IPFS live during a run (hours away for a full sim, see project notes on
sim wall-clock), so this lets the UI demonstrate a genuine round trip against
whatever's already running, on demand.

Confirmed reachable and round-trip-verified by hand (add -> cat -> gateway
fetch, all matched) against 127.0.0.1:5002 (API) / 127.0.0.1:8081 (gateway) —
see ~/.ipfs/config for the non-default ports (5001/8080 are NOT in use here).

This never falls back to a fabricated hash the way the simulator's FNV-1a
stub does (04_state_globals.h:391) — if the daemon isn't reachable, callers
get IpfsUnreachable and must show that honestly, not a fake CID.
"""

import json
import urllib.error
import urllib.request
import uuid

API_URL = "http://127.0.0.1:5002/api/v0"
GATEWAY_URL = "http://127.0.0.1:8081/ipfs"
TIMEOUT_S = 5.0


class IpfsUnreachable(Exception):
    pass


def _post(path: str, timeout: float = TIMEOUT_S) -> dict:
    req = urllib.request.Request(f"{API_URL}/{path}", method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise IpfsUnreachable(str(e)) from e


def status() -> dict:
    """Real, right-now daemon status — not read from any log file."""
    try:
        idinfo = _post("id")
        ver = _post("version")
        return {
            "reachable": True,
            "peer_id": idinfo.get("ID"),
            "addresses": idinfo.get("Addresses", [])[:2],
            "version": ver.get("Version"),
        }
    except IpfsUnreachable as e:
        return {"reachable": False, "error": str(e)}


def add_json(payload: dict, filename: str = "data.json") -> dict:
    """Real `ipfs add` (pinned) of real JSON — returns the genuine CID.
    Raises IpfsUnreachable rather than ever fabricating a hash."""
    body = json.dumps(payload, indent=2, default=str).encode("utf-8")
    boundary = uuid.uuid4().hex
    parts = [
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
        b"Content-Type: application/json\r\n\r\n",
        body,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    data = b"".join(parts)

    req = urllib.request.Request(
        f"{API_URL}/add?pin=true",
        method="POST",
        data=data,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            result = json.loads(resp.read())
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise IpfsUnreachable(str(e)) from e

    return {
        "cid": result["Hash"],
        "size_bytes": int(result["Size"]),
        "gateway_url": f"{GATEWAY_URL}/{result['Hash']}",
    }
