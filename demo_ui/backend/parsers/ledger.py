"""Client for the Fabric gateway daemon's Unix socket.

scratch/mptd_pqs_sdvn/fabric_gateway_daemon/main.go listens on
FABRIC_GW_SOCKET (default /tmp/mptd_fabric.sock) for newline-delimited JSON:

    {"action":"query","function":"<chaincode fn>","args":[...]}  ->
    {"ok":true,"payload":"<json-encoded string>"}

NOTE — scratch/mptd_pqs_sdvn/fabric_invoke.sh is BROKEN on this machine: it
hardcodes /home/niranga/fabric-samples/test-network (a different machine's
path) and targets localhost:7051, which is not part of this 64-RSU network.
The socket above is the only path confirmed working here (2026-08-15).

A single chaincode query can legitimately take up to ~20-30s under load
(verified: registering 264 identities took ~12 min at ~2.4s/call, and one
individual call was clocked in the tens of seconds while four unrelated
CPU-heavy simulations were competing for the box). Near-zero CPU / long wait
is this workload's NORMAL signature, not a hang — see
project-demo-ui-capture-run.md in memory for the full story of how that was
first misdiagnosed.
"""

import json
import socket
from pathlib import Path

SOCKET_PATH = "/tmp/mptd_fabric.sock"
DEFAULT_TIMEOUT = 45.0


class LedgerError(Exception):
    pass


def query(function: str, args: list[str] | None = None, timeout: float = DEFAULT_TIMEOUT):
    """Call a chaincode query function; returns the decoded payload."""
    req = json.dumps({"action": "query", "function": function, "args": args or []}) + "\n"
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(SOCKET_PATH)
        s.sendall(req.encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(1 << 20)
            if not chunk:
                break
            buf += chunk
        s.close()
    except (OSError, socket.timeout) as e:
        raise LedgerError(f"gateway socket unavailable: {e}") from e

    if not buf:
        raise LedgerError("empty response from gateway daemon")
    try:
        resp = json.loads(buf.decode().split("\n", 1)[0])
    except json.JSONDecodeError as e:
        raise LedgerError(f"malformed gateway response: {e}") from e

    if not resp.get("ok", False):
        raise LedgerError(f"chaincode query failed: {resp}")

    payload = resp.get("payload")
    if isinstance(payload, str) and payload[:1] in "[{":
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload
    return payload


# The queries the demo cares about, one place so the snapshot script and any
# live-refresh path stay in sync.
SNAPSHOT_QUERIES = {
    "rsu_trust": "GetAllRSUTrustScores",
    "controller_trust": "GetAllControllerTrustScores",
    "vehicle_trust": "GetAllTrustScores",
    "revocations": "GetAllRevokeRecords",
    "controller_flags": "GetAllControllerFlags",
    "reassignments": "GetControllerReassignments",
    "registrations": "GetAllRegistrations",
}


def build_snapshot() -> dict:
    """Query every ledger surface the demo shows. Partial failure per-query
    is tolerated (recorded as an error string) so one bad call doesn't lose
    everything else — this ran against a shared, concurrently-loaded Fabric
    network and individual calls are not guaranteed to succeed."""
    out: dict = {}
    for key, fn in SNAPSHOT_QUERIES.items():
        try:
            out[key] = query(fn)
        except LedgerError as e:
            out[key] = {"_error": str(e)}
    return out


def load_snapshot(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)
