"""Parse [SC-REVOKE-VOTE-RSU*] stdout lines — real BFT revocation votes cast
against a specific vehicle, from the same capture log [FUSION-RSU*] and
[METRICS] are parsed from (see fusion.py, metrics.py). This is the real
per-vehicle mitigation signal for that same run: a vote accumulates toward a
threshold (paper Sec 3.5.5 Eq 3.65, 2f+1 BFT) before a vehicle is actually
revoked — most votes in any short window never cross it, which is itself a
real, honest thing to show rather than implying every flag ends in revocation.

Example line:
  [SC-REVOKE-VOTE-RSU10] V127 ts=7.070 payload={"voted":true,"votes":1,"threshold":3,"revoked":false} (paper §3.5.5 Eq 3.65 BFT 2f+1, window T_w)
"""

import json
import re
from dataclasses import dataclass
from typing import Iterator, TextIO

_LINE_RE = re.compile(
    r"^\[SC-REVOKE-VOTE-RSU(?P<rsu_id>\d+)\]\s+"
    r"V(?P<vehicle_id>\d+)\s+"
    r"ts=(?P<t>[\d.]+)\s+"
    r"payload=(?P<json>\{[^}]*\})"
)


@dataclass
class RevokeVote:
    rsu_id: int
    vehicle_id: int
    t: float
    voted: bool
    votes: int
    threshold: int
    revoked: bool


def parse_line(line: str) -> RevokeVote | None:
    m = _LINE_RE.search(line)
    if not m:
        return None
    try:
        payload = json.loads(m.group("json"))
    except json.JSONDecodeError:
        return None
    return RevokeVote(
        rsu_id=int(m.group("rsu_id")),
        vehicle_id=int(m.group("vehicle_id")),
        t=float(m.group("t")),
        voted=bool(payload.get("voted", False)),
        votes=int(payload.get("votes", 0)),
        threshold=int(payload.get("threshold", 0)),
        revoked=bool(payload.get("revoked", False)),
    )


def iter_votes(fh: TextIO) -> Iterator[RevokeVote]:
    for line in fh:
        v = parse_line(line)
        if v is not None:
            yield v
