"""Decode the 9-bit rule-signature mask into plain-language accusations.

Source of truth: scratch/mptd_pqs_sdvn/08_detection_engine.h:1069-1092
(SIG_WEIGHTS table + bit layout comment). Weights sum to 1.0; psi_th = 0.09.

Bit layout: all_flags = tp_flags | (mp_flags << 5)
  bits 0-4 = TP-S1..TP-S5 (tp_flags)
  bits 5-8 = MP-S1..MP-S4 (mp_flags << 5)
"""

from dataclasses import dataclass

PSI_TH = 0.09

SIGNATURES = [
    {"bit": 0, "code": "TP-S1", "weight": 0.15, "name": "Teleported",
     "detail": "Moved further than physically possible for the elapsed time."},
    {"bit": 1, "code": "TP-S2", "weight": 0.10, "name": "Turned too sharply",
     "detail": "Heading changed faster than a vehicle at this speed can turn."},
    {"bit": 2, "code": "TP-S3", "weight": 0.10, "name": "Accelerated too hard",
     "detail": "Reported acceleration exceeds the physical bound."},
    {"bit": 3, "code": "TP-S4", "weight": 0.15, "name": "Broke its own prediction",
     "detail": "Position doesn't match where its last report predicted it would be."},
    {"bit": 4, "code": "TP-S5", "weight": 0.15, "name": "Story has drifted",
     "detail": "Cumulative drift from a consistent trajectory over time."},
    {"bit": 5, "code": "MP-S1", "weight": 0.15, "name": "Too many claimants",
     "detail": "Identity density exceeds what one location can hold (ghost injection)."},
    {"bit": 6, "code": "MP-S2", "weight": 0.05, "name": "Radio timing is off",
     "detail": "Beacon timing doesn't match a real DSRC radio's sync window."},
    {"bit": 7, "code": "MP-S3", "weight": 0.10, "name": "Doesn't match its neighbours",
     "detail": "Speed distribution diverges (KL) from the surrounding traffic."},
    {"bit": 8, "code": "MP-S4", "weight": 0.05, "name": "Impossible crossing",
     "detail": "Appeared at a second RSU faster than travel between them allows."},
]

_BY_BIT = {s["bit"]: s for s in SIGNATURES}


@dataclass
class Accusation:
    code: str
    name: str
    detail: str
    weight: float


def decode(sig_mask: int) -> list[Accusation]:
    """sig_mask -> ordered list of tripped signatures (highest weight first)."""
    hits = [
        Accusation(s["code"], s["name"], s["detail"], s["weight"])
        for bit, s in _BY_BIT.items()
        if sig_mask & (1 << bit)
    ]
    return sorted(hits, key=lambda a: -a.weight)


def psi_from_mask(sig_mask: int) -> float:
    """Recompute psi from the mask alone, for cross-checking against psi_score."""
    return sum(s["weight"] for bit, s in _BY_BIT.items() if sig_mask & (1 << bit))


def is_anomalous(sig_mask: int) -> bool:
    return psi_from_mask(sig_mask) > PSI_TH
