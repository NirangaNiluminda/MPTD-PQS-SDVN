"""Parse [FUSION-RSU*] stdout lines — the single richest per-vehicle event.

Source of truth: scratch/mptd_pqs_sdvn/08_detection_engine.h:2529-2550 (Eq 3.46).
One line carries the full defence stack for one vehicle at one instant:
rule-signature score (psi), GAT spatial score (S), LSTM-AE error (ae_raw/ae_norm),
fused decision (phi), predicted attack class (khat), and ground truth.

Example line:
  [FUSION-RSU12] epoch=3 t=142.300 vid=47 psi=0.150 psi_fuse=1.000 S=24.81
  thetaS=19.74 S_over_thetaS_raw=1.257 S_over_thetaS_clamped=1.000 ae_norm=0.412
  ae_raw=13.881 dumped=0 gt_pois=1 gt_atk=2 sig_mask=17 phi=0.673 khat=1
  gatflag=1 full_anom=YES (Eq 3.46)

TRAP (documented in RUN_CONFIG.md): full_anom is case-sensitive —
"YES" (uppercase) vs "no" (lowercase). Only an exact "YES" means anomalous;
anything else (including unexpected casing) must resolve to False, not raise.
"""

import re
from dataclasses import dataclass
from typing import Iterator, TextIO

_LINE_RE = re.compile(
    r"^\[FUSION-RSU(?P<rsu_id>\d+)\]\s+"
    r"epoch=(?P<epoch>\d+)\s+"
    r"t=(?P<t>[\d.]+)\s+"
    r"vid=(?P<vid>\d+)\s+"
    r"psi=(?P<psi>[\d.]+)\s+"
    r"psi_fuse=(?P<psi_fuse>[\d.]+)\s+"
    r"S=(?P<S>[\d.]+)\s+"
    r"thetaS=(?P<thetaS>[\d.]+)\s+"
    r"S_over_thetaS_raw=(?P<S_over_thetaS_raw>[\d.]+)\s+"
    r"S_over_thetaS_clamped=(?P<S_over_thetaS_clamped>[\d.]+)\s+"
    r"ae_norm=(?P<ae_norm>[\d.]+)\s+"
    r"ae_raw=(?P<ae_raw>[\d.]+)\s+"
    r"dumped=(?P<dumped>\d+)\s+"
    r"gt_pois=(?P<gt_pois>\d+)\s+"
    r"gt_atk=(?P<gt_atk>-?\d+)\s+"
    r"sig_mask=(?P<sig_mask>\d+)\s+"
    r"phi=(?P<phi>[\d.]+)\s+"
    r"khat=(?P<khat>-?\d+)\s+"
    r"gatflag=(?P<gatflag>\d+)\s+"
    r"full_anom=(?P<full_anom>\S+)"
)


@dataclass
class FusionEvent:
    rsu_id: int
    epoch: int
    t: float
    vid: int
    psi: float
    psi_fuse: float
    S: float
    thetaS: float
    S_over_thetaS_raw: float
    S_over_thetaS_clamped: float
    ae_norm: float
    ae_raw: float
    dumped: bool
    gt_pois: bool
    gt_atk: int
    sig_mask: int
    phi: float
    khat: int
    gatflag: bool
    full_anom: bool  # True iff full_anom=="YES" exactly (case-sensitive)


def parse_line(line: str) -> FusionEvent | None:
    m = _LINE_RE.search(line)
    if not m:
        return None
    g = m.groupdict()
    return FusionEvent(
        rsu_id=int(g["rsu_id"]),
        epoch=int(g["epoch"]),
        t=float(g["t"]),
        vid=int(g["vid"]),
        psi=float(g["psi"]),
        psi_fuse=float(g["psi_fuse"]),
        S=float(g["S"]),
        thetaS=float(g["thetaS"]),
        S_over_thetaS_raw=float(g["S_over_thetaS_raw"]),
        S_over_thetaS_clamped=float(g["S_over_thetaS_clamped"]),
        ae_norm=float(g["ae_norm"]),
        ae_raw=float(g["ae_raw"]),
        dumped=g["dumped"] == "1",
        gt_pois=g["gt_pois"] == "1",
        gt_atk=int(g["gt_atk"]),
        sig_mask=int(g["sig_mask"]),
        phi=float(g["phi"]),
        khat=int(g["khat"]),
        gatflag=g["gatflag"] == "1",
        full_anom=g["full_anom"] == "YES",  # case-sensitive, exact match only
    )


def iter_events(fh: TextIO) -> Iterator[FusionEvent]:
    for line in fh:
        ev = parse_line(line)
        if ev is not None:
            yield ev
