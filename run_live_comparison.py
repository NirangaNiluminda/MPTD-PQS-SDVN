#!/usr/bin/env python3
"""
Full-system comparison: B1 (Ghaleb) / B2 (Ercan RF) / B3 (Sharma RF) vs the
REAL MPTD-PQS stack = LW-DETECT + GAT (mptd_pqs/gat_detector.py) +
Temporal-AE (mptd_pqs/temporal_autoencoder.py) + FusionEngine(variant="FULL").

Runs on analytics/ml/data/beacon_train_master.csv (the actual dataset the
7 uploaded charts were built from), grouped by (attack_number, attack_pct).

Computes all 7 project metrics (MCC, FPR, PARR, CDER, TDEE, TPE, PBPO) for
every method and saves the same style of 7 multi-panel PNGs (one per metric,
one subplot per attack a1-a7) as run_live_comparison.py, plus a CSV.

Two real bugs fixed in B1 (see run_b1() and the RSU_POS patch below):
  1. RSU_POS was a hardcoded legacy 4-RSU grid instead of the real
     mobility/rsu_positions_urban.csv grid.
  2. df.iterrows() upcasts int vehicle_id -> float in one loop but not the
     other inside GhalebB1Detector.run(), so the self-peer exclusion check
     never matched and Module 2c fired on every single beacon.
"""
import json
import math
import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import matthews_corrcoef, confusion_matrix

_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(_HERE, "mptd_pqs")):
    ROOT = _HERE
elif os.path.exists(os.path.join(_HERE, "MPTD-PQS-SDVN", "mptd_pqs")):
    ROOT = os.path.join(_HERE, "MPTD-PQS-SDVN")
else:
    raise FileNotFoundError(
        f"Can't find the MPTD-PQS-SDVN project (mptd_pqs/ package) near {_HERE}. "
        "Place this script either inside the project root or in its parent folder."
    )
sys.path.insert(0, ROOT)

from mptd_pqs import ghaleb_b1_detector as b1mod
from mptd_pqs import ercan_b2_detector_v2 as b2mod
from mptd_pqs import sharma_b3_detector_v2 as b3mod
from mptd_pqs.lightweight_detector import LightweightDetector, TrajectoryPoint
from mptd_pqs.gat_detector import GATDetector, VehicleState
from mptd_pqs.temporal_autoencoder import TemporalAEDetector
from mptd_pqs.fusion import FusionEngine

BEACON_CSV = os.path.join(ROOT, "analytics/ml/data/beacon_train_master.csv")
RSU_CSV = os.path.join(ROOT, "mobility/rsu_positions_urban.csv")
OUT_DIR = os.path.join(ROOT, "results")
os.makedirs(OUT_DIR, exist_ok=True)

CDER_THRESHOLD = 10.0  # metres

# ---- FIX #1: patch B1's hardcoded legacy RSU grid with the real CSV grid ----
REAL_RSU_POS = b2mod.load_rsu_positions(RSU_CSV)
b1mod.RSU_POS = REAL_RSU_POS
print(f"[fix] B1 RSU_POS patched -> {list(REAL_RSU_POS.items())[:2]} ... "
      f"({len(REAL_RSU_POS)} RSUs from real CSV, was hardcoded legacy 4-RSU grid)")

# ── plotting config (mirrors run_live_comparison.py) ────────────────────────
ATTACK_ORDER = [1, 2, 3, 4, 5, 6, 7]
ATTACK_TITLES = {
    1: "a1: TP-S1 (RSU drift)", 2: "a2: TP-S2 (speed/heading)",
    3: "a3: MP-S1 (Sybil ghost)", 4: "a4: MP-S2 (impersonation)",
    5: "a5: TP-S3 (flooding)", 6: "a6: MitM intercept", 7: "a7: Controller poison",
}

# Method labels used in the results dataframe -> plot style. Kept distinct
# from run_live_comparison.py's STYLES because this script has 5 methods
# (LW-only and FULL stack shown separately) instead of 4.
STYLES = {
    "B1_Ghaleb":                            dict(color="#b19cd9", marker="^", linestyle="-"),
    "B2_Ercan":                              dict(color="#1f77b4", marker="s", linestyle="-"),
    "B3_Sharma":                             dict(color="#2ca02c", marker="s", linestyle="-"),
    "MPTD-PQS_LW-only":                      dict(color="#ff7f0e", marker="o", linestyle="--"),
    "MPTD-PQS_FULL(LW+GAT+LSTM-AE+Fusion)":  dict(color="#8b0000", marker="D", linestyle="--"),
}

METRIC_SPECS = [
    ("MCC",     "Matthews Correlation Coefficient (MCC)", None),
    ("FPR",     "False Positive Rate (FPR)", None),
    ("PARR",    "Poisoned Attack Rejection Rate (PARR)", None),
    ("CDER",    "Control Decision Error Rate, CDER [m]", "log"),
    ("TDEE",    "Trajectory Deviation Error Energy, TDEE [m^2]", "log"),
    ("TPE",     "Trajectory Poisoning Effectiveness (TPE)", None),
    ("PBPO_ms", "Per-Beacon Processing Overhead (PBPO) [ms]", "log"),
]


def load_beacon():
    df = pd.read_csv(BEACON_CSV)
    df["real_pos_x"] = df["gt_pos_x"]
    df["real_pos_y"] = df["gt_pos_y"]
    df["disp_err_m"] = np.hypot(df["pos_x"] - df["gt_pos_x"], df["pos_y"] - df["gt_pos_y"])
    return df


def compute_metrics(y_true, y_pred, disp_err, n_total, pbpo_ms):
    """Same formula as run_live_comparison.py's compute_metrics, so numbers
    are directly comparable across both scripts."""
    y_true = np.asarray(y_true); y_pred = np.asarray(y_pred)
    disp_err = np.asarray(disp_err, dtype=float)
    if len(np.unique(y_true)) < 2:
        return None

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    mcc = float(matthews_corrcoef(y_true, y_pred))
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    parr = tp / (tp + fn) if (tp + fn) else 0.0

    fn_mask = (y_true == 1) & (y_pred == 0)
    fn_devs = disp_err[fn_mask]
    exceeded = fn_devs[fn_devs > CDER_THRESHOLD]
    cder = float(exceeded.mean()) if len(exceeded) else 0.0
    tdee = float(np.sum(fn_devs ** 2))

    n_poisoned = int((y_true == 1).sum())
    tpe = n_poisoned / n_total if n_total else 0.0
    pbpo_missrate = int(fn) / n_total if n_total else 0.0

    return dict(TP=int(tp), FP=int(fp), TN=int(tn), FN=int(fn),
                MCC=round(mcc, 4), FPR=round(fpr, 4), PARR=round(parr, 4),
                CDER=round(cder, 4), TDEE=round(tdee, 2), TPE=round(tpe, 4),
                PBPO_missrate=round(pbpo_missrate, 4), PBPO_ms=round(pbpo_ms, 4))


def run_b1(beacon_aug):
    # FIX #2: GhalebB1Detector.run() builds its peer_map via df.iterrows(),
    # which upcasts the whole row (including int vehicle_id) to a common
    # dtype because other columns are float -> str(vehicle_id) becomes
    # "3.0" there, but the outer groupby loop keeps vehicle_id as int -> "3".
    # The self-exclusion filter (`pvid != str(vid)`) then never matches, so
    # every vehicle appears as its own "peer" at distance 0 -> Module 2c
    # (anti-Sybil min-separation check) fires on every single beacon,
    # regardless of attack. Casting vehicle_id to str up front keeps the
    # dtype consistent across both loops and fixes it.
    beacon_aug = beacon_aug.copy()
    beacon_aug["vehicle_id"] = beacon_aug["vehicle_id"].astype(str)
    det = b1mod.GhalebB1Detector()
    t0 = time.perf_counter()
    out = det.run(beacon_aug)
    ms = (time.perf_counter() - t0) * 1000.0 / max(len(out), 1)
    return compute_metrics(out["label"].values, out["pred"].values,
                            out["disp_err_m"].values, len(out), ms)


def run_b2(beacon_aug):
    t0 = time.perf_counter()
    feat = b2mod.extract_features(beacon_aug)
    cols = json.load(open(os.path.join(ROOT, "models_global/ercan_feature_cols.json")))["ercan"]
    model = joblib.load(os.path.join(ROOT, "models_global/ercan_global_RF.joblib"))
    pred = model.predict(feat[cols])
    ms = (time.perf_counter() - t0) * 1000.0 / max(len(feat), 1)
    return compute_metrics(feat["label"].values, pred, feat["disp_err_m"].values, len(feat), ms)


def run_b3(beacon_aug):
    t0 = time.perf_counter()
    feat = b3mod.extract_features(beacon_aug)
    cols = json.load(open(os.path.join(ROOT, "models_global/sharma_feature_cols.json")))["sharma"]
    model = joblib.load(os.path.join(ROOT, "models_global/sharma_global_RF.joblib"))
    pred = model.predict(feat[cols])
    ms = (time.perf_counter() - t0) * 1000.0 / max(len(feat), 1)
    return compute_metrics(feat["label"].values, pred, feat["disp_err_m"].values, len(feat), ms)


def to_points(beacon_aug):
    points = []
    for _, r in beacon_aug.iterrows():
        hdg = float(r["heading"])
        spd = float(r["speed"])
        acc = float(r["accel"])
        points.append(TrajectoryPoint(
            vehicle_id=str(r["vehicle_id"]),
            rsu_id=str(int(r["rsu_id"])),
            timestamp=float(r["sim_time"]),
            pos_x=float(r["pos_x"]), pos_y=float(r["pos_y"]),
            vel_x=spd * math.cos(hdg), vel_y=spd * math.sin(hdg),
            acc_x=acc * math.cos(hdg), acc_y=acc * math.sin(hdg),
            is_poisoned=bool(r["is_poisoned"]),
        ))
    return points


def snapshot_bucket(t, width=0.1):
    """Round sim_time into ~0.1s windows. Beacons in this dataset are
    staggered per-vehicle by ~0.00625s (16 vehicles cycling every ~0.1s),
    so grouping by exact float timestamp gives singleton "snapshots" of 1
    vehicle. GATDetector normalizes each snapshot's error by its own max
    (scores_norm = err / max_err), so a singleton snapshot always scores
    exactly 1.0 regardless of whether the vehicle is actually anomalous.
    Bucketing recovers real multi-vehicle graphs so the reconstruction
    error is measured against actual neighbours."""
    return round(t / width) * width


def run_full_system(beacon_aug):
    points = to_points(beacon_aug)
    clean_pts = [p for p in points if not p.is_poisoned]
    disp_err = beacon_aug["disp_err_m"].values  # same row order as to_points()
    n_total = len(points)

    # LW-DETECT
    lw_det = LightweightDetector()
    t0 = time.perf_counter()
    lw_results = lw_det.process_batch(points)
    ms_lw = (time.perf_counter() - t0) * 1000.0 / max(n_total, 1)

    # GAT (trained fresh per group on clean snapshots)
    gat_det = GATDetector(threshold=0.4, train_epochs=30)
    by_time = {}
    for p in clean_pts:
        by_time.setdefault(snapshot_bucket(p.timestamp), []).append(p)
    for t, pts in by_time.items():
        gat_det.add_training_snapshot([VehicleState(
            vehicle_id=p.vehicle_id, rsu_id=p.rsu_id, timestamp=p.timestamp,
            pos_x=p.pos_x, pos_y=p.pos_y, vel_x=p.vel_x, vel_y=p.vel_y,
            acc_x=p.acc_x, acc_y=p.acc_y, is_poisoned=p.is_poisoned) for p in pts])
    gat_det.finalize_training()

    all_by_time = {}
    for p in points:
        all_by_time.setdefault(snapshot_bucket(p.timestamp), []).append(p)
    gat_lookup = {}
    t0 = time.perf_counter()
    for t, pts in all_by_time.items():
        states = [VehicleState(
            vehicle_id=p.vehicle_id, rsu_id=p.rsu_id, timestamp=p.timestamp,
            pos_x=p.pos_x, pos_y=p.pos_y, vel_x=p.vel_x, vel_y=p.vel_y,
            acc_x=p.acc_x, acc_y=p.acc_y, is_poisoned=p.is_poisoned) for p in pts]
        for r in gat_det.score_snapshot(states):
            gat_lookup[(r["vehicle_id"], r["timestamp"])] = r
    ms_gat = (time.perf_counter() - t0) * 1000.0 / max(n_total, 1)

    # Temporal AE (trained fresh per group on clean sequences)
    ae_det = TemporalAEDetector(seq_len=5, theta_ae=8.0, train_epochs=30)
    for p in sorted(clean_pts, key=lambda x: (x.vehicle_id, x.timestamp)):
        ae_det.add_training_point(p)
    ae_det.finalize_training()
    ae_lookup = {}
    t0 = time.perf_counter()
    for p in sorted(points, key=lambda x: (x.vehicle_id, x.timestamp)):
        r = ae_det.process(p)
        if r:
            ae_lookup[(r["vehicle_id"], r["timestamp"])] = r
    ms_ae = (time.perf_counter() - t0) * 1000.0 / max(n_total, 1)

    # Fusion
    engine = FusionEngine(variant="FULL")
    t0 = time.perf_counter()
    y_true, y_pred_lw, y_pred_full = [], [], []
    for lw, pt in zip(lw_results, points):
        key = (pt.vehicle_id, pt.timestamp)
        gat_r = gat_lookup.get(key)
        ae_r = ae_lookup.get(key)
        psi = lw.psi
        gat = gat_r["gat_score"] if gat_r else 0.0
        ae = ae_r["ae_score"] if ae_r else 0.0
        fr = engine.fuse(pt.vehicle_id, pt.rsu_id, pt.timestamp,
                          psi=psi, gat_score=gat, ae_score=ae,
                          ground_truth_poisoned=pt.is_poisoned)
        y_true.append(int(pt.is_poisoned))
        y_pred_lw.append(int(lw.flagged))
        y_pred_full.append(int(fr.flagged))
    ms_fusion = (time.perf_counter() - t0) * 1000.0 / max(n_total, 1)

    y_true = np.array(y_true)
    m_lw = compute_metrics(y_true, np.array(y_pred_lw), disp_err, n_total, ms_lw)
    m_full = compute_metrics(y_true, np.array(y_pred_full), disp_err, n_total,
                              ms_lw + ms_gat + ms_ae + ms_fusion)
    return m_lw, m_full


def make_plots(res, pcts_available):
    """Same visual style as run_live_comparison.py: one PNG per metric,
    one subplot per attack (a1-a7), one line per method."""
    for metric, title, yscale in METRIC_SPECS:
        fig, axes = plt.subplots(2, 4, figsize=(20, 8))
        axes = axes.flatten()
        for i, a in enumerate(ATTACK_ORDER):
            ax = axes[i]
            sub = res[res.attack_number == a]
            for method, style in STYLES.items():
                d = sub[sub.detector == method].sort_values("attack_pct")
                if d.empty:
                    continue
                ax.plot(d["attack_pct"], d[metric], label=method, **style)
            ax.set_title(ATTACK_TITLES[a], fontsize=10)
            ax.set_xlabel("Attack penetration pct (%)")
            ax.set_ylabel(metric)
            if yscale:
                ax.set_yscale(yscale)
            ax.grid(alpha=0.3)
            if i == 0:
                ax.legend(fontsize=6)
        axes[-1].axis("off")
        fig.suptitle(f"{title} vs attack penetration "
                      f"(full_system_comparison, pct={sorted(pcts_available)})",
                     fontweight="bold")
        fig.tight_layout()
        out_path = os.path.join(OUT_DIR, f"{metric.lower()}_chart.png")
        fig.savefig(out_path, dpi=130)
        plt.close(fig)
        print(f"[saved] {out_path}")


def main():
    df = load_beacon()
    rows = []
    for (an, pct), grp in df.groupby(["attack_number", "attack_pct"]):
        grp = grp.copy()
        n = len(grp)
        n_pos = int(grp["is_poisoned"].sum())
        print(f"\n=== attack a{an}  pct={pct}%  (n={n}, poisoned={n_pos}) ===")

        b1 = run_b1(grp)
        b2 = run_b2(grp)
        b3 = run_b3(grp)
        lw, full = run_full_system(grp)

        for name, m in [("B1_Ghaleb", b1), ("B2_Ercan", b2), ("B3_Sharma", b3),
                         ("MPTD-PQS_LW-only", lw),
                         ("MPTD-PQS_FULL(LW+GAT+LSTM-AE+Fusion)", full)]:
            if m is None:
                print(f"  {name:38s}: skipped (single-class group)")
                continue
            print(f"  {name:38s}: MCC={m['MCC']:.3f}  FPR={m['FPR']:.3f}  PARR={m['PARR']:.3f}")
            rows.append(dict(attack_number=an, attack_pct=pct, detector=name, **m))

    res = pd.DataFrame(rows)
    out_path = os.path.join(OUT_DIR, "full_system_comparison.csv")
    res.to_csv(out_path, index=False)
    print(f"\nSaved: {out_path}")

    print("\n=== Mean MCC across all (attack, pct) groups ===")
    print(res.groupby("detector")["MCC"].mean().sort_values(ascending=False))

    # attack_number in the CSV may come out as e.g. "a1" strings or ints
    # depending on the source data; normalize to the plain int used by
    # ATTACK_ORDER/ATTACK_TITLES before plotting.
    if res["attack_number"].dtype == object:
        res["attack_number"] = (res["attack_number"].astype(str)
                                 .str.extract(r"(\d+)").astype(int))

    pcts_available = sorted(res["attack_pct"].unique())
    make_plots(res, pcts_available)
    print(f"\nAll 7 charts + CSV written to ./{OUT_DIR}/")


if __name__ == "__main__":
    main()