#!/usr/bin/env python3
"""
compute_ttd.py — Time-To-Detect (TTD), paper Eq.~ttd.

Stage 0 of the 7->11 evaluation-metrics upgrade (see
scratch/mptd_pqs_sdvn/METRICS_UPGRADE_PLAN.md). TTD is derived purely from the
existing per-beacon `beacon_log.csv` — no simulator change or rebuild required.

For each attacker vehicle i (any vehicle poisoned at least once):
    t_start_i = first sim_time with is_poisoned == 1        (attack onset)
    t_alert_i = first sim_time with detected == 1 AND sim_time >= t_start_i
    TTD_i     = t_alert_i - t_start_i

The paper's Eq.~ttd averages (t_alert - t_start) over the malicious set. An
attacker that is NEVER flagged has no t_alert (detection failed — e.g. the
Detection Infeasible Zone at high speed), so it is reported separately as
"never-detected" rather than silently dropped or counted as zero delay. The
reported mean/median TTD is over DETECTED attackers only; the never-detected
fraction is the honest companion number.

Usage:
    python3 compute_ttd.py <beacon_log.csv> [--by-class] [--out ttd_rows.csv]
"""
import argparse
import sys

import numpy as np
import pandas as pd

REQUIRED = {"sim_time", "vehicle_id", "is_poisoned", "detected"}


def compute_ttd(df: pd.DataFrame) -> pd.DataFrame | None:
    """Return a per-attacker TTD table, or None if there are no attackers."""
    if (df["is_poisoned"] == 1).sum() == 0:
        return None
    rows = []
    for vid, g in df.groupby("vehicle_id"):
        gp = g[g["is_poisoned"] == 1]
        if gp.empty:
            continue  # honest vehicle — not an attacker, excluded from TTD
        t_start = gp["sim_time"].min()
        # first alert at or after attack onset (a flag before onset is not a TTD alert)
        ga = g[(g["detected"] == 1) & (g["sim_time"] >= t_start)]
        if ga.empty:
            rows.append((vid, t_start, np.nan, False))  # censored: never detected
        else:
            rows.append((vid, t_start, ga["sim_time"].min(), True))
    res = pd.DataFrame(rows, columns=["vehicle_id", "t_start", "t_alert", "detected"])
    res["ttd"] = res["t_alert"] - res["t_start"]
    return res


def summarize(res: pd.DataFrame, label: str = "") -> dict:
    n = len(res)
    det = res[res["detected"]]
    n_det = len(det)
    miss = n - n_det
    mean_ttd = det["ttd"].mean() if n_det else float("nan")
    med_ttd = det["ttd"].median() if n_det else float("nan")
    tag = f" {label}" if label else ""
    print(
        f"[TTD{tag}] attackers={n} detected={n_det} "
        f"never-detected={miss} ({100 * miss / max(n, 1):.1f}%)  "
        f"mean_TTD={mean_ttd:.4f}s median_TTD={med_ttd:.4f}s"
    )
    return dict(
        label=label or "overall", attackers=n, detected=n_det,
        never_detected=miss, mean_ttd_s=mean_ttd, median_ttd_s=med_ttd,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Time-To-Detect from a beacon_log.csv")
    ap.add_argument("beacon_log", help="path to a beacon_log.csv")
    ap.add_argument("--by-class", action="store_true",
                    help="also break TTD down by attacker_class")
    ap.add_argument("--out", help="write the per-attacker TTD rows to this CSV")
    args = ap.parse_args()

    df = pd.read_csv(args.beacon_log)
    missing = REQUIRED - set(df.columns)
    if missing:
        sys.exit(f"beacon_log missing required columns: {sorted(missing)}")

    res = compute_ttd(df)
    if res is None:
        print("[TTD] no poisoned beacons — nothing to compute (clean run?)")
        return

    summarize(res, "overall")
    if args.by_class and "attacker_class" in df.columns:
        vclass = df.groupby("vehicle_id")["attacker_class"].agg(
            lambda s: s.mode().iat[0] if not s.mode().empty else -1)
        res = res.merge(vclass.rename("attacker_class"), on="vehicle_id")
        for cls, g in res.groupby("attacker_class"):
            summarize(g, f"class={cls}")

    if args.out:
        res.to_csv(args.out, index=False)
        print(f"[TTD] per-attacker rows -> {args.out}")


if __name__ == "__main__":
    main()
