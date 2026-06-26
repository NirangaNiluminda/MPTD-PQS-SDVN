"""
synthetic_data.py
=================
Generates clean + attack beacon CSVs in the exact schema of DATA_FORMAT.md so
you can build and debug the whole GAT pipeline on a laptop CPU BEFORE your
NS-3/SUMO export exists. When real data arrives, stop using this file — the
schema is identical, so train.py / calibrate.py / score.py are unchanged.

It fabricates simple but plausible mobility:
  * vehicles travel along a dominant heading with small per-step noise
  * urban  -> dense, slow, varied headings
  * highway-> sparse, fast, near co-directional (platoon-like)
The attack file injects a "smooth trajectory drift" malicious class:
  positions drift off the true path gradually (the hard case described in the
  report) while staying kinematically plausible per step.

Usage:
  python synthetic_data.py --scenario urban    --out data/urban
  python synthetic_data.py --scenario highway  --out data/highway
"""
import argparse
import math
import os
import numpy as np
import pandas as pd

# per-scenario generation knobs (NOT the model config; just the simulator)
GEN = {
    "urban":    dict(n_vehicles=40, speed=(5, 12),  heading_spread=1.2, area=600),
    "suburban": dict(n_vehicles=28, speed=(12, 22), heading_spread=0.6, area=1200),
    "highway":  dict(n_vehicles=18, speed=(25, 35), heading_spread=0.15, area=2500),
}


def _simulate(scenario, seed, n_steps, dt, attack, atk_frac, rng):
    g = GEN[scenario]
    n = g["n_vehicles"]
    # init each vehicle: a base heading cluster + position + speed
    base_heading = rng.uniform(0, 2 * math.pi)
    headings = base_heading + rng.uniform(-g["heading_spread"], g["heading_spread"], n)
    speeds = rng.uniform(*g["speed"], n)
    pos = rng.uniform(0, g["area"], size=(n, 2))

    # choose malicious vehicles (only meaningful in attack mode)
    n_mal = int(round(atk_frac * n)) if attack else 0
    mal_ids = set(rng.choice(n, size=n_mal, replace=False).tolist()) if n_mal else set()
    # per-malicious cumulative drift direction
    drift_dir = {m: rng.uniform(0, 2 * math.pi) for m in mal_ids}
    drift_accum = {m: 0.0 for m in mal_ids}

    rows = []
    for step in range(n_steps):
        t = round(step * dt, 3)
        # small heading wobble + speed wobble
        headings = headings + rng.normal(0, 0.03, n)
        speeds = np.clip(speeds + rng.normal(0, 0.3, n), 1.0, None)
        vx = speeds * np.cos(headings)
        vy = speeds * np.sin(headings)
        prev_speed = speeds.copy()
        pos[:, 0] += vx * dt
        pos[:, 1] += vy * dt
        accel = (speeds - prev_speed) / dt

        for i in range(n):
            rx, ry = pos[i]
            label = 0
            if i in mal_ids:
                # gradual position falsification: accumulate a small offset each
                # step so per-step jump stays plausible but the path is corrupted
                drift_accum[i] += rng.uniform(0.3, 0.8)  # metres of drift per step
                rx += drift_accum[i] * math.cos(drift_dir[i])
                ry += drift_accum[i] * math.sin(drift_dir[i])
                label = 1
            rows.append(dict(
                scenario=scenario, seed=seed, t=t, vehicle_id=i,
                x=round(float(rx), 3), y=round(float(ry), 3),
                speed=round(float(speeds[i]), 3),
                heading=round(float(headings[i] % (2 * math.pi)), 5),
                accel=round(float(accel[i]), 3),
                label=label,
            ))
    return rows


def generate(scenario, out_prefix, seeds=(1, 2, 3), n_steps=200, dt=0.1,
             atk_frac=0.2):
    os.makedirs(os.path.dirname(out_prefix) or ".", exist_ok=True)

    clean_rows, attack_rows = [], []
    for s in seeds:
        clean_rows += _simulate(scenario, s, n_steps, dt, attack=False,
                                atk_frac=0.0, rng=np.random.default_rng(1000 + s))
        attack_rows += _simulate(scenario, s, n_steps, dt, attack=True,
                                 atk_frac=atk_frac,
                                 rng=np.random.default_rng(2000 + s))

    clean_path = f"{out_prefix}_clean.csv"
    attack_path = f"{out_prefix}_attack.csv"
    pd.DataFrame(clean_rows).to_csv(clean_path, index=False)
    pd.DataFrame(attack_rows).to_csv(attack_path, index=False)
    n_mal = sum(r["label"] for r in attack_rows)
    print(f"[{scenario}] clean -> {clean_path}  ({len(clean_rows)} rows)")
    print(f"[{scenario}] attack-> {attack_path} ({len(attack_rows)} rows, "
          f"{n_mal} malicious = {100*n_mal/len(attack_rows):.1f}%)")
    return clean_path, attack_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=list(GEN))
    ap.add_argument("--out", required=True, help="output path prefix, e.g. data/urban")
    ap.add_argument("--atk_frac", type=float, default=0.2)
    args = ap.parse_args()
    generate(args.scenario, args.out, atk_frac=args.atk_frac)
