#!/usr/bin/env python3
"""
recalibrate_combined.py — recalibrate θ_S / θ_ae for the COMBINED-attack scenario.

The single-attack calibration (models/urban/, θ_S=8.31) over-fires on the combined
attack because the heavily-poisoned graph pushes even CLEAN beacons to high GAT-S
(~11.6). We recompute, on a combined-attack beacon_log, the paper's Phase-1b
thresholds — θ_S = 95th percentile of CLEAN GAT-S, θ_ae = 95th percentile of CLEAN
AE-error — using the SAME frozen ONNX models. Writes models/urban_combined/.

Usage: python3 recalibrate_combined.py <calib_beacon_log.csv>
Reuses the GAT+AE forward from faithful_baselines_eval.py (mptd machinery).
"""
import sys, os, json, numpy as np, pandas as pd
import onnxruntime as ort

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "analytics", "ml"))
from gat_detector import build_edge_index, SIG_BITS

SRC = os.path.join(ROOT, "analytics", "ml", "models", "urban")           # unchanged models
DST = os.path.join(ROOT, "analytics", "ml", "models", "urban_combined")  # write here
_FEAT = ["pos_x", "pos_y", "speed", "heading", "accel"]; W = 50

sc = json.load(open(f"{SRC}/scaler.json")); MEAN = np.array(sc["mean"]); SCALE = np.array(sc["scale"])
gat = ort.InferenceSession(f"{SRC}/gat_model.onnx"); ae = ort.InferenceSession(f"{SRC}/lstm_ae_model.onnx")

bl = sys.argv[1] if len(sys.argv) > 1 else "analytics/datasets/urban/a0_p40_m0/beacon_log.csv"
d = pd.read_csv(bl).drop_duplicates(["vehicle_id", "sim_time"]).sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)
d["_tick"] = (d.sim_time / 0.1).round().astype(int)
print(f"[recal] {bl}: {len(d)} beacons  clean={int((d.is_poisoned==0).sum())} poisoned={int((d.is_poisoned==1).sum())}")

# ── GAT forward per tick → raw S per (tick, vehicle) ──────────────────────────
gS = {}
for _, g in d.groupby("_tick"):
    if len(g) < 2: continue
    raw = g[_FEAT].values.astype(np.float32)
    kin = ((raw - MEAN[:5]) / np.where(SCALE[:5] == 0, 1, SCALE[:5])).astype(np.float32)
    tau = np.ones((len(g), 1), np.float32); psi = g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1, 1)
    sm = g["sig_mask"].fillna(0).values.astype(np.int64)
    bits = np.stack([((sm >> b) & 1) for b in range(SIG_BITS)], 1).astype(np.float32)
    x = np.hstack([kin, tau, psi, bits]).astype(np.float32)
    ei = build_edge_index(raw[:, :2].astype(np.float32), raw[:, 3].astype(np.float32),
                          raw[:, 2].astype(np.float32)).numpy().astype(np.int64)
    S = gat.run(None, {"x": x, "edge_index": ei})[0].reshape(-1)
    for i, (_, r) in enumerate(g.iterrows()):
        gS[(int(r._tick), int(r.vehicle_id))] = float(S[i])

# ── AE forward per vehicle window → raw reconstruction error per beacon ───────
rows = []
for vid, g in d.groupby("vehicle_id"):
    g = g.reset_index(drop=True); arr = g[_FEAT].values.astype(np.float32)
    w6 = ((np.hstack([arr, np.ones((len(g), 1), np.float32)]) - MEAN) / np.where(SCALE == 0, 1, SCALE)).astype(np.float32)
    for j in range(W - 1, len(g)):
        rec = ae.run(None, {"x": w6[j - W + 1:j + 1][None]})[0]
        ae_err = float(np.mean((rec - w6[j - W + 1:j + 1][None]) ** 2))
        key = (int(g._tick[j]), int(vid))
        rows.append((gS.get(key, np.nan), ae_err, int(g.is_poisoned[j])))

r = pd.DataFrame(rows, columns=["S", "ae", "pois"]).dropna(subset=["S"])
clean = r[r.pois == 0]; pois = r[r.pois == 1]
print(f"[recal] windowed beacons: {len(r)}  clean={len(clean)} poisoned={len(pois)}")
print(f"[recal] GAT-S : clean mean={clean.S.mean():.3f}  poisoned mean={pois.S.mean():.3f}  "
      f"(want poisoned > clean for informative)")
print(f"[recal] AE-err: clean mean={clean.ae.mean():.4f}  poisoned mean={pois.ae.mean():.4f}")

theta_s  = float(np.percentile(clean.S,  95))
theta_ae = float(np.percentile(clean.ae, 95))
print(f"\n[recal] NEW θ_S  = {theta_s:.4f}  (was {open(f'{SRC}/theta_s.txt').read().strip()})")
print(f"[recal] NEW θ_ae = {theta_ae:.6f} (was {open(f'{SRC}/theta_ae.txt').read().strip()})")
# how well does GAT alone discriminate at the new θ_S?
tp = (pois.S  > theta_s).sum(); fn = (pois.S  <= theta_s).sum()
fp = (clean.S > theta_s).sum(); tn = (clean.S <= theta_s).sum()
print(f"[recal] GAT@θ_S: poisoned>θ={tp/max(len(pois),1):.2f}  clean>θ={fp/max(len(clean),1):.2f}  "
      f"(poisoned rate should exceed clean rate)")

open(f"{DST}/theta_s.txt",  "w").write(f"{theta_s:.6f}\n")
open(f"{DST}/theta_ae.txt", "w").write(f"{theta_ae:.6f}\n")
print(f"[recal] wrote {DST}/theta_s.txt, theta_ae.txt")
