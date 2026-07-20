#!/usr/bin/env python3
"""
faithful_baselines_eval.py — SOTA baselines implemented AS IN THEIR PAPERS,
with ZERO training on our data (per sir: "implement them as they mention in
their paper. No need to train them using our data. Those are not our methods").

  B1 Ghaleb 2014  — context/plausibility rules (already training-free).
  B2 Ercan  2021  — RSSI plausibility z-test (paper_rule_predict), no ML fit.
  B3 Sharma 2021  — LP/MP plausibility rule (paper_rule_predict), no ML fit.

No RandomForest is fitted. No our-data thresholds are tuned. Each detector only
touches declared kinematics + is_poisoned label — never detected/sig_mask/
psi_score/gt_pos_* (those are MPTD outputs / the buggy gt column).

Usage: python3 faithful_baselines_eval.py
"""
import sys, os, math
import numpy as np, pandas as pd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3
from mptd_pqs import ghaleb_b1_detector as B1
from sklearn.metrics import confusion_matrix

DATASETS = {
    "standard": "/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/urban",
    "stealthy": "/home/sdvn_mobility_flooding/Desktop/dataset_G50_stealthy_cp/urban",
}
ATTACKS = [1, 2, 3, 4, 5, 6, 7]
PCTS    = [20, 40, 60, 80]
EPS     = 1e-12
B2_CI   = 1.96   # Ercan RSSI plausibility at the 95% propagation-model CI (untuned)

# Urban map for Ghaleb B1 (both datasets are urban → same road network + RSU grid).
_ROOT     = os.path.dirname(os.path.abspath(__file__))
ROAD_TREE = B1.load_road_index(os.path.join(_ROOT, "sumo", "urban", "urban.net.xml"))
RSU_POS   = B1.load_rsu_positions(os.path.join(_ROOT, "mobility", "rsu_positions_urban.csv"))
ROAD_TOL  = 25.0
print(f"[map] road index: {'loaded' if ROAD_TREE is not None else 'FAILED'}; "
      f"RSU grid: {len(RSU_POS) if RSU_POS else 0} RSUs")


def _b1_detector():
    return B1.GhalebB1Detector(road_tree=ROAD_TREE, road_tol=ROAD_TOL, rsu_pos=RSU_POS)


# ── MPTD-PQS (our method) — deployed GAT/LSTM-AE ONNX + attack-conditioned fusion
import json
MPTD_OK = True
try:
    import onnxruntime as ort
    sys.path.insert(0, os.path.join(_ROOT, "analytics", "ml"))
    from gat_detector import build_edge_index, SIG_BITS
    MLU = os.path.join(_ROOT, "analytics", "ml", "models", "urban")
    _FEAT = ["pos_x", "pos_y", "speed", "heading", "accel"]; PSI_TH, PHI_TH, W = 0.09, 0.5, 50
    _sc = json.load(open(f"{MLU}/scaler.json")); MEAN = np.array(_sc["mean"]); SCALE = np.array(_sc["scale"])
    THETA_S = float(open(f"{MLU}/theta_s.txt").read()); THETA_AE = float(open(f"{MLU}/theta_ae.txt").read())
    _FW = json.load(open(f"{MLU}/fusion_weights.json"))
    WSETS = {s["attack"]: np.array(s["w"]) for s in _FW.get("sig_weight_sets", [])}
    WGLOB = np.array(_FW["sig_weight_global"]) if "sig_weight_global" in _FW else None
    TC = _FW.get("theta_conf", 0.7)
    LAM = {s["attack"]: (s["psi"], s["gat"], s["ae"]) for s in _FW["lambda_sets"]}
    GLOB = (_FW["lambda_psi"], _FW["lambda_gat"], _FW["lambda_ae"])
    _gat = ort.InferenceSession(f"{MLU}/gat_model.onnx"); _ae = ort.InferenceSession(f"{MLU}/lstm_ae_model.onnx")
except Exception as e:
    MPTD_OK = False
    print(f"[mptd] disabled: {e}")


def mptd_counts(scen_dir):
    f = os.path.join(scen_dir, "beacon_log.csv")
    if not os.path.isfile(f):
        return None
    d = pd.read_csv(f).sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)
    d["_tick"] = (d.sim_time / 0.1).round().astype(int)
    gi = {}
    for _, g in d.groupby("_tick"):
        if len(g) < 2:
            continue
        raw = g[_FEAT].values.astype(np.float32)
        kin = ((raw - MEAN[:5]) / np.where(SCALE[:5] == 0, 1, SCALE[:5])).astype(np.float32)
        tau = np.ones((len(g), 1), np.float32); psi = g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1, 1)
        sm = g["sig_mask"].fillna(0).values.astype(np.int64)
        bits = np.stack([((sm >> b) & 1) for b in range(SIG_BITS)], 1).astype(np.float32)
        x = np.hstack([kin, tau, psi, bits]).astype(np.float32)
        ei = build_edge_index(raw[:, :2].astype(np.float32), raw[:, 3].astype(np.float32),
                              raw[:, 2].astype(np.float32)).numpy().astype(np.int64)
        o = _gat.run(None, {"x": x, "edge_index": ei}); S = o[0].reshape(-1); ap = o[1]
        for i, (_, r) in enumerate(g.iterrows()):
            mx = int(ap[i].argmax())
            gi[(r._tick, r.vehicle_id)] = (min(1., max(0., float(S[i]) / THETA_S)), mx + 1, float(ap[i][mx]))
    tp = fp = tn = fn = 0
    for vid, g in d.groupby("vehicle_id"):
        g = g.reset_index(drop=True); arr = g[_FEAT].values.astype(np.float32)
        w6 = (np.hstack([arr, np.ones((len(g), 1), np.float32)]) - MEAN) / np.where(SCALE == 0, 1, SCALE)
        sm = g["sig_mask"].fillna(0).values.astype(np.int64)
        for j in range(W - 1, len(g)):
            key = (int(g._tick[j]), vid)
            if key not in gi:
                continue
            gat_n, kh, conf = gi[key]
            rec = _ae.run(None, {"x": w6[j - W + 1:j + 1].astype(np.float32)[None]})[0]
            ae_n = min(1., max(0., float(np.mean((rec - w6[j - W + 1:j + 1][None]) ** 2)) / THETA_AE))
            use_k = kh if (kh > 0 and conf >= TC and WSETS and kh in WSETS) else -1
            if use_k > 0:
                w = WSETS[kh]; b = np.array([((int(sm[j]) >> bb) & 1) for bb in range(9)], float)
                psi_n = min(1., max(0., float(b @ w) / PSI_TH))
            elif WGLOB is not None:
                b = np.array([((int(sm[j]) >> bb) & 1) for bb in range(9)], float)
                psi_n = min(1., max(0., float(b @ WGLOB) / PSI_TH))
            else:
                psi_n = min(1., max(0., float(g.psi_score[j]) / PSI_TH))
            lp, lg, la = LAM.get(use_k, GLOB) if use_k > 0 else GLOB
            phi = lp * psi_n + lg * gat_n + la * ae_n
            flag = phi > PHI_TH; gt = int(g.is_poisoned[j]) == 1
            tp += flag & gt; fp += flag & (not gt); tn += (not flag) & (not gt); fn += (not flag) & gt
    return tp, fp, tn, fn


def emcc_counts(tp, fp, tn, fn):
    num = (tp + EPS) * (tn + EPS) - (fp + EPS) * (fn + EPS)
    den = math.sqrt((tp + fp + EPS) * (tp + fn + EPS) * (tn + fp + EPS) * (tn + fn + EPS))
    return num / den, (fp / (fp + tn) if (fp + tn) else 0.0)


def pooled_mptd(ds_root, a):
    if not MPTD_OK:
        return None
    T = [0, 0, 0, 0]
    for p in PCTS:
        c = mptd_counts(os.path.join(ds_root, f"a{a}_p{p}"))
        if c:
            T = [T[i] + c[i] for i in range(4)]
    return emcc_counts(*T) if sum(T) else None


def emcc(y, yp):
    """ε-smoothed MCC + FPR from binary label/pred arrays."""
    y = np.asarray(y).astype(int); yp = np.asarray(yp).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yp, labels=[0, 1]).ravel()
    num = (tp + EPS) * (tn + EPS) - (fp + EPS) * (fn + EPS)
    den = math.sqrt((tp + fp + EPS) * (tp + fn + EPS) * (tn + fp + EPS) * (tn + fn + EPS))
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return num / den, fpr


def b3_eval(scen_dir):
    f = B3.load_scenario(scen_dir)
    if f is None:
        return None
    f = f.dropna(subset=B3.FEATURE_COLS + ["label"])
    if len(f) < 2:
        return None
    return emcc(f["label"].values, B3.paper_rule_predict(f))


def b2_eval(scen_dir):
    f = B2.load_scenario(scen_dir)
    if f is None:
        return None
    f = f.dropna(subset=B2.FEATURE_COLS + ["label"])
    if len(f) < 2:
        return None
    return emcc(f["label"].values, B2.paper_rule_predict(f, ci=B2_CI))


def b1_eval(scen_dir):
    try:
        aug = B1.load_scenario(scen_dir)
    except Exception:
        return None
    if aug is None or "is_poisoned" not in aug or len(aug) < 2:
        return None
    dd = _b1_detector().run(aug)
    y  = aug["is_poisoned"].values.astype(int)
    yp = dd["pred"].values.astype(int)
    n  = min(len(y), len(yp))
    return emcc(y[:n], yp[:n])


def pooled(fn, ds_root, a):
    """Run a detector over all penetration folders of one attack, pool the rows."""
    ys, yps = [], []
    for p in PCTS:
        d = os.path.join(ds_root, f"a{a}_p{p}")
        if not os.path.isdir(d):
            continue
        # re-run per folder but pool at the confusion-matrix level via re-eval:
        if fn is b1_eval:
            aug = B1.load_scenario(d)
            if aug is None or len(aug) < 2:
                continue
            dd = _b1_detector().run(aug)
            n = min(len(aug), len(dd))
            ys.append(aug["is_poisoned"].values[:n].astype(int)); yps.append(dd["pred"].values[:n].astype(int))
        elif fn is b2_eval:
            f = B2.load_scenario(d)
            if f is None:
                continue
            f = f.dropna(subset=B2.FEATURE_COLS + ["label"])
            if len(f) < 2:
                continue
            ys.append(f["label"].values.astype(int)); yps.append(B2.paper_rule_predict(f, ci=B2_CI))
        else:
            f = B3.load_scenario(d)
            if f is None:
                continue
            f = f.dropna(subset=B3.FEATURE_COLS + ["label"])
            if len(f) < 2:
                continue
            ys.append(f["label"].values.astype(int)); yps.append(B3.paper_rule_predict(f))
    if not ys:
        return None
    return emcc(np.concatenate(ys), np.concatenate(yps))


for name, root in DATASETS.items():
    if not os.path.isdir(root):
        print(f"\n### {name}: dataset dir not found ({root}) — skipped")
        continue
    print(f"\n================ {name} dataset ({root}) ================")
    print(f"{'atk':>4} | {'MPTD-PQS (ours)':>16} | {'B1 Ghaleb':>16} | {'B2 Ercan':>16} | {'B3 Sharma':>16}")
    print(f"{'':>4} | {'MCC':>8}{'FPR':>8} | {'MCC':>8}{'FPR':>8} | {'MCC':>8}{'FPR':>8} | {'MCC':>8}{'FPR':>8}")
    acc = {"MPTD": [], "B1": [], "B2": [], "B3": []}
    for a in ATTACKS:
        rm = pooled_mptd(root, a)
        r1 = pooled(b1_eval, root, a)
        r2 = pooled(b2_eval, root, a)
        r3 = pooled(b3_eval, root, a)
        def fmt(r):
            return f"{r[0]:8.3f}{r[1]:8.2f}" if r else f"{'--':>8}{'--':>8}"
        print(f"  a{a} | {fmt(rm)} | {fmt(r1)} | {fmt(r2)} | {fmt(r3)}")
        if rm: acc["MPTD"].append(rm[0])
        if r1: acc["B1"].append(r1[0])
        if r2: acc["B2"].append(r2[0])
        if r3: acc["B3"].append(r3[0])
    def mfmt(k):
        return f"{np.mean(acc[k]):8.3f}{'':>8}" if acc[k] else f"{'--':>8}{'':>8}"
    print(f" MEAN | {mfmt('MPTD')} | {mfmt('B1')} | {mfmt('B2')} | {mfmt('B3')}")
