#!/usr/bin/env python3
"""
retrain_ae_displacement.py — AB4 fix: the deployed AE consumes ABSOLUTE position
normalised by scaler.json (scale ~545 m in x, ~494 m in y). The TP-S1 stealth
drift injects 1-7 m of CUMULATIVE offset, i.e. 0.003-0.013 in normalised units —
an order of magnitude below the reconstruction noise floor. Measured consequence:
AE ROC-AUC 0.463 on the eps_max sweep (no signal), so AB4 cannot show a gap.

Candidate feature sets (all 6-dim so the deployed model shape / C++ ring stay
compatible), trained FRESH on the SAME clean urban data, L=50:

  A  abs   : pos_x, pos_y, speed, heading, accel, tau      <- current deployment
  B  disp  : dx, dy, speed, heading, accel, tau            <- per-beacon displacement
  C  resid : res_x, res_y, dspeed, dheading, accel, tau    <- dead-reckoning residual
             res = (dpos) - v*T_b*(cos hdg, sin hdg)
             TP-S1 modifies POSITION ONLY and leaves speed/heading honest, so the
             residual isolates the injected increment directly.

Each candidate gets its OWN scaler fitted on clean data (fair comparison), its own
theta_ae = mean + 1.645*std of clean validation error. Adopt only if it clearly
beats A on ROC-AUC of poisoned-vs-honest. Nothing is deployed by this script.

Usage: python3 retrain_ae_displacement.py
"""
import os, sys, json, math, glob
import numpy as np, pandas as pd, torch
from sklearn.metrics import roc_auc_score

ROOT = os.path.dirname(os.path.abspath(__file__))
ML   = os.path.join(ROOT, "analytics", "ml")
sys.path.insert(0, ML)
from lstm_ae import LSTMAEDetector

SCEN  = "urban"
DS    = f"/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/{SCEN}"
L     = 50
T_B   = 0.1          # beacon interval (s) — must match the sim
KAPPA = 1.645
EPS   = 1e-12
DEV   = "cuda" if torch.cuda.is_available() else "cpu"


def build_feats(g, kind):
    """Per-vehicle frame -> (n,6) raw feature matrix for the given candidate."""
    px = g["pos_x"].values.astype(np.float64)
    py = g["pos_y"].values.astype(np.float64)
    sp = g["speed"].values.astype(np.float64)
    hd = g["heading"].values.astype(np.float64)
    ac = g["accel"].values.astype(np.float64)
    n  = len(px)
    if kind == "abs":
        f = np.stack([px, py, sp, hd, ac], 1)
    else:
        dx = np.zeros(n); dy = np.zeros(n)
        dx[1:] = np.diff(px); dy[1:] = np.diff(py)
        if kind == "disp":
            f = np.stack([dx, dy, sp, hd, ac], 1)
        elif kind == "resid":
            # dead-reckoning prediction from the REPORTED speed/heading
            pred_x = sp * T_B * np.cos(hd)
            pred_y = sp * T_B * np.sin(hd)
            rx = dx - pred_x; ry = dy - pred_y
            rx[0] = 0.0; ry[0] = 0.0
            dsp = np.zeros(n); dsp[1:] = np.diff(sp)
            dhd = np.zeros(n)
            dhd[1:] = (np.diff(hd) + np.pi) % (2 * np.pi) - np.pi   # wrap
            f = np.stack([rx, ry, dsp, dhd, ac], 1)
        else:
            raise ValueError(kind)
    return np.hstack([f, np.ones((n, 1))]).astype(np.float32)   # + tau


def windows(df, kind, mean=None, scale=None, label=False):
    df = df.sort_values(["vehicle_id", "sim_time"])
    Xs, ys = [], []
    for _, g in df.groupby("vehicle_id"):
        if len(g) < L:
            continue
        f = build_feats(g, kind)
        if mean is not None:
            f = (f - mean) / np.where(scale == 0, 1, scale)
        Xs.append(np.stack([f[i:i + L] for i in range(len(f) - L + 1)]))
        if label:
            poi = g["is_poisoned"].values.astype(int)
            ys.append(np.array([poi[i + L - 1] for i in range(len(f) - L + 1)]))
    if not Xs:
        return np.zeros((0, L, 6), np.float32), np.zeros((0,), int)
    X = np.concatenate(Xs).astype(np.float32)
    y = np.concatenate(ys) if label else np.zeros(len(X), int)
    return X, y


def fit_scaler(df, kind):
    rows = [build_feats(g, kind) for _, g in df.sort_values(["vehicle_id", "sim_time"]).groupby("vehicle_id")]
    allf = np.concatenate(rows)
    mean = allf.mean(0)
    scale = allf.std(0)
    scale[scale < 1e-9] = 1.0
    return mean.astype(np.float32), scale.astype(np.float32)


def train_ae(X, epochs=40):
    torch.manual_seed(42)
    m = LSTMAEDetector(feat_dim=6).to(DEV)
    opt = torch.optim.Adam(m.parameters(), lr=1e-3)
    vi = int(len(X) * 0.8)
    Xt, Xv = torch.tensor(X[:vi]), torch.tensor(X[vi:])
    for _ in range(epochs):
        m.train()
        perm = torch.randperm(len(Xt))
        for i in range(0, len(Xt), 128):
            b = Xt[perm[i:i + 128]].to(DEV)
            opt.zero_grad()
            ((m(b) - b) ** 2).mean().backward()
            opt.step()
    m.eval()
    with torch.no_grad():
        err = ((m(Xv.to(DEV)) - Xv.to(DEV)) ** 2).mean(dim=(1, 2)).cpu().numpy()
    return m, float(err.mean() + KAPPA * err.std())


def ae_err(m, X):
    m.eval(); out = []
    with torch.no_grad():
        for i in range(0, len(X), 256):
            b = torch.tensor(X[i:i + 256]).to(DEV)
            out.append(((m(b) - b) ** 2).mean(dim=(1, 2)).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0)


def emcc(err, y, theta):
    flag = err > theta; g = y > 0.5
    tp = np.sum(flag & g); fp = np.sum(flag & ~g)
    tn = np.sum(~flag & ~g); fn = np.sum(~flag & g)
    num = (tp + EPS) * (tn + EPS) - (fp + EPS) * (fn + EPS)
    den = math.sqrt((tp + fp + EPS) * (tp + fn + EPS) * (tn + fp + EPS) * (tn + fn + EPS))
    return num / den, (fp / (fp + tn) if (fp + tn) else 0.0)


clean = pd.read_csv(f"{ML}/data/beacon_clean_{SCEN}.csv")
print(f"[ae-disp] clean {SCEN}: {len(clean)} rows, {clean.vehicle_id.nunique()} vehicles, L={L}")

# evaluation sets: a1 = RSU-side stealth drift (the AB4 attack), a2 = malicious vehicle
evalsets = {}
for atk in ("a1", "a2"):
    frames = []
    for d in sorted(glob.glob(f"{DS}/{atk}_p*")):
        f = os.path.join(d, "beacon_log.csv")
        if os.path.isfile(f):
            try:
                frames.append(pd.read_csv(f))
            except Exception:
                pass
    if frames:
        evalsets[atk] = pd.concat(frames, ignore_index=True)
        n_p = int(evalsets[atk]["is_poisoned"].sum())
        print(f"[ae-disp] eval {atk}: {len(evalsets[atk])} rows, {n_p} poisoned")

print(f"\n{'cand':>6} {'feat':<34} {'theta_ae':>9} | " +
      "  ".join(f"{a}_AUC  {a}_eMCC  {a}_FPR" for a in evalsets))
print("-" * 100)
FEATNAME = {"abs":   "pos_x,pos_y,spd,hdg,acc,tau",
            "disp":  "dx,dy,spd,hdg,acc,tau",
            "resid": "res_x,res_y,dspd,dhdg,acc,tau"}
results = {}
for kind in ("abs", "disp", "resid"):
    mean, scale = fit_scaler(clean, kind)
    Xc, _ = windows(clean, kind, mean, scale)
    m, theta = train_ae(Xc)
    row = []
    for atk, df in evalsets.items():
        Xe, ye = windows(df, kind, mean, scale, label=True)
        if len(Xe) == 0 or ye.sum() == 0 or ye.sum() == len(ye):
            row += [float("nan")] * 3
            continue
        e = ae_err(m, Xe)
        auc = roc_auc_score(ye, e)
        mc, fpr = emcc(e, ye, theta)
        row += [auc, mc, fpr]
    results[kind] = (m, mean, scale, theta, row)
    print(f"{kind:>6} {FEATNAME[kind]:<34} {theta:>9.5f} | " +
          "  ".join(f"{v:6.3f}" if v == v else "   nan" for v in row))

print("\nDecision: adopt a candidate only if its a1 AUC clearly beats 'abs'.")
base = results["abs"][4][0]
for kind in ("disp", "resid"):
    v = results[kind][4][0]
    if v == v and base == base:
        print(f"  {kind:>6}: a1 AUC {v:.3f} vs abs {base:.3f}  -> delta {v-base:+.3f}")
np.save("/tmp/ae_cand_results.npy", {k: (v[3], v[4]) for k, v in results.items()}, allow_pickle=True)
torch.save({k: (v[0].state_dict(), v[1], v[2], v[3]) for k, v in results.items()},
           "/tmp/ae_candidates.pt")
print("\nsaved candidate models -> /tmp/ae_candidates.pt (nothing deployed)")
