#!/usr/bin/env python3
"""
retrain_ae_resid_fixed.py — retrain the urban LSTM-AE on DEAD-RECKONING RESIDUAL
features, using data from the map-bounds-FIXED binary.

Why: the deployed AE consumes absolute position normalised by ~545 m, so the 0.6-3.2 m
TP-S1 stealth drift is ~0.005 in normalised units — below the reconstruction noise
floor (measured in-sim ROC-AUC 0.463 = no signal). TP-S1 modifies POSITION ONLY and
leaves the reported speed/heading honest, so the residual

    r(t) = [p(t) - p(t-1)] - v(t)*T_b*[cos h(t), sin h(t)]

isolates the injected increment exactly. Raw single-beacon |r| already separates at
AUC 0.966 on fixed-binary data; this trains the windowed AE on it.

Protocol: train on HONEST windows only (unsupervised, as an AE must be), split by
VEHICLE so evaluation vehicles are never seen in training. Compare abs vs disp vs
resid under identical conditions. Nothing is deployed by this script.
"""
import os, sys, json, math, glob
import numpy as np, pandas as pd, torch
from sklearn.metrics import roc_auc_score

ROOT = os.path.dirname(os.path.abspath(__file__))
ML   = os.path.join(ROOT, "analytics", "ml")
NS3  = "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35"
sys.path.insert(0, ML)
from lstm_ae import LSTMAEDetector

L, T_B, KAPPA, EPS = 50, 0.1, 1.645, 1e-12
DEV = "cuda" if torch.cuda.is_available() else "cpu"


def feats(g, kind):
    px = g["pos_x"].values.astype(np.float64); py = g["pos_y"].values.astype(np.float64)
    sp = g["speed"].values.astype(np.float64); hd = g["heading"].values.astype(np.float64)
    ac = g["accel"].values.astype(np.float64); n = len(px)
    if kind == "abs":
        f = np.stack([px, py, sp, hd, ac], 1)
    else:
        dx = np.zeros(n); dy = np.zeros(n)
        dx[1:] = np.diff(px); dy[1:] = np.diff(py)
        if kind == "disp":
            f = np.stack([dx, dy, sp, hd, ac], 1)
        else:  # resid
            rx = dx - sp * T_B * np.cos(hd); ry = dy - sp * T_B * np.sin(hd)
            rx[0] = ry[0] = 0.0
            dsp = np.zeros(n); dsp[1:] = np.diff(sp)
            dhd = np.zeros(n); dhd[1:] = (np.diff(hd) + np.pi) % (2*np.pi) - np.pi
            f = np.stack([rx, ry, dsp, dhd, ac], 1)
    return np.hstack([f, np.ones((n, 1))]).astype(np.float32)


def windows(df, kind, mean=None, scale=None, vehicles=None):
    """Windows built on the CONTIGUOUS per-(run,vehicle) series.

    Features are differences, so the series must never be filtered before
    diffing — in TP-S1 a vehicle alternates honest/poisoned as it moves between
    compromised and clean RSUs, and dropping rows first makes dx span a time gap
    (garbage). Build on the full series, then label each window by its poisoned
    fraction so callers can select all-honest windows for training.
    Returns X, y (1 = any poisoned beacon in window), frac (poisoned share).
    """
    df = df.sort_values(["run", "vehicle_id", "sim_time"]) if "run" in df.columns \
         else df.sort_values(["vehicle_id", "sim_time"])
    keys = ["run", "vehicle_id"] if "run" in df.columns else ["vehicle_id"]
    Xs, ys, fs = [], [], []
    for k, g in df.groupby(keys):
        v = k[-1] if isinstance(k, tuple) else k
        if vehicles is not None and v not in vehicles: continue
        if len(g) < L: continue
        f = feats(g, kind)
        if mean is not None: f = (f - mean) / np.where(scale == 0, 1, scale)
        Xs.append(np.stack([f[i:i+L] for i in range(len(f)-L+1)]))
        poi = g["is_poisoned"].values.astype(int)
        fr = np.array([poi[i:i+L].mean() for i in range(len(f)-L+1)])
        fs.append(fr); ys.append((fr > 0).astype(int))
    if not Xs:
        return np.zeros((0, L, 6), np.float32), np.zeros((0,), int), np.zeros((0,))
    return (np.concatenate(Xs).astype(np.float32),
            np.concatenate(ys), np.concatenate(fs))


def train_ae(X, epochs=40):
    torch.manual_seed(42)
    m = LSTMAEDetector(feat_dim=6).to(DEV)
    opt = torch.optim.Adam(m.parameters(), lr=1e-3)
    vi = int(len(X)*0.8); Xt, Xv = torch.tensor(X[:vi]), torch.tensor(X[vi:])
    for _ in range(epochs):
        m.train(); perm = torch.randperm(len(Xt))
        for i in range(0, len(Xt), 128):
            b = Xt[perm[i:i+128]].to(DEV); opt.zero_grad()
            ((m(b)-b)**2).mean().backward(); opt.step()
    m.eval()
    with torch.no_grad():
        e = ((m(Xv.to(DEV))-Xv.to(DEV))**2).mean(dim=(1,2)).cpu().numpy()
    return m, float(e.mean() + KAPPA*e.std())


def ae_err(m, X):
    m.eval(); out = []
    with torch.no_grad():
        for i in range(0, len(X), 256):
            b = torch.tensor(X[i:i+256]).to(DEV)
            out.append(((m(b)-b)**2).mean(dim=(1,2)).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0)


def emcc(err, y, th):
    fl = err > th; g = y > 0.5
    tp=np.sum(fl&g); fp=np.sum(fl&~g); tn=np.sum(~fl&~g); fn=np.sum(~fl&g)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS)
    den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den, (fp/(fp+tn) if (fp+tn) else 0.0)


# ── load all fixed-binary runs (map-bounds fix present) ──────────────────────
paths = sorted(glob.glob(f"{NS3}/analytics/results/urban_pid*/beacon_log.csv"),
               key=os.path.getmtime, reverse=True)[:12]
frames = []
for p in paths:
    try:
        d = pd.read_csv(p)
        if len(d) and (d.pos_x > 2000).any():   # fixed runs exceed the old clamp
            d["run"] = os.path.basename(os.path.dirname(p)); frames.append(d)
    except Exception: pass
all_df = pd.concat(frames, ignore_index=True)
print(f"[resid-ae] fixed-binary data: {len(all_df)} rows from {all_df.run.nunique()} runs, "
      f"{int(all_df.is_poisoned.sum())} poisoned, {all_df.vehicle_id.nunique()} vehicles")

veh = np.array(sorted(all_df.vehicle_id.unique()))
rng = np.random.RandomState(0); rng.shuffle(veh)
tr_v, te_v = set(veh[:len(veh)//2]), set(veh[len(veh)//2:])
print(f"[resid-ae] vehicles: train {len(tr_v)} / test {len(te_v)} (disjoint)")

print(f"\n{'cand':>6} {'features':<34} {'theta':>9} {'AUC':>7} {'eMCC':>7} {'FPR':>7} {'AUCpure':>8}")
print("-"*86)
out = {}
for kind in ("abs", "disp", "resid"):
    # windows on the contiguous series; TRAIN only on all-honest windows of train vehicles
    Xa, ya, fa = windows(all_df, kind, vehicles=tr_v)
    Xtr_raw = Xa[ya == 0]
    if len(Xtr_raw) < 50: print(f"{kind:>6}  too few clean train windows ({len(Xtr_raw)})"); continue
    flat = Xtr_raw.reshape(-1, 6)
    mean = flat.mean(0); scale = flat.std(0); scale[scale < 1e-9] = 1.0
    Xtr = ((Xtr_raw - mean) / scale).astype(np.float32)
    m, th = train_ae(Xtr)
    Xte_raw, yte, fte = windows(all_df, kind, vehicles=te_v)
    if len(Xte_raw) == 0 or yte.sum() in (0, len(yte)):
        print(f"{kind:>6}  degenerate test set"); continue
    Xte = ((Xte_raw - mean) / scale).astype(np.float32)
    e = ae_err(m, Xte); auc = roc_auc_score(yte, e); mc, fpr = emcc(e, yte, th)
    # AUCpure: fully-poisoned windows vs fully-honest (drops ambiguous mixed windows)
    pure = (fte == 0) | (fte == 1.0)
    aucp = roc_auc_score(yte[pure], e[pure]) if pure.sum() > 10 and 0 < yte[pure].sum() < pure.sum() else float("nan")
    out[kind] = (auc, mc, fpr, m, mean, scale, th)
    nm = {"abs":"pos_x,pos_y,spd,hdg,acc,tau","disp":"dx,dy,spd,hdg,acc,tau",
          "resid":"res_x,res_y,dspd,dhdg,acc,tau"}[kind]
    print(f"{kind:>6} {nm:<34} {th:>9.5f} {auc:>7.3f} {mc:>7.3f} {fpr:>7.3f} {aucp:>8.3f}")

if "abs" in out and "resid" in out:
    print(f"\n  resid vs abs (held-out vehicles): AUC {out['resid'][0]:.3f} vs {out['abs'][0]:.3f}"
          f"  -> delta {out['resid'][0]-out['abs'][0]:+.3f}")
    print(f"  test windows={len(yte)} poisoned={int(yte.sum())}")
torch.save({k:(v[3].state_dict(), v[4], v[5], v[6]) for k,v in out.items()},
           "/tmp/ae_resid_fixed.pt")
print("\nsaved -> /tmp/ae_resid_fixed.pt (nothing deployed)")
