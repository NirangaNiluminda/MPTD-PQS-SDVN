#!/usr/bin/env python3
"""
Per-scenario Option-A GAT calibration (paper Eq 3.39/3.42, Phase-1b).

The shared GAT (gat_model.pt) is trained across all attack types but a SINGLE
urban mobility regime (~40 km/h). Deployed unchanged to rural (90) and highway
(150) it mis-scores clean fast motion, inflating FPR (rural 0.19-0.35,
highway 0.37). The conv weights transfer, but the CLEAN normalization
(x̄'_clean, σ'_clean, θ_S) must be re-derived per scenario so S_i is measured
against each scenario's own clean baseline — exactly the per-scenario Phase-1b
calibration the paper (Table pipeline-settings) already specifies.

For each scenario this:
  1. Loads CLEAN SUMO beacons  (analytics/ml/data/beacon_clean_<scen>.csv).
  2. Normalizes the 5 kinematic features with THAT scenario's scaler.json
     (first 5 dims) and appends tau_i=1.0 raw — byte-for-byte the same feature
     pipeline the C++ inference uses (06d_ai_inference.h::gat_infer, which scales
     5 dims by models/<scen>/scaler.json and appends tau UNSCALED).
  3. Runs the shared conv layers -> 16-dim embeddings on CLEAN nodes,
     computes locked x̄'_clean, σ'_clean and θ_S = 95th pctl of clean S_i.
  4. Exports models/<scen>/gat_model.onnx (RAW-S_i variant, mu/sig baked in)
     + models/<scen>/theta_s.txt.  The C++ loads gat_model.onnx per scenario and
     auto-loads theta_s.txt from the same directory.

Run:  cd analytics/ml && python3 recalibrate_gat_per_scenario.py <urban|rural|highway|all>
"""
import os, sys, json
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

ML = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ML)
from gat_detector import GATDetector            # noqa: E402
from train import build_gat_dataset, normalise  # noqa: E402

THETA_S_PCTL = 95.0
PT = os.path.join(ML, "models", "gat_model.pt")


def scenario_scaler(scen):
    """StandardScaler over the 5 kinematic dims from models/<scen>/scaler.json.
    The C++ GAT path scales exactly these 5 and appends tau=1.0 raw, so we must
    match that (NOT the top-level urban scaler the old script used)."""
    j = json.load(open(os.path.join(ML, "models", scen, "scaler.json")))
    sc = StandardScaler()
    sc.mean_  = np.array(j["mean"][:5],  dtype=np.float64)
    sc.scale_ = np.array(j["scale"][:5], dtype=np.float64)
    sc.var_   = sc.scale_ ** 2
    sc.n_features_in_ = 5
    return sc


def embed(m, x, ei):
    e = m.act(m.conv1(x, ei)); e = m.act(m.conv2(e, ei)); return e   # (N,16)


class GATDetectorSI(nn.Module):
    """Shared conv weights; locked clean stats. forward returns (RAW S_i, atk):
    S_i is the z-scored embedding L2 norm (fusion GAT term), and atk are the
    per-attack-type head probabilities ŷ_i^(k) (argmax → k̂_i selects the
    attack-conditioned fusion weights)."""
    def __init__(self, base, mu, sig):
        super().__init__()
        self.conv1, self.conv2, self.act = base.conv1, base.conv2, base.act
        self.cls_heads = base.cls_heads           # multi-task per-attack heads
        self.register_buffer("mu_clean",  mu.view(1, -1))
        self.register_buffer("sig_clean", sig.view(1, -1))

    def forward(self, x, edge_index):
        e = self.act(self.conv1(x, edge_index))
        e = self.act(self.conv2(e, edge_index))
        z = (e - self.mu_clean) / self.sig_clean
        s_i = z.norm(dim=1, keepdim=True)
        atk = torch.sigmoid(self.cls_heads(e))     # (N, K)
        return s_i, atk


def recalibrate(scen):
    csv = os.path.join(ML, "data", f"beacon_clean_{scen}.csv")
    outdir = os.path.join(ML, "models", scen)
    if not os.path.isfile(csv):
        print(f"[{scen}] SKIP — no clean CSV at {csv}"); return
    df = pd.read_csv(csv)                       # already carries run_id
    df, _ = normalise(df, scenario_scaler(scen))
    graphs = build_gat_dataset(df)
    print(f"[{scen}] {len(graphs)} clean snapshot graphs from {len(df)} rows")

    model = GATDetector()
    model.load_state_dict(torch.load(PT, map_location="cpu"))
    model.eval()

    clean = []
    with torch.no_grad():
        for g in graphs:
            e = embed(model, g.x, g.edge_index)
            clean.append(e[g.y == 0])           # clean nodes only
    clean = torch.cat(clean, 0)
    mu  = clean.mean(0)
    sig = clean.std(0) + 1e-6
    s_i = ((clean - mu) / sig).norm(dim=1)
    theta_s = float(np.percentile(s_i.numpy(), THETA_S_PCTL))
    print(f"[{scen}] clean rows={clean.shape[0]}  S_i mean={s_i.mean():.3f} "
          f"p50={np.percentile(s_i,50):.3f} p95(θ_S)={theta_s:.3f} max={s_i.max():.3f}")

    si = GATDetectorSI(model, mu, sig).eval()
    n = 16
    from gat_detector import FEATURE_DIM
    dummy_x  = torch.randn(n, FEATURE_DIM)
    dummy_ei = torch.tensor([[i for i in range(n)], [i for i in range(n)]], dtype=torch.long)
    out_onnx  = os.path.join(outdir, "gat_model.onnx")     # C++ loads this per scenario
    out_theta = os.path.join(outdir, "theta_s.txt")
    torch.onnx.export(si, (dummy_x, dummy_ei), out_onnx,
        input_names=["x", "edge_index"], output_names=["scores", "attack_probs"],
        dynamic_axes={"x": {0: "N"}, "edge_index": {1: "E"},
                      "scores": {0: "N"}, "attack_probs": {0: "N"}},
        opset_version=16, dynamo=False)
    open(out_theta, "w").write(f"{theta_s:.6f}\n")
    print(f"[{scen}] -> {out_onnx}\n[{scen}] -> {out_theta}  (θ_S={theta_s:.6f})")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    scens = ["urban", "rural", "highway"] if which == "all" else [which]
    for s in scens:
        recalibrate(s)
    print("[done] per-scenario GAT recalibration complete")
