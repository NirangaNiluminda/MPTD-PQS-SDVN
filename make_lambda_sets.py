#!/usr/bin/env python3
"""
make_lambda_sets.py — write the attack-conditioned fusion_weights.json
(revised eq:fusion, supervisor multi-task/attack-conditioned patch 2026-07).

Emits K=7 fusion weight sets {psi,gat,ae}, one per attack class (index 0..6 →
attack_number 1..7), plus the global mean λ (fallback when k̂ is unavailable) and
Φ_th. The C++ loader (06d_ai_inference.h::load_fusion_weights_json) reads
"lambda_sets" and sets per_attack=true; fuse_scores() then selects λ^(k̂_i) where
k̂_i = argmax_k ŷ_i^(k) from the multi-task GAT heads.

IMPORTANT: the per-attack values below are PRINCIPLED SEED PRIORS, not tuned
results — they initialise each set by which detector is expected to carry that
attack (kinematic → ψ; relational/graph → GAT; temporal → AE). The final values
must be re-derived by the per-attack SLSQP sweep on Phase-2 labelled data
(lambda_offline_sweep.py --attack k). Each set obeys Σ=1 and λ_j≥0.05.

Usage: python3 make_lambda_sets.py [urban rural highway ...]   (default: all 3)
"""
import os, sys, json

PHI_TH = 0.5

# Seed priors per attack class (attack_number 1..7 → index 0..6).
# (psi, gat, ae); Σ=1; each ≥0.05. See threat model (Experiment 5 / §3.threat).
SEEDS = {
    1: (0.45, 0.40, 0.15),  # TP-S1 malicious-RSU position drift  → ψ + spatial GAT
    2: (0.55, 0.25, 0.20),  # TP-S2 speed/heading exaggeration    → kinematic ψ
    3: (0.25, 0.55, 0.20),  # MP-S1 Sybil ghost IDs               → relational GAT
    4: (0.30, 0.40, 0.30),  # MP-S2 impersonation                 → GAT + temporal AE
    5: (0.40, 0.30, 0.30),  # TP-S3 control-plane                 → balanced
    6: (0.55, 0.25, 0.20),  # MP-S3 MitM speed injection          → kinematic ψ
    7: (0.40, 0.30, 0.30),  # MP-S4 control-plane                 → balanced
}

ML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics", "ml", "models")


def build_blob():
    sets = []
    gp = gg = ga = 0.0
    for k in range(1, 8):
        p, g, a = SEEDS[k]
        s = p + g + a
        p, g, a = p / s, g / s, a / s               # renormalise defensively
        sets.append({"attack": k, "psi": round(p, 4), "gat": round(g, 4), "ae": round(a, 4)})
        gp += p; gg += g; ga += a
    n = len(sets)
    # Global mean λ = fallback when k̂ is unavailable (GAT off / degenerate snapshot).
    return {
        "phi_threshold": PHI_TH,
        "lambda_psi": round(gp / n, 4),
        "lambda_gat": round(gg / n, 4),
        "lambda_ae":  round(ga / n, 4),
        "lambda_sets": sets,
        "_note": "per-attack SEED priors; re-derive via lambda_offline_sweep.py --attack k on Phase-2 data",
    }


def main():
    scens = sys.argv[1:] or ["urban", "rural", "highway"]
    blob = build_blob()
    for scen in scens:
        d = os.path.join(ML, scen)
        if not os.path.isdir(d):
            print(f"[{scen}] SKIP — no dir {d}"); continue
        path = os.path.join(d, "fusion_weights.json")
        if os.path.exists(path):
            os.replace(path, path + ".bak_pre_attackcond")
        with open(path, "w") as f:
            json.dump(blob, f, indent=2)
        print(f"[{scen}] wrote {path}")
    print("[done] attack-conditioned fusion_weights.json deployed")
    print(json.dumps(blob, indent=2))


if __name__ == "__main__":
    main()
