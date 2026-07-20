# MPTD-PQS — Full-Mode Run & Baseline Evaluation Guide

_Last updated: 2026-07-20. Covers the current build (attack-conditioned ψ + θ_conf gate,
urban LSTM-AE L=50, δ_th=5, speed-bound signature, stealthy control-plane default) and the
faithful (no-train) SOTA baselines._

---

## 1. Building the binary

```bash
cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
./waf build --targets=mptd_pqs_sdvn
```

> ⚠️ Do **not** use `./waf --run` — it triggers a full build that fails on an unrelated
> broken target (`scratch/routing.cc`). Build our target alone, then run the binary directly.

---

## 2. Running full mode (proposed method)

**Full mode = `--ablation_mode=0`** (ψ rule-tier + GAT + LSTM-AE fusion + CP-DETECT).

```bash
cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:$HOME/.local/lib64"

./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn \
  --mobility_source=1 --mobility_scenario=0 --maxspeed=60 \
  --N_Vehicles=200 --N_RSUs=64 --skip_blockchain=true \
  --ablation_mode=0 \
  --attack_number=<1..7> --attack_percentage=<0..100> --simTime=30
```

- **Output:** `analytics/results/urban/beacon_log.csv` (overwritten each run) + stdout (redirect to a `sim.log`).
- **G50 config is mandatory:** `--N_Vehicles=200 --N_RSUs=64 --mobility_source=1 --mobility_scenario=0 --maxspeed=60`.
  Omitting these silently falls back to the 16-vehicle hardcoded provider.
- `--skip_blockchain=true` is fine — **CP-DETECT works without blockchain** (consensus is local; TRS-verify is stubbed).

### Attack numbering (our code — authoritative, `declare_attack_states()`)

| # | Class | Type | Notes |
|---|---|---|---|
| a1 | TP-S1 | compromised-RSU position drift | |
| a2 | TP-S2 | malicious-vehicle | |
| a3 | MP-S1 | Sybil (compromised RSU) | MPTD dominates; baselines ≈0 |
| a4 | MP-S2 | vehicle impersonation | caught via MP-S2 timing (near-simultaneous) |
| **a5** | **TP-S3** | **control-plane** | **stealthy by default** → beacon-blind, CP-DETECT catches |
| a6 | MP-S3 | MitM (extreme speed) | caught via speed-bound signature |
| **a7** | **MP-S4** | **control-plane** | **stealthy by default** → beacon-blind, CP-DETECT catches |

> Note: sir's grouped numbering differs — his a1/a5/a7 = our **a2/a4/a7**. We keep **our** numbering everywhere.

### Stealthy control-plane (a5/a7) — the DEFAULT

`stealthy_control_plane = true` by default ([02_config_globals.h:175](scratch/mptd_pqs_sdvn/02_config_globals.h#L175)).

- **Stealthy (default):** the controller falsification leaves the **beacon unchanged** → every beacon
  detector (B1/B2/B3 **and** MPTD's ψ+GAT+AE fusion) is blind by construction. Only **CP-DETECT**
  (controller-vs-RSU consensus, Algorithm 7) catches it — verified **0.57–0.98 detection at 0% FPR**
  on honest controllers.
- **Legacy loud variant:** add `--stealthy_control_plane=false` (beacon carries a loud footprint;
  baselines can then "see" the symptom). Only use for the loud-vs-stealthy comparison.
- a1–a4, a6 are unaffected by this flag (their controllers are honest).

### Sweeping all attacks × penetrations
Run sequentially (parallel runs clobber the shared `beacon_log.csv`) and copy the CSV after each run.
Reference scripts: `scratchpad/live_sweep_step8.sh` (+ `live_sweep_p0p100.sh`). ~10 min/sim at simTime=30.

### Ablation modes (for reference)
- `--ablation_mode=0` → **full mode** (what we report).
- `--ablation_mode=7` → standalone GAT tier only; `=8` → standalone LSTM-AE tier only.
- These modes 7/8 are **internal ablations, NOT the SOTA baselines** (see §3).

---

## 3. The SOTA baselines (B1/B2/B3)

### 3.1 Current status — FAITHFUL, no-training (2026-07-20)
The baselines were reworked from trained RandomForests to their **published paper rules with ZERO
training**. Reason: the RF was trained on our data and tested on the same distribution (memorised the
split → spurious ~1.0 MCC). Verified with leave-one-attack-out + group-k-fold. The faithful rules are
the fair comparison — and MPTD leads honestly (mean ε-MCC 0.84 vs Sharma 0.47).

| Baseline | File | Method | Status |
|---|---|---|---|
| **B1 Ghaleb** | `mptd_pqs/ghaleb_b1_detector.py` | road-boundary + RSU-range + speed rules | ✅ fixed with the real urban **map** (net.xml road KDTree + 64-RSU CSV); was FPR=1.0 |
| **B2 Ercan** | `mptd_pqs/ercan_b2_detector_v2.py` | RSSI plausibility z-test (95% CI) | ⚠️ **near-blind** — our logs have **no measured RSSI**; runs on observable features only (documented limitation) |
| **B3 Sharma** | `mptd_pqs/sharma_b3_detector_v2.py` | LP/MP kinematic plausibility rule | ✅ strongest baseline; genuinely good on overt spoofing (a2/a6) |

Each exposes `load_scenario(dir)` + a rule predictor (`paper_rule_predict(...)` for B2/B3;
`GhalebB1Detector(road_tree, road_tol, rsu_pos).run(aug)` for B1). **No `.fit()` is called.**

### 3.2 Deprecated artifacts (do NOT use)
- `models_global/{ercan,sharma}_global_RF.joblib` — the **old overfit RandomForests** (Jun 24). Kept for
  history only; the faithful rules supersede them.
- `models_ercan_b2/`, `models_sharma_b3/` — empty dirs.
- `--ablation_mode=7/8` (standalone GAT/AE) — these are **MPTD ablations**, not Ercan/Sharma.

### 3.3 How to run the baselines
The baselines are **scored offline in Python from the same `beacon_log.csv`** each sim produces — they
do **not** run inside ns-3. One `--ablation_mode=0` sim per (attack, pen) serves both MPTD and all baselines.

**(a) Per-attack pooled MCC/FPR table** (standard + stealthy datasets):
```bash
cd /home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN
python3 faithful_baselines_eval.py 2>/dev/null
```
Edit its `DATASETS` dict to point at whichever dataset you want (see §4).

**(b) 7-panel MCC-vs-penetration figure** (MPTD + B1/B2/B3, CP-DETECT overlay on a5/a7):
```bash
python3 live_mcc_figure.py 2>/dev/null
# → analytics/results/regen/live_mcc_7attacks_0-100.png
```
Uses faithful baselines + conditioned-ψ MPTD (reads `fusion_weights.json`), ε-MCC (Eq 4.1),
and the hard speed-bound override for a6.

---

## 4. Datasets

| Dataset (`~/Desktop/`) | What | Use |
|---|---|---|
| `dataset_G50_live_allfixes/urban` | **CURRENT** — new binary (conditioned ψ + AE L=50 + δ_th=5 + speed-bound), **a5/a7 stealthy**, 42 sims | ✅ the one to report |
| `dataset_G50_stealthy_cp/urban` | stealthy a5/a7 traces (loud-vs-stealthy study) | reference |
| `dataset_G50-mobility/urban` | OLD binary (δ_th=10, **loud** a5/a7) | legacy / `faithful_baselines_eval.py` "standard" |

Layout: `a{N}_p{P}/beacon_log.csv` + `sim.log` per (attack N, penetration P).
**Label = `is_poisoned`.** ⚠️ Never use the `gt_*` columns (pre-fix runs may have the NodeID off-by-2 issue).
Beacon logs may contain ~2× duplicate `(vehicle_id, sim_time)` rows — **dedup** before any per-vehicle temporal computation.

---

## 5. Deployed model files (gitignored)
`analytics/ml/models/urban/`:
- `fusion_weights.json` — attack-conditioned λ + `sig_weight_sets` + `sig_weight_global` + `theta_conf` (0.8)
- `lstm_ae_model.onnx` — urban AE, **L=50** input `[batch,50,6]` (rural/highway still L=10)
- `gat_model.onnx`, `scaler.json`, `theta_s.txt`, `theta_ae.txt`

The C++ loads these at runtime (AI-INIT). These are **gitignored** — back them up separately for reproducibility.

---

## 6. Current headline result
Live urban G50, faithful baselines, ε-MCC over p20–80:

**MPTD-PQS 0.84 > B3 Sharma 0.47 > B1 Ghaleb 0.12 > B2 Ercan 0.01**

MPTD leads or ties all 7 attacks: wins a1/a3/a4/a6, ties a2, and uniquely defends the stealthy
control-plane a5/a7 via CP-DETECT (baselines have no control-plane layer). See
`analytics/results/regen/live_mcc_7attacks_0-100.png`.
