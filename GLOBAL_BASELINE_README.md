# Existing-Methods Baseline Evaluation — Global Model Runbook

How the B1/B2/B3 baselines are evaluated against MPTD-PQS using **one global
detector per ML method**, where every file lives, and the exact commands to
train, freeze, run the live simulation, and produce the performance charts.

---

## 1. Concept

A deployable misbehaviour detector is **one model** that must flag an attacker
regardless of *which* attack type or *how many* attackers are present. So the ML
baselines are **not** trained per `(attack × pct)` scenario. Instead:

- All scenarios are **pooled into one feature table** per method.
- The data is **split by vehicle** (`GroupShuffleSplit`) so a vehicle's beacons
  never appear in both train and test — this prevents data leakage (which had
  produced a fake MCC ≈ 0.99).
- **One RandomForest is trained per method** and frozen to disk.
- The frozen model is then scored on a **fresh held-out simulation run**
  (`RngRun=2`) per attack scenario.

| Method | Type | Where its score comes from |
|--------|------|----------------------------|
| **B1 Ghaleb** | Rule-based (no training) | NS-3 sim, `ablation_mode=6` → `_m6` sweep CSV |
| **B2 Ercan** | ML (RandomForest) | Global model `models_global/ercan_global_RF.joblib` |
| **B3 Sharma** | ML (RandomForest) | Global model `models_global/sharma_global_RF.joblib` |
| **MPTD-PQS (ours)** | Our method | NS-3 sim, `ablation_mode=1` → `_m1` sweep CSV |

---

## 2. File / Folder Map

Paths assume `NS3=~/ns-allinone-3.35/ns-3.35` and `PROJ=~/Niranga/MPTD-PQS-SDVN`.

### Scripts
| File | Role |
|------|------|
| `$PROJ/global_baseline_eval.py` | **Trains + freezes** the global models; emits the averaged chart |
| `$PROJ/global_heldout_eval.py` | **Scores the frozen models** on fresh held-out runs; emits the per-attack chart |
| `$PROJ/mptd_pqs/ercan_b2_detector_v2.py` | B2 feature extractor (`load_scenario`, `FEATURE_COLS`, `compute_metrics`, `_rf`) |
| `$PROJ/mptd_pqs/sharma_b3_detector_v2.py` | B3 feature extractor (same interface) |
| `$NS3/scratch/mptd_pqs_sdvn/run_b1_sweep.sh` | Runs B1 (mode 6) across attacks/pcts |
| `$NS3/scratch/mptd_pqs_sdvn/run_heldout_perattack.sh` | Runs the 9 held-out sims + scores + plots |

### Inputs (training data)
| Path | Contents |
|------|----------|
| `$NS3/analytics/datasets/aN_pP/beacon_log.csv` | Per-scenario training data (one folder per attack × pct) |

### Outputs
| Path | Contents |
|------|----------|
| `$NS3/models_global/ercan_global_RF.joblib` | **Frozen** B2 global model |
| `$NS3/models_global/sharma_global_RF.joblib` | **Frozen** B3 global model |
| `$NS3/analytics/results/sweep/metrics_aN_pP_s60_m1.csv` | MPTD-PQS metrics |
| `$NS3/analytics/results/sweep/metrics_aN_pP_s60_m6.csv` | B1 Ghaleb metrics |
| `$NS3/analytics/results/beacon_log.csv` | Latest live-run log (overwritten each sim) |
| `$PROJ/live_results/global_baseline_vs_pct.png` | MCC/FPR vs % (averaged across attacks) |
| `$PROJ/live_results/global_heldout_perattack.png` | MCC/FPR per attack (a1/a2/a3) — **primary chart** |
| `$PROJ/live_results/global_heldout_results.csv` | Raw held-out metrics table |

---

## 3. Pipeline & Commands

```
set env once
  export NS3=~/ns-allinone-3.35/ns-3.35
  export PROJ=~/Niranga/MPTD-PQS-SDVN
```

### Step 0 — (Prereq) Phase-A datasets exist
The training folders `$NS3/analytics/datasets/aN_pP/` must already contain
`beacon_log.csv`. These come from earlier Phase-A simulation runs. Current pool:
`a1_p{30,60,90}`, `a2_p{30,60,90}`, `a3_p{30,60}` (attacks 1–3).

### Step 1 — Fill in B1 Ghaleb metrics (rule-based, no training)
```bash
cd "$NS3"
bash scratch/mptd_pqs_sdvn/run_b1_sweep.sh
```
Runs `ablation_mode=6` for attacks 1–3 × p30/60/90, writing the `_m6` sweep CSVs.

### Step 2 — TRAIN + FREEZE the global ML models
```bash
cd "$PROJ"
NS3="$NS3" python3 global_baseline_eval.py
```
This:
1. Pools every `analytics/datasets/aN_pP/` into one feature table per method.
2. Splits by vehicle (`GroupShuffleSplit`, 30% test, seed 42).
3. Trains one `RandomForest` per method and **freezes** it to
   `$NS3/models_global/{ercan,sharma}_global_RF.joblib`.
4. Writes the averaged chart `live_results/global_baseline_vs_pct.png`.

> The `.joblib` files ARE the frozen models. Re-running this command **retrains
> and overwrites** them. To keep models fixed, do not re-run Step 2.

### Step 3 — RUN THE LIVE SIMULATION + score the frozen models (held-out)
```bash
cd "$NS3"
bash scratch/mptd_pqs_sdvn/run_heldout_perattack.sh
```
For each attack 1–3 × pct 30/60/90 it:
1. Runs a **fresh** NS-3 sim with `ablation_mode=1 --RngRun=2` (a seed the models
   never trained on) → new `analytics/results/beacon_log.csv` + MPTD-PQS `_m1` CSV.
2. Loads the **frozen** global models and predicts on that run:
   `python3 global_heldout_eval.py predict <attack> <pct>`
   (appends MCC/FPR/PARR to `live_results/global_heldout_results.csv`; also pulls
   B1 `_m6` and MPTD `_m1`).
3. After all runs: `python3 global_heldout_eval.py plot`.

ETA ≈ 9 sims × ~8–12 min. The frozen models are **not** retrained here.

**Watch live:**
```bash
tail -F "$NS3/scratch/mptd_pqs_sdvn/sim_live.log"          # raw NS-3 sim
tail -F "$NS3"/scratch/mptd_pqs_sdvn/heldout_perattack_*.log  # high-level progress
```

### Step 4 — (Re)generate the performance charts
The held-out script already plots, but you can re-plot anytime without re-running
sims (reads the existing results CSV):
```bash
cd "$PROJ"
NS3="$NS3" python3 global_heldout_eval.py plot   # -> global_heldout_perattack.png
NS3="$NS3" python3 global_baseline_eval.py       # -> global_baseline_vs_pct.png (NOTE: also retrains)
```

---

## 4. Quick Run (full sequence)

```bash
export NS3=~/ns-allinone-3.35/ns-3.35
export PROJ=~/Niranga/MPTD-PQS-SDVN

cd "$NS3" && bash scratch/mptd_pqs_sdvn/run_b1_sweep.sh        # B1 metrics
cd "$PROJ" && NS3="$NS3" python3 global_baseline_eval.py        # train + freeze
cd "$NS3" && bash scratch/mptd_pqs_sdvn/run_heldout_perattack.sh  # live sim + score + per-attack chart
```

Final deliverables:
- `live_results/global_heldout_perattack.png` (primary, per-attack)
- `live_results/global_baseline_vs_pct.png` (averaged summary)
- `live_results/global_heldout_results.csv` (raw numbers)

---

## 5. Scope / Caveats

- The global model is currently trained on **attacks 1–3 only** (8 scenarios;
  `a3_p90` has no dataset folder). State this scope in the writeup, or add the
  missing scenarios and re-run Step 2 for an all-attack model.
- B1 Ghaleb has no model — it is rule-based and runs inside NS-3 (`mode 6`).
- Held-out evaluation uses `RngRun=2`; the training data came from earlier runs,
  so the test seed/vehicles are genuinely unseen.
