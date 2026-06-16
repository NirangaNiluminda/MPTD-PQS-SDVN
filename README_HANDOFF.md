# Baseline Evaluation Hand-off (B2 Ercan & B3 Sharma) — README

This folder lets you score the two trained state-of-the-art baselines
(**B2 = Ercan et al. 2022**, **B3 = Sharma & Liu 2021**) on a dataset and
produce all 7 project metric plots, alongside **MPTD-PQS (ours)** and
**B1 Ghaleb**.

The models are **trained once on the NS-3 dataset and frozen**. You do **not**
retrain. You only run the evaluation on your data.

---

## 0. One-time setup

Use the **exact** library versions — the frozen models were pickled with
scikit-learn 1.5.2 and loading them under a different version can silently
corrupt predictions.

```bash
pip install -r requirements.txt
```

`requirements.txt` pins:
```
scikit-learn==1.5.2
scipy
pandas
matplotlib
joblib
```

---

## 1. What's in this folder

```
MPTD-PQS-SDVN/
├── mptd_pqs/                     # feature extractors + detectors (needed)
│   ├── ercan_b2_detector_v2.py   # B2 baseline (Ercan 2022)
│   ├── sharma_b3_detector_v2.py  # B3 baseline (Sharma 2021)
│   └── ...
├── mobility/
│   └── rsu_positions_urban.csv   # RSU topology (needed by Ercan distance/AoA)
├── models_global/                # FROZEN trained models — DO NOT retrain
│   ├── ercan_global_RF.joblib
│   ├── ercan_feature_cols.json
│   ├── sharma_global_RF.joblib
│   └── sharma_feature_cols.json
├── train_global_models.py        # (only the trainer re-runs this; you don't)
├── eval_on_real_and_plot.py      # <-- YOU RUN THIS
└── datasets/                     # the NS-3 dataset (reference for the format)
```

---

## 2. Required data format (IMPORTANT)

**Your dataset must use the same layout as `datasets/`** — one folder per
scenario, named `a{attack}_p{pct}`, e.g. `a1_p30`, `a2_p60`, `a4_p90`.
Attack id and penetration % are read from the folder name.

Each scenario folder must contain:

| File | Required? | Purpose |
|------|-----------|---------|
| `beacon_log.csv` | **Yes** | one row per received beacon; carries the label |
| `metrics.csv`    | Yes (for the MPTD-PQS / B1 overlay) | the simulation's own metrics |
| `tp_s1_poison_log.csv` | a1 only | real vs fake positions → feeds Ercan's RSSI feature |
| `vehicle_tx_log.csv`   | a2, a4 only | real vs sent positions → feeds Ercan's RSSI feature |
| (a3/a5/a6/a7 side logs) | optional | not used by the baselines; safe to include or omit |

Plus, at the project root, `mobility/rsu_positions_urban.csv`
(`rsu_id,x,y`) must describe the RSU topology your data was generated with.
If it is missing, the code falls back to a legacy 4-RSU layout and the Ercan
distance/AoA features will be wrong.

### `beacon_log.csv` columns

These column names are required (extra columns are ignored):

```
sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, is_poisoned
```

- `is_poisoned` is the **ground-truth label** (1 = attacker beacon, 0 = honest).
  Metrics cannot be computed without it.
- If your real CSV uses different names, rename the columns in the CSV (or add a
  rename mapping at the top of `load_scenario` in each `*_detector_v2.py`).

### `metrics.csv` columns (for the MPTD-PQS / B1 overlay)

Produced by the NS-3 simulation. The evaluator reads:
`attack_number, attack_pct, ablation_mode, MCC, FPR, PARR, CDER, TDEE, TPE,
PBPO_LW_ms`. Rows with `ablation_mode=1` are plotted as **MPTD-PQS (ours)**,
`ablation_mode=6` as **B1 Ghaleb**. If your data has no `metrics.csv`, only the
B2/B3 lines are drawn.

---

## 3. Run it

```bash
python eval_on_real_and_plot.py  <your_data_folder>  ./models_global  ./real_plots
```

Example:
```bash
python eval_on_real_and_plot.py ./real_data ./models_global ./real_plots
```

Outputs in `./real_plots/`:
- `metric_MCC.png … metric_PBPO.png` — one figure per metric, one subplot per
  attack, every subplot has a legend, error bars are **95% CI (vehicle-level
  bootstrap)**, axes are labelled with units.
- `results_real.csv` — the tidy table behind every point
  (`method, attack, pct, metric, mean, ci95`).

---

## 4. How to read the plots

- **MCC** (primary, −1…1) and **FPR** (primary, 0…1) are true, comparable
  detection metrics across all methods.
- **PARR, CDER, TDEE, TPE, PBPO** are MPTD-PQS *system* metrics. For the ML
  baselines they are name-matching **proxies** (e.g. baseline PARR = recall,
  baseline TPE = attack prevalence). Plots label these `(baseline value is a
  proxy)`. Use them for completeness, argue head-to-head only on MCC/FPR.
- Expect baselines to be **strong but attack-dependent**: high where the attack
  violates kinematic plausibility, lower where it does not. The 0% column is
  dropped automatically (no attackers → metric undefined).

---

## 5. Troubleshooting

- **`InconsistentVersionWarning` / weird predictions** → you are not on
  scikit-learn 1.5.2. Fix with `pip install scikit-learn==1.5.2`.
- **`KeyError` on a column** → your `beacon_log.csv` column names don't match
  Section 2. Rename them.
- **A baseline line is missing for some attack/%** → that bucket had only one
  class (e.g. 90% penetration with no honest vehicles); it's skipped on purpose.
- **`UnicodeDecodeError` when grepping files on Windows** → environment quirk,
  not the code; open files with `encoding='utf-8'`.

---

## 6. Note for the report

This is a **cross-domain** evaluation: models trained on NS-3, tested on the
real-network data. State this explicitly; expect real-data MCC to be somewhat
lower than the NS-3 sanity value (~0.87 Ercan / ~0.83 Sharma) due to domain
shift. The baselines were adapted to RSU-relative distance/AoA, with RSSI
distance computed from the ground-truth position.
