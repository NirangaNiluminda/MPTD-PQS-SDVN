# Session Findings — HPC build & baseline evaluation (2026-06-12)

Notes captured while following `HPC_RUN_GUIDE.md` to build the project and run
the existing baseline techniques (B1/B2/B3) on the 64-RSU grid. Covers
environment gotchas, two real code/config bugs, and a new plotting helper.

---

## 1. Build environment (one-time setup)

The project lives at `~/Niranga/MPTD-PQS-SDVN` and is wired into NS-3 via
symlinks under `~/ns-allinone-3.35/ns-3.35`:

| ns-3 path | → target |
|-----------|----------|
| `scratch/mptd_pqs_sdvn` | (pre-existing) project `scratch/mptd_pqs_sdvn` |
| `mobility` | project `mobility` — **added this session** |
| `mptd_pqs` | project `mptd_pqs` — **added this session** |

`mobility/` and `mptd_pqs/` were missing from the NS-3 root; the sim reads them
at runtime (`mobility/mobility_urban_60.tcl`, the B2/B3 Python scripts), so both
must be symlinked in before running.

### 1a. `liboqs` was not installed
The `wscript` links `oqs`, but `~/.local` had only OpenFHE + ONNX Runtime.
Built from source into the prefix the wscript expects:
```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX=$HOME/.local -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build -j && cmake --install liboqs/build
# → $HOME/.local/lib/liboqs.so + $HOME/.local/include/oqs/
```

### 1b. NS-3.35 Python bindings break on Python 3.12
`./waf build` fails in `ns3module_*` with
`error: lvalue required as left operand of assignment` (the `Py_TYPE()` macro
changed in 3.12). The C++ simulation does not need the bindings — configure with
them off:
```bash
./waf configure --disable-python
./waf build
```

---

## 2. Stale 4-RSU datasets — must regenerate on the 64-RSU grid

`analytics/datasets/a<N>_p<P>/` held data from an **old 4-RSU layout**
(max `rsu_id` = 3). The supervisor-mandated grid is now **8×8 = 64 RSUs**
(`--N_RSUs=64`, max `rsu_id` = 63). B2/B3 compute RSSI/distance features against
the 64 grid-RSU positions, so models trained on 4-RSU data are invalid.

- Verified the mismatch by `cut`-ing the `rsu_id` column (old folders → 3,
  fresh `a2_p20` from a 64-RSU run → 61).
- The stale folders were removed this session; only freshly simulated
  `--N_RSUs=64` scenarios should be used for training.
- The sim **auto-dumps** each run into `analytics/datasets/a<N>_p<P>/`, so the
  guide's "copy into datasets/" step is largely automatic.

---

## 3. BUG — `sharma_b3_live_predict.py` imported a non-existent symbol

`mptd_pqs/sharma_b3_live_predict.py` imported `_attach_disp_err` from
`sharma_b3_detector_v2`, which does not exist → `ImportError` on every run.
The real helper (same as the working B2 script) is `_augment_with_real_pos`.
Fixed both the import and the call site. B2's script was already correct.

---

## 4. CONFIG mismatch — trainer percentage grid excludes 20

`*_train_save.py` iterate `ATTACK_PCTS = [0, 30, 60, 90]` (defined in the
`*_detector_v2.py` modules). The guide's TL;DR example uses
`--attack_percentage=20`, which the trainer therefore **silently skips** — it
produces 0 models with no error.

Two ways to reconcile:
- Run the evaluation matrix at **0/30/60/90** so the documented
  `python3 mptd_pqs/ercan_b2_train_save.py analytics/datasets models_ercan_b2`
  command works unchanged; **or**
- Override the list in memory for a one-off pct (e.g. 20):
  ```python
  import mptd_pqs.ercan_b2_train_save as T
  T.ATTACK_NUMS, T.ATTACK_PCTS = [2], [20]
  T.train_and_save("analytics/datasets", "models_ercan_b2")
  ```

---

## 5. Plotting — built-in baseline chart uses literature constants, not results

`mptd_pqs/metrics_visualization.py::plot_baseline_comparison` draws the B1/B2/B3
bars from a hardcoded `BASELINES` dict in `metrics_calculator.py`
(MCC 0.61/0.74/0.78). It does **not** read the `live_results/*.csv` predictions,
and its `__main__` only renders synthetic demo data (with a stale `/home/niranga`
path). So it never reflects the actual simulation/baseline numbers.

Added `plot_baselines_real.py` (repo root) which:
- computes MCC/FPR per classifier from `live_results/{ercan,sharma}_a<N>_p<P>.csv`
  (`label` vs `pred_*`), picking the best-MCC classifier per baseline;
- reads MPTD-PQS metrics from `analytics/results/sweep/metrics_a<N>_p<P>_s60_m1.csv`
  (A1) and B1 from the `_m6.csv` (ablation mode 6) when present;
- emits a grouped MCC/FPR bar chart per scenario.

```bash
python3 plot_baselines_real.py <attack> <pct> [out.png]
```

---

## 6. Held-out baseline result (sanity check) — attack 2 @ 20%, 64-RSU grid

Train on RUN A (`--RngRun=1`), predict on RUN B (`--RngRun=2`) — no leakage.

| Method | best clf | MCC | FPR |
|--------|----------|-----|-----|
| B2 (Ercan) | RF | 0.9985 | 0.0003 |
| B3 (Sharma) | RF | 1.0000 | 0.0000 |
| MPTD-PQS (A1, lightweight-only) | — | 0.8777 | 0.0520 |

Caveats:
- B2/B3 out-score MPTD-PQS here because MPTD-PQS ran as **A1** (no GAT/LSTM —
  ONNX models absent, §1d of the guide). A fair comparison needs MPTD-PQS in
  **full** mode.
- B3's `live_predict` reports PARR ≈ raw poison fraction (~0.187), unlike B2 —
  its PARR column is not computed the same way. MCC/FPR are the reliable numbers.

---

## 7. To produce the *full* evaluation plots

Per scenario (attacks 1–7 × pct {0,30,60,90}):
```
RUN A (--RngRun=1)             → analytics/datasets/aN_pP  (training data)
train_save (once, all folders) → frozen .joblib models
RUN B (--RngRun=2)             → fresh analytics/results/beacon_log.csv
live_predict (N, P)            → MCC/FPR per classifier  (live_results/)
run with --ablation_mode=6     → B1 metrics  (for the B1 bar; optional)
```
MPTD-PQS metrics fall out of each run's `metrics_aN_pP_s60_m1.csv`. These are
many heavy runs — prefer the SLURM wrapper (guide §7) over interactive shells.
