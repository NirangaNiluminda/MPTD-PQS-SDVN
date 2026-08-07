# Steps 1, 2 and 3 — results

**Summary up front:**
- **Step 1:** D1 = 0.4208, D4 = 0.4239, D6 = 0.4225. **Ordering D6 > D4 > D1 is NOT met** (D6 below D4 by 0.0014) — but Fix 2 shrank the AE penalty ~4.7× and D6 now exceeds D1 for the first time.
- **Step 2:** a4 median reconstruction error is 2.716 vs θ_ae = 33.69 — far below. Detection is intermittent by nature, not broken.
- **Step 3:** Fix A and Fix B implemented in `train.py` and verified (exported `scores` node is now `ReduceL2`, matching the deployed model; graphs are now uniform 10-node RSU windows). Retrain done through the corrected pipeline — **a3 scores are now genuinely graded (check 1 passed)**, a4 head accuracy +43.1%, but **a1 regressed −23.7%** and a3's score now falls *below* honest traffic, so a3 remains undetectable by this model. The original GAT model was **not** overwritten.
- **Additional (tested, not assumed):** the hypothesis that Step 4's Phase 2 reweighting closes the −0.0014 gap was tested directly and **does not survive held-out validation**. Details in Step 1 below.

## STEP 1 — D1/D4/D6 with Fix 2 (corrected AE) deployed

3 seeds, 30s, combined attack, ρ_a=0.60, urban, N_Vehicles=200, N_RSUs=64.
Verified at load time in every run: D1 `gat=NO lstm_ae=NO`; D4 `gat=YES lstm_ae=NO`; D6 `gat=YES lstm_ae=YES window=50`, **θ_ae=33.6939** (the Fix 2 value), θ_S=19.74.

```
  arm       MCC    recall      FPR     TP/FP/TN/FN
  D1     0.4208     0.627    0.0043    9787/10/2320/5814
  D4     0.4239     0.631    0.0043    9852/10/2320/5749
  D6     0.4225     0.630    0.0043    9823/10/2320/5778

  D4 − D1 = +0.0031      D6 − D4 = −0.0014      D6 − D1 = +0.0017
```

**D6 > D4 > D1 is NOT met.** D6 still sits below D4, by 0.0014.

**However, Fix 2 produced a large improvement in exactly the direction predicted.** The AE's dilution penalty shrank ~4.7×:

```
                    D6 − D4
  before Fix 2      −0.0066
  after  Fix 2      −0.0014
```

D6 also now exceeds D1 (+0.0017), which it did not before. So the AE went from clearly harmful to very nearly neutral. The ordering requirement is not satisfied, but the remaining gap is small and its cause is now measured exactly.

### Why the prediction did not hold

The predicted mechanism was: malicious ε/θ_ae ≈ 19.87 → clipped to 1.0 → λ_ae=0.307 contributes fully; honest ≈ 0.014 → negligible. **The honest half is confirmed. The malicious half holds for three attack types and fails for two — and those two are the bulk of the population.**

Measured `ae_norm` in the live D6 run:

```
             n       mean    p50     frac = 0    frac at 1.0
  honest    2330   0.0360  0.0050     26.2%         1.3%     ← as predicted (~0.014)
  malicious 15601  0.2025  0.0000     53.2%        15.5%     ← predicted ~1.0, actual 0.20
```

Per attack type:

```
  type    n      mean ae_norm   frac = 0   frac at 1.0    ghosts in type
  a1      810       0.7119       21.9%       69.1%              0     works as predicted
  a2      699       0.6052       39.5%       60.5%              0     works as predicted
  a6     1520       0.7281       21.4%       45.4%              0     works as predicted
  a4     5930       0.1562       30.3%       10.9%              0     WEAK
  a3     6642       0.0190       86.1%        1.5%           5349     ~ZERO
```

**a3 and a4 together are 12,572 of 15,601 malicious beacons — 80.6% of the malicious population — and the AE contributes essentially nothing on either.** The AE's strong signal (a1/a2/a6 at 45–69% saturation) covers only 19.4% of malicious traffic, yet λ_ae=0.307 is subtracted from ψ and GAT on *every* beacon. That residual mismatch is the remaining −0.0014.

**The a3 cause is structural, not a calibration issue: 86.1% of a3 beacons have ae_norm exactly 0 because 5,349 of 6,642 a3 beacons (80.5%) are ghosts, and ghosts never enter the LSTM ring at all.** This is deliberate in the code — `lstm_ring_push_resid` is explicitly not extended to ghosts (`08_detection_engine.h:3953`), since a fabricated identity has no beacon history to build a temporal window from. No AE threshold or retraining can change this; a ghost has no time series to reconstruct.

**Implication:** the remaining gap is a *weighting* problem, not an AE-quality problem. The per-attack λ sets already handle this correctly where they apply (a3's conditioned set is λ_ae=0.019, near zero — right). The leak is the global fallback path, which applies λ_ae=0.307 uniformly — and per DQ-NEW3, 88.9% of the fallback population is a3, i.e. precisely the beacons where the AE contributes nothing.

### Tested: can Step 4 close the −0.0014 by reweighting alone? No.

Rather than assume Phase 2 will fix this, I tested it directly by decision-level recomputation on the D6 logs (recomputing Φ per beacon under candidate global triples, applying them only to `khat = −1` rows since the per-attack sets govern the rest, and preserving speed-bound-override detections). The recomputation reproduces the deployed D6 MCC exactly (0.4225), which validates the method.

**In-sample, a reweighting does exist that would satisfy the ordering:**
```
  best global triple (psi 0.340, gat 0.560, ae 0.100)   MCC 0.4273
  → 0.4273 (D6) > 0.4239 (D4) > 0.4208 (D1)   ordering satisfied
```
Notably this is the λ_gat↑ / λ_ae↓ direction of the earlier Fix B/C mandate, which had previously failed — suggesting that mandate was directionally right but blocked by the uncorrected AE.

**But it does not survive held-out validation.** Fitting on seeds 1–2 and testing on seed 3:
```
  HELD-OUT seed 3          MCC
    D4 (AE removed)      0.5298   <-- bar
    D6 deployed          0.5278
    D6 refit             0.4927

    held-out dMCC (refit - deployed) = -0.0351
    held-out refit vs D4             = -0.0371
```

**So the fallback-reweighting hypothesis is not supported, and Step 4 should not be expected to close the ordering gap on its own.** This is the same in-sample-good / held-out-bad pattern as every previous refit attempt in this engagement, and it is why I tested it rather than reporting the in-sample number.

One observation worth flagging: per-seed MCC is substantially higher than the 3-seed pooled figure (seed 3 alone: D4 = 0.5298, D6 = 0.5278, versus pooled 0.4239 / 0.4225). Pooling across seeds changes the evaluated population, so the two are not directly comparable. **The D6 < D4 ordering holds in both views** — pooled by 0.0014, on held-out seed 3 by 0.0020 — so the conclusion is stable even though the absolute values are not.

---

## STEP 2 — a4 reconstruction error distribution vs θ_ae

Scored with the deployed Fix-2 AE using the exact residual features the runtime feeds it. θ_ae = 33.6939.

```
  source                       n        p50        p90         p95         p99    > θ_ae
  a4_p100 (identity theft)   885      2.716     42.062      72.804    1430.597    14.5%
  a4_p60                    2855      3.896  64014.419  108276.311  580948.535    25.3%
  a4_p30                    1970      1.380      9.664      73.517    2271.640     8.9%
  a2_p100 (detects at 100%)  959    153.568    357.112     430.766     835.597   100.0%
  honest (a4_p0)            2054      0.478      6.381      14.049      71.590     4.6%
```

**Confirmed: a4's median error (2.716) is far below θ_ae=33.69.** The more revealing comparison is against honest traffic — a4's median is only **5.7× the honest median** (2.716 vs 0.478), whereas a2, which detects at 100%, sits at **321× honest** (153.568 vs 0.478). To the residual-feature AE, the typical a4 beacon looks nearly honest.

**But the residual feature set is not blind to a4 — it is intermittent.** a4's p90/p95 (42.1 / 72.8) do clear θ_ae, and at ρ_a=0.60 the tail reaches 64,014 (p90) and 108,276 (p95). So the AE fires hard on *some* a4 beacons and not at all on most.

**Diagnosis:** dead-reckoning residuals measure *instantaneous* kinematic inconsistency — the discontinuity when an impersonated identity jumps. They do not measure *sustained* identity mismatch. Between jumps, the impersonator moves plausibly, and a plausible trajectory produces a small residual regardless of whose identity is attached to it. So a4 is detected only at its discontinuities, which is 14.5% of its beacons at ρ_a=1.00 and 25.3% at ρ_a=0.60.

Lowering θ_ae would recover some a4 recall but at direct cost to honest FPR (honest p95=14.05, p99=71.59 — already straddling the region a4's detectable beacons occupy). I have **not** changed θ_ae; reporting the values first as instructed.

---

## STEP 3 — Fix A and Fix B implemented in `train.py`

Both are done and verified. `train.py` is backed up as `train.py.bak_pre_step3_20260804`.

### Fix A — ONNX export contract

Added a `_GatExportRawScore` wrapper used by `export_gat_onnx()`. It re-emits the raw s_i computed *before* the affine+sigmoid, restoring the contract the C++ runtime expects. Training is unaffected — the sigmoid head still shapes the embedding via BCE (which requires [0,1]); only the exported graph changes.

**Verified exactly as you specified — the exported `scores` node type now matches the deployed model:**
```
  deployed model  : ReduceL2
  newly exported  : ReduceL2
  MATCH: True
```

### Fix B — graph grouping

`build_gat_dataset` now groups by `(run_id, rsu_id)` and chunks into consecutive 10-beacon windows ordered by `sim_time`, mirroring the RSU accumulate-then-flush behaviour. Window size is overridable via `MPTD_GAT_RSU_WINDOW`. A guarded fallback to the old per-tick path remains (with a printed warning) for inputs lacking `rsu_id`, so synthetic-data paths still run.

**Verified — every constructed graph is now exactly one RSU window:**
```
  graphs built : 923   (from a 4-run test subset)
  node counts  : min=10  max=10  mean=10.0
  all == 10 (RSU window)? True
```
Previously these were variable-size map-wide snapshots.

### Retrain through the corrected pipeline — done

Retrained on the ghost-inclusive combined-mode corpus (92,370 rows, 31 runs, 4,057 ghost beacons — ghost logging was itself a code fix, since ghosts were never written to `beacon_log.csv` at all). Validation loss improved monotonically (5.497 → 4.879), unlike the erratic pre-fix runs.

**Exported to `models/urban_step3_eval/`. The deployed GAT model was NOT overwritten** — per your instruction to keep the original for a3 detection.

**Check (1) — does a3 produce graded, non-saturated scores? YES.**
```
  raw s_i for a3      min      p25      p50      p75      max
  ORIGINAL          39.150  617.161  801.873  845.379  856.064   → /θ_S=19.74 ⇒ ALL clamp to 1.0
  STEP 3             0.144    0.339    0.549    0.772   10.896   → genuinely graded
```
The original model's a3 scores are 20–43× θ_S, so every one clamps to exactly 1.0 — the saturation, quantified. The retrained model produces a real distribution.

**Check (2) — per-head accuracy improved for a1 and a4? One yes, one no.**
```
  type    original    step 3     delta
  a1        92.7%     69.0%    -23.7%   <-- NOT improved (regressed)
  a2        99.9%     99.9%     +0.0%
  a3         0.0%     96.9%    +96.9%
  a4        33.7%     76.8%    +43.1%   <-- IMPROVED
  a5        61.8%     74.3%    +12.5%
  a6        76.1%     97.0%    +20.9%
  a7        46.4%     68.8%    +22.5%
```
**a4 improves substantially (+43.1%), a1 regresses (−23.7%).** Five of seven types improve overall. Note the original model classifies a3 at **0.0%** — it never identifies a3's *type* correctly, yet detects it at ~97% via saturation. That is precisely the OOD mechanism you described: it flags a3 as anomalous without recognising what it is.

**Important caveat on these numbers.** `train_gat` splits at the graph level, so no clean run-level holdout exists for the retrained model. This evaluation is therefore **in-sample for the Step 3 model and out-of-sample for the original** — a bias that favours the retrained model. The improvements are inflated; the a1 regression is if anything understated, since it regressed despite the bias.

**A blocking consequence for Step 4.** The retrained model's raw s_i scale is entirely different — max ≈ 11 versus the original's ≈ 1255. Under the current θ_S = 19.74, *nothing* would ever exceed threshold. θ_S must be recalibrated before this model can be used at all. More seriously:
```
  honest  p50 = 1.058
  a3      p50 = 0.549   ← BELOW honest
  a2      p50 = 1.895   a6 p50 = 1.381   ← above honest
```
**a3's anomaly score now sits below honest traffic**, so no θ_S choice can detect a3 with this model — it would fire on honest beacons first. a2/a6 retain positive signal. This independently confirms your design decision: **keep the original model for a3.** The retrained model's value is confined to type *classification* (routing) and to a4, not to a3 detection.
