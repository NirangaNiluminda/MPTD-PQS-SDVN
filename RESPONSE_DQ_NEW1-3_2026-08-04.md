# DQ-NEW1, DQ-NEW2, DQ-NEW3 — results

All three measured against the **pre-fix deployed state**, as requested. Two of the three returned something different from what the question anticipated, and in both cases the difference changes what Fix 1 and Fix 2 should actually be. Those are flagged inline rather than smoothed over.

---

## DQ-NEW1 — S/θ_S distribution for correctly-routed a3 beacons

**Your hypothesis is confirmed, and more strongly than the >80% bar you set.**

Held-out combined-mode run, ρ_a=0.60, all beacons with `gt_atk=3` routed to the a3 weight set (`k̂=2`):

```
                       n      min    p25    p50    p75    max    saturated at 1.0
  ALL correctly-routed  1324  1.000  1.000  1.000  1.000  1.000       100.0%
    ghosts only           33  1.000  1.000  1.000  1.000  1.000       100.0%
    real vehicles only  1291  1.000  1.000  1.000  1.000  1.000       100.0%
```

**100.0% saturated at exactly 1.0 — not 80%, not a distribution across [0.5, 1.0]. Every single correctly-routed a3 beacon, ghost and real alike, pins S/θ_S at the clamp ceiling.**

There is no spread whatsoever, which means the GAT is not expressing a graded spatial signature for a3 — it is emitting an out-of-range score that the `min(S/θ_S, 1)` clamp flattens to 1.0. **This is novelty-driven saturation, not a learned Sybil signature.** The "100% recall when correctly routed" figure from DQ-A3-26 is therefore not evidence of a working detector; it is the clamp doing the work.

This is the single most important of the three results, because it invalidates the assumption behind Fix 4. Lowering θ_conf for the a3 head would route *more* traffic into a weight set whose apparent perfection is an artifact. **Fix 4 should not be applied until Fix 1 produces a genuinely learned a3 signature** — exactly the ordering you specified, now with measured justification.

---

## DQ-NEW2 — synthetic τ_i test

**τ_i is not the cause. The zero separation had a different root cause, which is now found and fixed.**

Ran the test as specified (τ_i = 0.0 for confirmed-malicious windows, 1.0 for honest, 10-epoch retrain, re-run DQ-AE5):

```
  configuration                          honest p50    malicious p50
  constant τ = 1.0 (mimics deployed)        0.461          670.84
  genuine  τ = 0/1 (your DQ-NEW2 test)      0.461          671.01
```

**The two are identical to three significant figures (670.84 vs 671.01). Adding a genuine τ_i changed nothing.**

What *did* restore separation was a train/serve feature mismatch found while building the test. `deploy_ae_L50.py` — the script that produced the deployed L=50 model — reads **absolute** `pos_x, pos_y, speed, heading, accel` from the CSV, but `scaler.json` and the C++ runtime (`lstm_ring_push_resid`, `04_state_globals.h:477-497`) both use **dead-reckoning residuals** (`res_x, res_y, dspeed, dheading, accel`). The model was trained on absolute city-scale coordinates normalised by a residual-calibrated scaler, then served genuinely tiny residuals. Training and inference saw different input distributions entirely.

Computing residuals correctly, with τ left constant:

```
  honest (held-out)  p50 = 0.461    p95 = 10.90
  malicious          p50 = 670.84   p90 = 2757.46

  attack p50 (670.84) > clean p95 (10.90)?   YES — by ~60x
```

**Your Fix 2 success criterion is met, without τ_i.** The AE has been retrained on corrected residual features and redeployed; validation on real held-out data across attack types:

```
  honest (held-out)   FPR at θ_ae = 4.58%
  a1  recall 78.8%      a2  recall 100.0%      a6  recall 82.6%
  a4  recall 14.5%      a3  recall  4.6%
```

a3's near-zero AE recall is correct and expected — a3 is RSU-side identity duplication, so the real vehicle's own kinematics are untouched and there is no temporal anomaly to reconstruct. That is GAT's job, not the AE's, and the deployed weights already reflect it (λ_ae = 0.019 for a3).

τ_i is still worth wiring up properly as a genuine blockchain-sourced feature, but on this evidence it is not what was blocking the AE, and it should not be treated as the fix.

---

## DQ-NEW3 — fallback population composition

**Correction on the data source first:** `beacon_train_master.csv` cannot answer this. It has no `khat` column (it is the Phase-1 GAT beacon corpus, not the Phase-2 fusion corpus) and it is 100% `attack_number=3` single-type — 72,919 rows, one attack type. Fallback routing is a runtime fusion decision, so it only exists in the `[FUSION-RSU]` scoring records.

Answered from those instead (D6, 3 seeds, ρ_a=0.60, malicious beacons only):

```
  type    total malicious   in fallback   % of own population   % of ALL fallback
  a1                 810           274          33.8%                  8.1%
  a2                 699             7           1.0%                  0.2%
  a3                6642          3014          45.4%                 88.9%
  a4                5930            94           1.6%                  2.8%
  a6                1520             0           0.0%                  0.0%

  total malicious beacons in global fallback: 3389
```

**The fallback population is overwhelmingly a3 — 88.9% of it.** It is not balanced across attack types in any meaningful sense: a2, a4 and a6 are routed to their conditioned weight sets >98% of the time and contribute 3.0% of the fallback population combined.

**Implication for Fix 3:** the global fallback weights are, in practice, an a3-specific calibration wearing a "global" label. Any Phase 2 optimisation over this population will be fit almost entirely to a3, and its held-out performance will be an a3 result. This also explains why the earlier constrained refits kept failing held-out validation — they were being asked to find one weight triple that serves a population dominated by the one attack type whose signal (per DQ-NEW1) is currently an artifact.

---

## What these three imply for the fix sequence

1. **Fix 2 is done and validated** — but via the residual-feature correction, not τ_i (DQ-NEW2).
2. **Fix 1 is the true blocker.** DQ-NEW1 shows a3's apparent detection is saturation, and DQ-NEW3 shows a3 dominates the fallback population that Fix 3 would calibrate against. Both downstream fixes depend on it.
3. **Fix 4 should stay deferred** until Fix 1 yields a graded, non-saturated a3 score. Per-head θ_conf support is implemented and built, but no value has been set.
4. **Fix 3 should follow Fix 1**, since calibrating now would fit to the artifact.

**Status note on Fix 1:** attempting it surfaced a further pre-existing defect. `train.py::build_gat_dataset` groups training snapshots by `(run_id, tick)` — every vehicle across the whole map — while the runtime scores one RSU's ~10-beacon window. Since S_i is a snapshot-*relative* z-score (Eq 3.42), these are different tasks. Measured with the **unmodified deployed weights** on the same data:

```
  map-wide (run_id, tick) grouping   AUC = 0.4416   (no separation)
  per-RSU 10-beacon windows          AUC = 0.7439   (real separation)
```

The GAT has been trained on a different task than it is served on.

**A corrected retrain has since been run, and its result is a direct experimental confirmation of DQ-NEW1 — see the next section. The GAT model is currently reverted to its original state; nothing unvalidated is deployed.**

---

## DQ-NEW1 confirmed experimentally — the saturation *was* the detection

Your post-Fix-1 check asked: after retraining, is S/θ_S still uniformly saturated at 1.0 (novelty-driven), or spread across [0.5, 1.0] (learned signature)? I ran that exact check on a corrected retrain (runtime-matched per-RSU grouping, raw-s_i export, θ_S recalibrated).

**The saturation is gone:**
```
  correctly-routed a3, S/θ_S      before retrain          after retrain
    min / p25 / p50 / p75 / max   1.000 (all identical)   0.000 / 0.000 / 0.051 / 0.090 / 0.654
    fraction saturated at 1.0     100.0%                  0.0%
```

**Per-head accuracy improved for four of five types:**
```
  type   before    after
  a1      15.3%    40.0%    improved, still below 70%
  a2      64.6%    93.8%    now passes
  a3      36.5%    97.3%    now passes
  a4      51.2%    18.3%    REGRESSED
  a6      98.0%   100.0%    passes
```

**But end-to-end detection tells the decisive story:**
```
  per-type detection recall, live runtime, retrained model:
    a1 0.346    a2 0.963    a3 0.002    a4 0.580    a6 1.000
                            ^^^^^^^^  was ~0.97 with the original model
```

**a3 detection collapsed from ~97% to 0.2%.** With a genuinely graded score (p50 = 0.051) and λ_gat = 0.95, Φ ≈ 0.05 — nowhere near Φ_th = 0.5. Nothing fires.

**This is the definitive answer to DQ-NEW1: a3's detection was entirely the saturation artifact.** Remove the clamp behaviour and a3 detection disappears. The retrained model did not acquire a learned ghost signature to replace it — and on reflection the attack code explains why. Ghosts are deliberately constructed to be spatially plausible: placed at realistic offsets, speed capped below `s_max`, constant heading, and heading set *opposite* to the intercepted vehicle specifically so the GAT's heading-alignment edge predicate excludes them (the source comments call this "GAT's only remaining tell"). A ghost is engineered to be an in-distribution node with no graph neighbours. There is little learnable spatial signature there for a feature-based GAT to find.

**The retrained model was therefore reverted** — it is scientifically cleaner but operationally worse (a3 recall 0.002 vs ~0.97). This is a real trade-off, not a fixable bug:

- The **original** model detects a3 at ~97% via out-of-distribution saturation. That is a legitimate anomaly-detection mechanism, but it is fragile: a stealthier ghost designed to look in-distribution would evade it — which is precisely the fragility your DQ-NEW1 question was probing.
- The **retrained** model has honest graded scores and better attack-type classification, but cannot detect a3 at all.

**Neither is acceptable as-is, and the gap is not closable by further retraining on this data.** Detecting a3 robustly needs a signal the current GAT feature set does not carry — the relational/identity-density evidence (MP-S1 fires at only 19.4%) rather than per-node kinematics. That is a design change, and I did not want to make it unilaterally.

---
---

# Appendix — full status, findings, and failed attempts

Included so the record is complete and reproducible, including the attempts that did not work.

## A. Current deployed state (as of this writing)

```
  artifact                                  state
  models/urban/lstm_ae_model.onnx           NEW  — Fix 2 (residual features), validated
  models/urban/theta_ae.txt                 33.693885  — recalibrated for the new AE
  models/urban_combined/theta_ae.txt        33.693885  — synced (was stale at 1.3834)
  models/urban/gat_model.onnx               REVERTED to original 2026-07-18 model
  models/urban_combined/theta_s.txt         19.74      — original (Fix A reverted, see C)
  models/urban_combined/fusion_weights.json unchanged  (0.5071 / 0.1857 / 0.3071)
```

**The only net change to the deployed system is the LSTM-AE (Fix 2) and its threshold.** The GAT, θ_S and all fusion weights are at their original values.

Every change has a timestamped `.bak_*` alongside it. **Nothing unvalidated is deployed.**

## B. Code fixes made (all compiled and in the binary)

1. **Ghost beacons were never written to `beacon_log.csv`.** `log_beacon_to_csv()` was called from exactly one place — the real-vehicle receive path (`08_detection_engine.h:3077`). No ghost had ever entered any training corpus, and none could have, regardless of which runs were used to build one. Added the call in the ghost-injection path; verified 5,688 / 5,584 / 6,604 ghost rows across three fresh runs.
2. **Ground-truth lookup guard for ghost IDs.** Ghosts have no ns-3 `MobilityModel`, so the `get_gt_position()` lookup indexed a garbage vehicle. Guarded on `vid < GHOST_VID_BASE`.
3. **Per-head θ_conf support (Fix 4).** `theta_conf` was a single global scalar. Added optional `theta_conf_per_attack` parsing plus `theta_conf_k[]`, so one head can use a different gate. **Implemented and built, but no value set** — deliberately deferred per DQ-NEW1.
4. **θ_ae file desync.** `urban_combined/theta_ae.txt` (1.3834, dated Jul 21) did not match `urban/theta_ae.txt` (0.793731, Jul 26) — the combined runtime was loading a threshold calibrated for a superseded model. Synced.

## C. Fixes attempted and rejected on evidence

**Fix A (θ_S 95th → 99th percentile, 19.74 → 22.531).** Deployed, re-measured end-to-end, then reverted:
```
              MCC      recall    FPR          (vs θ_S=19.74: D1 0.4208 / D4 0.4239 / D6 0.4173)
  D1_fixA    0.4144    0.629    0.0047
  D4_fixA    0.4178    0.633    0.0047
  D6_fixA    0.4116    0.631    0.0140
```
Consistently ~0.006 MCC worse across all three arms. It reduced honest S-exceedance as designed (3.00% → 0.86%) but cost more recall than it bought precision. Reverted.

**Fixes B + C (constrained Phase 2 refit, λ_gat ≥ 0.50, λ_ae ≤ 0.08).** Fitted on fresh post-Fix-A calibration data, validated on a held-out seed:
```
  deployed     (0.507, 0.186, 0.307)   held-out MCC 0.2703   TP/FP/TN/FN 100/0/985/700
  constrained  (0.440, 0.560, 0.000)   held-out MCC 0.1632   TP/FP/TN/FN 104/40/945/696
  held-out ΔMCC = -0.1071  →  NOT deployed
```
Same shape as the earlier Round-6 refit failure: better on training data, collapses held-out (+4 TP for +40 FP). Per DQ-NEW3, this is expected — the fallback population being 88.9% a3 means any "global" fit is really an a3 fit.

## D. Fix 1 — failed attempts and hypotheses ruled out

Two full retrains were run and both were reverted. Both improved *classification* markedly (a3 head routing accuracy 36.5% → 100%) but collapsed the *anomaly score* to a constant, giving 0% detection recall on correctly-routed a3 — worse than the original.

```
  attempt              config                                    result
  1   default loss weighting, 30 epochs           S ≡ 0.026 constant, recall 0%  → reverted
  2   loss_k_weight=0.2, 20 epochs                S ≡ 0.028 constant, recall 0%  → reverted
```

Hypotheses tested to explain the collapse:

```
  #   hypothesis                                  verdict
  1   O(N²) edge builder / oversized snapshots    RULED OUT — max tick size 44; real cost was
                                                  97,080 graphs in an unbatched training loop
  2   classification loss drowning score loss     RULED OUT — isolating loss_s alone still collapsed
  3   missing feature normalisation               REAL BUG, FIXED — train.py's main() calls
                                                  normalise(df) before train_gat(); my driver
                                                  skipped it. Variance improved 3x — insufficient alone
  4   corpus class imbalance (15:1 malicious)     RULED OUT — rebalancing to ~50/50 made it WORSE
                                                  (std 0.0105, loss pinned at ln2 = 0.693)
  5   random init vs fine-tune from good weights  DECISIVE NEGATIVE — the ORIGINAL untouched weights
                                                  are ALSO degenerate on these graphs (std 0.011),
                                                  proving the fault is upstream of training entirely
  6   ONNX export contract mismatch               REAL BUG — deployed ONNX emits raw s_i (its scores
                                                  node is ReduceL2); current gat_detector.py exports
                                                  sigmoid(affine(s_i)). Sigmoid ≈ 0.52 ÷ θ_S 19.74
                                                  = 0.026 — exactly the observed constant
  7   train/serve graph-grouping mismatch         ROOT CAUSE (see below)
```

**Root cause (7):** `build_gat_dataset` groups by `(run_id, tick)` — every vehicle across the map at one timestep — while the runtime scores one RSU's ~10-beacon window. S_i is a snapshot-*relative* z-score, so the two are different tasks. Measured with the **unmodified deployed weights**, same corpus, only the grouping changed:

```
  map-wide (run_id, tick)      AUC = 0.4416    (no separation, slightly inverted)
  per-RSU 10-beacon windows    AUC = 0.7439    (real separation)
```

Both (6) and (7) are **pre-existing defects in the training pipeline**, not regressions introduced here. They were invisible until now because this appears to be the first end-to-end GAT retrain attempted since the pipeline diverged.

## E. Corrections to previously reported answers

- **DQ-AE4 was wrong.** I previously reported θ_ae as `median + 3×MAD` from `lstm_detector/train.py`. The deployed model was actually produced by `deploy_ae_L50.py`, which uses **`mean + 1.645×std`**. Different script, different formula.
- **DQ-AE3 is stronger than reported.** The constant τ_i is not a fallback-path accident — `deploy_ae_L50.py:27` hardcodes `np.ones(...)` unconditionally.
- **DQ-NEW3's prescribed source file cannot answer the question** — see that section above.

## F. Fix 1 outcome — three retrains, all reverted

```
  attempt   grouping    export        outcome
    1       map-wide    sigmoid       S ≡ 0.026 constant, a3 recall 0%      reverted
    2       map-wide    sigmoid       S ≡ 0.028 constant, a3 recall 0%      reverted
    3       per-RSU     raw s_i       saturation ELIMINATED, classification
                                      improved 4/5 types, but a3 recall
                                      0.97 → 0.002                          reverted
```

Attempt 3 is not a failure of execution — it worked exactly as designed and produced the decisive scientific result above. It was reverted because it is operationally worse, not because it was wrong.

## G. Open items and recommendation

1. **Fix 1 cannot be completed by retraining alone.** Proven: the only thing detecting a3 is OOD saturation, and ghosts are deliberately engineered to be in-distribution with no graph neighbours. This needs a design decision from you — most plausibly routing a3 through the identity-density evidence (MP-S1) rather than expecting per-node kinematic features to carry it.
2. **Fix 3 is blocked on that decision.** Per DQ-NEW3 the fallback population is 88.9% a3, so any Phase 2 calibration today fits the artifact.
3. **Fix 4 stays deferred** — built, not activated. Lowering θ_conf for a3 would route more traffic into a weight set whose apparent perfection is the artifact.
4. **D1/D4/D6 re-run and the D6 > D4 > D1 ordering check** — pending 1–3.
5. **τ_i as a genuine blockchain-sourced feature** — worth doing on its own merits, but DQ-NEW2 shows it is not the AE blocker.
6. **`train.py` needs upstream repair** for the export-contract and graph-grouping defects. The corrected retrain worked around both in a separate script rather than editing the shared pipeline mid-investigation; that fix should be made properly before any future training run.

**Recommendation:** treat Fix 2 as done, and treat Fix 1 as answered-but-unresolved — the diagnosis is now complete and unambiguous, but closing it requires a modelling decision rather than more tuning. I did not want to make that call unilaterally.
