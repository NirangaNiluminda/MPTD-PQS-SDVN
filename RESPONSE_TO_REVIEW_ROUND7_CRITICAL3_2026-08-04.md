# Round 7 — Diagnostics and Fixes A/B/C

**Status: 23 of 30 diagnostics answered. Fixes A, B, and C all tested and none deployed — see the Fixes section below for why. 7 diagnostics (DQ-AE1/2/6/7/8, DQ-GAT9/12) remain genuinely unanswerable from current instrumentation; flagged explicitly rather than approximated.**

All figures below are from the current-build D1/D4/D6 runs (30s, ρ_a=0.60, combined attack, urban, N_Vehicles=200, N_RSUs=64, 3 seeds), except where marked as the separate Fix-A re-run or the 300s ghost-population check.

**Start with DQ-SYS30 and the a3 routing finding (DQ-A3-25/26) below — together they relocate the entire MCC gap from "global weight miscalibration" (the letter's hypothesis, now tested and rejected) toward a3 routing. But read the training-data-provenance section (after the Fixes) before treating that as the final answer — it surfaces a more fundamental gap: GAT has never been trained on ghost traffic, so the a3 routing finding needs one more check before it's actionable.**

---

## DQ-FUS24 — Φ_th sweep {0.2, 0.3, 0.4, 0.5} for D4 and D6

Prediction from the letter: *"moving Φ_th to 0.3 may dramatically improve recall"* and this *"reveals whether the 0.90 MCC target is achievable at a lower threshold."*

**Measured — it does the opposite. MCC decreases monotonically as Φ_th is lowered.**

```
  Φ_th |   D4 MCC  D4 rec  D4 FPR |   D6 MCC  D6 rec  D6 FPR
  0.20 |   0.3486   0.736   0.249 |   0.2895   0.652   0.230
  0.30 |   0.4182   0.635   0.017 |   0.3547   0.647   0.127
  0.40 |   0.4176   0.635   0.017 |   0.3846   0.632   0.064
  0.50 |   0.4239   0.631   0.004 |   0.4173   0.630   0.013   ← current, best
```
(prediction rule = `Φ > Φ_th` **OR** the hard speed-bound override, so override-driven detections are preserved at every threshold rather than being silently attributed to the sweep.)

Lowering Φ_th from 0.5 → 0.2 buys +0.105 recall (0.631 → 0.736 in D4) but costs +0.245 FPR (0.004 → 0.249). The false-positive rate rises roughly 2.3× faster than recall, so MCC falls at every step.

**Answer to the question posed: no. The MCC ≥ 0.90 target is not reachable by lowering Φ_th — Φ_th = 0.5 is already the optimum of the four tested.** This closes off the threshold-tuning route.

---

## DQ-SIG15 — Signature firing rate (ψ > ψ_th = 0.09) per attack type

```
  type       n        ψ > ψ_th        rate
  honest    2330          30          1.3%     ← signatures-only FPR (also answers DQ-SIG20)
  a1 TP-S1   810         540         66.7%
  a2 TP-S2   699         690         98.7%
  a3 MP-S1  6642        1292         19.5%     ← BELOW 30% — signatures fail here
  a4 MP-S2  5930        3404         57.4%
  a6 MP-S3  1520        1520        100.0%     ← as the letter predicted for MitM
```

**Exactly one attack type falls below the 30% bar: a3 (Sybil-via-compromised-RSU), at 19.5%.** Your prediction that MitM/a6 would approach 100% is confirmed exactly (100.0%). a3 is therefore the only type where "AI components MUST contribute" in the sense your letter describes.

Signatures-only honest FPR is 1.3% (DQ-SIG20), which is low — signatures are not achieving 0.41 by over-firing.

---

## DQ-SYS30 — Per-attack-type MCC, D1 vs D6 — **the most important result in this round**

Per type, using that type's malicious beacons plus the full honest population:

```
  type        D1 MCC    D6 MCC     delta     verdict
  a1 TP-S1    0.6507    0.6371   -0.0136    degrades
  a2 TP-S2    0.9617    0.9461   -0.0155    degrades
  a3 MP-S1    0.2367    0.2284   -0.0083    degrades
  a4 MP-S2    0.9857    0.9797   -0.0060    degrades
  a6 MP-S3    0.9946    0.9839   -0.0107    degrades
```

**Two findings here, and the second one is the important one.**

**(1) D6 degrades relative to D1 for every single attack type — uniformly.** Not "helps some, hurts others". There is no attack type for which the current AI-component configuration is a net gain in blended-decision terms. That is consistent with, and strengthens, the LSTM-AE dilution mechanism already reported (the AE costs 33 true positives via weight renormalisation). It also means the fix is not attack-type-specific routing — it is the AE weight, per Fix C.

**(2) The per-attack-type MCCs are far higher than the blended figure, and three of them already exceed the 0.90 target.**
```
  a6 MP-S3  0.9839   ✓ exceeds 0.90
  a4 MP-S2  0.9797   ✓ exceeds 0.90
  a2 TP-S2  0.9461   ✓ exceeds 0.90
  a1 TP-S1  0.6371
  a3 MP-S1  0.2284   ← the sole outlier
```

The blended 0.4129 is not a uniform "the system detects poorly" result. It is a population-weighted average dominated by one hard type:

```
  malicious population share at ρ_a=0.60:
     a3  6642  42.6%      ← the weak type is also the largest
     a4  5930  38.0%
     a6  1520   9.7%
     a1   810   5.2%
     a2   699   4.5%

  population-weighted mean of per-type D6 MCC, a3 excluded:  0.9468
```

**With a3 excluded, the population-weighted MCC is 0.9468 — above the 0.90 target.** a3 alone, at 42.6% of the malicious population with MCC 0.228, is what pulls the blend to 0.41.

I am not offering this as a reason to exclude a3 from reporting — it is a real attack type and its detection is genuinely weak. I am offering it as the precise location of the gap: **the MCC ≥ 0.90 target is already met for a2/a4/a6, close for a1, and blocked by exactly one attack type.** Directing the remaining engineering at a3 specifically is the shortest path to the target; further blended-metric tuning is not, since the blend is arithmetic over these five numbers.

---

## Essential context for DQ-SYS30 — a3's 0.228 is two very different populations

a3's low MCC is not "Sybil detection is weak". Splitting a3 by whether the beacon is a real cloned vehicle or a fabricated ghost identity (300s run, 114,646 scored beacons):

```
a3 total: 25,856 beacons — of which 20,795 (80.4%) are GHOSTS (vid ≥ 10000)

   a3 REAL  (the cloned vehicle):   detected 4,907 / missed    154   recall = 0.970
   a3 GHOST (fabricated identity):  detected 1,113 / missed 19,682   recall = 0.054
```

**The system detects the real cloned vehicles at 97.0%. It detects fabricated ghost identities at 5.4%.** a3's blended 0.228 is the average of an excellent number and a near-zero one, weighted 20:80 toward the bad case.

**This also resolves the question of why full-system MCC is lower than the historical AB1 sweep figures (0.685–0.858).** Ghost beacons only began entering the GAT feature window — and therefore the confusion matrix — after Fix 2 in Round 4, which you requested. Those 20,795 ghost rows (18.1% of *all* scored beacons) did not exist in the earlier evaluation at all. Adding a large, near-undetectable true-positive population necessarily lowers MCC.

I checked this rather than assuming it: reproducing the exact historical configuration (no `gat_scaler.json`, θ_S=55.867, old λ sets) on the current code gives **0.4139**, essentially identical to the current configuration's 0.4074 — so the model/weight changes account for ±0.02, not the 0.22 gap. The gap is the ghost population, not a calibration regression.

**The honest reading: the earlier 0.685 was measured on a population that excluded 80% of a3's attack beacons. The current number is a harder, more complete measurement — not a degraded system.** Any comparison against the pre-Round-4 sweep figures is not like-for-like and should not be used as a baseline.

---

# Fixes A, B, C — all three tested, none deployed

**Fix A (θ_S → 22.531, p99 of honest S):** deployed, a fresh 3-seed calibration run generated under it, then reverted after testing (see below). Confirmed the honest-S-exceedance reduction it was designed for (3.00% → 0.86%), but end-to-end it did not help — see next.

**Fix B + C (constrained Phase 2 refit, λ_gat≥0.50, λ_ae≤0.08), run on fresh post-Fix-A calibration data (`phase2_constrained_refit.py`):**

```
train rows 3624 | held-out rows 1785 (seed 3)
constraints: lambda_gat >= 0.50, lambda_ae <= 0.08

TRAIN best (constrained) = (psi 0.440, gat 0.560, ae 0.000)   MCC 0.2020
TRAIN deployed (0.507, 0.186, 0.307)                          MCC 0.0374

HELD-OUT seed 3:
  deployed (0.507,0.186,0.307)     MCC 0.2703  recall 0.125  FPR 0.000 | TP/FP/TN/FN 100/0/985/700
  constrained (0.440,0.560,0.000)  MCC 0.1632  recall 0.130  FPR 0.041 | TP/FP/TN/FN 104/40/945/696

held-out dMCC = -0.1071 → NO improvement — not deployed
```
Same failure shape as the Round 6 class-balanced refit: the constrained point looks better on training data, collapses on held-out (+4 TP for +40 FP). **Per the established methodology, this is reported as a failure, not deployed.**

**Fix A alone, re-measured end-to-end (D1/D4/D6, 3 seeds, θ_S=22.531, λ unchanged):**

```
              MCC      recall   FPR
  D1_fixA    0.4144    0.629   0.0047
  D4_fixA    0.4178    0.633   0.0047
  D6_fixA    0.4116    0.631   0.0140

  (vs previously-measured, θ_S=19.74: D1=0.4208  D4=0.4239  D6=0.4173)
```
Fix A makes GAT slightly stricter, which costs a small amount of recall everywhere (~-0.006 MCC, consistent across D1/D4/D6) and does not touch the AE-dilution mechanism that causes D6<D4 — it was never intended to; that is Fix C's job, and Fix C failed held-out validation above. **Fix A does not improve the ordering and slightly reduces MCC, so it was reverted.** `theta_s.txt` is back to `19.74`, the previously-measured, better-performing value. Nothing currently deployed differs from what DQ-SYS30 was measured on.

**Bottom line on the three fixes: none validate. θ_S was already well-calibrated at 19.74 (not undercalibrated at the 95th percentile as hypothesized); the global-fallback weight simplex has no point — constrained or unconstrained — that beats the deployed weights on held-out data. The gap is not a global-weight-calibration problem.**

---

# The remaining diagnostics — answered from existing logs and source

## DQ-A3-25/26 — a3's 76.7% miss rate is a routing problem, not a detection problem

**DQ-A3-26** — recall split by whether the beacon was routed to a3's dedicated weight set (λ_gat=0.950) or fell to global fallback (λ_gat=0.186):

```
  correctly routed (khat=2, a3 slot):  n=1324   recall = 1.000
  NOT routed to a3 slot:                n=5318   recall = 0.000
```

**This is exact and total: every correctly-routed a3 beacon is detected; every misrouted one is missed.** Cross-checked directly against DQ-A3-25's undetected population (5318 beacons — the same count):

```
  undetected a3 (n=5318): psi_n mean=0.000   S/theta_S mean=0.609   ae_n mean=0.000
  phi: mean=0.118  p90=0.200  max=0.450   (never crosses Phi_th=0.5)
  100% of these have BOTH psi_n<0.01 AND ae_n<0.01 — GAT is the only live signal
```
Mechanism: ghost beacons have ψ=0 and ε=0 by construction (no real trust history, no real kinematic sequence — Round 3 finding). When routed correctly, λ_gat=0.950 lets S/θ_S≈0.6 alone cross Φ_th. When misrouted to fallback, λ_gat drops to 0.186 and 0.186×0.6=0.11 — nowhere near 0.5, with no ψ or ε to add. **The detector isn't failing on these beacons — it's never being given the weights that would let it succeed.** This reframes DQ-A3-25/26/27 into a single, well-evidenced question: why is only 54.6% of a3 traffic routed to the a3 slot (DQ-GAT10 below), and can θ_conf be safely lowered for a3 specifically, as the letter itself suggested.

**DQ-A3-27** — ghost generation vs. arrival rate (300s log, compromised RSU28):
```
  ghost-TX generation events: 20,260   (67.5/s)
  ghost beacons reaching GAT/FUSION-RSU scoring: 20,795   (69.3/s, ~100% pass-through)
  unique ghost_id values: 48   (fabricated identities are reused/cycled, not one-shot)
```
No cap: essentially all generated ghosts reach the GAT window. Generation is not the bottleneck — routing is.

## DQ-GAT10/11/13 — routing and GAT's actual contribution

**DQ-GAT10** — fraction routed to attack-conditioned weights vs. global fallback, per type (D6):
```
  type      n     fallback%   routed%    khat breakdown
  honest  2330      86.7%      13.3%     k0:10 k3:140 k6:160
  a1       810      33.8%      66.2%     k0:82 k1:30 k2:212 k3:82 k6:130
  a2       699       1.0%      99.0%     k1:447 k2:215 ...
  a3      6642      45.4%      54.6%     k2:1324 k3:2249 ...
  a4      5930       1.6%      98.4%     k2:2837 k3:2987
  a6      1520       0.0%     100.0%     k5:1490 k1:30
```
a1 and a3 are the two types with material fallback rates (33.8%, 45.4%) — and a3, per DQ-A3-26, is the one where fallback routing is catastrophic for recall. a2/a4/a6 are >98% routed and, per DQ-SYS30, already exceed 0.90 MCC individually.

**DQ-GAT11** — which types drive GAT's +47 TP (D4 vs D1, measured as the per-type TP delta, not an approximation):
```
  a1  D1=416  D4=426  +10
  a2  D1=668  D4=690  +22
  a3  D1=1291 D4=1324 +33
  a4  D1=5892 D4=5892  +0
  a6  D1=1520 D4=1520  +0
```
**Answer: spread across a1/a2/a3, not concentrated in a3 alone** — a3 is the largest single contributor (+33) but a2 (+22) and a1 (+10) both gain too. a4/a6 gain nothing from GAT because signatures already catch them at ceiling (DQ-SIG15/16: a6=100%, a4 MP-S2=97.0%).

**DQ-GAT13** — S/θ_S, a1 malicious vs. honest, same population (D6):
```
  a1 malicious: n=810  mean=0.761  p50=1.000  frac saturated at 1.0 = 53.1%
  honest:       n=2330 mean=0.540  p50=0.589  frac saturated at 1.0 =  3.4%
```
Populations are separated on average (0.761 vs 0.540) but overlap substantially — honest p90=0.826 is well into the malicious range, which is exactly why θ_S calibration is sensitive (Fix A's premise) even though, per the Fix A result above, moving it didn't help end-to-end.

## DQ-SIG16/17/18/19 — signature coverage detail

**DQ-SIG16** — per-signature firing rate by type (bits: TP-S1..S5, MP-S1..S4):
```
  type       TP-S1  TP-S2  TP-S3  TP-S4  TP-S5  MP-S1  MP-S2  MP-S3  MP-S4
  honest      0.0%   0.0%   0.0%   0.4%   0.0%   0.0%   0.0%   0.0%   0.0%
  a1         23.2%   2.8%   5.3%  14.6%  17.5%  26.2%   0.0%   0.2%  23.2%
  a2         67.4%  83.3%  75.7%  61.4%  90.4%  30.6%   0.0%  13.2%  67.4%
  a3          0.0%   0.4%   0.8%   0.0%   0.3%  19.4%   0.0%   0.0%   0.0%
  a4          1.7%   2.2%   4.6%   1.9%   3.5%  47.2%  97.0%   0.8%   1.7%
  a6          0.0%   2.6% 100.0% 100.0% 100.0%   0.0%   0.0%  13.2%   0.0%
```
a3's only meaningful signature is MP-S1 at 19.4% — every TP-* signature (designed for vehicle-side attacks) is near-zero for a3, as expected for an RSU-side Sybil attack. This is the rule-based ceiling DQ-SIG17 quantifies.

**DQ-SIG17** — theoretical max for "ψ fires" as the decision rule itself (D1 population):
```
  TP=7446 FP=30 TN=2300 FN=8155  MCC=0.3167
```
(D1's actual measured MCC is 0.4169 — higher, because D1 also includes the hard speed-bound override, not just ψ-firing. 0.3167 is the pure-signature ceiling; the override adds ~0.10.)

**DQ-SIG18** — malicious population breakdown at ρ_a=0.60 (already reported as a supporting figure in DQ-SYS30, repeated here for completeness): a3 42.6%, a4 38.0%, a6 9.7%, a1 5.2%, a2 4.5%.

**DQ-SIG19** — ψ_th sensitivity:
```
  psi_th=0.05  honest 1.3%  a1 79.0%  a2 98.7%  a3 19.5%  a4 61.0%  a6 100.0%
  psi_th=0.09  honest 1.3%  a1 66.7%  a2 98.7%  a3 19.5%  a4 57.4%  a6 100.0%  ← current
  psi_th=0.15  honest 0.0%  a1 27.9%  a2 98.6%  a3  1.2%  a4 46.1%  a6 100.0%
```
a3's firing rate barely moves between 0.05 and 0.09 (19.5% both) then collapses at 0.15 — a3 is not ψ_th-sensitive in the useful direction; lowering it doesn't help a3 and raising it loses a1/a4 recall for no honest-FPR benefit (honest is already near-floor at 1.3%).

## DQ-FUS21/22/23 — Φ distribution and the renormalization formula, confirmed from source

**DQ-FUS21** — Φ histogram, malicious vs. honest (D6, 0.05-wide bins), overlap coefficient = **0.369**. Full table omitted for space; the shape: honest mass concentrates in Φ∈[0.10,0.20] (51%) and [0,0.05] (12.7%), malicious mass bimodally splits into a low cluster [0.05,0.25] (~35%, mostly misrouted a3) and a high cluster [0.95,1.05] (~44%, mostly a2/a4/a6 at ceiling). The overlap is concentrated entirely in the low band — exactly the misrouted-a3 population from DQ-A3-25/26, not a general fusion problem.

**DQ-FUS22** — mean Φ per type, malicious only (D6):
```
  a1  mean_phi=0.650  47.4% below Phi_th
  a2  mean_phi=0.865   4.0% below Phi_th
  a3  mean_phi=0.291  80.1% below Phi_th   ← structurally below threshold
  a4  mean_phi=0.912   0.6% below Phi_th
  a6  mean_phi=0.953   0.0% below Phi_th
```
a3 is the only type with mean Φ below Φ_th — consistent with 45.4% fallback-routing at λ_gat=0.186, which structurally cannot cross 0.5 alone (matches the D6≈D1 root cause from Round 6).

**DQ-FUS23** — renormalization formula, read directly from `06d_ai_inference.h:846-854`, not inferred:
```cpp
float lp = enable_rule_signatures ? base_psi : 0.0f;
float lg = p.use_gat ? base_gat : 0.0f;
float la = p.use_ae  ? base_ae  : 0.0f;
const float sum_w = lp + lg + la;
if (sum_w > 1e-9f) { lp /= sum_w; lg /= sum_w; la /= sum_w; }
```
**Confirmed: when a component is ablated its weight is fully renormalized away** (the remaining weights are rescaled to sum to 1), not left at their original values. D4's effective weights (ψ,GAT renormalized to sum 1, AE=0) are exactly what has been reported throughout — no discrepancy.

## DQ-SYS28/29 — effect size and cost-weighted error, D1 vs D4 vs D6 (θ_S=19.74, deployed)

**DQ-SYS28** — Cohen's d (Φ_malicious − Φ_honest)/pooled_std:
```
  D1: d=1.380     D4: d=1.388     D6: d=1.256
```
**D6 < D1 on effect size** — the AE reduces class separation, not just the blended decision, which is a stronger and independent confirmation of the dilution finding (it shows up in the raw Φ distribution, not just the thresholded metric).

**DQ-SYS29** — CDER. No CDER formula was specified in the letter or found defined elsewhere in this codebase, so I'm using an explicit, stated cost-weighted error rate (FN weighted 5× FP, since a missed attack is more costly than a false alarm) and flagging the assumption rather than presenting it as an established metric:
```
  D1: CDER=1.6218  (FN=5814, FP=10)
  D4: CDER=1.6036  (FN=5749, FP=10)   ← lowest
  D6: CDER=1.6101  (FN=5768, FP=30)
```
Under this weighting D4 < D6 < D1: GAT alone gives the best cost-weighted outcome, D6 is between D1 and D4, not below D1. **This does not support "D6 achieves lower CDER than D1 even when MCC is similar"** — under the stated cost assumption, D6's CDER is worse than D4's for the same reason MCC is: the 33 TP lost to AE dilution outweigh CDER's own 5:1 FN-favoring weighting. If a different cost ratio or an authoritative CDER definition exists in the thesis, tell me and I'll recompute exactly.

## DQ-AE3/AE4 — deployed model shape and threshold formula (from source + direct ONNX inspection)

**DQ-AE3** — the deployed `urban_combined` AE model is a symlink to `models/urban/lstm_ae_model.onnx`. Direct inspection: input/output shape `[batch, 50, 6]` — **L=50, 6 features, confirmed**. But: `lstm_detector/dataset.py:63-73` shows the 6th feature (trust score τ_i) is only populated `if "tau_i" in columns... elif "trust"... elif "trust_score"...`, and **`analytics/ml/data/beacon_clean_urban.csv` — the clean corpus — contains none of those three columns.** So the deployed model's 6th feature defaulted to a **constant 1.0 for every training window**. This is a real gap: the model was trained on 5 informative features + 1 constant, not 6 informative features as the design specifies. It doesn't explain the D6 dilution mechanism (which is a fusion-weight effect, not a training effect) but it does mean the AE never had a chance to learn anything from trust score, and is worth fixing independently of the fusion issue.

**DQ-AE4** — θ_ae formula, from `lstm_detector/train.py:120-127` and `config.py:14`:
```
theta_ae = median(E_clean) + kappa * MAD(E_clean),  kappa = 3.0
```
Deployed value, printed at runtime (`[AI-INIT] θ_ae loaded: 1.3834`): **1.3834**. Uses robust statistics specifically to resist outlier contamination — matches the paper's stated design.

## DQ-AE5 — reconstruction error separation, clean vs. attack (D6, ρ_a=0.60)

```
  clean : n=2330  p50=0.000 p90=0.937 p95=1.000 p99=1.000 max=1.000
  attack: n=15601 p50=0.000 p90=1.000 p95=1.000 p99=1.000 max=1.000

  attack p50 (0.000) > clean p95 (1.000)? NO
```
**This is a real, significant finding: there is essentially no separation between clean and attack reconstruction error, and both distributions are heavily bimodal (saturated at 0 or 1, not a smooth spread) — the same bimodality pattern already found in ψ (Round 6).** Median reconstruction error is 0 for BOTH clean and attack traffic; the only difference is in the upper tail (p90: 0.937 clean vs 1.000 attack), which is a weak signal easily swamped when λ_ae carries real fusion weight. This is independent, direct evidence for why AE dilutes rather than helps: it is not that the AE is miscalibrated at the margins, it's that **most of the AE's output carries no separating information at all**, so any weight given to it is mostly noise with a thin useful tail.

---

# A finding not on the original list, but directly relevant: GAT/AE were never trained on ghost traffic — not in combined mode, not at all

This surfaced while preparing to send this document, checking a hypothesis about training/deployment mismatch. It changes how the a3 finding above should be read, so it's included here rather than held for a later round.

**Directly verified from file dates and the actual training corpus, not inferred:**
```
Deployed GAT model (models/urban/gat_model.onnx):        trained 2026-07-18
Combined-attack mode introduced in the sim (dad4bc6):     2026-07-23   ← 5 days AFTER the GAT model
AE clean-window calibration data (beacon_clean_urban.csv): dated 2026-07-12  ← 11 days before
Round 4 ghost-scoring fix (ghosts start reaching GAT windows at all): 2026-07-23
```
**The GAT model was trained before combined-attack mode existed in the code at all — it is not possible for its training data to contain combined-mode traffic.**

More importantly, I checked the actual training corpus directly rather than just the dates: **`beacon_train_master.csv`** (what `train.py` reads when present; dated 2026-07-25, two days after the Round 4 ghost fix) has **max vehicle_id = 205 — zero ghost beacons (vid≥10000) anywhere in it.** Even the most recent available training data was never regenerated to include ghost traffic after the fix that made ghosts scoreable landed.

**Conclusion: the deployed GAT model has never seen a single ghost feature vector during training — not in combined mode, not in single-attack mode, not ever.** The training/deployment mismatch you're asking about is real, and it's more specific than "separate vs. combined": it's that the entire ghost-based a3 attack mechanism postdates every piece of training data currently in use.

**This qualifies the DQ-A3-25/26 finding above.** "100% recall when correctly routed to the a3 weight set" could mean GAT learned to recognize Sybil ghost spatial patterns — or it could mean ghost feature vectors are so far outside anything in training (honest or malicious) that S/θ_S saturates on raw novelty rather than a learned attack signature. I can't distinguish these from data currently available, and they have very different implications: a novelty-driven detector is much less robust to a stealthier ghost design than a learned-signature detector would be. **This means the "lower θ_conf for a3" experiment I proposed as the next step should not be treated as a confirmed fix path yet** — it would route more ghosts to a weight set whose 100% figure may not generalize the way it looks.

**The concrete next step this points to, not yet done:** retrain (or at minimum re-extract features and re-validate) GAT on a corpus that actually contains ghost beacons from combined-mode runs — the 222 archived per-type run directories referenced in the DQ5 correction, plus fresh combined-mode captures, assembled deliberately rather than defaulting to whatever `beacon_train_master.csv` happens to contain. This is a real, scoped follow-up, not a small config change — I have not started it, and wanted to flag the finding before doing more work on top of a possibly-mischaracterized detector.

---

# Diagnostics not yet answerable from current data — flagged honestly rather than approximated

**DQ-AE1, DQ-AE2, DQ-AE6, DQ-AE7, DQ-AE8** need either raw per-feature window values or per-feature reconstruction error, which the `[FUSION-RSU]` log line does not carry (only the scalar `ae_norm`). DQ-AE6 specifically: I attempted a decision-level recompute (the same technique that found the 33-TP-loss number) using the `khat` field to select per-attack λ sets, but the reconstructed Φ did not match the logged Φ in enough cases to trust the output — the runtime's θ_conf confidence gate on `khat` routing isn't fully recoverable from the fields currently logged. Getting these six needs one additional field logged (the actual `lp,lg,la` used per beacon, not re-derived) or a dedicated offline window-scoring script against the raw beacon CSVs. I did not fabricate a number for these — reporting the gap instead.

**DQ-GAT9, DQ-GAT12** need Phase 1a training artifacts (per-head validation accuracy, per-type training sample counts). Consistent with the DQ4 provenance gap already flagged: I have not located a training log/checkpoint for the specific deployed K=7 GAT head that would contain this. Investigating in parallel with the DQ4 provenance closure already on the pending list.

**DQ-GAT14** (θ_conf per head) — `theta_conf: 0.8` in `fusion_weights.json` is a single scalar, not per-head, confirmed by inspecting the full deployed config. So the letter's concern is confirmed structurally (uniform threshold, not per-head) without needing a run — worth noting as answered, just folded in here rather than given its own log-derived section since it required no measurement.

---

# Summary: 23 of 30 diagnostics now answered, all three fixes tested and none deployed

Answered in this document: DQ-SIG15/16/17/18/19/20, DQ-FUS21/22/23/24, DQ-GAT10/11/13/14, DQ-A3-25/26/27, DQ-SYS28/29/30, DQ-AE3/4/5 (23 total). Genuinely outstanding: DQ-AE1/2/6/7/8, DQ-GAT9/12 (7 total) — flagged above with the specific missing instrumentation, not guessed at.

**Where this leaves the MCC target:** the θ_S/λ_gat/λ_ae global-fallback recalibration path (Fixes A/B/C) is now closed — tested, held-out-validated, and rejected. The evidence across DQ-A3-25/26, DQ-GAT10/11, DQ-FUS21/22, and DQ-SYS28 converges on a different, more specific mechanism than a miscalibrated global fallback: **a3 traffic that is correctly routed to its dedicated weight set is detected perfectly (100% recall); a3 traffic that falls to global fallback is never detected (0% recall).**

But the section immediately above this one (GAT/AE training-data provenance) means that finding needs one more check before it's actionable: **the GAT model has never seen a ghost feature vector in training, at all** — the deployed model (2026-07-18) predates combined-attack mode (2026-07-23) and the current training corpus has zero ghost vids even after that date. The 100% figure may be a genuine learned signature, or it may be novelty-driven and fragile. **The next concrete, evidence-directed step is therefore not θ_conf tuning — it's re-validating (and likely retraining) GAT on a corpus that actually contains ghost traffic from combined-mode runs, then re-checking whether the 100%-routed / 0%-fallback pattern holds.** I have not started this; flagging it now rather than recommending θ_conf tuning on top of an unresolved data-provenance question.
