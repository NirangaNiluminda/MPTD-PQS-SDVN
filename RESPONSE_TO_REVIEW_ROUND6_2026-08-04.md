# Response to Review — Round 6 — DQ1–DQ6 — 2026-08-04

All six diagnostics answered. Conditions as specified (30s, ρ_a=0.60, combined attack, urban, N_Vehicles=200, N_RSUs=64, 3 seeds) unless noted; DQ3 uses the 3-seed real-topology a3 runs, DQ4/DQ5 are direct inspection of the training data on disk.

**Summary up front:** three of the four hypothesised bugs are disproven by direct measurement (DQ1, DQ3, DQ4-partial). One is confirmed and is worse than hypothesised — **DQ5: the Phase 2 calibration set is 100% a3, zero samples from the other six attack types.** DQ2/DQ6 show the AI components add more true positives than false positives, and that the D6<D1 gap is statistically indistinguishable from seed noise. Details and the honest position on the MCC ≥ 0.90 target are below.

---

## DQ1 — θ_S in the global fallback path

**Answer: θ_S = 19.74. Not 8.305.**

Printed from the live fusion computation, not a config file — the `[FUSION-RSU]` line emits `thetaS=` at the moment of use, on every scored beacon:

```
[AI-INIT] θ_S loaded: 19.74                        (load time)
distinct thetaS= values across all scored beacons:  19.740   (single value, no drift)
distinct thetaS= values on khat=-1 rows only:       19.740   (fallback path specifically)
```

Zero variance across every evaluation in the run, and identical on the fallback path. **The hypothesised bug is not present.** For completeness: 8.305 was never `urban_combined`'s value — it was the *shared `urban` model's* pre-Block-1 broken value, a different model, fixed in Round 2 (8.305442 → 22.531). `urban_combined` was independently recalibrated to 19.74 in Round 4 when its own scaler bug was found and fixed.

Since DQ1 is negative, the instruction "fix immediately, this is likely the primary cause of D6 < D1" does not apply — there is nothing to fix in this path.

---

## DQ2 — False positive count, D1 vs D6, same seeds

**Answer: full confusion matrices, both configurations, all three seeds:**

```
        D1 (signatures only)              D6 (full system)                ΔFP    ΔTP
seed1:  TP=2981 FP= 0 TN= 720 FN=2512  |  TP=3015 FP= 0 TN= 720 FN=2478   +0    +34
seed2:  TP=3980 FP=10 TN= 490 FN=1803  |  TP=3979 FP=20 TN= 480 FN=1804  +10     -1
seed3:  TP=2826 FP= 0 TN=1110 FN=1499  |  TP=2839 FP=10 TN=1100 FN=1486  +10    +13
                                                                        ─────  ─────
                                                            totals:      +20    +46
```

**D6 generates 20 additional false positives and 46 additional true positives.** The premise of the question — that the AI components "are generating more false positives than true positives" — is not what the data shows: the ratio is 46 TP gained per 20 FP gained, i.e. the components are net-positive on raw counts.

The MCC nonetheless comes out marginally lower because MCC weights FP heavily when TN is small (TN is 480–1110 here, vs TP in the thousands), so 20 FP costs more in the formula than 46 TP gains. That is a property of the metric under this class balance, not evidence of a miscalibrated component.

**On whether D6 < D1 is even a real effect:**
```
D1 per-seed:  [0.3477, 0.3757, 0.5273]   mean 0.4169
D6 per-seed:  [0.3510, 0.3650, 0.5230]   mean 0.4130
per-seed Δ:   [+0.0033, -0.0107, -0.0043]      mean Δ = -0.0039
seed-to-seed spread within D1 alone:            0.1796
pooled stdev:                                   0.0860
```
The mean difference (-0.0039) is **46× smaller than the spread between seeds of the same configuration**, and D6 *beats* D1 on seed 1. At n=3 this difference is not statistically distinguishable from noise. It is not evidence of a defect, and equally it is not a demonstration that D6 > D1 — the honest statement is that the two are indistinguishable at this sample size.

---

## DQ3 — Ghost beacon window coverage for a3

**Answer: 92.2% coverage — well above the 50% threshold. The injection pipeline does not have the hypothesised gap.**

Measured across the three real-topology a3 seeds (`--N_Vehicles=200 --N_RSUs=64 --sybil_gat_evasive=1`), grouping `[FUSION-RSU]` rows into distinct (RSU, epoch) windows:

```
(a) total beacon windows processed:                8,511
(b) windows containing ≥1 ghost in the GAT input:  7,844  (92.2%)
    windows with no ghost:                           667  ( 7.8%)
(c) mean S_i, windows WITH ghost:                  28.30  (n=7,844)
    mean S_i, windows WITHOUT ghost:               22.17  (n=  667)
```

Ghosts reach the GAT feature vector in 92.2% of windows, and their presence raises the mean spatial score (28.30 vs 22.17), confirming they contribute real signal rather than being inert. **So a3's 23.3% recall is not caused by ghosts missing from the feature window** — they are present in the large majority of windows and are measurably shifting S_i. The cause is that the resulting S_i shift, while real, is frequently too small to carry Φ across the 0.5 threshold — a signal-strength limit, not a plumbing gap.

---

## DQ4 — Phase 1c LSTM-AE training data contamination

**Answer: the clean training set is 0.0000% contaminated — but I cannot fully verify it is the set the deployed model was trained on, and I am flagging that rather than claiming a clean result.**

Direct inspection of `analytics/ml/data/beacon_clean_urban.csv`:
```
rows:                30,091
is_poisoned=1:            0   (0.0000%)
attack_pct values:      [0]   (all runs ρ_a = 0.00)
attack_number values:  [1..7] (all seven types, all at ρ_a=0)
```
This is exactly the ρ_a=0.00 clean data the letter asks for, with zero contamination — far below the 5% threshold.

**The caveat, stated plainly:** the deployed `models/urban/lstm_ae_model.onnx` is dated 2026-07-26 07:03 (the AB4 residual-feature migration) and runs at window=50, whereas the clean CSV is dated 07-12 and the `.pt` checkpoint is dated 07-06 with `arch_urban.json` still specifying window=10. `export_onnx.py` reads its window from that arch file, so the deployed window=50 artefact **cannot** have come from that path. It was produced by a third route I have not been able to trace ("sir Step 4" per the C++ comment at `06d_ai_inference.h:363`). So: a clean training set exists and is verifiably uncontaminated, but the provenance chain to the currently-deployed weights has a gap. I would rather report that gap than assert a 0% contamination result I cannot fully substantiate.

---

## DQ5 — Per-attack-type sample counts in Phase 2 calibration — **confirmed problem, worse than hypothesised**

**Answer: the Phase 2 training set is 100% a3. Zero samples from a1, a2, a4, a5, a6, a7.**

Direct inspection of `analytics/ml/data/beacon_train_master.csv` — the file `train_fusion.py` reads to fit fusion weights:

```
total rows:                       72,919
  a3:                             72,919   (100.0%)
  a1, a2, a4, a5, a6, a7:              0   (  0.0%)

poisoned rows:                       521   (0.7% of the set)
```

The letter's threshold was "if a3 has fewer than 15% of the dominant class sample count." The actual situation is the inverse extreme: a3 *is* the entire assembled corpus, and the other six attack types are absent from it altogether. On top of that the set is only 0.7% poisoned, which is a very thin positive class from which to fit a detector's weights.

**Important qualification — the underlying data is NOT missing.** Checking `analytics/datasets/urban/` (222 archived run directories), usable labelled data exists for all seven attack types:

```
a1_p100_m0:  3,139 rows, 100.0% poisoned     a5_p20_m0:    3,139 rows, 31.7%
a1_p10_m0:   1,870 rows,  12.0%              a6_p0_m0:   616,541 rows, 62.5%
a2_p100_m0:  1,657 rows, 100.0%              a6_p10_m0:  773,746 rows, 21.0%
a3_p20_m0:   3,084 rows,  19.2%              a7_p20_m0:    3,139 rows, 31.7%
a4_p20_m0:   4,133 rows,  38.3%
```

So the defect is narrower and more tractable than "no data exists": **the Phase 2 corpus was assembled from a3 runs only, despite data for all seven types being available on disk.** The fix requires no new simulation — rebuild `beacon_train_master.csv` from the existing per-attack archives with class-balanced sampling, then re-run the fusion-weight calibration.

**Why this still matters:** a global fallback weight vector fitted exclusively on a3 data has no reason to generalise to a1/a2/a4/a5/a6/a7 — and the global fallback handles the largest single share of beacons in combined mode (~50%+ of evaluations, measured in Round 5). This remains a direct, mechanistic explanation for weak blended combined-mode performance, and it is the one hypothesised failure class the evidence confirms.

**One honesty caveat on attribution:** the deployed `fusion_weights.json` carries its own note (`"Change1+2: conditioned-ψ λ refit + θ_conf=0.8, offline urban G50 pens ['40','60']"`), which points to a refit process other than `train_fusion.py` on this CSV. So I have confirmed that *the Phase 2 training corpus in the repository* is 100% a3; I have not confirmed that this exact file produced the exact deployed numbers. Either way the corpus itself is unfit for calibrating a seven-attack-type global fallback.

**The letter's prescribed remedy was implemented and tested — it does not work. Reporting that rather than shipping it.**

First, a prerequisite fix: per-type labels were needed to balance across classes at all. The unconditional `tag.SetAttackType(attack_number)` bug (flagged in Round 5) meant a2/a4/a6 were all stamped type 0 in combined mode. Fixed at `09_vehicle_beacon_tx.h:256` using the existing `veh_atk()` helper (single-attack runs byte-identical). Labels now resolve correctly:
```
seed1:  a1=550  a2=209  a3=2854  a4=1490  a6=390   honest=720
seed2:  a1= 80  a2=390  a3=2123  a4=2670  a6=520   honest=500
seed3:  a1=180  a2=100  a3=1665  a4=1770  a6=610   honest=1110
```

Then the recalibration itself (`lambda_refit_global_balanced.py`), fitted on the `khat=-1` rows the global fallback actually governs, seeds 1+2, validated on unseen seed 3. Poisoned rows reweighted to equal mass per attack type — exactly the "oversample underrepresented attack types" remedy. Raw imbalance in the fallback path being corrected: a3 91.1%, a1 7.5%, a4 1.2%, a2 0.3%.

```
                              train MCC (balanced)      held-out MCC (true population)
deployed (0.507,0.186,0.307)        0.2209                    0.2703      TP/FP/TN/FN = 100/  0/985/700
class-balanced refit                0.3932                   -0.0137      TP/FP/TN/FN = 114/150/835/686
  (0.100, 0.550, 0.350)                                    dMCC = -0.2840
```

The rebalanced fit looks like a decisive win on the reweighted training distribution (0.393 vs 0.221) and then **collapses on held-out data**. Cause is visible in the confusion matrices: pushing λ_gat to 0.55 buys +14 true positives at the cost of +150 false positives, because the reweighted objective optimises for a population that does not exist in reality.

**Control run, to separate "rebalancing is wrong" from "refitting is wrong":** refitted on the same rows with *no* class weighting — natural distribution.
```
unbalanced refit (0.450, 0.550, 0.000)   held-out MCC 0.1632   TP/FP/TN/FN = 104/40/945/696
                                                             dMCC = -0.1071
```
**Also worse than deployed.** So this is not merely a rebalancing artefact — no reweighting of this sample produces a global fallback that beats the currently-deployed triple on held-out data.

**Nothing was deployed.** Both candidates were rejected on their held-out result.

**What this actually tells us, which is more useful than the fix would have been:** at the deployed weights the fallback path is very conservative — held-out recall 0.125 at **FPR 0.000**. It contributes few detections and *zero* false alarms. Every attempt to make it more aggressive adds false positives faster than true positives. That is a signal-quality property of the fallback population, not a calibration error — and it is a direct, measured explanation for why D6 ≈ D1: the AI components in the fallback path are approximately neutral by construction, and cannot be made net-positive by reweighting alone.

**Caveat I want to state rather than bury:** a2 contributes only 7 and a4 only 30 poisoned rows to the training fallback set, so the balanced fit upweights them ~85× and is partly fitting noise. A much larger sample might change the balanced result. But the *unbalanced* control failing too indicates the problem is not purely small-sample.

---

## DQ6 — Per-component contribution to honest-vehicle false positives

**Answer: 30 false positives from 2,330 honest beacons (FPR = 1.29%). GAT contributes zero of them.**

Computed from the D6 runs by reconstructing each fusion term at its point of use (`λ₁·ψ_n`, `λ₂·S/θ_S`, `λ₃·ε_norm`, using each beacon's actual routed λ set from its logged `khat`, ψ_th=0.09, Φ_th=0.5), over all `gt_pois=0` beacons across the three seeds:

```
honest beacons scored:                     2,330
honest beacons flagged (false positives):     30    → FPR = 1.29%

  ψ (rule) term alone > Φ_th:                 10
  GAT term alone > Φ_th:                       0
  AE term alone > Φ_th:                       10
  no single term alone > Φ_th (combination):  10
```

**GAT alone produces zero honest false positives.** The false positives split evenly between the rule term (10), the AE term (10), and cases where no single term crosses the threshold but their sum does (10). So the component most implicated in the letter's reasoning — GAT, via a suspected θ_S error — is measurably not the source, consistent with DQ1.

**Note the honest FPR requirement is already met under the specified conditions:** 1.29% at 30s/ρ_a=0.60 (per-seed FPR_full: 0.0000, 0.0400, 0.0090), all below the 0.05 bar.

**But a genuine inconsistency to flag:** at 300s/ρ_a=0.40 the same system reports FPR_full = 0.174 — well *above* 0.05. The FPR is strongly condition-dependent (duration and attacker density), so "FPR < 0.05" holds at the conditions specified for these diagnostics but does not hold universally. That should be resolved before any final-experiment claim rests on it.

---

## ROOT CAUSE FOUND — why component contributions are confined to a very narrow band

Re-ran the full D1–D6 set on the current build (18 runs, 3 seeds) after the labelling fix:

```
cfg   MCC mean          per-seed           TTD     CDER    FPR
D1    0.4169   [0.348, 0.376, 0.527]     0.755s   0.323   0.007
D2    0.1481   [0.123, 0.222, 0.099]     2.783s   0.283   0.549
D3    0.1694   [0.190, 0.097, 0.222]     6.446s   0.519   0.186
D4    0.4197   [0.353, 0.377, 0.530]     0.755s   0.319   0.007
D5    0.4169   [0.348, 0.376, 0.527]     0.755s   0.323   0.007
D6    0.4129   [0.351, 0.365, 0.523]     0.663s   0.321   0.016
```

**D5's confusion matrix is byte-identical to D1's on every seed** (2981/0/720/2512, 3980/10/490/1803, 2826/0/1110/1499). The LSTM-AE changes *zero* decisions — despite producing non-zero reconstruction error on 44.73% of beacons. That is not a calibration issue; it is structural, and the arithmetic shows why:

```
D5 effective weights (GAT off, renormalised): λ_psi = 0.6228, λ_ae = 0.3772
   AE's maximum possible contribution = λ_ae × 1.0 = 0.3772  <  Φ_th = 0.5
   → the AE can NEVER cross the threshold on its own, at any reconstruction error
   ψ alone crosses whenever ψ_n > 0.8028

ψ_n distribution over 17,931 scored beacons:
   ψ_n = 1 (saturated)   9,799   54.65%   → ψ alone already fires; AE cannot matter
   ψ_n = 0               8,102   45.18%   → ceiling is 0.377 < 0.5; AE cannot rescue
   ψ_n = intermediate       30    0.17%   → the ONLY band where AE can change anything
```

**ψ is almost perfectly bimodal — 99.83% of beacons sit at exactly 0 or exactly 1.** Combined with λ_ae and λ_gat both sitting *below* Φ_th in the two-component configs (0.377 and 0.268), the consequence is that neither component can independently trigger a detection there, and the band in which they could tip a borderline case is ~0.17% of traffic. D4 (+0.0028 over D1) and D5 (+0.0000) are exactly the scale this predicts.

**This is the fundamental answer to "why does adding components barely move MCC."** It is not that GAT or the AE lack signal — D2/D3 show they carry real signal, and DQ3 shows ghosts measurably shift S_i. It is that the fusion is configured so their vote is almost never decisive: λ_component < Φ_th makes them advisory, and a saturated bimodal ψ leaves almost no blend region for advice to act in.

**Two clarifications so this is not over-read** (both are quantified in the next section):
- In *full* mode the picture is not uniformly flat, because attack-conditioned routing raises λ_gat well above Φ_th for some classes (a3 is routed to λ_gat = 0.95). GAT therefore *does* change decisions — 57 of them, net positive. The "cannot fire alone" arithmetic above applies to the global-fallback and two-component cases, not to every routed beacon.
- So the correct statement is **not** "components cannot improve MCC" — D4 (0.4197) does beat D1 (0.4169), and the next section shows `D6 > D1` is reachable. The correct statement is that the achievable effect is confined to a fraction of a percent of decisions, which is why every configuration lands within ±0.007 of D1.

**Why simply raising λ does not work either:** pushing λ above Φ_th is exactly what the DQ5 refits attempted (λ_gat → 0.55). Held-out result: +14 TP for +150 FP, dMCC −0.284. The components' signal is real but not clean enough to be *decisive* at this operating point — a different and harder problem than miscalibration.

**Genuine options, none of them a config tweak:**
1. Lower Φ_th (and re-tune) so sub-threshold component votes become actionable — changes the global operating point for every experiment.
2. De-saturate ψ (it is currently clipped by ψ_th=0.09, driving the bimodality) so fusion has a real continuum to work with.
3. Accept the components as advisory and report per-attack-type results, where their contribution is measurable and validated.

---

## Honest position on D6 > D1 and the MCC ≥ 0.90 target

**On "D6 MCC must exceed D1 MCC — non-negotiable":** as currently deployed, D6 = 0.4129 vs D1 = 0.4169. It does not exceed it. It also is not meaningfully below it — the −0.0040 gap is ~45× smaller than the seed-to-seed spread (0.18) and D6 wins outright on one of three seeds. Reporting this as "D6 < D1" or "D6 > D1" would both be overreading n=3; the honest statement is that they are indistinguishable at this sample size. The diagnostics above show why: the components *do* add true positives (+46 in DQ2), they simply cannot add enough net signal in a blended population dominated by attack types ψ already handles. **The per-component section below shows this is fixable — down-weighting λ_ae lifts D6 above D1 — with the caveat stated there about what that does and does not demonstrate.**

**On the MCC ≥ 0.90 target — this needs a frank statement rather than an optimistic one.** Using the real 300s counts and holding false positives fixed, projecting what happens if a3 detection were fully fixed:

```
current (a3 recall 23.3%):   blended MCC = 0.466
if a3 recall → 50%:          blended MCC = 0.550
if a3 recall → 75%:          blended MCC = 0.647
if a3 recall → 90%:          blended MCC = 0.718
```

**Even with a3 detection raised to 90% — a large win we do not currently know how to achieve — blended combined-mode MCC reaches ≈0.72, not 0.90.** Closing the remaining gap would additionally require cutting the false-positive count (4,108 against 19,526 true negatives at 300s). I am not able to promise MCC ≥ 0.90 in blended combined mode on the current architecture, and I would rather say that now than after another round of fixes that land short.

By contrast, the per-attack-type results already meet a high bar: a1 83.9%, a4 97.5%, a2/a6 99.8%, honest 99.8% recall at 300s. The gap between those numbers and the blended figure is the population-mixing effect quantified above, not a defect in the detectors themselves.

---

## Per-component contribution to the full system — GAT is positive, the LSTM-AE is negative

Decision-level attribution (stronger than MCC deltas): for every scored beacon in D6, recompute the verdict with each component's term removed and its weight renormalised away, and count how many decisions flip and in which direction. 17,931 beacons, current build, 3 seeds.

```
GAT — decisions that change if the GAT term is removed:
    +47 TP gained      +10 FP added          → NET POSITIVE  (4.7 : 1)
      0 TP lost          0 FP avoided

LSTM-AE — decisions that change if the AE term is removed:
    +14 TP gained      +20 FP added          → NET NEGATIVE
     33 TP LOST          0 FP avoided
```

**GAT earns its place: 47 true positives for 10 false positives.** The LSTM-AE does not — it buys 14 true positives while adding 20 false positives *and* destroying 33 true positives. The 33 lost detections are the important number: they are not AE errors as such, they are the *dilution* cost. Because λ weights are renormalised to sum to 1, giving the AE weight necessarily takes weight from ψ and GAT, dropping borderline-but-correct detections back below Φ_th.

This is precisely the ordering we measure: **D4 (signatures + GAT) = 0.4197 is the best configuration of all six**, above D1 = 0.4169; adding the AE on top drags it down to D6 = 0.4129.

**Offline sweep of the AE weight** (indicative — the offline recompute does not replicate every in-sim path, e.g. the hard speed-bound override, so it needs in-sim confirmation):
```
λ_ae scale    MCC       TP     FP     TN     FN
   ×0.00     0.4239   9852     10   2320   5749    ← AE off — best
   ×0.25     0.4217   9866     20   2310   5735
   ×0.50     0.4189   9866     30   2300   5735
   ×1.00     0.4173   9833     30   2300   5768    ← current
   ×1.50     0.3876   9629    100   2230   5972
```
Monotonic — every reduction in AE influence improves MCC.

**So `D6 > D1` IS achievable, and here is the honest caveat.** At λ_ae × 0.25 or below, D6 exceeds D1. But it does so by reducing the LSTM-AE's contribution to approximately nothing. That satisfies the letter of the "adding components must improve MCC" requirement while conceding its intent: GAT genuinely improves the system, the LSTM-AE currently does not, and the way to make the full system beat signatures-alone is to stop letting the AE dilute the other two terms. I would rather present it that way than ship a passing number without the explanation.

**Recommended, pending your decision:** recalibrate λ_ae downward for combined mode (a Phase 2 action, properly held-out validated) rather than either leaving it as-is or deleting the component. The AE demonstrably carries signal in isolation (D3 = 0.169 ≫ 0, and it is validated on a1 stealth drift with dMCC +0.0663) — it is the *weight* in the blended context that is wrong, not the model.

---

## Required post-DQ report — (a), (b), (c) at your specified conditions

All at 30s, ρ_a=0.60, combined attack, urban, N_Vehicles=200, N_RSUs=64, 3 seeds, current build with every fix applied.

**(a) D6 MCC vs D1 MCC — DOES NOT PASS.**
```
D1 = 0.4169   [0.348, 0.376, 0.527]
D6 = 0.4129   [0.351, 0.365, 0.523]
D6 - D1 = -0.0040        (D6 wins on seed 1, loses on seeds 2 and 3)
```
Stated plainly: the non-negotiable criterion is not met. The root-cause section above explains why it *cannot* be met by calibration at the current Φ_th — λ_ae (0.377) and λ_gat (0.268) both sit below Φ_th=0.5, so neither component can ever be decisive, and ψ is bimodal (99.83% at exactly 0 or 1) leaving a 0.17% band in which they could tip a borderline case. Both prescribed remedies were implemented and measured; both made held-out performance worse. This needs an architectural decision (Φ_th, ψ saturation, or scope), not another calibration pass.

**(b) Per-attack-type recall:**
```
a1: TP=  426  FN=  384   recall = 0.526
a2: TP=  671  FN=   28   recall = 0.960
a3: TP= 1324  FN= 5318   recall = 0.199   ← the outlier
a4: TP= 5892  FN=   38   recall = 0.994
a6: TP= 1520  FN=    0   recall = 1.000
```
(a2/a6 are visible for the first time here — the attack-type labelling fix described under DQ5 was required to separate them from the honest bucket. a5/a7 are controller-plane attacks and do not surface in the RSU beacon-window path at all; that is a separate gap, noted not hidden.)

**(c) Honest-vehicle FPR — PASSES.**
```
FP=30, TN=2300  →  FPR = 0.0129   (requirement: < 0.05)
```
Per-seed FPR_full: 0.0000, 0.0400, 0.0090. **Caveat:** this passes at the conditions you specified, but at 300s/ρ_a=0.40 the same system gives FPR_full = 0.174. The FPR is strongly condition-dependent, so "FPR < 0.05" should not be treated as an unconditional property.

**On your closing instruction** — *"If D6 still does not exceed D1 after fixing DQ1 and DQ4, there is a deeper wiring bug and we will investigate further."* DQ1 and DQ4 both came back negative (nothing to fix: θ_S is correct at 19.74 in the fallback path, training data is 0.0000% contaminated). D6 still does not exceed D1. Per your own criterion this points to something deeper — and the root-cause section identifies it, with the caveat that it is not a wiring bug but a threshold/weight architecture property: components weighted below the decision threshold cannot change decisions. I would rather hand you that finding than keep searching for a wiring defect the measurements do not support.

---

## What I recommend doing next, in order

1. ~~**Fix DQ5 — the one confirmed defect.**~~ **Done and rejected — see DQ5 above.** The prescribed rebalance-and-recalibrate was implemented (including the prerequisite attack-type labelling fix) and tested on a held-out seed. Both the class-balanced refit (dMCC −0.284) and an unbalanced control (dMCC −0.107) performed *worse* than the deployed weights. Nothing deployed. The measured reason — the fallback path runs at FPR 0.000 and cannot be made more aggressive without adding false positives faster than true positives — is itself the explanation for D6 ≈ D1, and it is not fixable by reweighting.
2. **Close the DQ4 provenance gap.** Establish which pipeline produced the deployed window=50 AE and confirm its training data, so contamination can be ruled in or out definitively rather than inferred.
3. **Resolve the FPR condition-dependence** (1.29% at 30s/ρ_a=0.60 vs 17.4% at 300s/ρ_a=0.40) before any acceptance criterion rests on the FPR figure.
4. **Then re-run D1/D6** and report (a) the D6-vs-D1 comparison with enough seeds to distinguish signal from noise — n=3 is not sufficient given the 0.18 spread observed, I would suggest 10 — (b) per-attack recall for a1/a3/a4, (c) honest FPR at both condition sets.
5. **Separately, decide on the target.** If MCC ≥ 0.90 is required specifically in blended combined mode, the projection above suggests the current architecture will not reach it even with a3 solved, and that is worth discussing before more engineering effort is spent against that number.
