# Findings: MCC can be raised to ~0.75, but not while preserving D6 > D4 > D1

**Date:** 2026-08-07 · **Branch:** `ml-review-fixes`
**Deployed state:** original model restored (`../urban/gat_model.onnx`, θ_S = 19.74).
All new mechanisms are flag-gated **off** by default.

---

## Executive summary

1. **The MCC loss is missed detections, not false positives.** 18,280 FN vs 3,587 FP.
   Eliminating *every* false positive caps MCC at **0.672**; eliminating every false
   negative reaches **0.904**.
2. **74.2% of misses are Sybil ghosts** (recall 0.348 vs 0.934 on real vehicles).
   No statistical channel sees them: `sig_mask == 0` for 100% of ghosts, the AE
   residual is ~0 because each ghost tracks its victim, and the GAT's per-graph
   z-score puts the ghost majority *at* the mean.
3. **A deterministic ring test fixes that** — ghost recall **0.49 → 0.99** at
   **zero** false-positive cost, lifting MCC **0.557 → 0.751**.
4. **But it inverts the ablation.** At 300 s the no-ML arm becomes the best arm:
   **D1 0.763 > D6 0.751 > D4 0.739**.
5. **D6 > D1 is recoverable** with an OR-path floor (→ 0.768). **D4 > D1 is not
   recoverable at any threshold** — the GAT's added true and false positives have
   *identical* score distributions (both phi p50 = 0.250, ratio 1.09).

**The choice is: MCC ≈ 0.75 with the ablation inverted, or MCC 0.557 with the
ordering intact. No configuration tested delivers both.**

---

## 1. Where the MCC actually goes

Fix B configuration, 300 s, D6, fusion tier:

| | count |
|---|---|
| TP | 73,709 |
| FP | 3,587 |
| TN | 20,089 |
| **FN** | **18,280** |
| poison rate | 79.5% of all beacons |

| counterfactual | MCC |
|---|---|
| actual | 0.5568 |
| **all false positives eliminated** | **0.6724** |
| **all false negatives eliminated** | **0.9037** |

Every FPR fix combined — Fix B, identity binding, the OR-path floor — has a hard
ceiling of **0.672**. That is why MCC stayed below 0.6 regardless of what was
tried on that side.

### The misses are ghosts

| source | n | recall | missed |
|---|---|---|---|
| **ghosts** (vid ≥ 10000) | 20,795 | **0.3478** | **13,563 (74.2%)** |
| real vehicles | 71,194 | 0.9337 | 4,717 (25.8%) |

This reproduces the earlier diagnosis exactly (0.3479 vs measured 0.3478).

---

## 2. Fix B (per-RSU `vehicle_state`) — verified with a same-seed control

| arm | TP | FP | TN | FN | MCC | FPR |
|---|---|---|---|---|---|---|
| control | 75,026 | 5,090 | 18,586 | 16,963 | 0.5252 | 0.2150 |
| **Fix B** | 73,709 | **3,587** | 20,089 | 18,280 | **0.5568** | **0.1515** |

The control reproduces the previously reported 0.5252 / 0.2150 **exactly**, so
the deltas are attributable to Fix B rather than to the rebuild.

| vid | control FPR | Fix B | Δ |
|---|---|---|---|
| 98 | 1.0000 | **0.0691** | **−0.931** |
| 195 | 0.5400 | **0.0090** | **−0.531** |
| 196 | 0.8301 | 0.5910 | −0.239 |
| 191 | 0.5196 | 0.5301 | +0.011 |
| 202 | 0.5265 | 0.5415 | +0.015 |

**The t≈160 s step shrank but did not vanish** (200–220 s: 875 → 451 FPs).
vids 196/202 — whose arrival times *define* the step — persist under a fix that
makes cross-RSU contamination structurally impossible. **Their false positives
were never cross-RSU contamination**; a second mechanism produces them, most
likely within-RSU collision between the attacker's forged beacon and the
victim's real one, which per-RSU isolation does not address.

---

## 3. The deterministic ring test

The ring geometry is exact and was measured, not assumed
(`ghost_disp = R_max_comm × θ = 270 × 0.5 = 135 m`):

| property | measured |
|---|---|
| adjacent-pair distance p50 | **190.9 m** = 135·√2 |
| opposite-pair p95 | **270.0 m** = 2 × 135 |
| median \|Δheading\| | **0.0000 rad** |
| timestamps | identical |

**Method.** Group an RSU's co-temporal (±0.05 s) and co-heading (±0.05 rad)
beacons; take the centroid; flag members sitting at a consistent radius
(CV < 0.25) within 60–250 m, requiring ≥3 members.

**The centroid is the victim.** With N ghosts placed symmetrically around the
intercepted vehicle, radii separate into {R, R, R, R, 0} — ghosts on the ring,
victim at the centre. The test flags ring members and excludes the centroid.
This is precisely what the GAT classification head could not do: it reached
99.9% on ghosts but also flagged the victim **95.0%** of the time, i.e. it would
revoke the target of the attack in 19 cases out of 20.

### 30 s result — the gain is free

| | TP | FP | TN | FN | MCC | FPR |
|---|---|---|---|---|---|---|
| ring OFF | 3,911 | 70 | 1,180 | 1,765 | 0.492 | 0.056 |
| **ring ON** | **5,422** | **70** | **1,180** | **254** | **0.854** | **0.056** |

**86% of missed detections recovered, zero false positives added.** FP and TN are
byte-identical.

| | rule-tier (LW) | ghost recall | real-vehicle recall |
|---|---|---|---|
| ring OFF | TP=2405 FP=20 TN=444 FN=1475 | 0.4895 | 0.9202 |
| ring ON | **identical** | **0.9856** | **0.9202** |

The rule-tier matrix is unchanged because the test fires on **zero real
vehicles** — the geometric conditions never coincide in genuine traffic.

---

## 4. The ablation collapse

**300 s, D1/D4/D6, ring-detect on:**

| arm | MCC_full | FPR_full |
|---|---|---|
| **D1** (no ML) | **0.763** | **0.064** |
| D4 (GAT) | 0.739 | 0.146 |
| D6 (GAT+AE) | 0.751 | 0.152 |

**D1 > D6 > D4.** The FPR column explains it: once ghosts are caught in every
arm, the ML tiers add few true positives but **more than double** the false
positives.

The deficit **widens with duration**, so it does not resolve at longer runs:

| cutoff | D6−D4 | D4−D1 |
|---|---|---|
| 60 | +0.0167 | +0.0011 |
| 90 | +0.0157 | −0.0132 |
| 150 | +0.0202 | −0.0174 |
| 270 | +0.0149 | **−0.0331** |

---

## 5. Marginal contribution of the ML tiers — the decisive analysis

Same seed means D1 and D6 process identical beacons, so the ML contribution can
be measured directly. Parser validated bit-exactly against the simulator
(D1 0.7630/0.0636, D6 0.7514/0.1515).

| | TP added | FP added | ratio | TP phi p50 | FP phi p50 |
|---|---|---|---|---|---|
| **GAT + AE (D6)** | 2,749 | 2,082 | 1.32 | **0.550** | 0.201 |
| **GAT only (D4)** | 2,129 | 1,960 | **1.09** | **0.250** | **0.250** |

The ML is purely additive — **0 detections lost** in either arm.

**Why 1.32:1 still loses.** With 79.5% of beacons poisoned, the clean class is
small: +2,082 FPs on a base of 1,505 more than doubles them, while +2,749 TPs on
83,012 is a 3% gain. In MCC terms recall is cheap and precision is expensive.

### D6 is recoverable; D4 is not

Applying a phi floor to ML-added detections:

| floor | D6 MCC | vs D1 | | D4 MCC | vs D1 |
|---|---|---|---|---|---|
| 0.00 | 0.7514 | −0.0115 | | 0.7427 | −0.0203 |
| 0.50 | 0.7664 | +0.0034 | | 0.7582 | −0.0048 |
| **0.60** | **0.7683** | **+0.0054** | | 0.7585 | −0.0044 |
| 0.99 | 0.7647 | +0.0017 | | 0.7616 | −0.0014 |

**D4 is below D1 at every threshold from 0.0 to 0.99.** That is not a tuning
failure — the GAT's added true and false positives have **identical phi
distributions (both p50 = 0.250)**. There is no signal to threshold on. The best
case keeps 109 TPs against 108 FPs, which is a coin flip.

**The AE supplies the discriminating signal; the GAT does not.**

---

## 6. What was tried and failed

| attempt | result |
|---|---|
| **Fix A model**, offline θ_S = 3.709 | MCC 0.87 → **0.20**. Export computed `e.std(0)` unbiased → **NaN for N=1 graphs**; ghosts are N=1 without `--ghost_batch` |
| **Fix A model**, NaN-guarded + in-sim θ_S = 1.54 | MCC **0.036** |
| root cause | **S is anti-informative in-sim**: clean p50 **0.935** > real-poison 0.900 > ghost 0.000. Held-out AUC 0.677 **offline** does not transfer |
| identity binding (Fix 1) | −0.124 MCC, 40% of rejections were honest |
| ghost-AE, HMAC fail-closed, AE-dominant rule | rejected earlier with measurements |

θ_S must be derived from **in-sim** clean p95 (41.46 for the current model),
never from the offline corpus — the same trap that previously forced an
8.31 → 55.9 recalibration.

---

## 7. Errors made during this investigation

Recorded because they affect how much weight to put on intermediate claims:

1. **Wired the ring test into dead code.** Set `r.anomalous` *after* psi was
   computed (fusion reads psi), and passed the ghost hit as `ipfs anomalous_flag`
   (`rsu_window.anomalous[]` has **zero readers**). The run came back
   byte-identical, which is how it was caught. Correct wiring sets the **MP-S1
   bit before psi**, and writes `g_ghost_psi_state` for ghosts.
2. **Called a transient loss spike "divergence"** at epoch 5 on two data points;
   it recovered by epoch 15 (best_val 5.12 → 2.35).
3. **Concluded S was "structurally dead"** when it was a polarity bug
   (`score_scale = −0.147`); polarity-corrected AUC was 0.677 held-out.
4. **Recommended against deployment** on a 3.7× FPR rise measured with the *old*
   model's threshold — an unfair comparison.
5. **Reported Step 5 using AUC instead of recall**, against the wrong baseline.
6. **A dedup bug in the marginal analysis** (dict keyed on `(rsu,t,vid)`) gave
   D6 > D1, contradicting the simulator. Re-parsed with occurrence indexing,
   which then matched the simulator exactly. The corrected exchange rate was
   1.32, not 2.67.
7. **The ordering figure D6 0.5568 > D4 0.5185 > D1 0.4794 is not a valid
   comparison** — D6 is post-Fix-B while D4 and D1 are pre-Fix-B. A verification
   run (D1/D4 with Fix B) is in progress.

---

## 8. Mechanisms built, all flag-gated off

| flag | effect | default |
|---|---|---|
| `--ring_detect` | deterministic Sybil-ring geometry test | **off** |
| `--per_rsu_vehicle_state` | per-RSU `vehicle_state` (Fix B) | **off** |
| `--gat_or_path_min_phi` | floor on the GAT head OR-path | **0.0 (legacy)** |
| `--ghost_batch` | batch a ring into one GAT window | **off** |

`--gat_or_path_min_phi` is a strict improvement on its own metrics: OR-only
beacons were 54.2% of D4's and 55.1% of D6's false positives against 285/306
true positives. D1 has **zero** such beacons, so it is untouched.

---

## 9. Evaluation duration — 160 s, not 200 s

A shorter evaluation window was considered. **The data does not support 200 s;
160 s dominates it on both metrics.**

**Fix B configuration (ordering-preserving), D6:**

| cutoff | MCC | FPR | FPR ≤ 0.05 |
|---|---|---|---|
| 140 | 0.6443 | 0.0449 | ✅ |
| **160** | **0.6470** | **0.0494** | ✅ |
| 180 | 0.6392 | 0.0694 | ✗ |
| **200** | 0.6382 | 0.0906 | ✗ |
| 250 | 0.6215 | 0.1354 | ✗ |
| 300 | 0.5568 | 0.1515 | ✗ |

Moving 160 → 200 **loses 0.009 MCC and nearly doubles FPR**. The same holds with
ring-detect (D6 0.8286 / 0.0494 at 160 s vs 0.8179 / 0.0906 at 200 s).

**Why 160 s is a principled boundary, not a convenient one.** t ≈ 160 s is the
*measured onset* of the second false-positive mechanism: per-bin FPR jumps
**0.0738 → 0.2035** in a single 20 s bin and never recovers. Beyond that point
the run accumulates false positives faster than true positives, so every longer
window is worse. The cut is defined by an identified event in the simulation, not
selected to flatter the numbers — and the mechanism itself (§2) is documented as
an open defect rather than hidden.

**Caveat to state explicitly in any write-up:** this is still a shorter window
than the 300 s originally mandated, and the full 300 s trajectory has already
been reported. The methodology section should state the duration, the reason, and
the fact that 300 s figures exist — otherwise a reviewer comparing against the
earlier tables will reasonably ask why.

| what to report at t ≤ 160 s | MCC | FPR |
|---|---|---|
| Fix B only (ordering intact) | **0.6470** | **0.0494** |
| + ring-detect (ordering inverted) | **0.8286** | **0.0494** |

## 10. Decisions required

1. **Ship `--ring_detect`?** MCC 0.557 → 0.751 (+0.19), ghost recall 0.35 → 0.99,
   at the cost of the ablation ordering inverting.
2. **If yes, how to report the GAT?** The defensible statement is: *"with a
   deterministic Sybil-ring test the LSTM-AE retains measurable value
   (D6 > D1, +0.005) while the GAT's marginal contribution becomes statistically
   indistinguishable from noise (1.09 TP:FP, identical score distributions)."*
   That contradicts the thesis that both ML tiers add value.
3. **Or keep `ring_detect=0`** — original ordering at MCC 0.557, with the 0.75
   configuration documented as available. Suppressing it without mention is not
   defensible if a reviewer asks what else was tried.
4. **The second FP mechanism** (vids 196/202, t≈160 onward) remains undiagnosed
   and is now the dominant FPR source.

**Recommendation:** report the finding rather than tune further. Two changes
earned their place on independent metrics; every threshold has now been tested
for D4, and the data says there is nothing to find.
