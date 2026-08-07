# Response — DQ-VAR-POST1 to POST5 (post-Fix-2 per-variant analysis)
**Date:** 2026-08-06 · **Branch:** `ml-review-fixes`
**Source:** Fix-2-applied 300 s D6 run, ρ_a = 0.40, seed 1, `ablation_mode=0`

All five diagnostics below are extracted from the completed Fix-2 300 s run — no
new simulations were required.

**Headline:** your arithmetic is correct — **0.84 is reachable if ghost recall
reaches 1.0**. But ghost recall after Fix 2 is **0.3479, not ~1.0**, and §2
explains why the 1.0000 figure does not transfer. Fix 2 has **no wiring gap**;
routing is 100 % correct. The remaining gap requires GAT retraining, not a patch.

---

## 1. DQ-VAR-POST3 — ghost routing after Fix 2 (answered first: it is not a wiring gap)

```
ghost beacons              20 795
routed to k̂ = 2           20 795   (100.0 %)
routed to fallback              0   (0.0 %)
recall                     0.3479   (7 234 / 20 795)
mean Φ                     0.4890
detections via Φ > 0.5      7 231
detections via OR-flag          3
```

**Fix 2's routing is perfect — every ghost reaches the a3 weight set.** Recall
nonetheless remains 0.3479, because routing selects the λ weights; it does not
by itself constitute a detection. The beacon must still cross Φ > 0.5.

---

## 2. Why ghost recall did not approach 1.0 — the DQ-G1 figure does not transfer

Your expectation rests on DQ-G1, where ghosts reaching k̂ = 2 showed recall
1.0000. Two properties of that measurement prevent it generalising:

**It was a self-selected population.** Those 1 105 ghosts were routed to a3 by
the ML classifier *on its own*, i.e. precisely the ghosts the model already found
distinctive. Forcing the other 19 690 into the same slot does not confer the
property that got the first group there.

**And that cohort was detected by the OR-flag, not by fusion.** DQ-G2 recorded
the split. The OR-flag at `08_detection_engine.h:2288` fires on `k̂` **without
requiring the GAT to have scored**:

```c
if (g_gat_det_flag_heads != 0u && k_hat_i >= 0 && k_hat_i < 32 &&
    (g_gat_det_flag_heads & (1u << (uint32_t)k_hat_i)) != 0u)
    full_flag = true;
```

`g_gat_det_flag_heads = 46` includes bit 2. So `k̂ = 2` set from the vehicle ID
forces `full_flag = true` on identity alone.

**We implemented your prescription verbatim and it reproduced your predicted
number exactly:**

```
ghost recall 1.0000 in ALL THREE ARMS — including D1
D1: 2 619 ghost detections — 0 via Φ>0.5, 2 619 (100 %) via the OR-flag bypass
```

D1 has no GAT and previously detected **zero** ghosts. Its MCC rose to 0.8610 and
**the ablation ordering inverted** (D1 0.8610 > D4 0.8377 > D6 0.8252).

`vid >= GHOST_VID_BASE` is an artifact of the attack generator
(`GHOST_VID_BASE + rsu_idx*100 + vid*10 + gi`); a real Sybil adversary would
forge plausible IDs. Detecting on it is reading the ground-truth label. **We did
not ship it.** The deployed version applies `k̂ = 2` for weighting but tags it
`khat_from_ghost_id` and excludes it from the OR-flag bypass, so detection must
come from Φ. That is why recall is 0.3479 and why only 3 of 7 234 detections come
via the bypass.

Had we shipped it verbatim, we would be reporting MCC ≈ 0.83–0.86 — matching your
target — on a result that would not survive review.

---

## 3. DQ-VAR-POST1 — per-variant breakdown after Fix 2

| variant | beacons | recall | TP | FN | % of all FN |
|---|---|---|---|---|---|
| **MP-S1** | 25 856 | **0.4670** | 12 074 | **13 782** | **81.2 %** |
| **TP-S1** | 23 858 | 0.8849 | 21 111 | 2 747 | 16.2 % |
| MP-S2 | 32 653 | 0.9871 | 32 233 | 420 | 2.5 % |
| TP-S2 | 6 827 | 0.9979 | 6 813 | 14 | 0.1 % |
| MP-S3 | 2 795 | **1.0000** | 2 795 | 0 | 0.0 % |

**MP-S1 split:** ghost **0.3479** (7 234 / 20 795) · real-vehicle **0.9563**
(4 840 / 5 061).

Honest beacons 23 676 · total FP 5 090 · FPR 0.2150.

**Three of five variants are effectively solved** (0.987–1.000). The FN budget is
**97.4 % MP-S1 + TP-S1**, and MP-S1 is **95 % ghosts**.

### Per-variant FP and precision (completing POST1)

False positives land on honest beacons, which carry no attack label, so a
variant's FPs must be **attributed**. We attribute each FP to every variant that
was actively forging **at the same RSU within the same 10 s window**:

| variant | FPs attributed | % of 5 090 | **precision** TP/(TP+FP) |
|---|---|---|---|
| TP-S2 | 1 785 | 35.1 % | 0.7924 |
| MP-S2 | 1 080 | 21.2 % | 0.9676 |
| MP-S3 | 840 | 16.5 % | 0.7689 |
| **TP-S1** | **0** | 0.0 % | 1.0000 |
| **MP-S1** | **0** | 0.0 % | 1.0000 |
| *no variant active at that RSU/window* | 1 942 | 38.2 % | — |

---

## 3b. DQ-VAR-POST2 — which variant's presence contaminates honest vehicles

The table above is the POST2 answer. Two results are worth stating explicitly,
and they revise the working assumption.

**MP-S1 contributes ZERO false positives.** This is structural, not marginal:
ghosts are generated at RSUs **28, 10, 46, 32**, and those four RSUs host **no
false positives at all**. The FP-hosting RSUs are 36 (1 811), 43 (1 298),
20 (864), 44 (752). The sets are disjoint. **Fix 2 therefore cannot have
introduced FPs, and MP-S1 is not a contamination source.**

**TP-S1 also contributes zero** attributable FPs under this measure.

**MP-S2 is not the largest FP contributor after Fix 2.** By raw count TP-S2
(1 785) exceeds MP-S2 (1 080). However **MP-S2 has by far the highest precision
(0.9676 vs 0.7924)**, i.e. relative to how much it is detected it generates the
fewest FPs. The earlier conclusion that MP-S2 is "the primary culprit" holds for
the *mechanism* (pre-arrival identity contamination of specific victims) but not
for the raw FP count.

**Caveat we state rather than gloss:** this attribution is **co-location, not
causation**. A variant active at the same RSU in the same window is associated
with the FP, not proven to have caused it, and a single FP can be attributed to
more than one variant. **38.2 % of FPs (1 942) had no variant active at their RSU
and window at all** — those cannot be attributed to any variant by this method,
and are consistent with the *residual* contamination mechanism (state poisoned
earlier, expressed later) rather than concurrent forging.

---

## 3c. DQ-VAR-POST4 — the six FP-concentrated vehicles

Variants active at the RSU processing each vehicle's beacons at the time of its
false positives:

| vid | variants active during its FPs |
|---|---|
| 98 | MP-S3: 272 |
| 196 | **TP-S2: 595**, MP-S2: 113 |
| 191 | MP-S3: 85, MP-S2: 82 |
| 195 | MP-S2: 201, MP-S3: 87 |
| 202 | **MP-S2: 449**, MP-S3: 198 |
| 129 | **TP-S2: 461**, MP-S2: 13 |

**Answering your question directly: the FP generator is NOT exclusively MP-S2.**
Every one of the six has multiple variants active during its false positives, and
for vid 196 and vid 129 the dominant co-active variant is **TP-S2**, not MP-S2.
vid 98 shows only MP-S3 co-active.

This is consistent with the §3b caveat: much of the contamination is **residual**
— `vehicle_state` poisoned earlier by MP-S2 pre-arrival forging, then expressed
as false positives later, when a *different* variant happens to be active at that
RSU. Co-location at the moment of the FP therefore identifies what is happening
concurrently, not necessarily what caused the contamination.

**Neither MP-S1 nor TP-S1 appears for any of the six.**

---

## 4. DQ-VAR-POST5 — algebraic scenarios (your arithmetic, confirmed)

| scenario | recall | FPR | **MCC** |
|---|---|---|---|
| current (Fix 2 applied) | 0.8156 | 0.2150 | **0.5252** |
| **(a)** ghost recall = 1.0 | 0.9630 | 0.2150 | **0.7692** |
| **(b)** (a) + top-6 FPs removed (3 758) | 0.9630 | 0.0563 | **0.8795** |

**Your reasoning is arithmetically sound: (b) exceeds the 0.84 target.** The
entire question is whether ghost recall can reach 1.0.

---

## 5. Why ghost recall cannot reach 1.0 by routing or thresholds

The ghost Φ distribution is **bimodal, not marginal**:

| Φ band | ghosts | share |
|---|---|---|
| < 0.30 | 6 752 | **32.5 %** |
| 0.30 – 0.40 | 4 579 | 22.0 % |
| 0.40 – 0.45 | 1 374 | 6.6 % |
| **0.45 – 0.50** | 856 | **4.1 %** |
| 0.50 – 0.55 | 1 191 | 5.7 % |
| 0.55 – 0.70 | 1 165 | 5.6 % |
| > 0.70 | 4 878 | 23.5 % |

**54.5 % of ghosts sit below Φ = 0.40.** Only **4.1 %** are within reach of a
small score or threshold change. The mean of 0.4890 is the average of two
clusters and is misleading on its own.

These ghosts are not narrowly missed — **the GAT produces genuinely little signal
for more than half of them.** Reaching recall 1.0 requires a better model on
ghosts, not better routing. Routing is already 100 % correct (§1).

---

## 6. Approaches we tested and rejected, with measurements

| approach | result | why |
|---|---|---|
| **LSTM-AE extended to ghosts** | **no effect** (ghost recall 0.5013 → 0.5014) | mean `ae_norm` = **0.0105**. Each ghost tracks its victim at a fixed 135 m offset, so its own trajectory is smooth and its dead-reckoning residual is near zero. The ghost anomaly is *positional*, which is the GAT's domain, not the AE's. |
| **HMAC fail-closed (Eq 3.37)** | **no effect** (bit-identical) | the attacks stamp **valid** MACs using the victim's key — `lkh_compute_beacon_hmac(victim_v_idx, …)` at `09:406` (Sybil) and `:604` (MitM). Authentication cannot prevent this contamination by construction. |
| **Identity binding (Fix 1)** | **−0.095 MCC**, twice | ~40 % of its rejections carry `gt_pois = 0`. Blocking those writes starves detection of history; recall falls further than FPR improves. Re-implemented with the address read from each vehicle's own `Ipv4` object — **byte-identical rejections**, confirming the lookup was never the defect. |
| **AE-dominant rule (ae > 0.90)** | +0.011 MCC, **+0.038 FPR** | adds 2 407 TPs and 707 FPs. 89.3 % of those new FPs fall on the six contaminated vehicles. |

**Five approaches attempted after Fix 2; four produced no gain, one was
harmful.** We report this as evidence that the remaining gap is not reachable by
patching.

---

## 7. What we are proposing — we are not asking to stop

**Fix 2 delivered**, at the duration you mandated:

| arm | pre-fix | **post-Fix-2** |
|---|---|---|
| D1 | 0.4794 | **0.4794** (unchanged — no GAT, correctly untouched) |
| D4 | 0.4783 | **0.5185** |
| **D6** | 0.4855 | **0.5252** |

**D6 > D4 > D1 at 300 s**, restored from the pre-fix failure (D6 > D1 > D4, margin
−0.0011). FPR is byte-identical to pre-fix at every cutoff — Fix 2 is a clean
gain. Peak MCC 0.6621 at t ≈ 140–160 s with FPR 0.056–0.061.

**The remaining gap requires GAT retraining with ghosts in the training corpus.**
This is supported by the evidence rather than assumed:

- ghosts are a **spatial-relational** anomaly — four fabricated identities in a
  135 m ring around one vehicle, at one RSU
- that is the GAT's domain, and it already yields median S/θ_S = 0.392 on ghosts
  **without ever being trained on them**
- the AE cannot help (§6) and routing is already exhausted (§1)

**This is model work, not a patch** — we estimate a day plus training-data
generation, and it carries the usual retraining risk of regressing other
variants, so it would need its own verification.

**The decision we need from you:** is GAT retraining in scope given the
submission deadline? If it is, we will proceed and report per-variant results
before and after. If it is not, we would report the Fix-2 result with the ghost
ceiling documented and the retraining identified as the specified next step.

We are not proposing to stop at 0.66 as a final answer. We are asking which of
those two you want, because the remaining work is a model retrain rather than
something we can patch in the time available.
