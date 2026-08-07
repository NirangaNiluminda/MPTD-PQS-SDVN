# Update — DQ-ORDER answers, root cause of D4 < D1, and a correction

**Date:** 2026-08-07 14:16 · Branch `ml-review-fixes` · seed=1, attack_number=0, ρ_a=0.40
**Deployed model unchanged** (`../urban/gat_model.onnx`, θ_S = 19.74). Every new
mechanism is flag-gated and defaults OFF.

**Headline:** your three diagnostics ruled out **both** of the fixes you had
pre-specified — but they led to the actual root cause, which was neither false
positives nor the OR-flag. **D4 was losing 158 true positives that D1 catches**,
because only a GAT-bearing arm derives k̂ and the k̂=4 weight set erases those
beacons' rule evidence.

A fix (`--psi_cond_floor`) is implemented and measured. It moves the point at
which the ordering fails from **t≈90 to t≈240** — D1 < D4 < D6 now holds across
six consecutive cutoffs (60–210) where every earlier configuration inverted at 90.
**It does not hold to 300 s**: at cutoff 240 D4 − D1 = −0.0041. We are stating
this plainly rather than quoting the 210 s cutoff, since selecting the window
where a result holds is the post-hoc choice you ruled out.

**Status against your two requirements:** the ordering is substantially repaired
but not yet met at full duration, and MCC at 300 s will land near 0.75–0.77 —
short of 0.85. §7 sets out what remains, and the false-positive ceiling (0.8591)
is where the remaining headroom is.

---

## 1. Your three diagnostics — answered

### DQ-ORDER1 — MCC on NON-GHOST beacons only (ring_detect ON, 300 s)

| arm | TP | FP | TN | FN | **MCC (non-ghost)** |
|---|---|---|---|---|---|
| D1 | 64,327 | 1,505 | 22,171 | 6,867 | **0.7888** |
| D4 | 65,915 | 3,465 | 20,211 | 5,279 | **0.7610** |
| D6 | 66,707 | 3,587 | 20,089 | 4,487 | **0.7759** |

**Answer: NO — D1 < D4 < D6 does not hold on non-ghost beacons.**
D4 − D1 = **−0.0277**, which is *wider* than on the full population (−0.0203).

**This rejects the hypothesis.** The inversion is not caused by ring_detect
making ghost detection identical across arms. Reporting ghost detection
separately would therefore **not** restore the ordering.

Note D4 does beat D1 on *recall* here (FN 5,279 vs 6,867). It loses on
precision (FP 3,465 vs 1,505).

### DQ-ORDER2 — D4's GAT-added detections: ghost vs real

| | ghost | real |
|---|---|---|
| added TP (2,129) | 375 | 1,754 |
| **added FP (1,960)** | **0** | **1,960** |

**Answer: 100% of D4's added false positives are on real, honest vehicles.**
Zero are on ghosts. By your framing, the GAT is misfiring on legitimate traffic —
this is not victim-contamination cost being charged to the GAT arm.

### DQ-ORDER3 — 160 s, ring ON, OR-flag fully disabled (`gat_det_flag_heads=0`)

| arm | MCC_full | FPR_full |
|---|---|---|
| D1 | **0.824** | 0.009 |
| D4 | **0.820** | 0.019 |
| D6 | **0.841** | 0.019 |

**Answer: D4 remains below D1 (−0.004).** Removing the OR-flag entirely does not
restore the ordering, so the second pre-specified fix also fails.

---

## 2. The actual root cause

Because both prescribed fixes failed, we measured D4's decisions against D1's on
identical beacons (same seed). The result was the opposite of what the FPR
figures suggested:

| D4 vs D1 (160 s) | count |
|---|---|
| TP gained | +224 |
| FP added | +89 |
| **TRUE POSITIVES LOST** | **−158** |
| FP avoided | 0 |

**D4 is below D1 because enabling the GAT loses detections, not because it adds
false positives.**

For those 158 lost true positives:

| | D1 | D4 |
|---|---|---|
| `psi_fuse` | 0.1770 | **0.0020** |
| `phi` | 1.0000 | **0.3480** |
| `k̂` | — (none) | **4 — for 155 of 158** |

### Mechanism

`08_detection_engine.h:2390`:

```c
const float *w = (k_hat_i >= 0 && k_hat_i < K_ATTACK)
                 ? g_fusion.sig_w_k[k_hat_i]     // attack-conditioned
                 : g_fusion.sig_w_global;        // global
```

Only a GAT-bearing arm produces k̂, so only D4/D6 take the conditioned branch.
The k̂=4 signature-weight set assigns ~zero weight to the bits these beacons
actually carry:

```
attack 4 : [0.0045, 0, 0, 0,      .3275, .2836, .3844, 0, 0    ]
global   : [0.0976, 0, 0, .1685,  .2018, .2214, .2310, 0, .0797]
```

Bit 0 falls 0.0976 → 0.0045 (22×) and bits 3 and 8 go to zero. ψ therefore
collapses 0.177 → 0.002, φ falls to 0.348, and the detection is lost — purely as
a consequence of enabling the GAT.

`fusion_weights.json` already documents this slot as a misrouting sink:
*"head 3 (a4 slot) is where a3 beacons are misrouted."* So k̂=4 is where
mis-classified beacons accumulate, and the weight set there discards their
evidence.

### Fix — `--psi_cond_floor`

Attack-conditioning may **raise** ψ but never lower it below the unconditioned
baseline: `psi_fuse = max(psi_conditioned, psi_global)`.

- keeps conditioning's benefit where routing is correct
- removes its ability to erase evidence on a misroute
- **D1 is provably unaffected** — with k̂ < 0 it already uses the global set, so
  the floor is a no-op there

This is the first mechanism found that helps GAT-bearing arms *by construction*.
Every earlier candidate (ring_detect, per-RSU state) fired in all three arms and
so lifted D1 as much or more, which is precisely why they compressed the ordering.

---

## 3. Result with the fix — ordering restored to t≈210, then lost again

300 s run in progress (t ≈ 242/300 at the time of writing). Cumulative MCC:

| cutoff | D1 | D4 | D6 | D6−D4 | D4−D1 | ordering |
|---|---|---|---|---|---|---|
| 30 | 0.8585 | 0.8754 | 0.8703 | −0.0051 | +0.0168 | broken¹ |
| 60 | 0.8541 | 0.8730 | 0.8792 | +0.0062 | +0.0189 | ✅ OK |
| 90 | 0.8339 | 0.8432 | 0.8477 | +0.0045 | +0.0093 | ✅ OK |
| 120 | 0.8317 | 0.8378 | 0.8425 | +0.0047 | +0.0061 | ✅ OK |
| 150 | 0.8232 | 0.8261 | 0.8376 | +0.0114 | +0.0030 | ✅ OK |
| 180 | 0.8205 | 0.8256 | 0.8386 | +0.0130 | +0.0052 | ✅ OK |
| 210 | 0.8099 | 0.8148 | 0.8216 | +0.0068 | +0.0049 | ✅ OK |
| **240** | 0.8036 | **0.7996** | 0.8066 | +0.0070 | **−0.0041** | ❌ **BROKEN** |

¹ k̂=4 does not occur before **t = 32.0**, so cutoff 30 cannot reflect this fix.

**What the fix achieved.** Every previous configuration inverted at cutoff 90
(both the OR-flag-off and the OR-floor runs reached −0.0015 there and worsened
after). With the floor, D1 < D4 < D6 holds across **six consecutive cutoffs,
60 → 210**.

**What it did not achieve.** At cutoff 240 the ordering breaks again
(D4 − D1 = −0.0041). **So the fix delays the collapse from t≈90 to t≈240; it does
not prevent it.** We are reporting this rather than quoting the 210 cutoff, since
selecting the window where the result holds is exactly the kind of post-hoc choice
you ruled out.

**D6 > D4 remains solid throughout** (+0.0045 → +0.0130, never negative). It is
specifically the GAT-only arm that cannot hold above the no-ML arm in the final
third of the run.

Isolating the fix's effect at the 60 s cutoff, same configuration with and
without it:

| | D1 | D4 | D4 − D1 |
|---|---|---|---|
| without floor | 0.8541 | 0.8629 | +0.0088 |
| **with floor** | **0.8541** | **0.8730** | **+0.0189** |

**D4 gains +0.0101; D1 is byte-identical.** That is the intended behaviour and
confirms the floor cannot flatter the baseline arm.

Isolating the fix's effect at the 60 s cutoff, same configuration with and
without it:

| | D1 | D4 | D4 − D1 |
|---|---|---|---|
| without floor | 0.8541 | 0.8629 | +0.0088 |
| **with floor** | **0.8541** | **0.8730** | **+0.0189** |

**D4 gains +0.0101; D1 is byte-identical.** That is the intended behaviour and
confirms the floor cannot flatter the baseline arm.

**Not yet established:** cumulative MCC declines with duration in every
configuration measured (D6 fell 0.87 → 0.78 across the ring-only 300 s run), so
the 300 s endpoint will sit below 0.8477. Whether the ordering survives to 300 s
is exactly what this run is measuring. We will report the endpoint as measured.

---

## 4. Correction to a figure already sent

The ordering line in the earlier reports —
**D6 0.5568 > D4 0.5185 > D1 0.4794** — was **not a valid comparison**. D6 was
measured with Fix B applied while D4 and D1 were pre-Fix-B values.

All three have now been measured under Fix B, same seed:

| arm | previously reported | **measured under Fix B** | FPR |
|---|---|---|---|
| D1 | 0.4794 | **0.518** | 0.064 |
| D4 | 0.5185 | **0.552** | 0.146 |
| D6 | 0.5568 | **0.557** | 0.152 |

**The ordering does hold** — D6 0.557 > D4 0.552 > D1 0.518 — but the margins are
much tighter than reported:

| | as reported | **actual** |
|---|---|---|
| D6 − D4 | +0.038 | **+0.005** |
| D4 − D1 | +0.039 | +0.034 |

D6 separates from D4 by 0.005, not 0.038 — a 7× overstatement. The conclusion
survives; the numbers do not. We are flagging this rather than leaving it in the
record.

---

## 5. Per-variant false positives and negatives (your question)

### False negatives (D6 + ring, 300 s)

| variant | missed | of | recall | MCC if fixed |
|---|---|---|---|---|
| **TP-S1** | **3,798** | 23,858 | **0.8408** | **0.8377** |
| MP-S1 | 1,742 | 25,856 | 0.9326 | 0.7888 |
| MP-S2 | 673 | 32,653 | 0.9794 | 0.7655 |
| TP-S2 | 15 | 6,827 | 0.9978 | 0.7518 |

### False positives — which signature fired on a CLEAN beacon

| variant | FP | % of FP | precision |
|---|---|---|---|
| **MP-S2** | **1,465** | **40.8%** | **0.9549** ← worst |
| MP-S1 | 956 | 26.7% | 0.9871 |
| TP-S3 | 208 | 5.8% | 0.9798 |
| TP-S2 | 128 | 3.6% | 0.9814 |
| TP-S4 / TP-S5 / MP-S3 | 22 / 30 / 12 | <1% | ≥0.991 |
| TP-S1, MP-S4 | 0 | 0% | 1.0000 |
| **no signature (ML/OR-path only)** | **1,914** | **53.4%** | — |

### Root causes and treatment status

| root cause | magnitude | treatment | status |
|---|---|---|---|
| k̂=4 misrouting erases ψ | 158 lost TPs | `--psi_cond_floor` | ✅ ordering restored to cutoff 90 |
| ML/OR-path firing without rule evidence | 53.4% of FPs | `--gat_or_path_min_phi` / OR-flag off | ✅ |
| ghosts invisible to all channels | 74% of FNs | `--ring_detect` | ✅ recall 0.348 → 0.986 |
| cross-RSU state contamination | vid 98 FPR 1.0000 | per-RSU `vehicle_state` | ✅ → 0.0691 |
| **MP-S2 precision 0.9549** (within-RSU contamination) | 40.8% of FPs | attempted, **failed** | ❌ |
| **TP-S1 recall 0.8408** | 3,798 FNs | none | ❌ **untreated** |

**MCC ceilings (D6 + ring, 300 s):** eliminating all FPs → **0.8591**;
eliminating all FNs → 0.9037. **The false-positive side alone clears 0.85.**

**FP concentration:** six vehicles produce **77.7%** of all 3,587 false positives
(196: 640, 191: 608, 202: 470, 129: 408, 154: 338, 157: 324) — the impersonation
victims.

---

## 6. Results to date (300 s, full duration)

| configuration | D1 | D4 | D6 | D6 FPR |
|---|---|---|---|---|
| baseline | 0.479 | 0.519 | 0.525 | 0.215 |
| **Fix B** (per-RSU state) | 0.518 | 0.552 | **0.557** | 0.152 |
| + ring_detect | **0.763** | 0.739 | 0.751 | 0.152 |
| + ring + OR-floor | 0.763 | 0.755 | **0.766** | 0.095 |
| + ring + OR-off (160 s) | 0.824 | 0.820 | **0.841** | 0.019 |
| **+ psi_cond_floor** | **in progress** — cutoff 90: 0.8339 / 0.8432 / **0.8477** | | | |

### Approaches tested and rejected, with measurements

| attempt | outcome |
|---|---|
| GAT retrain, offline θ_S | MCC 0.87 → **0.20** — export produced NaN for single-node graphs |
| GAT retrain, NaN-guarded + in-sim θ_S | MCC **0.036** |
| — root cause | **S is anti-informative in-sim**: clean p50 0.935 > real-poison 0.900 > ghost 0.000. Held-out AUC 0.677 offline does not transfer. |
| drop anomalous beacons from history | **FPR 0.535** — starves the history |
| identity binding | −0.124 MCC; 40% of rejections were honest |

---

## 7. Open items and what would close them

**Where the ordering now fails.** D4 − D1 stays positive to cutoff 210 and turns
−0.0041 at 240. The failure is confined to the last third of the run, and only to
the GAT-only arm — D6 > D4 never inverts. Whatever degrades D4 late is not the k̂
misrouting (that is now floored); it is a separate effect in the final third that
has not been isolated.

**Where the MCC gap is.** At 300 s the FP-only ceiling is **0.8591** — eliminating
false positives alone clears your 0.85, while eliminating all false negatives
gives 0.9037. Two concrete targets, both measured:

| target | magnitude | status |
|---|---|---|
| **MP-S2 precision 0.9549** | **40.8% of all FPs** | one fix attempted (dropping anomalous beacons from history) — **failed, FPR 0.535**. Undiagnosed. |
| **six-vehicle FP concentration** | **77.7% of all FPs** (vids 196/191/202/129/154/157 — the impersonation victims) | within-RSU contamination; per-RSU isolation only closed the cross-RSU path |
| **TP-S1 recall 0.8408** | 3,798 FNs; fixing alone → 0.8377 | **no treatment attempted** |

**Honest assessment.** MCC ≥ 0.85 at 300 s is reachable in principle — the
arithmetic ceiling allows it — but it requires closing the within-RSU
contamination that produces MP-S2's false positives, and that mechanism is not
yet understood. We would rather say that than propose another patch on the
strength of a projection; the last three attempts on this exact problem
(identity binding, dropping anomalous writes, retraining the GAT) each failed
with measured evidence.

**Also unresolved:** whether D1 < D4 < D6 can hold to 300 s at all. Every
mechanism we have found that raises MCC lives in the rule tier and therefore
lifts D1 as much as D6; `psi_cond_floor` is the only GAT-arm-specific effect
identified so far, and it runs out at t≈240.
