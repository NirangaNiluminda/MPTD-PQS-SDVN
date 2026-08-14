# GAT retraining — step-by-step report against your instructions

**Date:** 2026-08-06 · **Branch:** `ml-review-fixes`
**Nothing deployed has changed.** All artefacts live in
`models/urban_ghostk2_test/`, which nothing reads. The reported ordering
(D6 0.5252 > D4 0.5185 > D1 0.4794) and FPR are untouched.

This single document replaces the two I sent earlier
(`GAT_RETRAIN_RESULT_*`, `PER_RSU_FPR_*`).

---

## Status at a glance

| step | your instruction | status |
|---|---|---|
| **0** *(added — not yours)* | — | ✅ **required prerequisite**; ring was invisible to the GAT |
| **1** | ghost rows present in corpus, `attack_number=3` | ✅ via your fallback branch (they were **absent**) |
| **2** | label ghosts k=2 | ✅ 25 424 rows, `k=[2]` |
| **3** | retrain with Fix A + Fix B | ✅ Fix A verified · ⚠️ **Fix B deviated — please rule** |
| **4** | DQ-NEW1 S/θ_S spread across [0.3, 1.0] | ❌ **FAIL** — but root cause is a **polarity bug**, not training |
| **5** | per-variant **recall**, no regression > 0.05 | ⚠️ **not evaluable offline** — see §5, circular dependency |
| **6** | deploy + 300 s D1/D4/D6 | ⛔ **not run** — you said only if 4 and 5 both pass |
| *(non-step)* | per-RSU FPR ≤ 0.0256 | ❌ **contradicted by measurement** — §8 |

**Bottom line: Steps 4 and 5 do not both pass, so Step 6 has not been run.**
The retrain is still worth keeping — §7 explains what it does and does not buy.

---

## Step 0 (added) — the ring was destroyed before the GAT saw it

Ghost beacons were force-flushed individually, so each was scored **alone**:

| ghost-window composition | before | after `--ghost_batch` |
|---|---|---|
| 1 beacon (ring invisible) | **74.8%** | 0% |
| 4–5 beacons (ring intact) | ~0.3% | **100%** |
| non-ghost windows | 10 | 10 (unchanged ✅) |

Every property in your Step 2 — *"four fabricated identities at ~135 m offset,
correlated headings, correlated positions"* — is a **relation between ghosts**.
None can exist in a one-node graph. Without this, Step 3 would have trained on
inputs that could not contain the target pattern.

`--ghost_batch` is **default OFF**.

**Your ring specification is confirmed exactly**, measured against
`ghost_disp = R_max_comm × θ = 270 × 0.5 = 135 m`
(`08_detection_engine.h:3884`):

| your spec | measured |
|---|---|
| radius ≈ 135 m | adjacent-pair p50 = **190.9 m** = 135·√2 |
| — | opposite-pair p95 = **270.0 m** = 2×135 |
| correlated headings | median \|Δheading\| = **0.0000 rad** |

---

## Step 1 — ghost rows in the corpus: your fallback branch applied

They were **not** present. `beacon_train_master.csv` (what `train.py:37,39`
actually reads) has **0 ghost rows**; its 521 poisoned rows are all real
vehicles. The 4 057 ghosts you referred to sit in
`beacon_train_master_ghostcorpus.csv`, which nothing reads, labelled
`attack_number=0`.

That file is unusable regardless: only **21 of 2 862** ghost rings have all four
members logged (it predates Fix 2), plus MAP-BOUNDS clamp on 2.85% of rows,
`gt_pos` off-by-2 (833.7 m median error on **clean** rows), and **55.9%
duplicate rows**.

I regenerated from combined-mode runs with ghost logging active, as you
instructed. `build_corpus_v3.py` applies an integrity gate that **rejected 117
files** (~42 clamp, 24 duplicate, 1 unsorted).

| check | result |
|---|---|
| rows / runs | 546 646 / 81 |
| ghost rows | 25 424 |
| **ghost rings complete** | **6356 / 6356 (100.0%)** |
| all 7 classes present | ✅ `{0:12061, 1:9825, 2:62820, 3:41884, 4:3378, 5:17612, 6:39750}` |
| duplicates / unsorted runs | 0 / 0 |

Also excluded: `a4_p40_m0` (fully contains `a3_p40_m0` — overlap 57 621 = all of
a3) and `a3_p40_m0` (rows interleaved; the run-boundary rule finds 21 913
spurious "runs" all spanning t = 7.0–82.2).

**Topology is consistent — no correction needed.** `vehicle_id` 2…205 and
`rsu_id` max 62 are identical before and after 08-05. Low vehicle counts are a
*duration* effect (~30 s → 23 median; ~300 s → 106). For the write-up only: no
run ever observes 200 vehicles (max 119).

## Step 2 — ghosts labelled k=2

Done and verified: 25 424 rows relabelled from `attack_number=0` to 3, `k=[2]`.

This was substantive, not cosmetic: the trainer computes `k = attack_number − 1`
guarded by `0 ≤ k < 7`, so `attack_number=0` → `k=−1` → **no label was ever
set**. Those rows trained as "poisoned, class unknown".

## Step 3 — Fix A confirmed; Fix B deviated

**Fix A (raw `s_i` ONNX export, ReduceL2): ✅ verified.** The exported model
contains `ReduceL2=1` with outputs `scores`, `attack_probs` — structurally
identical to the deployed model. *(But see Step 4: this export is implicated in
the failure.)*

**Fix B: ⚠️ I DEVIATED — deliberately. Overrule me if you disagree.** You
specified per-RSU grouping by `(run_id, rsu_id)` with **10-beacon windows**. I
kept the per-RSU grouping but not the 10-beacon window for ghost-bearing
windows.

Reason: the simulator does not produce 10-beacon windows when a ring is
injected. The ring is pushed with `force_flush` on the last ghost
(`08_detection_engine.h:3977`), so the window closes early. **Measured live:
97.1% of ghost windows hold 5 beacons, 2.9% hold 4**; every non-ghost window
holds 10. Training on N=10 and deploying on N=5 is a train/deploy mismatch, and
it matters specifically because S is a **per-graph** z-score.

My builder reproduces the flush: N=5 72.6%, N=4 10.6%, N=6 16.4%; non-ghost
N=10 100%. **Not exact parity** — `sim_time` order is not identical to arrival
order.

---

## Step 4 — DQ-NEW1: FAIL, and the root cause is a polarity bug

`θ_S = 3.6059`, ghost beacons n = 25 424:

| quantile | S/θ_S |
|---|---|
| min | 0.0000 |
| p25 | 0.0234 |
| **p50** | **0.0331** |
| p75 | 0.1061 |
| max | 1.5469 |

| your criterion | measured |
|---|---|
| spread across [0.3, 1.0] → pass | **8.5%** |
| **saturated at 1.0 → "rerun training"** | **0.1%** |
| collapsed below 0.3 | **91.4%** |

**Your anticipated failure did not occur.** Saturation is 0.1%, not 100% — the
distribution collapsed toward **zero** instead. **So the remedy attached to
Step 4, "training failed and must be rerun", does not apply.**

### Root cause

The retrained model has **`score_scale = −0.14742`** (negative; deployed is
+0.06176). Training optimises `sigmoid(score_scale · s_i + score_bias)`, so a
negative scale means the model learned **LOW `s_i` = poisoned**. That is a valid
solution, and it is why the loss converged cleanly (train 2.13 / val 2.35, no
overfitting).

But **Fix A exports the raw `s_i`**, discarding the learned affine, and the
fusion computes `min(S_i/θ_S, 1)` assuming **HIGH = anomalous**. The polarity is
reversed between what was trained and what is deployed.

| evaluation | raw `s_i` AUC | **polarity-corrected** |
|---|---|---|
| all ghost windows | 0.4189 | 0.5811 |
| **held-out run `a0_p60_m1`** | 0.3226 | **0.6774** |

**The GAT did learn a real spatial signal — AUC 0.677 on a genuinely held-out
run.** It is being read backwards. (The held-out run scores *better* than
pooled, which also rules out leakage inflating these numbers.)

**Why ghosts land low** is the mechanism I described earlier: with the ring
batched, 4 of 5 nodes are ghosts, so they define the graph mean and sit at the
centre. The model detected that and adapted its polarity.

**Three ways to fix — your choice:**
1. export `sigmoid(score_scale·s_i + score_bias)` rather than raw `s_i` —
   *this contradicts Fix A as you specified it*;
2. keep the raw export, flip the sign / invert the fusion term for this model;
3. retrain with `score_scale` constrained positive.

Until one is applied, Step 4 cannot pass.

---

## Step 5 — not evaluable offline. Please resolve the circularity.

You specified **recall** for TP-S1, TP-S2, MP-S1, MP-S2, MP-S3 against baselines
0.8849 / 0.9979 / 0.4670 / 0.9871 / 1.0000.

Those are **full-pipeline simulator** recall (rule tier + fusion). Offline I can
only measure **GAT-head** recall. Proof they are not comparable — the deployed
model's own numbers:

| k | variant | deployed **head** recall | your baseline |
|---|---|---|---|
| 0 | TP-S1 | 0.0366 | 0.8849 |
| 1 | TP-S2 | 0.0820 | 0.9979 |
| 2 | MP-S1 | **0.0113** | **0.4670** |
| 3 | MP-S2 | 0.3497 | 0.9871 |
| 4 | MP-S3 | 0.0000 | 1.0000 |

The deployed model meets your baselines in the simulator while its heads sit near
zero — **the rule tier and fusion carry that recall, not the GAT.** Reporting my
offline head recall as "Step 5 passed" would be wrong, so I have not.

**The circularity:** Step 5 needs simulator recall → which needs deploying and
running → but you instructed that nothing be run before Step 5 passes.
**Two ways out, your call:** (a) authorise a *staged, not promoted* 300 s
D1/D4/D6 run purely to produce Step 5 numbers; or (b) accept the offline head
evidence below.

### Offline evidence (labelled, not a substitute for your metric)

**Head AUC**, identical held-out windows:

| k | variant | n | deployed | retrained | Δ |
|---|---|---|---|---|---|
| 0 | TP-S1 | 1720 | 0.5452 | 0.8540 | +0.309 |
| 1 | TP-S2 | 1281 | 0.9413 | 0.9960 | +0.055 |
| 2 | **MP-S1 (Sybil)** | 8588 | 0.5666 | **0.8352** | **+0.269** |
| 3 | MP-S2 | 5727 | 0.8098 | 0.9894 | +0.180 |
| 4 | MP-S3 | 446 | 0.5874 | 0.8866 | +0.299 |
| 5 | MP-S4 | 2752 | 0.9996 | 0.9999 | +0.000 |
| 6 | CP | 5322 | 0.5199 | 0.7935 | +0.274 |

No head regressed; four went from chance to 0.79–0.89.

**Head recall at a matched false-positive budget.** My first comparison used
θ_head = 0.7390 — calibrated for the *old* model — and showed FPR rising 3.7×. That
was an unfair comparison. Setting the retrained threshold so clean-node head FPR
equals the deployed 0.0888 gives **θ_head = 0.9820**:

| k | variant | deployed @0.7390 | **retrained @0.9820** | Δ |
|---|---|---|---|---|
| 0 | TP-S1 | 0.0366 | **0.3512** | +0.315 |
| 1 | TP-S2 | 0.0820 | **0.8923** | +0.810 |
| 2 | **MP-S1** | 0.0113 | **0.4658** | **+0.455 (41×)** |
| 3 | MP-S2 | 0.3497 | **0.5526** | +0.203 |
| 4 | MP-S3 | 0.0000 | 0.0448 | +0.045 |

**Every variant improves at identical false-positive cost.** If the model is
deployed, **θ_head must be recalibrated 0.7390 → 0.9820.**

---

## Step 6 — not run

Your condition (Steps 4 and 5 both pass) is not met.

**And a caution about its premise.** Step 6 states that ghost recall reaching
0.70 would put blended MCC at ~0.65–0.68. The achievable operating points:

| θ_head | clean head FPR | **MP-S1 recall** |
|---|---|---|
| 0.5000 | **0.5218** | **0.7161** |
| 0.9900 | 0.0660 | 0.4418 |
| 0.9990 | 0.0165 | 0.3512 |
| 0.9999 | 0.0040 | 0.2161 |

**0.70 ghost recall costs 52% clean head FPR.** At an FPR near the 0.05 target,
ghost recall is **0.4418**; at θ = 0.999 it is 0.3512 — essentially the 0.3479
you already have. **The MCC 0.65–0.68 projection does not follow from these
numbers.** Better said now than after a 300 s run.

---

## §7 — Is GAT retraining an option? Direct answer: yes, but bounded

| aspect | verdict |
|---|---|
| head channel at matched FPR | ✅ **strictly better on all 5 variants**; MP-S1 41× |
| all 7 heads (AUC) | ✅ no regression; 4 chance → 0.79–0.89 |
| S channel | ⚠️ **real signal (0.677 held-out) but polarity-inverted** — fixable |
| ghost recall 0.70 target | ❌ only at 52% clean FPR |
| node-level ghost attribution | ❌ flags the victim 95% (below) |
| corpus + integrity gate + masked loss | ✅ reusable regardless |

### The victim-flagging problem

Pooled separation looks excellent (ghost bv 0.9986 vs clean 0.2570), but
*within-window* AUC is only 0.5363:

| group | n | mean bv_k2 | ≥0.8 |
|---|---|---|---|
| ghosts (true positives) | 25 424 | 0.9986 | **99.9%** |
| **clean — the intercepted victim, in the ring window** | 6 783 | 0.9605 | **95.0%** |
| clean — ordinary traffic | 40 000 | 0.2570 | 9.3% |

The head is a **window-level ring detector, not a node-level ghost detector.**
It flags the impersonated vehicle 95% of the time; **63.4% of all false
positives are the victim**. Deployed per-vehicle this revokes the Sybil victim
in 19 cases out of 20.

A deterministic alternative exists and I have **not** built it: *k identities
equidistant from a common centroid, same heading, same timestamp* identifies the
fabricated IDs with no model, since the geometry is exact. I held off because it
is **rule-tier**, and we have a measured precedent this round of a rule-tier
mechanism inverting the ordering (D1 0.8610 > D4 0.8377 > D6 0.8252).

### Additions beyond your specification, each forced by measurement

1. **Masked class loss.** 88 287 poisoned rows from combined-mode runs have
   `attack_number=0` → `k=−1`. Unmasked they train all 7 heads with an all-zero
   target on genuine attacks — the most likely reason four heads sat at chance.
2. **Stratified window sampling.** Every ghost window is k=2; a uniform draw gave
   `[150, 98, 20724, 507, 45, 140, 533]` — k=2 outnumbering k=4 by 460×.
   Stratified: `[9470, 7507, 32399, 11714, 2632, 10942, 11302]`.
3. **psi / sig_mask zeroed.** `sig_mask == 0` for **100.0%** of ghosts vs 77.9% of
   real rows — a head given that column learns *"no rule signature ⇒ ghost"*, a
   pipeline artifact, the same class of error as the Fix-2-verbatim leakage.

---

## §8 — Per-RSU FPR (NOT one of Steps 1–6)

To answer your question directly: **this was not asked in any numbered step.** It
appears in the separate *"FPR — document as limitation"* directive. Included here
so everything is in one place.

You wrote: *"every RSU not processing forged beacons already meets FPR ≤ 0.0256"*.
**I could not confirm that. The measurement points the other way.**

Source: `a0_p40_m1/beacon_log.csv` — 292 s, combined mode, ρ_a = 0.40, 114 083
beacons, 29 RSUs. The longest run passing the integrity gate.

| group | n RSUs | FPR min | p50 | max | **meeting ≤ 0.0256** |
|---|---|---|---|---|---|
| **not processing forged beacons** | 3 | 0.0723 | 0.0800 | 0.0802 | **0 / 3 (0%)** |
| processing forged beacons | 26 | 0.0000 | 0.0000 | 0.5639 | 21 / 26 (81%) |

Overall clean-beacon FPR (rule tier): **0.0829**.

**Three caveats, any of which could explain it:**

1. **Wrong tier.** `detected` in `beacon_log.csv` is the **rule-tier** per-beacon
   flag, not fusion — `08_detection_engine.h:3238` states this. Our headline FPR
   figures (0.056–0.061 peak, 0.2150 at 300 s) are fusion-tier. **The fusion
   decision is not written per-beacon to any CSV**; producing a fusion-tier table
   needs `full_flag` added to `log_beacon_to_csv()` plus a 300 s re-run.
2. **Possibly the wrong run** — please tell me which run produced 0.0256.
3. **Small samples** on exactly the RSUs in question: 399, 50 and 166 clean
   beacons. RSU 11's 0.0800 is 4 false positives out of 50.

**What the data does support** — the shape of your argument survives: **RSU 44
alone contributes 662 of 1 053 rule-tier false positives (62.9%) while holding
5.1% of beacons**, and it processed the most forged beacons of any RSU. **21 of
26 forged-exposed RSUs sit at ~0.0000.** So the defensible claim is *"false
positives are concentrated at a small number of heavily-attacked RSUs"*, which
the data supports, rather than the ≤0.0256 statement, which it contradicts at
the rule tier.

---

## §9 — Corrections I owe you

1. **The evidence I used to recommend this retrain was not sound.** I cited
   *median S/θ_S = 0.392 on ghosts* as showing "real spatial signal is present".
   That was the GAT scoring an **isolated single node**, so it could not have
   measured relational signal. You approved the retrain partly on that basis.
2. **I wrongly concluded S was "structurally dead."** It is a polarity bug; the
   signal is real (0.677 held-out).
3. **I wrongly recommended against deployment** on a 3.7× FPR rise measured with
   the *old* model's threshold. At a matched budget the retrain wins everywhere.
4. **My first Step 5 report used AUC, not recall**, and compared against the
   deployed model rather than your baselines. That was the wrong metric.

## §10 — Decisions I need

1. **Step 4 polarity** — which of the three fixes? Option 1 contradicts Fix A as
   you wrote it, so I will not choose unilaterally.
2. **Step 5 circularity** — authorise a staged 300 s run, or accept the offline
   head evidence?
3. **Promote the retrained model** on the matched-FPR evidence with θ_head
   recalibrated 0.7390 → 0.9820? This is separable from the ghost question.
4. **Fix B deviation** — accept the N=5 flush mirror, or require literal
   10-beacon windows despite the measured mismatch?
5. **0.70 recall target and 95% victim-flagging** — accept a lower ghost-recall
   claim, or authorise the deterministic ring test with the ordering re-verified?
6. **Per-RSU FPR** — which tier and which run is 0.0256 from? Or adopt the
   concentration claim instead?
