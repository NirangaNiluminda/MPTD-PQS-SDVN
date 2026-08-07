# Response — DQ-FPR-R1/R2/R3, DQ-MP1, DQ-MP1-2, and the ablation_mode fix
**Date:** 2026-08-05 · **Branch:** `ml-review-fixes`

The DQ figures below are measured from the 300 s / ρ_a = 0.40 / seed 1
combined-attack D6 run. **Provenance stated up front:** those logs were produced
in A1-scored mode (the defect in Critical Issue 1), so the simulator's *summary*
was lightweight-only. The per-beacon `[FUSION-RSU]` verdicts they analyse are
genuine full-mode fusion outputs and differ correctly by arm.

**This caveat is now discharged rather than merely declared.** §0 shows that our
post-hoc recomputation reproduces the simulator's own `MCC_full` and `FPR_full`
to three decimals once A0 scoring is enabled. The two are the same arithmetic, so
the A1-mode provenance does not weaken any number in this document.

---

## 0. Ablation_mode fix — implemented and CONFIRMED

**Your diagnosis is correct.** All three 300 s runs report:

```
[ABLATION] Active mode: A1   (D1 gat=NO ae=NO | D4 gat=YES ae=NO | D6 gat=YES ae=YES)
MCC = 0.537   FPR = 0.094          <- identical across all three arms
CDER_full = -1.000  (0/0 wrong)    <- fusion path scored ZERO decisions
```

**One precision, because it affects whether Item 4 stands.** The arms were not
wholly identical. The `--enable_gat` / `--enable_lstm_ae` overrides *did* take
effect on the fusion computation, so the per-beacon fusion verdicts differ
substantially by arm — MP-S1 recall is 0.1901 / 0.3516 / 0.3516 across D1/D4/D6.
What is true is that this never reached the simulator's own scored output: the
summary line was blind to it, and the ordering had to be recovered by hand. So
Item 4's ordering is a real measurement of genuinely different fusion verdicts,
but your requirement stands — it must be reproducible from the simulator's own
MCC before it can be claimed.

**Root cause.** `ablation_mode` defaults to `1` (A1, lightweight-scored). The R7f
`--enable_gat` / `--enable_lstm_ae` flags act on the *detector toggles*
independently of `ablation_mode`, so forcing the detectors on while leaving the
default in place computes a full-mode fusion verdict for every beacon and then
scores none of them. Nothing warns.

**Fix applied** (`12_main.h`, before the R7f toggle derivation): a guard that
detects the inconsistent combination and promotes the run to A0, loudly.

```
[ABLATION][GUARD] --enable_gat/--enable_lstm_ae forced ON but ablation_mode=A1
scores the LIGHTWEIGHT tier only (MCC/FPR would be LW-only and identical across
arms, CDER_full=-1). PROMOTING ablation_mode A1 -> A0 (full) so the fusion
verdict is actually scored.
[ABLATION] Active mode: A0  use_pq_crypto=YES  enable_gat=YES  enable_lstm_ae=YES
```

Verified by smoke test. Mode 6 (B1) warns but is **not** promoted — it is an
AI-free baseline by design and rewriting it would destroy its meaning.

**Note on D1.** The guard cannot fire for D1, which passes
`--enable_gat=0 --enable_lstm_ae=0` — that combination is genuinely consistent
with A1. D1 must therefore pass `--ablation_mode=0` explicitly, or it would score
in A1 while D4/D6 score in A0. All three verification runs pass it explicitly.

### Confirmation — three distinct MCC values from the simulator's own output

D1/D4/D6, ρ_a = 0.40, 30 s, seed 1, `--ablation_mode=0`. All three started in
`Active mode: A0` with the correct detector combinations.

| Arm | `Active mode` | **`MCC_full` (simulator)** | `FPR_full` | `CDER_full` |
|---|---|---|---|---|
| D1 | A0, gat=NO, ae=NO | **0.331** | 0.016 | 0.472 |
| D4 | A0, gat=YES, ae=NO | **0.429** | 0.048 | 0.332 |
| D6 | A0, gat=YES, ae=YES | **0.422** | 0.056 | 0.334 |

**Three distinct values, from the simulator, not recomputed.** `CDER_full` is
also a real number for the first time — it was `-1.000 (0/0 wrong)` in every
prior run, i.e. the fusion path was scoring nothing at all. The wiring defect is
fixed.

**One point to avoid a false alarm:** the *lightweight* `MCC` line still reads
0.383 identically across all three arms. That is correct and expected — the
lightweight tier does not consult the GAT or LSTM-AE, so it cannot differ between
these arms. The quantity that must differ, and now does, is `MCC_full`.

### Your "post-hoc recomputation" objection — resolved, and it validates Item 4

You objected that Item 4's ordering came from manual recomputation rather than
the simulator's decisions. We can now show the two are the **same number**.
Recomputing these runs from `full_anom` vs `gt_pois`, exactly as we did for the
300 s figures:

| Arm | simulator `MCC_full` | our post-hoc recomputation |
|---|---|---|
| D1 | 0.331 | 0.3315 |
| D4 | 0.429 | 0.4286 |
| D6 | 0.422 | 0.4224 |

Agreement to three decimals, and `FPR_full` matches exactly
(0.016/0.048/0.056). **The post-hoc method is arithmetically equivalent to the
simulator's own scoring**, so the 300 s Item 4 figures were not a different or
weaker measurement — they were the same computation performed outside the binary
because the binary had been told not to perform it.

### But the 30 s ordering is D4 > D6, and we are not going to hide that

At 30 s the ordering is **D4 (0.429) > D6 (0.422) > D1 (0.331)** — the AE arm is
*below* the GAT-only arm, contradicting the 300 s ordering of D6 > D4 > D1.

Looking at the components, the reason is visible: **D4 and D6 have identical
recall at 30 s (0.6052 both), while D6's FPR is higher (0.056 vs 0.048).** At
this duration the LSTM-AE contributes no additional detections and only
additional false positives.

**This is measured, not inferred.** Comparing the AE's own output between the two
durations:

| | mean `ae_norm` | `ae_norm = 0` | `ae_norm > 0.5` |
|---|---|---|---|
| D6 @ 30 s | 0.1256 | **58.2 %** | 11.2 % |
| D6 @ 300 s | 0.3904 | 21.7 % | 37.3 % |

**At 30 s the LSTM-AE emits nothing at all on 58.2 % of beacons**, against 21.7 %
at 300 s. Its window is L = 50 beacons, and in the first 30 s of simulation most
vehicles have not transmitted 50 beacons — so the detector is structurally
starved. D6 therefore reduces to D4 plus residual AE noise, which is precisely
the 0.007 inversion observed.

At 300 s the AE is active on 78 % of beacons and does add recall
(0.7744 → 0.7821).

**There is nothing here to fix.** A 50-beacon window cannot be populated in the
first seconds of a run; forcing the AE to score on partial history would make it
worse, not better. The correct reading is that **30 s is below the minimum
duration at which the D6 arm is meaningful**, and the ablation ordering should be
quoted only at the paper's primary evaluation condition.

**So the ordering is duration-dependent, and 30 s is below the threshold at which
the AE contributes.** We are reporting this rather than quietly presenting only
the confirmation you asked for.

### Both MCC and the ordering recover at 300 s — measured, not projected

Placing the two conditions side by side, every arm improves with duration, and
D6 overtakes D4 between 30 s and 300 s:

| Arm | MCC @ 30 s | MCC @ 300 s | Δ |
|---|---|---|---|
| D1 | 0.3315 | 0.4802 | **+0.1487** |
| D4 | 0.4286 | 0.4855 | +0.0569 |
| **D6** | 0.4224 | **0.4918** | **+0.0694** |
| ordering | D4 > D6 > D1 ❌ | **D6 > D4 > D1** ✅ | |

The crossover is the LSTM-AE becoming usable. At 30 s it is silent on 58.2 % of
beacons and adds only false positives; at 300 s it is active on 78 % and adds
recall (D4 → D6: 0.7744 → 0.7821). D6 gains **+0.0694** against D4's **+0.0569**,
which is exactly the margin by which it overtakes.

**So the ablation ordering is not fragile — it is duration-gated**, and 30 s sits
below the gate. The paper's primary evaluation condition (300 s) is above it.

**What this does and does not establish:**

- **Established, from measurement:** the wiring is fixed; three distinct scored
  MCCs; the post-hoc method is arithmetically equivalent to simulator scoring;
  and at 300 s the ordering D6 > D4 > D1 holds with MCC improving for every arm.
- **In flight, and reported either way:** three 300 s runs under A0 are executing
  now, which would emit the ordering *natively* rather than by recomputation and
  close your objection completely. Given the equivalence demonstrated above we
  expect them to reproduce 0.4802 / 0.4855 / 0.4918. **We are recording that
  expectation here before the result so it cannot be fitted afterwards — and if
  they come out otherwise, we will report that instead.**

---

## 1. DQ-FPR-R1 — top FP vehicles and per-vehicle FPR

D6, 300 s. Overall: **23 624 honest beacons, 4 906 FP, FPR = 0.2077.**

| vid | FP | honest beacons | per-vehicle FPR |
|---|---|---|---|
| 196 | 830 | 1 063 | 0.7808 |
| 195 | 720 | 1 339 | 0.5377 |
| 191 | 631 | 1 146 | 0.5506 |
| **98** | 622 | 622 | **1.0000** |
| 129 | 461 | 1 292 | 0.3568 |
| 202 | 457 | 868 | 0.5265 |

**The FPR is not a diffuse property of the detector — it is six vehicles.** The
top 6 account for **3 721 of 4 906 FPs (75.8 %)**. There are only **27 distinct
honest vehicles** in the entire run (combined mode poisons ~88 % of beacons), and
24 of them register at least one FP.

**vid = 98 is flagged on 100 % of its honest beacons (622/622)** — not a rate, a
constant. A vehicle whose every honest beacon is anomalous is the signature of
persistent per-vehicle state contamination, not of a marginal threshold.

**On your question of whether these are the same impersonation victims as before
the fix:** we cannot answer that honestly from the data in hand. The pre-fix
per-vehicle FP list was not retained, so a same-vehicle comparison would be
reconstruction rather than measurement. We will produce it from the A0 runs
against a matched pre-fix run rather than assert it now.

### A sample-size caveat we should raise ourselves

The run contains **139 distinct vehicles in the fusion stream: 127 poisoned, 27
honest** (114 595 fusion rows, 79.4 % poisoned / 20.6 % honest). Combined mode
applies three attack planes at 40 % each, giving a measured poison rate of
~88 % at beacon level.

**So the entire 300 s FPR figure rests on 27 honest vehicles, and 6 of them
generate 75.8 % of the false positives.** The beacon count (23 624) is
respectable, but the *vehicle* diversity is not, and FPR is a per-vehicle
phenomenon here — vid 98 alone contributes 12.7 % of all FPs at a rate of
1.0000.

We flag this before you have to ask: **the FPR estimate is fragile to which
honest vehicles happen to survive the combined-attack assignment.** Any FPR
target — 0.05 or otherwise — evaluated on this configuration is being estimated
from a small, skewed honest population. If the FPR requirement is to be a
gating criterion for the paper, the evaluation condition likely needs a lower
combined poison rate or a seed sweep so that the honest population is large
enough to estimate a rate stably. We would like your view on this before
optimising against the current number.

---

## 2. DQ-FPR-R2 — FP versus time, 10 s bins

```
t=  0- 80   50, 20,  -,  -, 20,  -, 10, 20        (sparse start-up)
t= 80-160   65, 66, 56, 48, 48, 57, 59, 76        <- plateau ~50-76
t=160-190  141,194,164                            <- STEP 1 (~2.4x)
t=190-250  380,401,402,414,467,523                <- STEP 2 (~2.5x), then climb
t=250-300  376,363,116,185,185                    <- decline
```

**The growth is neither linear nor a single step — it is two discrete step
changes**, at **t ≈ 160 s** and **t ≈ 190 s**, separated by a plateau and
followed by a high-level regime that decays after t ≈ 250 s.

This argues against a steady contamination source. A linear ramp would indicate
gradual drift accumulation; what we see is a stable regime, an event, a new
stable regime, a second event, then a third regime. **That points to specific
triggering events at ~160 s and ~190 s.**

**We have identified the shape but not yet the triggering event, and we are not
going to guess at it.** Identifying what occurs at those two timestamps — by
mechanism and line number, as you asked — is the next step, and the A0 runs will
be the substrate for it.

---

## 3. DQ-FPR-R3 — which signatures fire on false positives

Signature bits per `08_detection_engine.h:1226-1234`
(bit0 = TP-S1, bit3 = TP-S4, bit4 = TP-S5, bit5 = MP-S1, bit6 = MP-S2, bit8 = MP-S4).

| sig_mask | decoded | count | share |
|---|---|---|---|
| 64 | **MP-S2 alone** | 1 535 | 31.3 % |
| **0** | **no rule signature at all** | 1 509 | **30.8 %** |
| 313 | TP-S1 + TP-S4 + TP-S5 + MP-S1 + MP-S4 | 650 | 13.2 % |
| 281 | TP-S1 + TP-S4 + TP-S5 + MP-S4 | 340 | 6.9 % |
| 287 | TP-S1..TP-S5 + MP-S4 | 310 | 6.3 % |
| 319 | TP-S1..TP-S5 + MP-S1 + MP-S4 | 250 | 5.1 % |

**Answer to your question: it is no longer only the TP-S1/S4/S5 cluster. The FP
population is now three roughly equal thirds.**

1. **~31 % — MP-S2 alone** (`sig_mask=64`). A single signature, not the
   kinematic cluster.
2. **~31 % — no rule signature whatsoever** (`sig_mask=0`). These are **pure
   AI-layer false positives**: the GAT and/or LSTM-AE fire with zero rule
   support. No rule fix can address them.
3. **~31 % — the TP-S1/TP-S4/TP-S5 cluster you identified**, which persists
   (masks 313/281/287/319 all contain bits 0,3,4) but now co-fires with MP-S4
   (bit 8) in every case.

Per-vehicle, the split is clean rather than mixed: vid 195/196/202 are dominated
by `sig_mask=64` (MP-S2), vid 98 by the 281/287 cluster, and **vid 129 by
`sig_mask=0` (453 of its 461 FPs are pure-AI)**. Different vehicles are failing
for different reasons, which is why a single fix has not moved the aggregate.

---

## 3b. Critical Issue 2 — contamination source, by mechanism and line number

You asked us not to accept the FPR as a limitation until the source was
identified by mechanism and line number. It is identified.

### It is not a rule-tier problem at all

Decomposing the false positives by what actually drove the verdict:

| group | FPs | mean ψ | mean S/θ_S | mean ae | mean φ |
|---|---|---|---|---|---|
| `sig_mask=0` | 1 509 | 0.0152 | **0.9456** | 0.1299 | **0.2239** |
| `sig_mask=64` (MP-S2) | 1 535 | 0.1161 | **0.8165** | 0.2569 | 0.8147 |
| cluster | 1 862 | 0.5600 | 0.9930 | 0.9056 | 0.9665 |

**The MP-S2 group is not caused by MP-S2.** Its ψ is 0.1161 — the MP-S2
signature weight is **0.05** (`SIG_WEIGHTS`, and the code already annotates bit 6
as *"FP-prone near τ_sync boundary"* at `08_detection_engine.h:1076`). A ψ of
that size cannot move a fusion score past a 0.5 threshold. What carries these
beacons is the GAT, at S/θ_S = 0.8165. **We pursued MP-S2 as the culprit and it
was wrong** — patching that signature would have removed none of these.

### The actual mechanism

`08_detection_engine.h:2249-2252`:

```c
if (g_gat_det_flag_heads != 0u && k_hat_i >= 0 &&
    (g_gat_det_flag_heads & (1u << (uint32_t)k_hat_i)) != 0u)
    full_flag = true;          // <-- bypasses the Φ threshold entirely
```

`g_gat_det_flag_heads` defaults to **46** (heads 1, 2, 3, 5 —
`02_config_globals.h:448`). When a beacon's `k̂` matches one of those heads and
the GAT fires, `full_flag` is forced true **regardless of Φ**.

Measured consequence:

| group | FPs | Φ ≤ 0.5 | gatflag = 1 | **flagged ONLY via this path** |
|---|---|---|---|---|
| `sig_mask=0` | 1 509 | 1 237 | 1 509 | **1 237** |
| `sig_mask=64` | 1 535 | 0 | 1 535 | 0 |
| cluster | 1 862 | 13 | 1 712 | 13 |

**1 250 of 4 906 false positives — 25.5 % — are beacons whose fusion score is
below threshold and which are flagged solely because this OR-path overrides it.**

This is why every rule-side fix so far moved the aggregate only partially: a
quarter of the FP population never passed through the rule tier or the fusion
threshold at all.

### The lever, and its exact cost

`g_gat_det_flag_heads` is a CLI flag, so the change is configuration, not code.
Recomputing the 300 s verdicts with the OR-path removed:

| | FPR | recall | MCC |
|---|---|---|---|
| current (`gat_det_flag_heads=46`) | 0.2077 | 0.7821 | 0.4918 |
| **with `=0`** | **0.1548** | 0.7375 | 0.4850 |
| delta | **−0.0529** | −0.0446 | **−0.0068** |

**FPR falls by a quarter for an MCC cost of 0.0068.**

**Two things we will not do without your instruction.**

1. **This reverses your own accepted improvement.** `eq:gat_det_flag` was
   introduced to raise MCC 0.4225 → 0.5121 and you approved it. Switching it off
   the following round, silently, is exactly the class of change this engagement
   has spent weeks eliminating. It is your call, not ours.
2. **0.1548 is still 3× the 0.05 requirement.** This is a real improvement, not
   a solution, and we will not present it as one.

The remaining ~75 % of FPs are the impersonation-contamination cluster and the
genuinely fused detections; those are separate work.

---

## 4. DQ-MP1 — ghost versus real in the missed MP-S1 population

**Your hypothesis is confirmed, and decisively.**

```
MP-S1 total          25 805
missed by D6         16 733  (64.84 %)
  of which GHOST     16 589  (99.14 %)   mean psi=0.0000  mean phi=0.0871
  of which REAL         144  ( 0.86 %)
```

**99.14 % of the missed population is ghost beacons** (vid ≥ 10000). The ceiling
for MP-S1 on the fusion path is therefore already known from the prior ghost
analysis, exactly as you anticipated.

### The reframing this forces

Splitting the class by population changes the picture completely:

| MP-S1 population | beacons | share of class | **recall** |
|---|---|---|---|
| **Real vehicles** | 5 051 | 19.6 % | **0.9715** |
| **Ghosts** (vid ≥ 10000) | 20 754 | **80.4 %** | **0.2007** |
| Combined (as reported) | 25 805 | 100 % | 0.3516 |

**On real vehicles MP-S1 detection is 97.15 %** — fully in line with every other
attack class (0.88–1.00). The 35 % headline is produced by ghosts, which are
80.4 % of the class.

This matters because **ghosts are not the fusion path's responsibility.** They
are fabricated identities handled by SYB-DETECT (Algorithm 2); the code says so
explicitly at `08_detection_engine.h:2341`. Scoring them in a beacon-fusion
recall metric measures the wrong detector against the wrong population.

**We are not proposing to quietly redefine the metric to make the number look
better.** The question is a measurement-definition one and it is yours: should
MP-S1 recall on the fusion path be reported over real victims only, with ghost
detection reported separately against SYB-DETECT? If the combined figure is the
right one to publish, then 35 % stands and the ghost detection path — not the
GAT — is what needs work.

---

## 5. DQ-MP1-2 — the 144 missed non-ghost MP-S1 beacons

Mean feature values over all 144:

```
psi = 0.0000     S/theta_S = 0.3874     ae_norm = 0.9947     phi = 0.3773
sig_mask = 0     for 144 of 144 (100 %)
khat     = -1    for 144 of 144 (100 %)
```

**Routing breakdown, directly answering your question: zero of them reach the a3
weight set. 100 % fall back to the global λ set.**

The causal chain is visible end to end in these five numbers:

1. `sig_mask = 0` — no rule signature fires on these beacons, so `psi = 0`.
2. `k̂` is derived *from* the rule signature
   (`if (sig_mask_i & (1u<<5)) k_hat_i = 2;` at `08_detection_engine.h:2187`).
   With `sig_mask = 0` there is nothing to derive from, so **`k̂ = -1`
   unconditionally**.
3. `k̂ = -1` means the a3 weight set (λ_gat = 0.950) is never selected; the
   fallback global λ applies (λ_gat = 0.1857, λ_ae = 0.3071).
4. The evidence *is present* — `ae_norm = 0.9947` is essentially saturated, and
   the GAT is at `S/θ_S = 0.3874` — but under the fallback weights it sums to
   `phi = 0.3773`, below the 0.5 threshold.

**These beacons are missed by a weighting decision, not by a lack of signal.**
The LSTM-AE is at 0.99 on every one of them. Had the a3 weight set been applied
(λ_gat = 0.950), the GAT term alone would carry them past threshold.

**This is a structural limitation, not a global defect — and we want to be precise
about the difference.** Measured over all 114 595 fusion rows in this run:

| `k̂` | rows | share |
|---|---|---|
| 2 (a3 weight set) | 56 728 | 49.50 % |
| **−1 (fallback)** | **35 825** | **31.26 %** |
| 3 | 9 506 | 8.30 % |
| 0 | 4 558 | 3.98 % |
| 1 | 3 705 | 3.23 % |
| 6 | 2 992 | 2.61 % |
| 5 | 809 | 0.71 % |
| 4 | 472 | 0.41 % |

So the attack-conditioned λ machinery **is** working for **68.7 %** of traffic —
an earlier internal note of ours claiming "k̂ = −1 always" is wrong for this
build and we withdraw it. The real finding is narrower and sharper:

`k̂` is derived *from the rule signature*, so **any beacon that fires no rule
signature is structurally unroutable** — 31.26 % of all traffic, and 100 % of the
non-ghost MP-S1 misses. The attack-conditioned fusion therefore cannot assist
exactly the stealthy population it was designed to catch, because stealth means
firing no rule signature. That is a design coupling worth raising in the paper,
not a wiring bug to be patched.

---

## 6. Summary

| Question | Answer |
|---|---|
| **ablation_mode** | Confirmed as you described. Guard implemented; **three distinct simulator MCCs: 0.331 / 0.429 / 0.422**, `CDER_full` real for the first time. Post-hoc method shown equivalent to simulator scoring. 30 s ordering is D4 > D6 (AE silent on 58.2 % of beacons at that duration); **at 300 s MCC rises for every arm and the ordering D6 > D4 > D1 is restored** — the ordering is duration-gated, not fragile |
| **Eq 3.69 quorum** | Implemented as instructed, deployed and retested. `CFLAG` 1 → **14** — but **all 4 controllers excluded and `C_trusted` left EMPTY**; sustained trust decay still not demonstrated. Needs a floor guard before it can be used. **See §8 — this is the most consequential result of this round** |
| **DQ-FPR-R1** | 6 vehicles = 75.8 % of all FPs; vid 98 at **FPR 1.0000** (622/622). Same-victim comparison deferred rather than asserted |
| **DQ-FPR-R2** | **Two discrete steps** (t≈160 s, t≈190 s), not linear, not a single step. Trigger not yet identified |
| **DQ-FPR-R3** | Three equal thirds: MP-S2-alone / **no signature at all (pure AI)** / the TP-S1/S4/S5 cluster |
| **DQ-MP1** | **99.14 % of misses are ghosts.** Real-vehicle MP-S1 recall is **0.9715** |
| **DQ-MP1-2** | **0 % reach the a3 weight set**; `k̂ = -1` for all 144 because `sig_mask = 0`. AE saturated at 0.9947 but under-weighted |

**We have not accepted the FPR as a known limitation.** Its shape and its
per-vehicle concentration are now measured; the triggering events at t ≈ 160 s
and t ≈ 190 s are the remaining unknown, and we will identify them by mechanism
and line number before proposing any fix.

---

## 7. Three new issues this analysis raises

These were not in your list. We surface them rather than let them emerge later.

1. **~31 % of false positives carry no rule signature at all** (§3). These are
   pure GAT/LSTM-AE false positives with zero rule support, so no rule-side fix
   can reach them. Any FPR reduction plan has to address the AI layer directly.

2. **Attack-conditioned fusion is structurally blind to stealthy traffic** (§5).
   `k̂` is derived from the rule signature, so the 31.26 % of beacons that fire
   no signature always fall back to global λ. This is a design coupling between
   the rule tier and the fusion tier that the paper currently does not
   acknowledge.

3. **The FPR is estimated from 27 honest vehicles, 6 of which produce 75.8 % of
   the errors** (§1). This questions whether the current evaluation condition can
   support an FPR *requirement* at all, as distinct from an FPR *observation*.

**Correction to an earlier internal claim.** A previous note of ours recorded
"k̂ = −1 always → per-attack λ dead." Measurement shows that is wrong for this
build: `k̂` resolves for 68.7 % of traffic. We withdraw the earlier claim; the
accurate statement is the narrower one in §5.

---

## 8. Eq 3.69 quorum — implemented as instructed, with one risk flagged

Implemented in `chaincode/chaincode/smartcontract.go` (`CPDetectCheck`):

```go
f := fByzantine(len(seenRSU))   // was: fByzantine(cfg.NumRSUs)
```

`seenRSU` holds exactly the trusted, de-duplicated RSUs that submitted evidence
for this `(vehicle, epoch)` — your `R^obs_ck`. Chaincode compiles clean.
`NETCFG.NumRSUs` left untouched at 4 as you instructed.

**The risk we are obliged to put in front of you.** `fByzantine(n)` returns 0 for
`n < 4`, so `f + 1 = 1` whenever a vehicle-epoch has one, two or three witnesses.
Our measured witness distribution is **179 pairs with one witness against 4 with
two** — so in practice the quorum becomes **1 almost everywhere.**

A quorum of one means **a single trusted RSU disagreeing with the controller is
sufficient to flag it, exclude it from `C_trusted`, and trigger failover.** In
this threat model that is load-bearing: TP-S1 and MP-S1 are *malicious-RSU*
attacks, and we have already observed an RSU carrying ψ = 0.85 before being
revoked. A compromised RSU that has not yet been demoted could therefore
unilaterally exclude an honest controller — the exact inversion the f+1 threshold
exists to prevent.

We have implemented it as you specified and have **not** second-guessed the
decision in code. But the combination of "quorum base = observing set" and
"observing set is almost always 1" removes Byzantine tolerance at this RSU
density, and you may want either a floor (`max(f+1, 2)`) or an explicit statement
in the paper that CP-DETECT assumes at least one honest witness per epoch.

### RETEST RESULT — the change fires, and it collapses the control plane

Chaincode redeployed (CCAAS image rebuilt, container swapped under the same
package ID — no sequence bump or re-approval needed, since only the
implementation changed) and a 30 s chain-on run executed. **We recorded the
prediction before running: `CFLAG` would rise sharply, and the Byzantine risk
above might materialise. Both happened, the second one completely.**

| | before (quorum = 2) | **after (quorum = observing set)** |
|---|---|---|
| `CFLAG` records | 1 | **14** |
| Controllers excluded | 1 of 4 | **4 of 4** |
| `GetActiveController` | CTRL_0 | **"no active controller in C_trusted"** |
| Controller `TrustScore` | 0.99999 (recovered) | 1.0 (never updated — see below) |

Every flag has `ConflictCount = 1`, `NumRSUs = 1`, `ThresholdFP1 = 1` — i.e. a
**single RSU** was sufficient in every case, exactly as the arithmetic predicted.

The exclusions cascade, and the chain of succession is exhausted:

```
CTRL_0 -> CTRL_2      CTRL_1 -> CTRL_0
CTRL_2 -> CTRL_3      CTRL_3 -> ""      <-- no successor remains
```

**All four were flagged inside epoch E7, within four seconds of wall clock.** The
run then logged "no active controller" 22 times. The network finished the
simulation with **no trusted controller at all.**

### Why trust still shows 1.0 — and why that is not the good news it looks like

Controller `TrustScore` reads 1.0 with `MeanConflict = 0` and
`NumRSUsLastEpoch = 0` for all four. That is **not** recovery: exclusion halts
trust updates, so the EMA simply stopped being evaluated. **Sustained trust decay
is therefore still not demonstrated** — the mechanism now removes controllers
before their trust has a chance to decay at all.

So the original objective is still unmet, and the system is in a worse state than
before the change.

### Root cause of the collapse — an asymmetry in the lifecycle guards

`fByzantine(n)` returns 0 for n < 4, so with one witness the quorum is 1. That
alone would be tolerable if exclusion were floored — but it is not:

- **RSUs are protected.** `smartcontract.go:2144-2153` enforces a BFT floor,
  `|R_trusted(t)| ≥ 3f+1`, before demoting an RSU.
- **Controllers are not.** `excludeAndReassignController` checks only that the
  target is an ACTIVE controller and excludes it. There is no floor, no check
  that a successor exists, and no guard against emptying `C_trusted`.

The RSU lifecycle was written defensively and the controller lifecycle was not.
Under the old quorum this never surfaced, because a flag was almost unreachable.

### What we recommend, and what we have not done

We have **implemented your instruction exactly and left it in place** — the
quorum base is now `R^obs_ck` as you specified. We have **not** added a floor or
otherwise softened it, because that would be re-deciding your decision.

Our recommendation is a floor mirroring the RSU guard: refuse to exclude a
controller when doing so would leave `C_trusted` empty (minimally), or enforce
`|C_trusted| ≥ 2` (conservatively). That preserves your quorum semantics while
preventing total loss of the control plane. A second, independent option is to
require corroboration across epochs before a single-witness flag becomes an
exclusion.

**Please advise which you want.** As it stands the mechanism is demonstrably
live — it writes flags, excludes controllers and performs failover, which is what
you asked to see — but at this RSU density it will always terminate with an empty
control plane, so it cannot be used for the final experiments in this form.

**Testing note:** the chaincode test suite does not currently compile —
`smartcontract_test.go:504` calls `SCInitNetworkConfig` with 7 arguments where 9
are required. This predates our change, but it means `TestCPDetectCheck` could
not be used as a regression check on this edit. Worth fixing separately.
