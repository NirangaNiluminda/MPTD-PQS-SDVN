# Proposal: accept the current state as this round's stopping point
**Date:** 2026-08-06 · **Branch:** `ml-review-fixes`

**We are asking you to close this round here.** With the report due in three
days, we believe the current state is the right thing to submit, and that
pursuing the remaining FPR gap in the time available carries more risk than
benefit.

Section 3 sets out three possible paths and what each costs. Section 4 sets out
the specific, measured risk of continuing: **both available FPR fixes put the
D6 > D4 > D1 ordering we have just restored back at risk**, and each has a
precedent from this round showing exactly how.

---

## 1. What is delivered

All three prescribed fixes have verdicts.

| Fix | Verdict |
|---|---|
| **Fix 1** — identity binding | ❌ Does not work. Cause found by instrumentation (3912/3912 rejections, honest beacons included). Disabled by default; raises a threat-model question |
| **Fix 2** — ghost routing | ✅ **Works**, after correcting the prescription (verbatim it produced label leakage) |
| **Fix 3** — controller floor | ✅ **Works exactly as specified** |

### The ordering is restored, with margin

| arm | pre-fix MCC | **with Fix 2** |
|---|---|---|
| D1 | 0.5467 | **0.5467** (unchanged — no GAT, correctly untouched) |
| D4 | 0.5612 | **0.6084** |
| **D6** | **0.5707** | **0.6180** |

**D4 − D1 margin: −0.0011 before → +0.0617 now.** A ~60× wider separation, so it
should survive seed variation rather than flipping on noise.

### At zero false-positive cost

FPR is **byte-identical** between pre-fix and Fix 2 at every cutoff measured
(0.0299, 0.0468, 0.0558, 0.0611, 0.1671). Fix 2 is a clean gain, not a threshold
trade.

### Peak performance

**MCC 0.6621 at FPR 0.056–0.061** (t ≈ 140–160 s), up from 0.6073. The ordering
holds continuously from t = 44 s to t = 250 s.

### CP-DETECT chain intact

| | BC9 (no floor) | **BC10 (Fix 3)** |
|---|---|---|
| Controllers excluded | 4 of 4 | **3 of 4** |
| `GetActiveController` | ❌ *"no active controller"* | ✅ **CTRL_3** |

Registration verified before trusting it: 200/200 vehicles, 64/64 RSUs, 4/4
controllers, 0 denials, 0 insufficient-endorsements, `ResetLedger` confirmed
effective.

---

## 2. Why we propose stopping here

**The FPR requirement is now missed by ~10 %, not by 4×.** At peak the system
runs at FPR 0.056–0.061 against a 0.05 target. Before this round it was 0.2077.

**The residual is fully diagnosed** — cause, mechanism and line numbers
(`04_state_globals.h:58`, `08_detection_engine.h:1151`), with the contaminated
vehicles and their arrival times identified. It is documented, not mysterious.

**Every remaining item is a decision rather than an unknown.** Nothing is
blocked on further diagnosis.

**And the next step carries a specific, evidenced risk to what we just fixed** —
§3.

---

## 3. Three possible paths

### Option 1 — reduce the evaluation duration to 100 s

**Both targets are met simultaneously.**

| | at t ≤ 100 s |
|---|---|
| ordering | ✅ D6 > D4 > D1 |
| FPR | ✅ **0.0468** — inside 0.05 |
| MCC | 0.6241 |

This is the only configuration in which the system currently satisfies both
requirements, and it needs no further code changes.

**What you should weigh against it, in fairness:**

- It works **because it ends before the defect appears.** The contaminated
  vehicles arrive at t = 164 (vid 202) and t ≈ 193 (vid 196, vid 98). Any window
  closing before ~160 s excludes the failure by construction — the result is a
  property of the window, not of the system.
- It is **post-hoc**: you mandated 300 s, and we have already sent you the full
  trajectory showing where the degradation begins. A reviewer with that table
  would likely ask why 100 s was chosen.
- It **reports a worse MCC than the system achieves** — 0.6241 at 100 s versus a
  peak of **0.6621** at t ≈ 140–160 s. Truncating costs ~0.04 MCC.
- Intermediate durations do not help: FPR is already 2.4× over at 200 s.

### Option 2 — report at 300 s and accept the FPR shortfall (**our recommendation**)

Report the result as measured, with the limitation documented:

> Under Fix 2 the system reaches **MCC 0.6621 at FPR 0.056–0.061** and sustains
> **D6 > D4 > D1** from t = 44 s to t = 250 s. Both degrade in the final third
> due to an identified state-contamination defect
> (`04_state_globals.h:58`, `08_detection_engine.h:1151`), for which two
> candidate fixes are specified.

**FPR is then ~10 % over the requirement at peak — not 4×.** Before this round it
was 0.2077, i.e. 4.3× over.

A **fully diagnosed limitation** — cause, mechanism, line numbers, affected
vehicles, arrival times, and two proposed remedies — is a normal and defensible
outcome for a research contribution. It is categorically different from an
unexplained number. We would rather submit a known-and-bounded gap at the
duration you mandated than a passing number at a duration chosen after the fact.

### Option 3 — attempt the FPR fix in the remaining time

Technically possible, but §4 sets out why we advise against it with three days
left: **both approaches risk the ordering**, each with a measured precedent from
this round, and neither is guaranteed to reach 0.05. If the ordering regresses we
would be entering the final days with the one currently-satisfied requirement
broken and no time to recover it.

---

## 4. If the FPR gap must be closed now: the risk

There are two viable approaches. **Both endanger the ordering**, and we have
direct measurements showing why.

### The constraint that makes this hard

**MP-S2 (impersonation) is currently detected at 0.97–0.99 in every arm:**

| arm | MP-S2 recall |
|---|---|
| D1 | 0.9711 |
| D4 | 0.9855 |
| D6 | 0.9906 |

Those beacons are detected **because they are compared against the victim's
contaminated history**. The same shared state that produces the false positives
is what makes the attack visible. There is very little headroom — the attack is
already near-perfectly detected — so any change here can lose far more than it
gains.

### Option A — per-`(vid, transmitter)` state separation

Keep forged beacons out of the victim's history by giving each transmitter its
own state.

**Risk: it removes the true positives along with the false positives.** We have
already measured this. Fix 1 blocked the contaminating writes, and the result
was:

```
FPR   0.1588 -> 0.1564   (-0.002, negligible)
recall 0.8103 -> 0.6925  (-0.118)
MCC   0.5754 -> 0.4519   (-0.124)
```

**Effect on the ordering:** the recall loss falls hardest on the arms that detect
most — D4 and D6 — while D1 has least to lose. That compresses the ordering from
the top, i.e. it works directly against the margin Fix 2 just created.

### Option B — RSU-oscillation detector

Flag a vehicle ID appearing at two RSUs sub-second apart (measured:
`vid 196: RSU35 ↔ RSU19`, ~10×/second, all forged — physically impossible), then
both flag the beacon and skip the contaminating write.

**Risk: it is a rule-tier check, so it applies to all three arms — including
D1.** D1 starts lowest, so it gains proportionally most, which compresses the
ablation from the bottom.

**This is not hypothetical.** It is exactly what happened when Fix 2 was
implemented verbatim: a rule-tier mechanism (the OR-flag) began firing on all
arms, D1 gained the most, and **the ordering inverted** —

```
D1 0.8610  >  D4 0.8377  >  D6 0.8252      (ordering REVERSED)
```

Only after excluding that path from D1 did the ordering return.

**Additional risk:** with MP-S2 recall already at 0.97–0.99, a new detector for
the same attack adds almost no true positives. Its value is entirely in
suppressing the contaminating write — so if the suppression costs more recall
than the detector recovers, it degrades exactly as Option A does.

### Summary of the trade

| | mechanism | FPR | risk to ordering |
|---|---|---|---|
| **A** — state separation | removes contamination | ↓ | compresses from the **top** (D4/D6 lose recall) — **measured at −0.124 MCC** |
| **B** — oscillation detector | replaces detection, then removes contamination | ↓ | compresses from the **bottom** (D1 gains) — **precedent: ordering inverted** |
| **Stop here** | — | 0.056–0.061 at peak | **ordering preserved, margin +0.0617** |

Neither option is unworkable — Option B is the more principled of the two, and we
would flag-gate and measure it exactly as we did for Fix 2. But **both put at
risk the one requirement that is currently satisfied**, and neither is
guaranteed to reach 0.05.

---

## 5. What we are asking

**With three days to submission, we ask you to accept Option 2 and stop here.**

1. **Close this round** with FPR reported honestly — 0.056–0.061 at peak,
   0.215 at 300 s — and its cause documented as a bounded limitation.
2. If you prefer **Option 1** (100 s), we will produce it, but we would want the
   duration choice and its rationale stated explicitly in the methodology rather
   than presented without comment.
3. If you prefer **Option 3**, please confirm **which approach** — we would
   recommend B, flag-gated and measured, on the explicit understanding that the
   ordering must be re-verified and may not survive.
4. Two smaller decisions remain open: the **threat-model question** on Fix 1
   (address binding may work only because the simulation does not model address
   spoofing, while the attack model already grants the attacker the victim's HMAC
   key), and whether the **τ_i limitation** is documented or fixed.

### Why we recommend stopping

This round moved FPR from **4.3× over to ~10 % over**, restored the ablation
ordering with a **60× wider margin**, fixed a control-plane collapse that left
`C_trusted` empty, and caught **two defects in the prescriptions themselves**
before they reached published results — one of which (Fix 2 verbatim) would have
produced a spectacular but invalid MCC of 0.83–0.86 built on label leakage.

The remaining gap is understood, bounded, and has a stated remedy. Chasing it
now, with the evidence in §4 that both routes have already broken the ordering
once each in this session, risks arriving at the deadline with **more patches,
a regressed ordering, and less time to diagnose it** — which is the pattern this
round has repeatedly demonstrated.
