# Response — Blocking Issues 1–3, Eq 3.69 quorum retest, and the 35 diagnostics
**Date:** 2026-08-06 · **Branch:** `ml-review-fixes`

Covers all three Blocking Issues, the Eq 3.69 quorum retest, and the diagnostics
from both letters — **35 items: 28 answered in full, 4 partial, 3 outstanding**,
with exactly what each of the last seven requires set out in §4.

**Read §0 first** — it reframes the FPR, the MCC gap and the ordering failure as
one defect rather than three, which changes what the remaining work is for.
**§5 lists the decisions we need from you.**

Two results contradict premises in your letter, one contradicts a prediction we
recorded in writing beforehand, and one contradicts a claim we made earlier in
this same document. All are marked.

---

## 0. HEADLINE — one root cause explains the FPR growth, the MCC gap AND the ordering failure

We have been treating these as three problems. They are one.

### The MCC trajectory

Computing MCC at increasing cutoffs of the same 300 s run (all three arms, all
scored on an identical beacon population):

| cutoff | D1 | D4 | **D6** | D4 − D1 | ordering |
|---|---|---|---|---|---|
| t ≤ 44 | 0.3775 | 0.4633 | 0.4694 | +0.0858 | ✅ |
| t ≤ 80 | 0.4368 | 0.5107 | 0.5167 | +0.0739 | ✅ |
| t ≤ 120 | 0.5303 | 0.5713 | 0.5824 | +0.0410 | ✅ |
| **t ≤ 160** | 0.5711 | 0.5917 | **0.6073** | +0.0206 | ✅ **PEAK** |
| t ≤ 180 | 0.5752 | 0.5841 | 0.5987 | +0.0089 | ✅ |
| t ≤ 200 | 0.5673 | 0.5734 | 0.5834 | +0.0061 | ✅ |
| t ≤ 250 | 0.5218 | 0.5271 | 0.5366 | +0.0053 | ✅ |
| **t ≤ 300** | **0.4794** | **0.4783** | **0.4855** | **−0.0011** | ❌ |

**Two facts that change the framing:**

1. **MCC peaks at t ≈ 160 s (D6 = 0.6073) and then collapses to 0.4855** — a loss
   of **0.122**, a 20 % relative degradation. The system does not *converge* to
   0.49; it *decays* to it. The number you have been treating as our detection
   capability is a post-degradation figure.
2. **The ablation ordering holds at every cutoff from t = 44 s through t = 250 s
   and breaks only at 300 s.** The D4 − D1 margin erodes monotonically —
   +0.0206 → +0.0089 → +0.0061 → +0.0053 → −0.0011 — rather than fluctuating.
   This is not noise. Something is eating it.

### What is eating it

The decay begins at **t ≈ 160 s**. From §3b, the false-positive onsets are:

| vid | first honest beacon | first FP | first *forged* beacon under its ID |
|---|---|---|---|
| 202 | **164.003** | 164.003 | none |
| 196 | **192.996** | 192.996 | 72.809 (**−120.2 s**) |
| 98 | **193.546** | 193.546 | 72.809 (**−120.7 s**) |

**The MCC collapse and the ordering failure begin exactly when the
pre-contaminated impersonation victims enter the simulation.** Their identities
were forged for ~120 s before they ever transmitted, so `vehicle_state[vid]` was
built entirely from attacker kinematics. Every genuine beacon they emit
contradicts that stored state and is flagged — vid 98 at 622/622.

D4 and D6 carry a higher FPR than D1 partly because the OR-flag
(`08_detection_engine.h:2249-2252`) fires **only on GAT-bearing arms** — D1 has
no `k̂`, so the OR-path cannot fire for it.

**Correction — we tested this and it is NOT the cause of D4 falling below D1.**
We initially wrote that the OR-flag was why D4 specifically drops under D1. The
OR-flag-off runs at 300 s (§3j) disprove it: with the OR-flag disabled, D4 is
*still* below D1, and marginally further below (gap −0.0011 → −0.0017). The
OR-flag inflates D4's FPR but is not what decides the D4/D1 ordering. We have
left the claim visible and corrected rather than deleting it.

### Why this is good news

Three symptoms we have been chasing separately — FPR growing 0.05 → 0.21, MCC
stuck at 0.49, and the ablation ordering failing — are **downstream of one
defect**: state contamination of a vehicle identity that is forged *before the
victim ever appears*.

**This also revises the ceiling estimate upward.** DQ-MCC3 (§3) values the FP fix
at 0.4918 → 0.6137 by removing false positives from the final confusion matrix.
But the trajectory shows the real prize is **holding MCC near its t ≈ 160 peak of
0.6073 instead of letting it decay to 0.4855** — and that compounds with the
ghost fix rather than overlapping it.

We are **not** claiming this reaches 0.90; §3 shows the two known causes cap out
at 0.8418, and this reframing does not repeal that arithmetic. What it does say
is that the FP work is worth more than we previously estimated, and that it is
the single highest-value target because it fixes three reported problems at once.

**The mechanism is now fully traced (§3e).** `vehicle_state` is a **single global
array** (`04_state_globals.h:58`), not per-RSU. For vid 98 the forged beacons are
heard only by RSU 18/19 and the genuine ones only by RSU 44 — **completely
disjoint sets** — so the impersonators poison a shared entry that a different RSU
later reads. That is why the existing RSU-side guard cannot work: it is a
per-RSU guard on a globally shared variable, and there is no genuine state to
protect at the time the forging starts.

**And the FPR requirement is closer than it looks (§3f).** Every RSU that
processes no forged beacons already has FPR <= 0.0256, inside your 0.05 target.
Four RSUs generate 92.6 % of all false positives. The same vehicle (vid 195) runs
at FPR 0.034 under one RSU and 0.758 under another — so this is an RSU-level
defect, not a detector-wide limitation.

**Important qualification, added after the a4-only run (§3l).** Pre-arrival
contamination is **necessary but not sufficient**. Running a4 alone gives vid 98
an even *longer* forging lead (179 s vs 120.7 s) yet only **FPR 0.1768** instead
of 1.0000. The severity requires the second path in §3f — per-RSU spatial-baseline
poisoning from concurrent attacks. **There are two compounding contamination
paths, not one.** We are correcting our own framing here rather than leaving the
stronger claim standing.

**Recommended priority: fix the pre-arrival identity contamination first.**
It is upstream of both paths, and everything else in your two letters is
downstream of it. The fix is architectural — per-RSU vehicle state, or an identity-binding check that refuses
to initialise `vehicle_state[vid]` from a beacon whose physical transmitter is
not the registered owner of that ID.

---

## 1. Correction — the 300 s ordering was NOT confirmed from simulator output

Your letter states, under "What is confirmed":

> "D6 > D4 > D1 confirmed at 300s from simulator output."

**That was not accurate when written, and having now produced it, it does not
hold.** Every prior 300 s figure was post-hoc recomputed from A1-scored runs; no
simulator-native 300 s measurement existed. We have now run all three arms at
300 s under `ablation_mode=0`. Result:

| Arm | MCC_full (simulator) | post-hoc check | FPR_full | recall |
|---|---|---|---|---|
| D1 | **0.479** | 0.4794 | 0.1390 | 0.7206 |
| D4 | **0.478** | 0.4783 | 0.2122 | 0.7742 |
| **D6** | **0.486** | 0.4855 | 0.2150 | 0.7824 |

**Ordering is D6 > D1 > D4 — not D6 > D4 > D1.**

**We also recorded a prediction before this run** that it would reproduce
0.4802 / 0.4855 / 0.4918, and committed to reporting the outcome either way.
The prediction was wrong and this is that report.

### D6 did not fail — D4 did

To be precise about what moved, because it is easy to misread:

| Arm | run 1 (A1, post-hoc) | run 2 (A0, native) | change |
|---|---|---|---|
| D1 | 0.4802 | 0.4794 | ~unchanged |
| **D4** | **0.4855** | **0.4783** | **−0.0072** |
| D6 | 0.4918 | 0.4855 | still **best in both runs** |

**D6 is the top arm in both measurements.** The ordering broke because **D4 fell
below D1**, not because D6 slipped. D4's FPR rose 0.2047 → 0.2122 while its
recall was flat (0.7744 → 0.7742), which is what pushed its MCC down.

### Why we are NOT attributing this to run-to-run noise

The obvious explanation is nondeterminism, and we initially reached for it. It
does not survive checking, because **the two run-sets are not a controlled
comparison:**

| run-set | P (poisoned) | N (honest) | total | binary |
|---|---|---|---|---|
| run 1 (A1) | 90 971 | 23 624 | 114 595 | 18:13 build |
| run 2 (A0) | 91 989 | 23 676 | 115 665 | 22:36 build |

They processed **different beacon populations** (+1 070 beacons) and were
produced by **different binaries** — the second includes the ablation guard and
the CP-DETECT tier-3 flush added in between. Within each set all three arms share
identical ground-truth counts, so **arms are strictly comparable inside a set**,
but a cross-set delta confounds nondeterminism with a binary change and a
different beacon population. **We are not going to quote a variance figure we
cannot separate from those.**

### What is actually supported

- **Supported, from the only simulator-native measurement:** D6 > D1 > D4, with
  all three arms scored on an identical beacon population.
- **NOT supported:** the D4 > D1 ordering. **In the native run D4 and D1 are
  separated by 0.0011** — a gap far too small to carry an ablation claim,
  irrespective of what the variance turns out to be.
- **Unresolved:** whether the D4 shift is nondeterminism or an effect of the
  binary change. Settling this needs a controlled repeat — the same binary and
  configuration run twice. We have not done that yet and will not assert either
  explanation until we have.

**Consequence for the paper.** The cumulative ablation ordering D6 > D4 > D1
cannot be claimed from a single seed when two of its three positions are decided
by 0.0011. It needs **multiple seeds with a reported variance**, or the D4/D1
comparison must be dropped and the claim reduced to "D6 is the strongest arm" —
which *is* supported in both measurements. We would rather raise this now than
have it found at review. This directly affects Item 4, which you previously
accepted.

**However — see §0 before concluding the ordering is unsound.** The trajectory
analysis shows the ordering holds at *every* cutoff from t = 44 s to t = 250 s
and fails only in the last 50 s, as the D4 − D1 margin is eroded monotonically by
the contaminated late-arriving vehicles. So the correct reading is not "the
ablation ordering is unreliable" but **"the contamination bug destroys it in the
final 50 s of the run."** Fixing that defect is the principled route to a stable
ordering — not shortening the run, and not disabling the OR-flag.

**Immediate next step, already identified:** a controlled repeat — same binary,
same configuration, run twice — to establish the actual variance floor. Until
that exists, no ablation ordering should be quoted from a single run, including
the ones previously reported.

**Blocking Issue 1 is therefore only half-resolved:** the wiring is fixed and
30 s is confirmed invalid for ablation (AE silent on 58.2 % of beacons), so your
instruction to run everything at ≥300 s is correct and adopted. But the 300 s
ordering itself does not reproduce.

---

## 2. Quorum retest — the corrected Eq 3.69 collapses the control plane

You asked for the `CFLAG` count, controller trust trajectory, and whether
sustained decay now occurs. Chaincode redeployed (CCAAS image rebuilt, container
swapped under the same package ID — no sequence bump needed since only the
implementation changed), then a 30 s chain-on run.

| | before (quorum = 2) | **after (quorum = observing set)** |
|---|---|---|
| `CFLAG` records | 1 | **14** |
| Controllers excluded | 1 of 4 | **4 of 4** |
| `GetActiveController` | CTRL_0 | **"no active controller in C_trusted"** |
| Controller `TrustScore` | 0.99999 | 1.0 (never updated — see below) |

Every flag carries `ConflictCount = 1`, `NumRSUs = 1`, `ThresholdFP1 = 1`: a
**single RSU** sufficed in every case, because `fByzantine(n) = 0` for n < 4.

Exclusions cascade until succession is exhausted:

```
CTRL_0 -> CTRL_2      CTRL_1 -> CTRL_0
CTRL_2 -> CTRL_3      CTRL_3 -> ""     <-- no successor remains
```

All four were flagged inside epoch **E7, within ~4 s of wall clock**. The run
logged "no active controller" 22 times and finished with **no control plane at
all.**

**Sustained decay: still NOT achieved, and the reading is a trap.** Controller
`TrustScore` shows 1.0 with `MeanConflict = 0`. That is not recovery — exclusion
*halts* trust updates, so the EMA simply stopped being evaluated. Controllers are
now removed before their trust can decay at all. The original objective is
further away than before the change.

### Root cause — asymmetric lifecycle guards

- **RSUs are protected:** a BFT floor `|R_trusted(t)| ≥ 3f+1` is enforced at
  `chaincode/chaincode/smartcontract.go:2144-2153` before any demotion.
- **Controllers are not:** `excludeAndReassignController` checks only that the
  target is an ACTIVE controller, then excludes it. No floor, no
  successor-exists check, no guard against emptying `C_trusted`.

The RSU lifecycle was written defensively; the controller lifecycle was not.
Under the old quorum this never surfaced because a flag was nearly unreachable.

**We have left your change in place and have NOT added a floor**, because that
would be re-deciding your decision. Two options, and we need you to pick:

1. **Floor it**, mirroring the RSU guard — refuse an exclusion that would empty
   `C_trusted`, or require `|C_trusted| ≥ 2`. Preserves your quorum semantics.
2. **Require multi-epoch corroboration** before a single-witness flag escalates
   to exclusion.

**As it stands the mechanism cannot be used for final experiments** — at this RSU
density it will always terminate with an empty control plane.

---

## 3. DQ-MCC1 / DQ-MCC2 / DQ-MCC3 — the 0.90 target is not reachable this way

Computed algebraically from the 300 s / ρ_a = 0.40 D6 run.
Base counts: **TP = 71 147, FP = 4 906, TN = 18 718, FN = 19 824**
(ghost TP = 4 165, ghost FN = 16 589; top-6 FP = 3 721, top-6 TN = 2 609).

### DQ-MCC1 — four conditions

| | condition | MCC |
|---|---|---|
| (a) | current system as-is | **0.4918** |
| (b) | excluding ghosts from TP/FN | **0.7651** |
| (c) | excluding top-6 vehicles' honest beacons from FP/TN | **0.5552** |
| (d) | both exclusions | **0.8497** |

**Correction to a figure in your letter.** You state "Excluding ghosts from the
metric gives MCC = 0.7789." We measure **0.7651**. We cannot reproduce 0.7789
under this definition and would rather flag the 0.014 discrepancy than silently
adopt your number — if you used a different exclusion (e.g. removing ghosts from
FP/TN as well), please say so and we will recompute to match.

### DQ-MCC2 — ghost recall raised to 90 %

Replacing 90 % of ghost FNs with TPs (ghost TP 4 165 → 18 678, FN −14 513):

**MCC = 0.7294**

### DQ-MCC3 — top-6 FP vehicles' false positives eliminated

FP 4 906 → 1 185, TN +3 721:

**MCC = 0.6137**

### The combined ceiling — and why this is the important number

Applying **both** fixes at once — ghost recall to 90 % *and* the top-6 FPs
entirely removed:

**MCC = 0.8418**

> **Fixing both root causes completely still lands at 0.8418, short of the 0.90
> target.** This is arithmetic on the current confusion matrix, not a projection.

Your letter says "resolving them would push MCC substantially closer to the
target" — that is correct, 0.4918 → 0.8418 is a large gain. But it does **not**
reach 0.90, and no combination of the two identified root causes can. The
residual comes from 5 311 remaining false negatives (non-ghost misses plus the
last 10 % of ghosts) and 1 185 residual false positives outside the top-6.

**We are not proposing to abandon the 0.90 target.** We are reporting that it
requires a third source of improvement beyond the two currently identified, and
that this should be settled before compute is committed to final experiments.

---

## 3b. Blocking Issue 2 — the step triggers, identified

### DQ-STEP1 / DQ-FP13 — the six vehicles do NOT step together

Per-vehicle FP onset (10 s bins over the top-6) shows **six independent onsets,
not a shared trigger**:

| vid | first honest beacon | first FP | gap |
|---|---|---|---|
| 191 | 7.993 | 7.993 | **0.0 s** |
| 195 | 126.700 | 126.700 | **0.0 s** |
| 129 | 127.825 | 127.825 | **0.0 s** |
| **202** | **164.003** | 164.003 | **0.0 s** |
| **196** | **192.996** | 192.996 | **0.0 s** |
| **98** | **193.546** | 193.546 | **0.0 s** |

**Every one of the six is flagged on its very first honest beacon — gap 0.0 s in
all six cases.** Answering DQ-STEP3 and DQ-FP12 directly: vid 98 is flagged from
beacon 1, not from some later event.

**So the "steps" at t≈160 s and t≈190 s are vehicle ARRIVAL times, not
contamination events.** vid 202 enters at t=164; vid 196 and vid 98 both enter at
t≈193. The step structure in the aggregate histogram is simply when these
vehicles join the simulation. There is no shared trigger to find, and we withdraw
the framing in our previous document that implied one.

### DQ-STEP4 / DQ-FP2 — why they are wrong from beacon 1

Comparing the first *forged* beacon carrying each ID against the first *genuine*
beacon from that vehicle:

| vid | first forged | first honest | impersonation leads by |
|---|---|---|---|
| 98 | 72.809 | 193.546 | **+120.7 s** |
| 196 | 72.809 | 192.996 | **+120.2 s** |
| 129 | 7.162 | 127.825 | **+120.7 s** |
| 191 | 7.225 | 7.993 | +0.8 s |
| 195 | none | 126.700 | — |
| 202 | none | 164.003 | — |

**Attackers forge these identities for roughly 120 seconds before the victim ever
transmits.** By the time the real vehicle appears, `vehicle_state[vid]` has been
built entirely from forged kinematics — so its first genuine beacon is
inconsistent with the stored state and is flagged, and every subsequent one too.
That is why vid 98 reads FPR = 1.0000 on 622/622: it never had an uncontaminated
state to begin with.

**Why the existing RSU-side fix does not catch this.** The guard at
`08_detection_engine.h:~3910` saves and restores genuine state when a poisoned
beacon arrives for a vehicle. It presumes a genuine state exists to protect. Here
the forged beacons arrive when the victim has **never transmitted**, so there is
nothing to save — the attacker's beacons *create* the state entry. The fix
addresses contamination of existing state; this is contamination of state that
does not yet exist.

**This is the mechanism and the line number you asked for.**

### The residual — two vehicles this does NOT explain

**vid 195 and vid 202 carry no forged beacons at all**, yet are also flagged from
their first beacon (720 and 457 FPs). Whatever affects them is a second,
independent cause and we have not identified it. We flag this rather than let the
impersonation story appear to cover all six.

Note also that vid 129's false positives are 453/461 **pure-AI** (`sig_mask=0`),
so its mechanism may differ again despite it being an impersonation victim.

### DQ-FP8 — pure-AI false positives are NOT concentrated in the top-6

| vid | pure-AI FPs | in top-6? |
|---|---|---|
| 129 | 453 | yes |
| 36 | 176 | no |
| 157 | 163 | no |
| 91 | 143 | no |
| 154 | 106 | no |
| 205 | 82 | no |
| 191 | 78 | yes |

**1 509 pure-AI FPs spread across 20 vehicles**, only two of which are in the
top-6. So the pure-AI population is a genuinely *separate* failure mode with a
different victim set — eliminating the top-6 would not remove it.

`k̂` routing of those FPs: k=1: 922, k=3: 315, k=2: 177, k=6: 83, k=0: 12 — i.e.
they are routed to attack heads and scored there despite no rule signature firing.

---

## 3c. Your priority six — explicit status

You asked for DQ-MCC1/2/3 plus DQ-G6, DQ-G7, DQ-FP6, DQ-FP7 first. Rather than
imply the set is complete, here is exactly where each stands:

| Item | Status |
|---|---|
| **DQ-MCC1** | ✅ delivered (§3) |
| **DQ-MCC2** | ✅ delivered (§3) |
| **DQ-MCC3** | ✅ delivered (§3) |
| **DQ-G6** (ghost:honest ratio in the GAT graph) | ⚠️ **partial — see below**; full answer needs instrumentation |
| **DQ-G7** (ghost node's edge connections) | ⚠️ **partial — see below**; full answer needs instrumentation |
| **DQ-FP6** (D1, OR-flag off, 300 s) | ✅ delivered (§3j) — D1 bit-identical either way |
| **DQ-FP7** (a4 single-attack, 300 s) | ✅ delivered (§3l) — and it qualifies §0 |

### DQ-G6 / DQ-G7 — a partial answer that may matter more than the full one

The GAT graph structure is not currently logged per node, so we cannot yet report
a ghost's specific neighbours or a per-epoch ghost:honest ratio. That needs
instrumentation and we will add it.

But the diagnostic output already carries the **node count of every GAT
invocation**, and it is revealing. Across the 300 s D6 run (29 604 invocations):

| nodes in graph | invocations | share |
|---|---|---|
| **N = 1** | **15 703** | **53.0 %** |
| N = 2 | 4 761 | 16.1 % |
| N = 3 | 290 | 1.0 % |
| N = 10 | 8 850 | 29.9 % |

**The GAT is invoked with a single node in 53 % of calls, and with ≤ 2 nodes in
69 % of calls.** A one-node graph has no neighbourhood: attention over neighbours
is degenerate, and no relational comparison is possible.

This bears directly on the premise behind DQ-G5/G6/G7. Your reasoning was that if
ghosts carry physically implausible positions relative to their neighbours, the
GAT should detect them relationally — and that if ghosts are isolated they
produce no relational signal. **For the majority of invocations there are no
neighbours to compare against for any vehicle, ghost or honest.** If that is also
true of the ghost-carrying calls specifically, it would explain the 0.2007 ghost
recall directly, and the fix would be graph construction rather than model
weights or routing.

**We are not yet claiming that**, because `[GAT-SHAPE]` does not record which
vids are in each call — so we cannot yet confirm the ghost calls are the N = 1
ones. That is precisely what the instrumentation will resolve, and it is now the
highest-value item outstanding.

---

## 3d. Ghost diagnosis — DQ-G1, G2, G3, G8, G9

### DQ-G1 — ghost detection is decided entirely by routing

All 20 754 ghost beacons, by `k̂`:

| `k̂` | ghosts | share | detected | **recall** |
|---|---|---|---|---|
| **−1 (fallback)** | **14 827** | **71.4 %** | 0 | **0.0000** |
| 3 | 2 962 | 14.3 % | 2 962 | **1.0000** |
| 2 (a3 set) | 1 105 | 5.3 % | 1 105 | **1.0000** |
| 6 | 1 020 | 4.9 % | 0 | 0.0000 |
| 0 | 742 | 3.6 % | 0 | 0.0000 |
| 1 | 98 | 0.5 % | 98 | **1.0000** |

**Recall is perfectly bimodal — 1.0000 or 0.0000, never in between.** A ghost
routed to head 1, 2 or 3 is detected **every single time**; a ghost routed to
−1, 0 or 6 is detected **never**. Only **5.3 %** reach the a3 weight set;
**71.4 % fall to the `k̂ = −1` global fallback.**

Ghost detection is therefore not a scoring problem. It is a **routing** problem.

### DQ-G3 — and the GAT does have signal on the ghosts it misroutes

S/θ_S over the 19 649 misrouted ghosts (`k̂ ≠ 2`):

```
min 0.2000   p25 0.2920   p50 0.3920   p75 0.5890   max 1.0000
```

You framed the test precisely: *"If scores are non-trivial but weights are wrong,
routing is the bottleneck. If scores are near zero, the GAT has no signal."*

**The scores are non-trivial** — median 0.392, upper quartile 0.589, reaching
1.000. **So routing is the bottleneck, and the GAT is not blind to these ghosts.**
They are being scored under fallback λ weights that under-value the one component
carrying the signal.

### DQ-G9 — MP-S1 never fires on a ghost

| population | MP-S1 firing rate |
|---|---|
| ghost beacons | **0 / 20 754 = 0.0000** |
| real poisoned beacons | 54 470 / 70 217 = **0.7757** |

Your hypothesis was that ghosts transmitting at identical timestamps should make
MP-S1's synchronisation check fire **more** on ghosts. The measurement is the
exact opposite: it fires on 77.6 % of real poisoned beacons and on **not one
ghost**.

This closes the loop with DQ-G1. `k̂` is derived from the rule signature, MP-S1
(bit 5) is the signature that routes to the a3 head — and it never fires on a
ghost. That is *why* 71.4 % of ghosts land in the fallback. It also means the
1 105 ghosts that do reach `k̂ = 2` are routed by some path other than the rule
signature.

**DQ-G4 becomes the actionable question:** ghosts are trivially identifiable at
the routing stage (`vid ≥ 10000`). Given that every ghost reaching a real head is
detected with recall 1.0000, forcing ghost IDs to the a3 head is the obvious
lever — and the DQ-G3 distribution says the signal is there to support it.

### DQ-G2 / DQ-G8 — and a warning about the OR-flag

Ghosts routed to `k̂ = 2` (n = 1 105): **100 % detected via Φ > 0.5, 0 % via the
OR-flag.** But across *all* 4 165 detected ghosts:

| | count | share |
|---|---|---|
| `gatflag = 1` | 4 165 | **100 %** |
| Φ > 0.5 | 1 105 | 26.5 % |
| **detected ONLY via the OR-flag (Φ ≤ 0.5)** | **3 060** | **73.5 %** |

mean Φ over detected ghosts = 0.3707.

> **The OR-flag delivers 73.5 % of all ghost detections.**
> Disabling it would drop ghost recall from **0.2007 to ≈ 0.0532** — a ~4× loss.

This materially changes Blocking Issue 3. The OR-flag generates 1 250 false
positives (§3b of the previous document, 25.5 % of all FPs), but it is also
carrying three quarters of the ghost detections. **It is not a straightforward
"turn it off" decision**, and we would now advise against disabling it until the
ghost routing is fixed — at which point those detections would come through
Φ legitimately and the OR-flag could be retired without loss.

The OR-off runs at 300 s (§3j) quantify both sides of this.

---

## 3e. DQ-FP3, DQ-FP5, DQ-FP14, DQ-FP15 — one unguarded write, before detection

### DQ-FP3 — honest and forged beacons never meet at the same RSU

Every beacon carrying vid = 98, by the RSU that processed it:

| RSU | forged (`gt_pois=1`) | honest (`gt_pois=0`) |
|---|---|---|
| 18 | 28 | 0 |
| 19 | **2 195** | 0 |
| **44** | 0 | **622** |

**The sets are completely disjoint.** The impersonators are heard by RSU 18 and
RSU 19; the real vehicle is heard only by RSU 44. **No RSU ever sees both.**

You set the test precisely: *"If honest and forged beacons are processed by
different RSUs, `vehicle_state[98]` contamination cannot happen at a single RSU
and must involve cross-RSU state sharing. If the same RSU processes both, the
existing fix should have caught it."*

**It is the first case, and the cross-RSU sharing is structural:**

```c
VehicleBeaconState vehicle_state[total_size];      // 04_state_globals.h:58
```

`vehicle_state` is a **single global array indexed by vehicle ID**. It is not
per-RSU and never was. Every RSU reads and writes the same entry. So RSU 19
writes forged kinematics into `vehicle_state[98]`, and 120 seconds later RSU 44
reads that same contaminated entry when the genuine vehicle finally transmits.

### This is why the RSU-side fix at ~`:3910` cannot succeed

The existing guard saves and restores genuine state around the processing of a
poisoned beacon **within one RSU's code path**. It cannot help here for two
independent reasons:

1. **There is no genuine state to save.** The forged beacons arrive ~120 s before
   the victim ever transmits (§3b), so the attacker's beacons *create* the entry.
2. **Even if there were, the contamination crosses RSUs.** The guard operates
   inside RSU 19's processing; the damage is read by RSU 44 through a shared
   global array. A per-RSU guard cannot contain a globally shared variable.

**This closes Blocking Issue 2 at the mechanism-and-line-number level you asked
for:** `04_state_globals.h:58` (shared global state) combined with the ~120 s
pre-arrival forging window (§3b). The fix is architectural — either per-RSU
vehicle state, or an identity-binding check that refuses to initialise
`vehicle_state[vid]` from a beacon whose physical transmitter is not the
registered owner of `vid`.

### DQ-FP5 / DQ-FP15 — one unguarded write path, executed BEFORE detection

You asked for every write to `vehicle_state[vid]` where the key comes from a
beacon header field rather than the physical NS-3 node ID, with function and line
number, and for the call sequence from beacon receipt to the state update.

**There is exactly one write path in the entire codebase.**

| element | location |
|---|---|
| writer | `push_beacon(int vid, ...)` — `04_state_globals.h:98` |
| the write | `VehicleBeaconState &vs = vehicle_state[vid];` — `04_state_globals.h:101` |
| **its only call site** | `08_detection_engine.h:1151` |
| enclosing function | `run_lw_detect_per_beacon(uint32_t vehicle_id, BsmBeaconTag &tag, uint32_t rsu_id)` — `08_detection_engine.h:1140` |
| where `vehicle_id` comes from | `tag.GetVehicleId()` — **the beacon header field** (`08:3501`, `:3428`, `:4656`) |

**The full call sequence (DQ-FP15):**

```
RSU beacon receipt (handle_readone, 08:3445)
  -> vid = tag.GetVehicleId()             <-- attacker-controlled header field
  -> run_lw_detect_per_beacon(vid, tag, rsu_id)   08:1140
       -> push_beacon((int)vehicle_id, ...)       08:1151   <-- STEP 1
       -> "2. Run detection algorithms"           08:1157   <-- STEP 2
  -> vehicle_state[vid] already written
```

**Two facts that together are the whole defect:**

1. **The key is attacker-controlled.** `vehicle_id` is read straight from the
   beacon header. Nothing anywhere compares it against the physical transmitter.
   Your question asks which writes are "not guarded by the `atk_eff_rsu` check" —
   **the answer is the only write there is.** `push_beacon` has no identity
   parameter to check against, and its sole guard is a bounds test
   (`if (vid < 0 || vid >= total_size) return;`).

2. **The write is step 1, before detection is step 2.** The beacon is committed
   to `vehicle_state[vid]` *before* any signature or fusion runs. So detection
   cannot prevent contamination even in principle — by the time a beacon is
   judged malicious, it has already been written into the victim's history.

This is why the RSU-side guard at `~:3910` cannot work (§3e above): it operates
downstream of a write that has already happened, on a globally shared array, for
an identity nobody verified.

**The minimal fix is at `08:1151`:** verify that the physical transmitter owns
`vehicle_id` before calling `push_beacon`, or defer the push until after
detection. Both are small changes at a single site — the difficulty is deciding
the policy, not the code.

### DQ-FP14 — no third copy of the dead-code bug

All occurrences of the `((attack_number == N` pattern in
`08_detection_engine.h`:

| line | context | verdict |
|---|---|---|
| 2719 | `attack_number == 7 \|\| (g_combined_attack && vehicle_id%2==0)` | has combined fallback — OK |
| 2781 | `attack_number == 5 \|\| (g_combined_attack && vehicle_id%2==1)` | has combined fallback — OK |
| 3702 | `attack_number == 1 \|\| (g_combined_attack && g_rsu_attack[rsu]==1)` | has combined fallback — OK |
| 3775 | `attack_number == 3 \|\| (g_combined_attack && g_rsu_attack[rsu]==3)` | has combined fallback — OK |

**Four occurrences, all four carry the `g_combined_attack` fallback clause**, so
none is dead in combined mode. **We found no third copy of the bug.** Note that
this also means the dead-code class was never the cause of the vid-98
contamination — DQ-FP3 above shows the actual mechanism.

---

## 3f. DQ-G11, DQ-FP9 — the FPR is four RSUs, and the 0.05 target is already met elsewhere

### The decisive table

Per-RSU false-positive rate on honest traffic, against the number of forged
beacons that RSU processes (ghosts excluded):

| RSU | honest | FP | **FPR** | **forged beacons** | mean S/θ_S (honest) |
|---|---|---|---|---|---|
| 44 | 2 088 | 758 | **0.3630** | 3 742 | 0.9058 |
| 36 | 6 730 | 1 845 | **0.2741** | 1 780 | 0.6779 |
| 20 | 3 756 | 811 | **0.2159** | 2 464 | 0.9910 |
| 43 | 5 368 | 1 127 | **0.2099** | 792 | 0.7077 |
| 21 | 1 487 | 180 | 0.1210 | 733 | 0.4898 |
| 26 | 1 695 | 105 | 0.0619 | 475 | 0.4788 |
| 31 | 390 | 10 | **0.0256** | **0** | 0.4368 |
| 22 | 980 | 20 | **0.0204** | **0** | 0.4063 |
| 42 | 740 | 10 | **0.0135** | **0** | 0.6736 |
| 30 | 160 | 0 | **0.0000** | **0** | 0.4826 |

**The relationship is monotonic and exceptionless.** Every RSU that processes
forged beacons has an elevated FPR. **Every RSU that processes none has FPR ≤
0.0256** — i.e. already inside your 0.05 requirement.

**Four RSUs (44, 36, 20, 43) generate 4 541 of 4 906 false positives — 92.6 %.**

> **The 0.05 FPR target is not out of reach. It is already met at every RSU that
> is not processing impersonation traffic.** The requirement is not failing
> globally; it is failing at four locations, for an identified reason.

### DQ-FP9 — this explains vid 195 and vid 202

In our previous document we flagged that vid 195 and vid 202 carry **zero** forged
beacons of their own yet are flagged from their first beacon, and that we could
not explain them. We can now.

Both are served by **RSU 36**, which processes 1 780 forged beacons belonging to
*other* vehicles. And the effect is visible within a single vehicle:

| vid 195 | honest beacons | FP | FPR |
|---|---|---|---|
| at RSU 44 | 407 | 14 | **0.034** |
| at RSU 36 | 932 | 706 | **0.758** |

**The same vehicle, in the same run, has a 22× higher false-positive rate
depending on which RSU is listening.** That rules out any property of the vehicle
and localises the defect to the RSU.

So forged traffic contaminates **two** things:

1. **`vehicle_state[victim_id]`** — the global array (§3e), which flags the
   *impersonated* vehicle when it finally arrives.
2. **The RSU's spatial baseline** — which inflates scores for **every honest
   vehicle at that RSU**, impersonated or not. Mean S/θ_S on honest beacons runs
   0.91–0.99 at the heavily-forged RSUs against 0.41–0.48 at clean ones.

Mechanism (2) is what catches vid 195 and 202, and it is a second, distinct
contamination path from the one in §3e.

### DQ-G11 — the same effect from ghosts

Ghost generation is concentrated: **only 4 of 64 RSUs emit ghosts** — RSU 28
(10 386, 50.0 %), RSU 46 (6 736, 32.5 %), RSU 10 (3 292, 15.9 %), RSU 32 (340).

Your question was whether ghost presence contaminates the RSU-level spatial
baseline. It does:

| | mean S/θ_S on **real** beacons |
|---|---|
| ghost-carrying RSUs (n = 4) | **0.9866** |
| clean RSUs (n = 24) | **0.7533** |

**Confirmed — a ~31 % inflation of the spatial score for honest traffic at
ghost-carrying RSUs.** Note this is the same mechanism as (2) above arriving from
a different source, which is why we now regard RSU-level spatial contamination as
a first-class defect rather than a side effect.

**One correction to our own reasoning:** we hypothesised the top-6 FP vehicles
would sit at the ghost-carrying RSUs. They do not — they are at RSU 44, 43, 36
and 20, none of which emit ghosts. The two contamination sources are independent
and additive.

---

## 3g. DQ-G4, DQ-G5, DQ-G12, DQ-FP15 — ghosts are scored by ONE component out of three

### The measurement

| population | n | mean `ae_norm` | `ae_norm = 0` | mean ψ | mean S/θ_S |
|---|---|---|---|---|---|
| **ghost** | 20 754 | **0.0000** | **100.0 %** | **0.0000** | 0.5170 |
| real | 93 841 | 0.4767 | 4.4 % | 0.2459 | 0.9036 |

**Two of the three fusion components are identically zero for every ghost
beacon.** Ghost detection rests entirely on the GAT spatial term.

### DQ-G12 — why ψ and τ contribute nothing

**τ_i is a hardcoded constant.** `TAU_DEFAULT = 1.0f`
(`06d_ai_inference.h:308`), fed unconditionally: the AE call passes a literal
`1.0f` (`08_detection_engine.h:4079-4082`) and the GAT path uses
`tau ? tau[i] : TAU_DEFAULT` with the comment *"use TAU_DEFAULT (1.0) for all"*
(`06d:568,601`).

Your hypothesis was that ghosts carry τ_i = 1.0 because they have no blockchain
history, blinding the AE to trust. **The reality is broader: τ_i is 1.0 for
*every* beacon, ghost and honest alike.** It is never queried from SC-Trust. The
AE's sixth input feature is a constant, and the trained scaler has
mean = 1.0 / scale = 1.0, so it scales to 0.0 — it carries no information for any
vehicle.

**This means the on-chain trust score is never used as a detection feature at
all.** We flag it because it likely affects how trust-aware detection is
described in the paper.

**ψ = 0** follows from DQ-G9: the MP-S1 signature fires on 0/20 754 ghosts, so
the rule tier contributes nothing.

### DQ-G5 — what ghost beacons actually carry

Ghost construction, `08_detection_engine.h:3775-3840`. **Our runs used the legacy
placement**, not the GAT-evasive variant (`g_sybil_gat_evasive` defaults to
`false`, `02_config_globals.h:332`).

| field | value |
|---|---|
| ghost ID | `10000 + rsu_idx*100 + vid*10 + gi` |
| count per interception | `g_n_coord`, default **4** |
| **position** | **offset `ghost_disp` = `R_max_comm × poisoning_intensity_theta` = 270 × 0.5 = 135 m**, evenly spaced around the real vehicle |
| RSU registration | all ghosts registered at the **same** `rsu_idx` |
| `ghost_seen` marker | set on the RSU |
| **τ_i** | **1.0 constant** (see DQ-G12 below) |

**Answering your question directly: ghosts do NOT carry the real vehicle's exact
position — they are displaced 135 m and placed in a ring around it.** Four
fabricated identities appearing simultaneously in a 135 m ring around one vehicle,
all at one RSU, is a physically implausible configuration, so your reasoning holds:
the GAT *should* be able to detect this relationally.

**And it partly does** — DQ-G3 shows misrouted ghosts carry S/θ_S with median
0.392 and upper quartile 0.589, i.e. the relational signal is present. It is the
routing (DQ-G1: 71.4 % at `k̂ = −1`) that prevents that signal from being weighted
into a detection.

*Note for completeness:* a `--sybil_gat_evasive` mode exists which scatters ghosts
on a 250 m grid, one per RSU cell, with reversed heading and de-synchronised
timing explicitly to silence MP-S1/MP-S2/MP-S4. **It was not enabled in any run
reported here.** If you want the harder Sybil variant evaluated, that is a
separate experiment.

### DQ-G5b — the AE is deliberately not extended to ghosts

`08_detection_engine.h:4083-4095`, the ghost branch, states it explicitly:

> "LSTM-AE temporal scoring (`lstm_ring_push_resid`) is **intentionally NOT
> extended to ghosts** here — that's a fixed `total_size`-indexed array too, and
> ghost temporal scoring is a separate concern from this fix."

Ghosts accumulate ψ and `sig_mask` into a separate map (`GhostPsiState`) but
**never enter the AE ring buffer**, because that buffer is indexed by a
fixed-size array that cannot hold `vid ≥ 10000`. Hence `ae_norm = 0` for 100 % of
ghost beacons — confirmed in the table above.

### DQ-G4 — ghost IDs are trivially routable, and the fix is one line

The routing path (`08_detection_engine.h:2174-2188`):

```c
int k_hat_i = (gat_ok && i < gat_attack_types.size()) ? gat_attack_types[i] : -1;
if      (sig_mask_i & (1u << 5)) k_hat_i = 2;   // MP-S1 -> a3 slot
else if (sig_mask_i & (1u << 6)) k_hat_i = 3;   // MP-S2 -> a4 slot
```

For a ghost with `sig_mask = 0`, neither override fires, so `k̂` falls back to the
ML classifier's own prediction — and that is absent for 71.4 % of ghosts, giving
`k̂ = −1` and the global λ weights.

**Answering your question directly: yes, `vid ≥ 10000` is available at this exact
site and can force `k̂ = 2` without any rule signature.** The change belongs on
the same lines as the existing overrides.

This is also consistent with the code's own stated rationale. The comment above
those lines records that the ML classifier routes only **10.4 %** of true a3
beacons correctly and misroutes 34.7 % to a4, which is precisely why the rule bit
was trusted over `k̂`. Ghosts *are* a3 — they simply never fire the rule bit.
Forcing them by ID applies the existing design principle to the population it
currently misses.

### The complete ghost diagnosis — three independent defects

| # | defect | evidence |
|---|---|---|
| 1 | ψ ≡ 0 — MP-S1 never fires on ghosts | 0 / 20 754 (DQ-G9) |
| 2 | `ae_norm` ≡ 0 — AE explicitly not extended to ghosts | 100 % zero; code `:4088-4090` |
| 3 | `k̂ = −1` for 71.4 % — no ML prediction, no rule bit to override | DQ-G1 |

Only the GAT spatial term survives, and defect 3 ensures it is under-weighted for
most ghosts. **Where a ghost does reach a real head, recall is 1.0000** (DQ-G1) —
the signal is sufficient once weighted correctly.

**That is why MP-S1 ghost recall is 0.2007, and all three defects are fixable.**

---

## 3h. Does τ_i actually carry signal? — an offline experiment

§3g established that τ_i is a hardcoded constant and that the on-chain trust
score is never consumed by any detector. The obvious next question is whether
that is costing us anything. We measured it rather than assumed.

**Method, and why it is not circular.** Synthesising τ from ground-truth labels
would be leakage and worthless. Instead we reconstructed τ **exactly as SC-Trust
computes it** — Eq 3.55, `τ_i(t) = α·τ_i(t−1) + (1−α)(1 − ψ̄)` with α = 0.3 from
`NETCFG` — replayed causally over the 300 s D6 log. Each beacon is scored with
the τ value *before* its own ψ updates it, so no future or label information
enters. 114 595 beacons, 90 971 poisoned / 23 624 honest.

Reconstructed τ ranges 0.0561 – 1.0000 (mean 0.7989), i.e. it does move.

### Standalone discriminative power

| score | AUC |
|---|---|
| **−τ** (lower trust ⇒ poisoned) | **0.7161** |
| Φ (current fusion output) | 0.7862 |

**τ alone reaches AUC 0.7161** — well above chance, and not far below the entire
fusion pipeline. So the quantity the architecture computes and then discards does
carry substantial signal.

### Where it helps — and where it inverts

Marginal value of τ *within* bands of the current fusion score:

| Φ band | n | poisoned | AUC(−τ) |
|---|---|---|---|
| 0.0 – 0.3 | 37 398 | 19 818 | **0.0666** ← inverted |
| **0.3 – 0.5** | 6 452 | 4 064 | **0.7670** |
| **0.5 – 0.7** | 1 882 | 1 384 | **0.7657** |
| 0.7 – 1.0 | 68 863 | 65 705 | 0.5014 |

Two things stand out.

**1. τ is most informative exactly where Φ is least certain.** In the 0.3–0.7
band — straddling the 0.5 decision threshold — τ achieves AUC ≈ 0.767 *after*
conditioning on Φ. That is the region where extra information is worth most.
Above 0.7 it adds nothing (0.5014), but those beacons are already decided.

**2. In the low-Φ band τ is strongly *inverted* (AUC 0.0666)** — there, high
trust predicts *poisoned*. This is not noise, and it is explained by §3e/§3f:
the contaminated honest victims (vid 98 and the rest) are flagged constantly, so
their ψ history drives their τ **down** despite being honest, while genuinely
stealthy attackers keep ψ low and retain **high** τ. **The contamination bug
inverts the trust signal for the population it corrupts.**

### What we conclude — and what we do not

**Supported:** τ_i carries real, complementary signal in the uncertain band, and
the current architecture throws it away. Wiring it in is worth doing.

**Not supported, and we will not claim it:** that wiring τ in today would improve
MCC. Three reasons — (a) both scalers were fitted with τ constant
(`mean = 1.0, scale = 1.0`, the zero-variance signature), so any real value is
off-manifold for the trained models; (b) there is no local trust mirror — the C++
side never reads a vehicle trust score back from the chain, so the loop does not
close; (c) the inversion in the low-Φ band means τ would actively mislead until
the contamination in §3e/§3f is fixed.

**Sequencing this implies:** fix the contamination first (§0), then wire a local
τ mirror, then retrain the GAT and AE with τ varying, then re-fit the scalers.
Doing it in any other order risks a model consuming an inverted feature it was
never trained on.

The useful band is 8 334 of 114 595 beacons (7.3 %), so this is a refinement
rather than a route to 0.90 — but it is a real one, and it is currently free
signal being discarded.

---

## 3i. DQ-STEP2 — no trigger event exists in either window

You asked for every distinct log event type in t = 155–165 s and t = 185–195 s,
specifically looking for RSU handoffs, trust-score threshold crossings,
revocations, and new attacker activations.

| event type | W1 (155–165 s) | W2 (185–195 s) |
|---|---|---|
| DL-VEH-RX | 279 316 | 359 509 |
| FUSION-RSU | 3 970 | 4 220 |
| METRICS | 3 567 | 3 799 |
| A6-STEP | 2 726 | 2 726 |
| LL-POISON | 829 | 611 |
| MP-S1-RSU | 100 | 100 |
| SIM | 11 | 11 |
| LKH-REKEY | 5 | 7 |
| COVERAGE-DIAG | 5 | 5 |
| LKH-HMAC-FAIL | 4 | 1 |
| FABRIC-EVT | — | 4 |
| LKH-HMAC-REPLAY | — | 4 |

**None of the four event classes you asked us to look for occurs in either
window:**

- **RSU handoff events** — no such event type is emitted anywhere in the log.
- **Trust-score threshold crossings** — none present.
- **Revocation events** — none present.
- **New attacker vehicle activations** — none present.

The event *composition* is essentially identical across the two windows.
`A6-STEP` is constant at 2 726 in both, `MP-S1-RSU` constant at 100, `SIM` at 11.
The only material differences are per-RSU downlink volumes — RSU 36 rises
313 → 820 while RSU 44 falls 545 → 120 — which is exactly what vehicles moving
between coverage zones looks like.

**This confirms §3b independently.** There is no shared trigger event at t ≈ 160 s
or t ≈ 190 s to find, because the steps are not triggered — they are the arrival
times of vid 202, vid 196 and vid 98, each of which is flagged from its first
beacon because its identity was already contaminated. We had proposed a trigger
in an earlier document; this closes that line of enquiry negatively.

---

## 3j. Blocking Issue 3 — OR-flag ON vs OFF at 300 s (+ DQ-STEP5, DQ-FP6)

You asked for D6 at 300 s / ρ_a = 0.40 with the OR-flag on and off, reporting
FPR, MCC and the ordering for both. All three arms were run in both
configurations.

| arm | config | **MCC** | **FPR** | recall |
|---|---|---|---|---|
| D1 | OR-ON | 0.4794 | 0.1390 | 0.7206 |
| D1 | **OR-OFF** | **0.4794** | **0.1390** | **0.7206** |
| D4 | OR-ON | 0.4783 | 0.2122 | 0.7742 |
| D4 | **OR-OFF** | 0.4777 | **0.1532** | 0.7301 |
| D6 | OR-ON | 0.4855 | 0.2150 | 0.7824 |
| D6 | **OR-OFF** | 0.4841 | **0.1554** | 0.7381 |

**D1 is bit-identical between the two configurations** — confirming the flag
touches only GAT-bearing arms, and giving a clean control (this is DQ-FP6).

### The trade is better than we expected

| | ΔFPR | ΔMCC | Δrecall |
|---|---|---|---|
| D4 | **−0.0590** | −0.0006 | −0.0441 |
| D6 | **−0.0596** | **−0.0014** | −0.0443 |

**Disabling the OR-flag removes ~0.06 of FPR for an MCC cost of 0.0014** — very
nearly free on MCC. We should correct our own earlier estimate: the counterfactual
in the previous document predicted ΔMCC ≈ −0.007, and the t ≤ 44 s smoke test
suggested a much larger drop (0.4694 → 0.3906). Both overstated the cost, the
smoke test badly, because at 44 s the LSTM-AE has not filled its window. **The
measured 300 s cost is 5× smaller than our counterfactual and ~50× smaller than
the smoke test implied.**

### Two things that do NOT change

**1. The ordering is not restored.** With the OR-flag off:
**D6 (0.4841) > D1 (0.4794) > D4 (0.4777)** — still D6 > D1 > D4, and the D4−D1
gap widens slightly from −0.0011 to −0.0017. **The OR-flag is not what breaks the
ablation ordering** (this is the correction recorded in §0).

**2. It does not reach the 0.05 requirement.** 0.1554 is still ~3× over.

### DQ-STEP5 — measured FP-vs-time histogram, OR-flag ON vs OFF

| 10 s bin | OR-ON | **OR-OFF** | change |
|---|---|---|---|
| t = 140–150 | 59 | **4** | −93 % |
| t = 150–160 | 76 | **2** | **−97 %** |
| t = 160–170 | 141 | 64 | −55 % |
| t = 170–180 | 194 | 113 | −42 % |
| t = 180–190 | 162 | 107 | −34 % |
| **t = 190–200** | 424 | **403** | **−5 %** |
| t = 200–210 | 431 | 412 | −4 % |
| t = 210–220 | 444 | 371 | −16 % |

**The steps do not disappear — they become sharper.** Before the steps the OR-flag
accounts for essentially all false positives (76 → 2, a 97 % reduction). After
them it accounts for almost none (424 → 403, 5 %).

**This separates the false positives into two distinct populations:**

1. **Baseline FPs (t < 160 s)** — almost entirely OR-flag artefacts. Removable by
   disabling the flag, at the ghost-recall cost in §3d.
2. **Step FPs (t > 160 s)** — contamination-driven, and **essentially untouched by
   the OR-flag.** These are the impersonation victims arriving with poisoned
   state.

Answering your test directly: *"If the steps disappear, the OR-flag bypass is
causing them. If they persist, the contamination is in the rule or fusion tier."*
**They persist at 95 % of their magnitude. The contamination is not in the
OR-path**, which is also why disabling the flag moves FPR only 0.215 → 0.155: it
removes the baseline but leaves the spike intact.

**Correction to our own text:** an earlier draft of this section asserted the
steps persist *without* having measured the histogram. The table above is the
measurement, and it supports the claim — but we should not have written it before
running it.

### Our recommendation, updated

The OR-flag is a **cheap FPR reduction** (−0.06 for −0.0014 MCC) but it pays for
that by discarding **73.5 % of ghost detections** (§3d). Since ghost recall is
already the largest single component of the MCC gap, we still advise fixing ghost
routing first — after which those detections arrive through Φ legitimately and
the OR-flag can be retired with neither the FPR cost nor the recall loss.

If you want the FPR number down *now* and are willing to accept lower ghost
recall, disabling it is defensible on this evidence. That is your call, and we
have not changed the default.

---

## 3k. DQ-G10 — the a3-specialised model is dramatically WORSE

Single-attack run, `--attack_number=3`, ρ_a = 0.40, 100 s, which loads
`models/urban_a3/` instead of `models/urban_combined/`.

| | combined model (300 s) | **a3-specialised model (100 s)** |
|---|---|---|
| ghost recall | 0.2007 | **0.0074** |
| real-vehicle recall | 0.9715 | **0.4649** |
| honest FPR | 0.2077 | 0.0815 |
| ghosts as share of poisoned | 80.4 % | 80.4 % |

Your hypothesis was that the combined model may be **under-specialised** for a3
ghosts. **The measurement is the reverse: the a3-dedicated model detects 0.74 %
of ghosts against the combined model's 20.07 % — roughly 27× worse — and its
real-vehicle recall is less than half.**

**Caveat we state rather than gloss:** the durations differ (100 s vs 300 s), and
at 100 s the LSTM-AE is less well filled, so part of the gap is duration. But a
27× difference in ghost recall cannot plausibly be attributed to that alone —
particularly since ghosts receive **no AE scoring at all** (§3g), so AE window
filling cannot explain the ghost figure.

**Conclusion: model specialisation is not the lever for ghost detection.** This
reinforces §3g — the ghost problem is architectural (ψ ≡ 0, `ae_norm` ≡ 0,
`k̂ = −1` for 71.4 %), not a question of which weights are loaded. Retraining or
specialising a model that receives two of three inputs as hard zeros cannot help.

---

## 3l. DQ-FP7 — a4 alone does NOT reproduce the contamination (and this qualifies §0)

Single-attack run, `--attack_number=4`, ρ_a = 0.40, 300 s, which loads
`models/urban/` rather than `models/urban_combined/`.

| | combined (D6, 300 s) | **a4-only (300 s)** |
|---|---|---|
| overall honest FPR | 0.2150 | **0.3361** |
| MCC_full | 0.4855 | **0.679** |
| **vid 98 FPR** | **1.0000** (622/622) | **0.1768** (110/622) |
| vid 98 forged beacons | 2 223 | 1 212 |
| vid 98 forging lead | +120.7 s | **+179.0 s** |

### The finding that qualifies our own headline

You asked us to confirm vid 98 is an impersonation target in the a4-only run.
**It is** — 1 212 forged beacons, first at t = 14.357 s against a first honest
beacon at t = 193.377 s, a pre-arrival window of **179 s, longer than the 120.7 s
in combined mode.**

**And yet its FPR is 0.1768, not 1.0000.**

**So a longer pre-arrival forging window produced a *lower* false-positive rate.**
That directly contradicts a simple dose-response reading of §0, and we are
flagging it rather than leaving the headline overstated.

### What survives, and what we withdraw

**Survives:** the pre-arrival mechanism itself is real and traced (§3e) — forged
beacons build `vehicle_state[vid]` before the victim transmits, via a single
global array, with disjoint RSU sets. That is code-level fact, not inference.

**Withdrawn:** the implication that pre-arrival contamination *alone* accounts for
vid 98's 100 % FPR in combined mode. It is **necessary but not sufficient**. The
severity depends on something additional that is present in combined mode and
absent in a4-only.

**Most likely the RSU-level path from §3f.** In combined mode vid 98 is served by
RSU 44, which carries an overall honest FPR of 0.3630 from 3 742 forged beacons
belonging to *many* attacks. In a4-only there is only one attack contributing.
That is consistent with the a4-only top-FP list, where **six of the eight worst
vehicles have zero forged beacons of their own** (129, 196, 205, 195, 203, 91, 27)
— they are contaminated by their RSU, not by impersonation of their own ID.

So the correct statement is **two contamination paths that compound**: per-vehicle
state poisoning (§3e) and per-RSU spatial-baseline poisoning (§3f). Combined mode
supplies both; a4-only supplies mainly the first, and produces ~1/6 the effect.

### One comparison we will not draw

a4-only shows a **higher** overall FPR (0.3361 vs 0.2150) *and* a **higher** MCC
(0.679 vs 0.4855). These are not comparable to combined mode: the run loads a
different model (`models/urban/`), and its poisoned/honest mix differs. We report
the numbers for completeness but draw no conclusion from the cross-mode delta.

---

## 3m. DQ-FP11 — RSU transitions in the step windows are impersonation, not movement

You asked whether any attacker moves into a new RSU coverage zone at t ≈ 160 s or
t ≈ 190 s, on the theory that a new RSU joining the impersonation loop would
produce a discrete FP step.

**There are many RSU transitions in both windows, but they are not vehicle
movement.** A representative extract from t = 155–156 s:

```
t=155.060  vid=196  RSU35 -> RSU19  (forged)
t=155.121  vid=196  RSU19 -> RSU35  (forged)
t=155.260  vid=196  RSU35 -> RSU19  (forged)
t=155.413  vid=196  RSU19 -> RSU35  (forged)
t=155.086  vid=177  RSU27 -> RSU46  (forged)
t=155.187  vid=177  RSU46 -> RSU27  (forged)
t=155.103  vid=79   RSU44 -> RSU36  (forged)
t=155.255  vid=79   RSU36 -> RSU44  (forged)
```

**Each vehicle ID oscillates between a fixed pair of RSUs several times per
second, and every one of these beacons is forged.** vid 196 alternates
RSU35 ↔ RSU19, vid 177 RSU27 ↔ RSU46, vid 79 RSU44 ↔ RSU36.

No vehicle crosses a cell boundary ten times per second. **This is the signature
of two spatially separated transmitters emitting under the same vehicle ID** —
i.e. the impersonation itself, visible directly in the RSU assignment sequence.

**Answering your hypothesis:** it is not a *new* RSU entering the loop at the step
times. The oscillation is present throughout, so it is not what triggers the
steps — consistent with §3b, where the steps are victim arrivals.

### An unexploited detection signal

This pattern is worth flagging on its own. **Sub-second alternation of one
vehicle ID between two fixed RSUs is physically impossible for a real vehicle**,
and nothing in the current detector uses it. It requires no model, no training and
no trust score — only the RSU-assignment history that is already being recorded.

It is also precisely the signal the current architecture destroys: because
`vehicle_state` is a single global array keyed by header ID (§3e), beacons from
both transmitters are merged into one history, and the contradiction is averaged
away rather than detected. **A per-RSU or per-(RSU, vid) view would expose it.**

We raise this as a candidate mechanism for the contamination fix in §5.1 — an
identity-binding check could use exactly this evidence.

---

## 4. Status of the remaining diagnostics

**Coverage across both letters — 35 diagnostics in total** (DQ-STEP1–5 from the
first letter; DQ-G1–G12, DQ-FP1–FP15, DQ-MCC1–3 from the second):

| | count | items |
|---|---|---|
| **Answered in full** | **28** | DQ-STEP1, STEP2, STEP3, STEP5 · DQ-G1, G2, G3, G4, G5, G8, G9, G10, G11, G12 · DQ-FP3, FP5, FP6, FP7, FP8, FP9, FP11, FP12, FP13, FP14, FP15 · DQ-MCC1, MCC2, MCC3 |
| **Partial** | **4** | DQ-STEP4, DQ-FP2, DQ-G6, DQ-G7 |
| **Outstanding** | **3** | DQ-FP1, DQ-FP4, DQ-FP10 |

Also delivered, beyond the diagnostics: the **Eq 3.69 quorum retest** (§2), the
**Blocking Issue 1** 300 s confirmation (§1), **Blocking Issue 3** ON-vs-OFF
measurement (§3j), and an **offline τ_i experiment** (§3h) that you did not ask
for but which follows from DQ-G12.

**Outstanding — 3 fully, 3 partially. Stated precisely so the coverage is not
overstated:**

**Partial (answered in substance, one sub-question short):**

| item | what is answered | what is not |
|---|---|---|
| **DQ-STEP4** | the forging window for vid 98 (first forged t = 72.809, +120.7 s before its first honest beacon) and the RSU-pair oscillation in the step windows (§3m) | the **attacker vehicle IDs** themselves. The logs record the header vid, not the physical NS-3 transmitter, so we cannot name the forgers without instrumentation |
| **DQ-FP2** | when impersonation begins per victim (§0, §3b) | the **count of distinct physical attacker nodes** and their per-node start times — same reason |
| **DQ-G6 / DQ-G7** | GAT invocation node counts: **N = 1 in 53 %, ≤ 2 in 69 %** of calls (§3c) | which vids are in each call, so we cannot give a ghost's specific neighbours or a per-epoch ghost:honest ratio |

**Fully outstanding — all requiring new instrumentation:**

| item | what is missing | note |
|---|---|---|
| **DQ-FP1** | a dump of `vehicle_state[98]` at fixed timestamps vs SUMO ground truth | the array is never printed. **The key answer is already implied:** RSU 18/19 write forged data from t = 72.809 and no honest beacon exists until t = 193.546, so divergence begins at **t = 72.809** (§3e) |
| **DQ-FP4** | a counter on `save_state_rsu` (`08_detection_engine.h:3974`) | a local `bool`, never counted. **§3e already shows the path cannot help here** — honest and forged beacons for vid 98 never share an RSU |
| **DQ-FP10** | the dead-reckoning residual `r_i(t)` vs δ_th | computed as a local `double` at `:503-506` and never logged. **This is the one carrying genuinely new information** — whether residuals are marginally or enormously above threshold |

All three sit in the same code path, so **one instrumented run answers all three**
(~20 min to instrument, then a run of ≥ 200 s since vid 98 does not appear until
t = 193.5). We have not done this because the answers are confirmatory rather
than decision-changing, and your five decisions gate the next phase. Say the word
and we will run it.

**One caveat if DQ-FP1 is wanted:** it needs SUMO ground-truth positions, and we
have a recorded defect where `gt_pos_x/y` were wrong (a NodeID off-by-2). The fix
exists in `10_metrics_csv.h` but may not be in the current binary — we would
verify that before trusting any ground-truth comparison.

**DQ-FP7** is delivered in §3l.

**One scoping note.** DQ-G10 and DQ-FP7 specify single-attack mode
(`--attack_number=3` / `=4`). Single-attack runs load `models/urban/`, **not**
`models/urban_combined/`, so their absolute numbers are not directly comparable
to combined-mode results. They remain valid for the within-run comparisons you
asked for (ghost vs real recall; whether vid 98 is contaminated by a4 alone), and
we will label them accordingly.

---

## 5. What we need from you

**Priority order we propose — please confirm or reorder:**

**1. Pre-arrival identity contamination (§0, §3b, §3e, §3f) — do this first.**
It is the common cause of the FPR growth, the MCC decay from 0.6073 to 0.4855,
and the ordering failure. The fix is architectural: per-RSU `vehicle_state`, or
an identity-binding check that refuses to initialise `vehicle_state[vid]` from a
beacon whose physical transmitter is not the registered owner of that ID.
Everything else below is downstream of it.

**2. Ghost routing (§3d, §3g).** Three independent defects: ψ ≡ 0 (MP-S1 fires on
zero ghosts), `ae_norm` ≡ 0 (the AE is explicitly not extended to ghosts), and
`k̂ = −1` for 71.4 %. Ghosts that reach a real head are detected with recall
**1.0000**, and `vid ≥ 10000` is available at the routing site — so forcing
`k̂ = 2` is a one-line change on the same lines as the existing overrides.
DQ-G10 (§3k) shows model specialisation is **not** the lever; this is.

**3. The OR-flag — your call, and now measured (§3j).** Disabling it costs
**ΔMCC = −0.0014** and buys **ΔFPR = −0.060**, which is close to free on MCC. But
it also discards **73.5 %** of ghost detections (§3d). Our recommendation is to
fix ghost routing first, after which those detections arrive through Φ
legitimately and the flag can be retired with neither cost. If you want the FPR
number down immediately and accept lower ghost recall, disabling it is defensible
on this evidence. **We have not changed the default.**

**4. Controller floor (§2) — required before CP-DETECT can be used at all.**
The corrected quorum leaves `C_trusted` empty: all four controllers excluded
inside epoch E7. Either floor the exclusion (mirroring the RSU BFT guard at
`smartcontract.go:2153`) or require multi-epoch corroboration. We implemented
your quorum change exactly and did **not** add a floor, as that would be
re-deciding your decision.

**5. The 0.90 target (§3).** Fixing both known causes completely yields a
measured **0.8418**. Reaching 0.90 needs a third improvement source. Is that in
scope, or should the target be revisited?

**6. τ_i (§3g, §3h) — in scope this round, or documented as a limitation?**
τ_i is a hardcoded constant 1.0 and the on-chain trust score is never read back
by any detector. Replaying SC-Trust's own Eq 3.55 causally gives AUC 0.7161
standalone and 0.767 within the uncertain Φ band — real signal is being
discarded. Wiring it needs a trust mirror plus retraining both models, and must
come *after* the contamination fix, because τ is currently *inverted* in the
low-Φ band (AUC 0.0666) by that same contamination.

**7. Multi-seed (§1).** Needed regardless before any ablation ordering is
published, but note §0: the ordering is stable for 250 s of a 300 s run, so the
contamination fix is the higher priority.

We have not run any final experiment and will not until these are settled.

**One thing we want to be explicit about.** It would have been easy to present a
restored ordering by running at a shorter duration, or by switching off the
OR-flag, and both were suggested. We have done neither: 30 s is a duration we
ourselves demonstrated is invalid for ablation (the AE is silent on 58.2 % of
beacons, and at t ≤ 30 s D4 and D6 have *identical* recall), and disabling the
OR-flag costs recall we have not shown is worth trading. The ordering should be
restored by removing the defect that breaks it, and that is what §0 recommends.
