# Progress on Fixes 1–3, and a question about evaluation duration
**Date:** 2026-08-06 · **Branch:** `ml-review-fixes`

All three prescribed fixes are implemented and measured. Two work, one does not.
Section 5 puts a **scoping question** to you about evaluation duration — we have
a view on it and state it plainly, but the decision is yours.

---

## 1. Summary

| Fix | Verdict |
|---|---|
| **Fix 1** — vehicle-state identity binding | ❌ **Does not work.** Implementation defect found by instrumentation; also raises a threat-model question (§2) |
| **Fix 2** — ghost routing to a3 | ✅ **Works — after correcting the prescription.** Implemented verbatim it produced label leakage (§3) |
| **Fix 3** — controller floor | ✅ **Works exactly as specified** (§4) |

**Headline result:** with Fix 2, **D6 > D4 > D1 is restored with a real margin**
(D4 − D1 = **+0.0617**, against **−0.0011** before), at **zero false-positive
cost**, and peak MCC rises **0.6073 → 0.6621**.

**Still open:** FPR at 300 s. Fix 2 does not address it by design.

---

## 2. Fix 1 — implemented, verified to fire, and it does not work

Implemented as prescribed: an identity check **before** any `vehicle_state`
write, with the owner map built at startup from the NS-3 node registry (not
trust-on-first-use — the pre-existing `g_vehicle_dsrc_ip[]` map is populated on
first reception, and in this attack the **attacker transmits first**, so it would
have recorded the attacker as owner).

**It rejected everything.** Instrumented counters:

```
[FIX1] idbind checked=3912  rejected=3912  of which poisoned=2652  HONEST=1260
```

**3912 of 3912 — every beacon failed, honest ones included.** The owner lookup
derives the DSRC interface index from the vehicle node ID, and that inference is
wrong: observed source addresses are `3.0.0.(vid-8)` while the map computes
`3.0.0.(vid-5)`. No beacon could ever match.

**Consequence:** with the check on, nothing could write `vehicle_state`, which
suppressed detection — measured MCC 0.5754 → 0.4519, recall −0.118. **Default
OFF**, documented in code.

### A threat-model question this raises

Before we re-implement, we would like your view. Fix 1 binds identity to the
**network source address**. But the attack model grants the attacker the
victim's HMAC key — `lkh_compute_beacon_hmac(victim_v_idx, …)` at
`09_vehicle_beacon_tx.h:406` (Sybil) and `:604` (MitM). An adversary holding
stolen credentials would plausibly spoof the source address too.

If so, address binding works in simulation only because the simulation does not
model address spoofing — which is uncomfortably close to the leakage trap in §3.
**Is address-based identity binding within the threat model, or should the
defence be behavioural?**

*(Related: because forged beacons carry valid MACs, Eq 3.37 authentication cannot
prevent this contamination by construction. We tested a fail-closed variant of
the HMAC gate — results were bit-identical, confirming the attacks are not
exploiting a missing MAC. Flag left off.)*

---

## 3. Fix 2 — works, but the prescription needed correcting first

### Implemented verbatim, it produced label leakage

Your prescription was `if (vid >= GHOST_VID_BASE) k_hat_i = 2;`. Implemented
exactly, ghost recall jumped to **1.0000 in all three arms — including D1**,
which has no GAT and previously detected **zero** ghosts.

The cause: the OR-flag at `08_detection_engine.h:2288` fires on `k̂` **without
requiring the GAT to have scored**. Setting `k̂ = 2` from the vehicle ID
therefore forces `full_flag = true` on identity alone. Measured:

```
D1: 2619 ghost detections — 0 via Φ>0.5, 2619 (100%) via the OR-flag bypass
```

`vid >= 10000` is an artifact of the attack generator; a real Sybil would forge
plausible IDs. **This was reading the ground-truth label, not detecting.** We did
not ship it.

### The corrected version

`k̂ = 2` is still applied for **weighting**, but tagged `khat_from_ghost_id` and
**excluded from the OR-flag bypass**, so detection must come from Φ crossing
threshold on the GAT's real spatial score.

| | ghost recall | via Φ | via OR-flag |
|---|---|---|---|
| D1 | **0.0000** | 0 | **0** |
| D4 | **0.4877** | all | **0** |
| D6 | **0.4877** | all | **0** |

**Ghost recall 0.2011 → 0.4877 on the GAT arms, entirely genuine; D1 correctly
unchanged at zero.**

**A correction to the expected figure:** you anticipated recall 1.0000, citing
DQ-G1. That measurement was on ghosts the ML classifier had *already* routed to
a3 — a self-selected population. Forcing all ghosts in does not inherit that
property. The honest number is **0.4877**.

### Effect on the ablation (D6, matched cutoffs)

| cutoff | pre-fix MCC | **Fix 2 MCC** | FPR (**identical**) |
|---|---|---|---|
| t ≤ 60 | 0.5037 | **0.5926** | 0.0299 |
| t ≤ 100 | 0.5461 | **0.6241** | 0.0468 |
| t ≤ 140 | 0.5987 | **0.6621** | 0.0558 |
| t ≤ 160 | 0.6073 | **0.6621** | 0.0611 |
| t ≤ 225 | 0.5707 | **0.6180** | 0.1671 |

**FPR is byte-identical at every cutoff** — Fix 2 adds no false positives
whatsoever. Ordering at t ≤ 225: **D6 0.6180 > D4 0.6084 > D1 0.5467**, with
D1 unchanged from pre-fix in all three columns (the clean proof that Fix 2
reaches only the GAT arms).

---

## 4. Fix 3 — works as specified

Floor added to `excludeAndReassignController`, mirroring the RSU guard at
`smartcontract.go:2144-2153`; refuses any exclusion that would empty
`C_trusted`. Chaincode rebuilt, container swapped, verified live.

| | BC9 (no floor) | **BC10 (Fix 3)** |
|---|---|---|
| `CFLAG` records | 14 | **6** |
| Controllers excluded | **4 of 4** | **3 of 4** |
| `GetActiveController` | ❌ *"no active controller in C_trusted"* | ✅ **CTRL_3** |

**Detection is preserved and the control plane is retained.** The CFLAG count
differs from BC9 because Fix 2 changed detection upstream; the floor criterion is
the exclusion count, not the flag count.

Registration integrity verified before trusting any of this: **200/200 vehicles,
64/64 RSUs, 4/4 controllers, 0 access-denied, 0 insufficient-endorsements**, and
`ResetLedger` confirmed to have wiped BC9's state rather than silently no-opping.

---

## 5. The question: evaluation duration

### The measurement

D6 under Fix 2, same run, evaluated at increasing cutoffs:

| duration | MCC | FPR | meets FPR ≤ 0.05? |
|---|---|---|---|
| **t ≤ 100** | 0.6241 | **0.0468** | ✅ **yes** |
| t ≤ 120 | 0.6559 | 0.0517 | ✗ marginal |
| t ≤ 140 | **0.6621** | 0.0558 | ✗ 1.1× |
| t ≤ 160 | **0.6621** | 0.0611 | ✗ 1.2× |
| t ≤ 200 | 0.6356 | 0.1181 | ✗ 2.4× |
| t ≤ 225 | 0.6180 | 0.1671 | ✗ 3.3× |
| t = 300 | ~0.57 (proj.) | ~0.215 | ✗ 4.3× |

**Only t ≤ 100 satisfies both goals simultaneously** — ordering restored *and*
FPR inside 0.05. Intermediate durations (200 s, 250 s) do **not** help: FPR is
already 2.4× over at 200 s.

### The question we are asking

Given the time remaining, would you accept **reporting at 100 s** for this round,
with the 300 s result and its cause documented as a known limitation?

### What we are obliged to say against it

We do not recommend it, for three reasons, and you should have them before
deciding:

1. **The reason 100 s passes is that it excludes a known defect.** The
   contaminated vehicles arrive at t = 164 (vid 202) and t ≈ 193 (vid 196, 98).
   Any window ending before ~160 s excludes the failure by construction. That is
   a property of the window, not of the system.
2. **It is post-hoc.** You mandated 300 s, and we have already reported the 300 s
   trajectory to you. Choosing a shorter window afterwards, having seen which
   window flatters the result, is the kind of selection a reviewer is likely to
   query — and the trajectory is in our own prior document.
3. **It understates the system.** Peak MCC is at t ≈ 140–160 (**0.6621**), not at
   100 s (0.6241). Truncating at 100 s reports a *worse* MCC than the system
   actually achieves.

### The alternative we would prefer

Report at 300 s and state the result as it is:

> Under Fix 2 the system reaches **MCC 0.6621 at FPR 0.056–0.061** and sustains
> **D6 > D4 > D1** from t = 44 s through t = 250 s. Both degrade in the final
> third due to an identified state-contamination defect
> (`04_state_globals.h:58`, `08_detection_engine.h:1151`), for which two
> candidate fixes are specified.

That is FPR **10 % over** the requirement at peak — not 4× — and it is true at
the duration you mandated. Fix 2 moved us from "fails by 4×" to "misses by 10 %".

### If time is the binding constraint

Duration is the one axis we would not cut, because it is the axis the defect
lives on. These reduce compute without selecting the window:

- fewer seeds (3 rather than 5)
- fewer arms (D1/D6 only — D4 is the marginal one)
- a single ρ_a rather than a sweep

---

## 6. What remains, and our proposal

**Open:** FPR at 300 s. Cause identified to line numbers; two candidate fixes:

1. **Per-`(vid, transmitter)` state separation** — contain the contamination
2. **RSU-oscillation detector** — a vehicle ID alternating between two fixed RSUs
   sub-second (measured: `vid 196: RSU35 ↔ RSU19`, ~10×/second, all forged) is
   physically impossible. Needs no model, no training, no ground truth.

**One constraint on any such fix, which we found the hard way:** MP-S2 currently
has recall 0.9903 *because* forged beacons are compared against the victim's
contaminated history. The shared state that causes the false positives is also
what makes the attack visible. A fix that merely blocks or separates state
removes the FPs **and** the TPs — which is exactly what Fix 1 measured.

So the fix must **replace** the accidental detection with an intentional one.
Option 2 does this: it flags the impersonation (TP) *and* skips the contaminating
write (FP removed) from one mechanism.

**We propose implementing Option 2 behind a flag, default off, and measuring
it** — the same discipline that caught the Fix 2 leakage. Estimated one hour plus
one 300 s run.

**Decision needed:** the duration question in §5, the threat-model question in
§2, and approval to proceed with Option 2.
