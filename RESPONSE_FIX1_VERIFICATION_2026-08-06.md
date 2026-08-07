# Fix 1 verification — vehicle-state identity binding
**Date:** 2026-08-06 · **Branch:** `ml-review-fixes`

Fix 1 implemented as prescribed and verified to fire. The 300 s measurement is
still running; this section will carry its result. **One derived quantity is
reported first because it changes how the Fix 1 result should be read.**

---

## 1. Implied recall requirement — derived from your targets, not proposed by us

You have set two targets: **FPR ≤ 0.05** and **MCC ≥ 0.84** (revised from 0.90).
You have not set a recall target, and we are not proposing one. But with the
measured class balance of the 300 s condition — **91 989 poisoned and 23 676
honest beacons (79.5 % poisoned)** — those two targets *jointly* determine the
recall needed. This is arithmetic on your numbers:

| FPR | recall required for **MCC 0.84** | for MCC 0.90 |
|---|---|---|
| 0.00 | 0.9213 | 0.9542 |
| **0.05 (your requirement)** | **0.9409** | 0.9707 |
| 0.10 | 0.9585 | 0.9853 |
| 0.15 | 0.9741 | 0.9983 |
| 0.2150 (current) | 0.9918 | **unreachable at any recall** |

Two things follow.

**First, this independently confirms your decision to revise 0.90 → 0.84.** At the
current FPR of 0.2150, MCC 0.90 cannot be reached even with perfect recall. The
target was not merely difficult; it was arithmetically out of range.

**Second — and this is why we raise it — current recall is 0.7824, and Fix 1
moves it to 0.5962.** A change that improves FPR can therefore still put MCC 0.84
further out of reach. Reported against FPR and MCC alone, a recall regression is
invisible until it has already cost the target.

### The two fixes are jointly sufficient, and it is Fix 2 that closes recall

Ghost recall is 0.2007; real-vehicle recall is 0.9715 (§3d of the previous
document). If Fix 2 lifts ghost recall to 90 %:

```
ghosts   20 754 × 0.90   = 18 679 TP
real     71 235 × 0.9715 = 69 205 TP
overall recall = 87 884 / 91 989 = 0.9554     (above the 0.9409 needed)
```

So **Fix 2 is what satisfies the recall side, and Fix 1 the FPR side.** Together
they give MCC ≈ 0.84 — which is the same figure DQ-MCC1(d) produced by a
different route (0.8418), so the two calculations corroborate each other.

**Implication for sequencing:** Fix 1 alone should not be expected to raise MCC.
It should be judged on whether it removes the FPR explosion at t > 160 s without
costing more recall than Fix 2 can restore.

---

## 2. Fix 1 — what was implemented

Exactly as prescribed: an identity-binding check **before** any write to
`vehicle_state`, not after.

| element | location |
|---|---|
| owner map, registry-derived | `04_state_globals.h:255` — `g_vehicle_owner_ip[]` |
| populated at startup | `12_main.h:1806` — `dsrc_interfaces.GetAddress(v)` |
| the check | `08_detection_engine.h:4004` — sender IP vs registered owner |
| the guard | `08_detection_engine.h:1151` — `if (identity_verified) push_beacon(...)` |
| DQ-FP4 counters | `g_idbind_checked`, `g_idbind_rejected` |

Confirmed at startup: `[FIX1-IDBIND] bound 200 vehicle IDs to their registry DSRC IPs (v0=3.0.0.1)`

### A trap your prescription avoided

The codebase **already contained** a vehicle-ID → IP map (`g_vehicle_dsrc_ip[]`,
`08:3521`) — but it is populated on **first reception**:

```c
if (v_idx >= 0 && v_idx < LKH_MAX_VEH && !g_vehicle_ip_known[v_idx]) {
    g_vehicle_dsrc_ip[v_idx] = sender.GetIpv4();      // trust-on-first-use
```

In this attack the **attacker transmits first** — forged beacons carrying vid 98
from t = 72.809 s, the genuine vehicle not until t = 193.546 s. That map would
therefore have recorded the attacker as the owner and **authorised precisely the
writes we need to block.** Your instruction to populate from the NS-3 node
registry at startup is what avoids this. We have documented the trap in the code
comment so it is not later "simplified" back.

### Verified firing

```
[FIX1-REJECT] vid=37 claimed by 3.0.0.29 but owner is 3.0.0.32 (write skipped)
[FIX1-REJECT] vid=45 claimed by 3.0.0.37 but owner is 3.0.0.40 (write skipped)
[FIX1-REJECT] vid=23 claimed by 3.0.0.37 but owner is 3.0.0.18 (write skipped)
```

Note `3.0.0.37` claiming **both** vid 45 and vid 23 — a single attacker
impersonating multiple victims, which the check separates correctly.

### Design decisions, stated for the record

- **The write is skipped entirely** — no save, no restore — per your instruction.
- **Detection still runs** on the rejected beacon, scored against the victim's
  genuine history.
- **Ghost IDs are exempt from the check.** They are already excluded from
  `vehicle_state` by `push_beacon`'s bounds test and are injected locally with no
  physical node, so counting them as identity failures would corrupt the DQ-FP4
  numbers.
- **The controller re-run path is unchanged** (new parameter defaults to `true`),
  so only the RSU receive path enforces.

---

## 3. Interim measurement — matched cutoffs, D6

The 300 s runs have not finished. These are matched-truncation comparisons
against the pre-fix run, and are reported as interim:

| cutoff | pre-fix (MCC / FPR / recall) | **Fix 1** | ΔMCC |
|---|---|---|---|
| t ≤ 30 | 0.4249 / 0.0534 / 0.6049 | 0.3554 / 0.0382 / 0.4919 | −0.070 |
| t ≤ 60 | 0.5037 / 0.0299 / 0.6212 | 0.4148 / 0.0199 / 0.4931 | −0.089 |
| t ≤ 100 | 0.5461 / 0.0468 / 0.6719 | 0.4521 / 0.0311 / 0.5402 | −0.094 |
| t ≤ 130 | 0.5893 / 0.0540 / 0.7309 | 0.4742 / 0.0488 / 0.5962 | −0.115 |

**Fix 1 reduces FPR at every cutoff and reduces recall at every cutoff, and so
far the recall cost exceeds the FPR gain.**

**These cutoffs cannot evaluate Fix 1.** The contamination it targets does not
begin until t ≈ 160 s, so every figure above shows the cost with none of the
benefit. Pre-fix, FPR runs 0.0540 at t ≤ 130 → 0.2150 at 300 s; the entire
explosion is in the final third. **The 300 s result is the only valid test** and
is reported in §4.

### Mechanism behind the recall loss

Blocking the write leaves `vehicle_state[vid]` empty when the forging precedes
the victim's first beacon. With `count = 0` the dead-reckoning and rate checks
cannot execute, so **forged beacons become unjudgeable rather than caught**.
Before the fix, the attacker's own beacons built a history that later forged
beacons were scored against — which sometimes flagged them. The fix removes that
path along with the contamination.

If §4 confirms the trade is unfavourable, the implication is that the fix is
**incomplete rather than wrong**: forged beacons should be recorded in a separate
per-`(vid, transmitter)` state so they remain detectable without contaminating
the victim's history. That is the "per-RSU vehicle state" alternative you listed,
and it preserves both properties. **We have not implemented it** — Fix 1 stands
exactly as you prescribed, and this is a recommendation for your decision, not a
unilateral change.

---

## 4. 300 s verification result

*To be completed when the three runs finish. Will report, as you requested:
per-vehicle FPR for the top-6, the FP-vs-time histogram and whether the steps at
t ≈ 160 s and t ≈ 190 s disappear, and simulator MCC for D1/D4/D6.*

---

## 5. Fix 2 and Fix 3

Both are specified but **deliberately not built into the binary used for this
verification** — you asked for the Fix 1 result first, and combining them would
make the attribution ambiguous. They will follow as separate verifications.
