# Sensitivity analysis — exact replacement values and where they go

**No code was changed.** All 31 runs below used the unmodified, committed
binary (`result-combined-300s-20260807`), varying one CLI flag at a time,
`--simTime=30`, all other flags at the canonical values in `RUN_CONFIG.md`.
Full raw output: `$SCRATCH/sweep30/results.csv`.

Two numbers are reported for every run because the simulator prints two
confusion matrices — **this is the fact that makes the replacement non-trivial,
see §0.**

---

## §0 — Read this before replacing anything

The simulator prints:

```
Confusion matrix (LW / A1):     ...   MCC = ...   FPR = ...
Confusion matrix (Full/Fusion): ...   MCC_full = ...   FPR_full = ...
```

**The paper's `tab:set-lw` sweep tables (`tab:threshold-sensitivity`,
`tab:drift-sensitivity`, `tab:window-sybil-sensitivity`, `tab:kl-sensitivity`,
`tab:smax-sensitivity`) are all LW-mode tables** — they exist to calibrate the
*lightweight* detector, which is exactly what these parameters feed. Use the
**LW** column below for those five tables.

`tab:attackpct-sensitivity` is a whole-system table — use **Full**.

Do not swap these. A threshold that helps LW MCC does not necessarily help
Full MCC, and the data below shows exactly that split.

---

## §1 — Replace `tab:threshold-sensitivity` (ψ_th)

**Location:** `report/main.tex`, `sec:param-rationale`, table `tab:threshold-sensitivity`.

Current paper values do not reproduce (0.776 → 0.606 across the range; see
below for the actual response). Replace the table body with:

| ψ_th | MCC (LW) | FPR (LW) |
|---|---|---|
| **0.05** | **0.359** | 0.043 |
| 0.07 | 0.359 | 0.043 |
| 0.09 (code default) | 0.359 | 0.043 |
| 0.11 | 0.367 | **0.017** |
| 0.15 | 0.238 | 0.015 |

**Recommended selection: 0.11**, not 0.05. It gives the highest LW-MCC in the
sweep (0.367) at less than half the FPR of 0.05–0.09 (0.017 vs 0.043). 0.15
degrades MCC sharply (too strict, real detections lost) without recovering
much FPR.

If keeping ψ_th = 0.05 or 0.09 for consistency with other parts of the
pipeline, state explicitly that 0.11 was measured better and 0.05/0.09 is a
deliberate trade-off, not the empirical optimum — otherwise the "selected in
bold" convention used elsewhere in the paper is violated.

**Full-mode MCC is unaffected by ψ_th at every value (0.869 flat).** Confirms
what the code-side audit found: ψ_fuse saturates before the psi_th division
matters. Worth one sentence in the paper text, since it explains why this
parameter can be tuned for LW recall/precision without touching the headline
Full-mode number at all.

---

## §2 — Replace `tab:drift-sensitivity` (δ_th, TP-S5)

**Location:** `sec:param-rationale`, table `tab:drift-sensitivity`.

| δ_th (m) | MCC (LW) | FPR (LW) |
|---|---|---|
| 5.0 (code default) | 0.359 | 0.043 |
| 7.5 | 0.359 | 0.043 |
| 10.0 | 0.354 | 0.043 |
| 12.5 | 0.355 | **0.041** |
| **15.0** | **0.355** | **0.041** |

The response is nearly flat across the whole range (0.354–0.359), unlike the
paper's current table which swings 0.715 → 0.525 → 0.730. **Keep δ_th = 5.0 or
7.5** — both give the top MCC (0.359) at the code's current default, so no
change to the deployed value is needed. 12.5/15.0 trade 0.004 MCC for a
marginally lower FPR; not worth it unless FPR is the binding constraint.

---

## §3 — Replace `tab:window-sybil-sensitivity`, panel (a): drift window

**Location:** `sec:param-rationale`, table `tab:window-sybil-sensitivity`, left panel.

| window (beacons) | MCC (LW) | FPR (LW) |
|---|---|---|
| 5 | 0.356 | 0.043 |
| 10 (code default) | 0.359 | 0.043 |
| **15** | **0.362** | 0.043 |
| **20** | **0.362** | 0.043 |

15 and 20 tie for best and both beat the code's current default of 10.
**Recommend changing the code default from 10 to 15** (small, monotone gain;
20 buys nothing over 15). This is the one place in this sweep where the
deployed value is not already the best point — flag it to the project owner as
a candidate default change, separate from any paper-only correction.

## §3b — Replace `tab:window-sybil-sensitivity`, panel (b): K_sybil

| K_sybil | MCC (LW) | FPR (LW) |
|---|---|---|
| 3 | 0.359 | 0.043 |
| 4 | 0.359 | 0.043 |
| **5 (code default)** | 0.359 | 0.043 |
| 6 | 0.359 | 0.043 |

**Completely flat.** K_sybil has no measured effect at any value in 3–6 under
this configuration. The paper's current table (0.903 → 0.985 → 0.970 → 0.902)
does not reproduce at all. Either K_sybil interacts with `ring_detect` (which
also sets the MP-S1 bit and was OFF in whatever produced the original numbers)
or the original sweep used a different attack configuration. **This table
needs the widest caveat of any in this document** — state that K_sybil is
measured flat post-fix and the mechanism for the original curve is unresolved,
rather than silently replacing the numbers.

---

## §4 — Replace `tab:kl-sensitivity` (κ_th, MP-S3)

**Location:** `sec:param-rationale`, table `tab:kl-sensitivity`.

| κ_th (nats) | MCC (LW) | FPR (LW) |
|---|---|---|
| **0.10 (code default)** | **0.359** | 0.043 |
| 0.30 | 0.359 | 0.043 |
| 0.50 (paper's current selection) | 0.359 | 0.043 |
| 1.00 | 0.357 | 0.043 |

Nearly flat, consistent with the paper's own description of this parameter as
"insensitive over [0.1, 1.0]". **The direction is right; only the numbers need
replacing** — paper currently shows 0.345→0.316, actual is 0.359→0.357. Keep
the code default of 0.10 (marginal best) rather than the paper's 0.50; the
difference is in the fourth decimal, so this is a low-priority correction.

---

## §5 — Replace `tab:smax-sensitivity`, urban column only

**Location:** `sec:param-rationale`, table `tab:smax-sensitivity`, **urban third of the table only** — rural and highway were not part of this sweep (different scenario configs) and are unaffected by anything here.

| s_max (km/h) | MCC (LW) | FPR (LW) |
|---|---|---|
| 80 | 0.361 | 0.043 |
| **100 (code default)** | 0.357 | 0.043 |
| 120 | 0.359 | 0.043 |

Effectively flat (0.357–0.361). The paper's current urban column (0.662 →
0.645 → 0.571) does not reproduce. **Recommend bolding 80** (marginal best,
0.361) but the difference from 100 is within noise for a single seed — say so
if reporting only one run.

---

## §6 — Replace `tab:attackpct-sensitivity` — use the FULL-mode column

**Location:** `sec:param-rationale`, table `tab:attackpct-sensitivity`.

| ρ_a (%) | MCC (Full) | FPR (Full) | note |
|---|---|---|---|
| 0 | **undefined** | 0.026 | no positives exist — do not report as 0.000, see below |
| 20 | 0.894 | 0.016 | |
| **40 (default)** | **0.869** | 0.024 | |
| 60 | 0.855 | 0.000 | |
| 80 | 0.548 | 0.000 | |
| 100 | **undefined** | — | no negatives exist |

**Two rows must not be published as "0.000":**
- At ρ_a=0, confusion matrix is `TP=0 FP=80 TN=3040 FN=0` — zero positive
  ground truth. MCC's denominator has a zero factor; the value is
  mathematically undefined, not zero. Report as "—" or "undefined (no attack
  present)".
- At ρ_a=100, confusion matrix is `TP=5104 FP=0 TN=0 FN=106` — zero negative
  ground truth. Same issue, opposite class.

Reporting either as MCC=0.000 reads as "the detector performs at chance",
which is the opposite of what's actually happening (at ρ_a=100 the detector
still has 5104/5210 = 98% recall — it simply has no clean traffic to score a
false-positive rate against).

**The response is real and worth keeping:** MCC peaks at 20% (0.894), is still
strong at the reported default of 40% (0.869), and degrades under saturation
toward 80% (0.548) as the clean class shrinks — consistent with the "small
clean class costs more MCC per FP" mechanism already documented in this
project's memory. This qualitative story survives even though the exact
numbers (0.727/0.652/0.603 in the paper) don't reproduce.

---

## §7 — NOT covered by this sweep, still open

| item | status |
|---|---|
| θ_S (`theta_s.txt`) | **Offline-only finding, no run.** Lowering from 19.74 to 6–8 restores full-300s ordering D1<D4<D6 and raises D6 to ~0.796. Requires editing a deployed model artefact — awaiting your go-ahead, not run. |
| θ_ae formula (`tab:kappa-sensitivity`) | Paper's mean+κ·σ formula computes to ~301,229 vs deployed 33.69. This is a **formula defect**, not a sweep gap — no CLI flag fixes it. See `SENSITIVITY_RESWEEP_2026-08-07.md` §1. |
| Φ_th (`tab:phith-sensitivity`) | Already resolved from the 300s log re-derivation, no new run needed — see `SENSITIVITY_RESWEEP_2026-08-07.md` §1. Paper's selected 0.40 is the worst of 5 points measured; keep 0.50. |
| ring_detect's 6 thresholds, `gat_det_flag_heads`, per-head θ_conf | Never swept at all, no table exists yet. |

---

## §8 — Summary table: what changes where

| paper table | file location | verdict |
|---|---|---|
| `tab:threshold-sensitivity` | §param-rationale | replace values, §1 — consider default 0.09→0.11 |
| `tab:drift-sensitivity` | §param-rationale | replace values, §2 — no default change |
| `tab:window-sybil-sensitivity` (a) | §param-rationale | replace values, §3 — **recommend default 10→15** |
| `tab:window-sybil-sensitivity` (b) | §param-rationale | flat / unresolved, §3b — flag, don't silently replace |
| `tab:kl-sensitivity` | §param-rationale | replace values, §4 — no default change |
| `tab:smax-sensitivity` (urban col only) | §param-rationale | replace values, §5 — no default change |
| `tab:attackpct-sensitivity` | §fullmode-sensitivity | replace values, §6 — fix the 0%/100% rows |
| `tab:phith-sensitivity` | §fullmode-sensitivity | already done, no new run — keep 0.50 |
| `tab:kappa-sensitivity` | §fullmode-sensitivity | **formula must change**, not just values |
