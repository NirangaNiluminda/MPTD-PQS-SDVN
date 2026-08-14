# Progress update — SOTA experiment campaign

**What follows is real, measured data only.** Everything marked pending has not
been run yet and is not included in any number below.

---

## Completed: E5 (per-attack variant table), SENTINEL

7 attack variants, isolated (not combined), 200 vehicles, ρ_a = 0.40, 100s
sim time, 2–3 seeds each (mean shown). SENTINEL Full = GAT+LSTM-AE active;
SENTINEL LW-only = GAT/LSTM-AE disabled, rule signatures + HMAC only.

| Attack variant | SENTINEL Full — MCC | SENTINEL Full — FPR | SENTINEL LW-only — MCC | SENTINEL LW-only — FPR |
|---|---|---|---|---|
| TP-S1 (malicious RSU, trajectory) | 0.454 | 0.050 | 0.454 | 0.043 |
| TP-S2 (malicious vehicle, trajectory) | 0.925 | 0.048 | 0.943 | 0.029 |
| MP-S1 (Sybil via compromised RSU) | 0.710 | 0.041 | 0.679 | 0.043 |
| MP-S2 (Sybil via impersonation) | 0.900 | 0.088 | 0.925 | 0.043 |
| TP-S3 (control-plane trajectory) | **0.000*** | 0.048 | **0.000*** | 0.037 |
| MP-S3 (MitM, data-plane) | 0.927 | 0.052 | 0.950 | 0.039 |
| MP-S4 (control-plane global) | **0.000*** | 0.048 | **0.000*** | 0.037 |

\* **TP-S3 and MP-S4 are control-plane attacks — they never mark an individual
beacon as poisoned, so beacon-level MCC is structurally undefined (no
positives exist), not a genuine detection failure.** Confirmed with a separate
run: once the blockchain (CP-DETECT) is enabled and credited correctly, the
correct metric for these two — CDER (control decision error rate) —
comes out to **0.012**, i.e. the compromise *is* caught. This needs to be
finished properly for all 7 variants before it goes in the final table; noted
here so the two zeros above aren't misread as a detection failure.

## Completed: baseline retraining (B2/B3), fair 200-vehicle comparison

The B2 (Ercan) and B3 (Sharma) baseline classifiers had frozen models trained
on 135-vehicle data — a scale mismatch against our 200-vehicle scenario. Found
this, retrained both from scratch on pooled, **vehicle-grouped held-out** data
(620,504 beacons across attacks 1–7 × penetration 30/60/90%, so no vehicle's
beacons appear in both train and test):

| Method | MCC (held-out) | FPR (held-out) |
|---|---|---|
| B2 Ercan (global RF) | 0.64 (0.66 / 0.66 / 0.39 across 30/60/90%) | 0.20 |
| B3 Sharma (global RF) | 0.66 (0.68 / 0.67 / 0.38 across 30/60/90%) | 0.11 |

**Not yet integrated with E5** — these are the retrained models' own held-out
numbers, not yet scored per-attack against the same 7 scenarios E5 used.
B1 (Ghaleb, rule-based) also needs rerunning at 200 vehicles — the version
on file used stale 135-vehicle data. Both are the next concrete step.

---

## Currently running

| Experiment | Status |
|---|---|
| E2 (speed regime) | just started, 0/8 |
| E1 (penetration × intensity) | queued |
| E3 (scalability) | queued |
| E4 (threat level) | queued |
| E_A1 (AEGIS, TRS/PARR vs compromised ring) | queued |
| E_A2–E_A5 (AEGIS) | not yet built |
| RAPTOR (R1, R2, R4) | not yet built |

Current estimate for the SOTA portion of the campaign (excluding all
ablations, which come after): roughly 17–26 hours of continued execution
from now. This has moved twice already as real bugs were found and fixed
along the way (see below) — treat it as an order of magnitude, not a
committed deadline.

## Worth knowing: three real bugs found and fixed this session

1. Exported per-beacon data was being written to the wrong directory in every
   automation script — fixed; this also revealed the B1/B2/B3 scale mismatch
   above.
2. B1's default road-geometry assumption (a single road corridor) doesn't
   match our real 2D urban grid — fixed by wiring in the actual SUMO road
   network; B1's number went from a degenerate 0.0 to a genuine 0.25.
3. A naive same-run cross-validation setup for B2/B3 was producing a fake
   MCC ≈ 0.99 (data leakage) — caught before it was reported, replaced with
   the vehicle-grouped held-out split above.

None of this changes SENTINEL's own numbers — only the baseline comparison
methodology, which is now on solid footing.
