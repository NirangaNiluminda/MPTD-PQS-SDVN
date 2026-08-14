# Sensitivity analysis — what needs redoing, and the replacement data

**No code, no calibration file, and no model artefact was modified to produce
this.** All values below are re-derived from the existing 300 s logs of the
committed run (`result-combined-300s-20260807`).

## Method and its validation

Every fusion decision is recomputable from the per-beacon log, because the log
records the *raw* components (`psi_fuse`, `S`, `ae_raw`, `khat`) alongside the
derived `phi`. So fusion-tier parameters can be swept exactly, offline, with
zero reruns.

Validated before use, on all three arms:

| arm | rows | φ mismatch | **verdict mismatch** | re-derived MCC | simulator printed |
|---|---|---|---|---|---|
| D1 | 115,665 | 0 (0.00%) | **0** | 0.7630 | 0.763 |
| D4 | 115,665 | 529 (0.46%) | **0** | 0.7582 | 0.758 |
| D6 | 115,665 | 417 (0.36%) | **0** | 0.7664 | 0.766 |

Verdict mismatch is zero everywhere; the small φ deltas are float32-vs-float64
rounding and never flip a decision. The 781 / 72 / 441 rows the simulator
detects at φ ≤ Φ_th are the hard speed-bound override, which bypasses φ — they
are held detected at every swept threshold, as the code does.

---

## 1. Tables replaceable NOW (no rerun)

### `tab:phith-sensitivity` — fusion decision threshold Φ_th

Paper currently selects **0.40** with MCC 0.688 ± 0.069, FPR 0.085.
Measured (300 s, full mode D6):

| Φ_th | D6 MCC | D6 FPR | D4 MCC | D1 MCC |
|---|---|---|---|---|
| 0.30 | **0.7826** | 0.2535 | 0.7125 | 0.7630 |
| 0.40 | 0.7162 | 0.1921 | 0.7121 | 0.7630 |
| **0.50** (deployed) | 0.7664 | **0.0952** | 0.7582 | 0.7630 |
| 0.60 | 0.7661 | 0.0876 | 0.7585 | 0.7630 |
| 0.70 | 0.7495 | 0.0828 | 0.7503 | 0.7630 |

**The paper's selected 0.40 is the worst point of the five.** The response is
non-monotonic: 0.30 maximises MCC but at FPR 0.25, while the deployed 0.50 sits
at a much better MCC/FPR balance. Recommend replacing the table with these
values and keeping Φ_th = 0.5, which is also what the code and
`fusion_weights.json` actually use.

### `tab:kappa-sensitivity` — LSTM-AE threshold factor κ

**This table cannot be salvaged as designed.** Using the paper's own formula
θ_ae = μ + κ·σ over in-sim clean windows:

```
clean AE error, 23,676 honest rows:  mean = 45,279.35   std = 155,592.25
  =>  theta_ae(kappa=1.645) = 301,228.60      deployed file value = 33.693885
```

The formula produces a threshold **~8,900× the deployed value**. At any κ in
1–4 the AE term never fires, so MCC is flat at 0.7603 and κ tunes nothing:

| κ | θ_ae = μ+κσ | D6 MCC | D6 FPR |
|---|---|---|---|
| 1 | 200,872 | 0.7603 | 0.0891 |
| 1.645 | 301,229 | 0.7603 | 0.0891 |
| 2 | 356,464 | 0.7603 | 0.0891 |
| 3 | 512,056 | 0.7604 | 0.0890 |
| 4 | 667,648 | 0.7603 | 0.0889 |

Sweeping θ_ae **directly** shows where the AE actually operates:

| θ_ae | D6 MCC | D6 FPR |
|---|---|---|
| 1.0 | 0.7407 | 0.1306 |
| **33.693885** (deployed) | **0.7664** | 0.0952 |
| 1,000 | 0.7579 | 0.0940 |
| 10,000 | 0.7579 | 0.0932 |
| 100,000 | 0.7582 | 0.0922 |

The deployed value is empirically near-optimal — but it is **not derivable from
the formula the paper states**. Underlying distribution:

```
AE reconstruction error, non-zero rows only
  poisoned  n=67,805   p50 =    81.64   p95 = 506,770
  honest    n=22,764   p50 =     0.17   p95 = 498,437
  ae_raw == 0 (no full window):  poisoned 24,184,  honest 912
```

Three consequences for the paper:

1. **θ_ae must be defined by a robust/percentile rule, not mean+κ·σ.** The mean
   is destroyed by the heavy tail (mean 45,279 vs median 81.64), so the stated
   formula disables the detector. This is the same failure mode as the recorded
   θ_S trap — a threshold calibrated on one distribution and applied to another.
2. **Item A2's separation figures do not reproduce.** The claim is malicious
   p50 = 670 vs honest p50 = 0.46; measured in-sim is **81.64 vs 0.17**. The
   qualitative story (2–3 orders of magnitude at the median) survives; the
   numbers do not.
3. **26% of poisoned beacons carry no AE signal at all** (24,184 rows with
   `ae_raw = 0`, no full window) versus 4% of honest ones. Worth stating as a
   coverage limit.

### θ_S — no table exists, and there should be one

| θ_S | D1 MCC | D4 MCC | D6 MCC | D6 FPR | ordering D1<D4<D6 |
|---|---|---|---|---|---|
| **6.0** | 0.7630 | **0.7897** | **0.7964** | 0.1021 | ✅ **holds** |
| 8.0 | 0.7630 | 0.7897 | 0.7961 | 0.1021 | ✅ holds |
| 10.0 | 0.7630 | 0.7648 | 0.7687 | 0.1017 | ✅ holds |
| 12.0 | 0.7630 | 0.7610 | 0.7676 | 0.0992 | ✗ |
| 16.0 | 0.7630 | 0.7592 | 0.7664 | 0.0968 | ✗ |
| **19.74** (deployed) | 0.7630 | 0.7582 | 0.7664 | 0.0952 | ✗ |

**This is the significant result.** Lowering θ_S from 19.74 to 6–8 restores
**D1 < D4 < D6 over the full 300 s** — not at a 90 s cutoff — while raising D6
from 0.7664 to **0.7964** and D4 from 0.7582 to 0.7897. FPR rises only
0.0952 → 0.1021.

θ_S normalises the GAT term, so lowering it lets the GAT contribute on beacons
where it currently clips to near-zero. That is a **GAT-arm-only** effect, which
is exactly the property needed to separate D4/D6 from D1 — the same reasoning
that made `psi_cond_floor` work.

θ_S lives in `analytics/ml/models/urban_combined/theta_s.txt`. It is a
calibration artefact, not code — but it is the deployed value, so **I have not
changed it.** Confirming this needs one 300 s three-arm run with θ_S = 6.0,
which is a decision for the project owner.

### ψ_th — inert in its fusion role

| ψ_th | D6 MCC | D6 FPR |
|---|---|---|
| 0.05 | 0.7661 | 0.0956 |
| 0.07 | 0.7661 | 0.0956 |
| **0.09** (code) | 0.7664 | 0.0952 |
| 0.11 | 0.7651 | 0.0952 |
| 0.15 | 0.7647 | 0.0952 |

Because `psi_fuse` is near 0 or near 1 whenever a signature fires, dividing by
0.05 vs 0.15 rarely changes the clip. So the paper's `tab:threshold-sensitivity`
(MCC 0.776 → 0.606 across the same range) must be measuring the **lightweight**
decision role, not the fusion normaliser. That half is not derivable from the
fusion log and **needs a rerun**.

---

## 2. Tables that DO need reruns

These parameters change which signatures fire, so the recorded `psi_fuse` and
`sig_mask` would themselves differ. They cannot be re-derived — but every one is
a **CLI flag**, so sweeping them requires no code change.

| paper table | flag | values | runs |
|---|---|---|---|
| `tab:threshold-sensitivity` | `--psi_th` | 0.05, 0.07, 0.09, 0.11, 0.15 | 5 |
| `tab:drift-sensitivity` | `--delta_th` | 5.0, 7.5, 10.0, 12.5, 15.0 | 5 |
| `tab:window-sybil-sensitivity` (a) | `--drift_window_k` | 5, 10, 15, 20 | 4 |
| `tab:window-sybil-sensitivity` (b) | `--k_sybil` | 3, 4, 5, 6 | 4 |
| `tab:kl-sensitivity` | `--kappa_th` | 0.10, 0.30, 0.50, 1.00 | 4 |
| `tab:smax-sensitivity` (urban) | `--s_max_kmh` | 80, 100, 120 | 3 |
| `tab:attackpct-sensitivity` | `--attack_percentage` | 0, 20, 40, 60, 80, 100 | 6 |

**31 runs, full mode (D6) only.**

Not on the list, and they should be — these have never been swept and are now
headline mechanisms: the six `ring_detect` thresholds, `--gat_det_flag_heads`
(46 vs 0 moved MCC more than most swept parameters), and per-head θ_conf, whose
table `tab:pipeline-settings` promises but which does not exist.

### Proposed budget

Machine has 32 cores / 31 GB free, but **disk is at 95% with 49 GB left**, and a
300 s arm produces ~650 MB of log.

- Run at **`--simTime=90`**, matching the evaluation window actually being
  reported. Principled, not a shortcut.
- **6 concurrent runs**, `--per_pid_results=1` mandatory.
- **Extract `MCC_full`/`FPR_full` and delete each log immediately**, so disk
  stays flat instead of growing ~20 GB.
- Estimated **~5 hours** for all 31.

### Two rows to drop regardless

`tab:attackpct-sensitivity` at ρ_a = 0 has no positives and at ρ_a = 1.00 no
negatives, so MCC is undefined at both ends. Reporting 0.000 reads as
"chance-level detection" when it means "the metric does not apply".
