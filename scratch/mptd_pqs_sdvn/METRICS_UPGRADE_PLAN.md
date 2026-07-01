# Evaluation-Metrics Upgrade Plan (7 → 11 metrics)

**Date:** 2026-07-01. **Status:** analysis + plan only — no code changed yet.
**Trigger:** paper §4.2 "Primary Evaluation Metrics" was rewritten: FPR dropped as
a *primary* metric; **TTD, FRR, COO, BWO, TCL** added (several with two
sub-equations). This documents the code gap and a staged rollout.

---

## 1. What changed in the paper

| | Old (7) | New (11) |
|---|---|---|
| Detection | MCC, **FPR** | MCC, **TTD** |
| Mitigation | PARR, CDER | PARR, CDER, **FRR** (revoke+demote) |
| Attack impact | TDEE, TPE | TDEE, TPE |
| Overhead/scale | PBPO | PBPO, **COO**, **BWO** (ratio+scale), **TCL** (confirm+reassign) |

- **Removed as *primary*:** FPR (paper: "subsumed by MCC"). See §5 caveat — FPR is
  still the calibration criterion, so it is *not* deleted from the code.
- **Added:** TTD, FRR, COO, BWO, TCL (5 families, 8 equations).
- **Scope split:** 6 metrics vs external baselines B1–B3 (MCC, TTD, CDER, TDEE, TPE,
  PBPO); 5 are **ablation-only** (PARR, FRR, COO, BWO, TCL) — compared full-mode vs
  A4/A5, not against B1–B3.

## 2. Gap analysis (code today)

| Metric | Paper scope | Code today | What's needed | Depends on | Stage |
|---|---|---|---|---|---|
| MCC | all-baseline | ✅ `compute_MCC` + `cm_*` | keep | — | done |
| TTD | all-baseline | ❌ absent | derive from `beacon_log.csv`: `t_alert` (first `detected=1`) − `t_start` (first `is_poisoned=1`) per attacker | analytics (+ optional onset hook) | **0** |
| PARR | ablation | ✅ `compute_PARR` + trs counts | keep | — | done |
| CDER | all-baseline | ✅ `compute_CDER` + ctrl decisions | keep | — | done |
| FRR (revoke+demote) | ablation | ❌ absent | log `Revoke`/`ControllerRevoked` + demote-to-`client` events; cross-ref `is_malicious`; new CSV | **live Fabric / SC layer** | **3** |
| TDEE | all-baseline | ✅ `compute_TDEE` (SUMO-gated, −1 else) | keep; run with `--mobility_source=1` | SUMO | done/verify |
| TPE | all-baseline | ✅ `compute_TPE` | keep | — | done |
| PBPO | all-baseline | ✅ `PBPO_LW/Full` | keep | — | done |
| COO | ablation | ❌ absent | per-epoch wall-clock timers around TRS sign+aggregate & FHE enc/⊕/thresh-dec; one-time DKG setup latency | **full-mode crypto (HPC)** | **2** |
| BWO (ratio+scale) | ablation | ❌ absent | byte counters per msg type (BSM/FHE/TRS/chain/LKH); LKH-rekey sweep (`N_rekey` already logged); SYB-DETECT O(n²) count | partial LW (BSM+LKH), full for FHE/TRS | **1→2** |
| TCL (confirm+reassign) | ablation | ❌ absent | Fabric block submit→confirm latency; revoke→reassign-complete latency | **live Fabric (HPC)** | **3** |
| ~~FPR~~ | demoted | ✅ `compute_FPR` (+ plots) | **keep for calibration**; drop from *primary* plots/table | — | **0** |

## 3. Cross-cutting work (touches these regardless of metric)

1. **Metrics-CSV schema** ([10_metrics_csv.h:959](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L959)):
   add columns `TTD`, `BWO_ratio`, `BWO_scale`, `COO_epoch`, `COO_dkg`,
   `FRR_revoke`, `FRR_demote`, `TCL_confirm`, `TCL_reassign` (or a companion CSV).
   Keep `FPR`/`FPR_full` (calibration) but mark non-primary.
2. **Evaluation harness** (`analytics/run_evaluation.sh`): honour the scope split —
   run **B1–B3** for the 6 all-baseline metrics; run **A4** (PARR/COO) and **A5**
   (FRR/BWO/TCL) for the 5 ablation-only metrics.
3. **Analytics plots** (`analytics/plot_*.py`): add TTD/FRR/COO/BWO/TCL figures;
   **drop FPR, DR, Precision, F1** from primary reporting (paper: redundant given MCC).

## 4. Staged rollout (by dependency, smallest first)

- **Stage 0 — analytics-only, no rebuild (quick wins).**
  - TTD from existing `beacon_log.csv` (per-attacker first-alert − first-poison).
  - Demote FPR (+ drop DR/Precision/F1) from the primary metric plots; keep
    `compute_FPR` for calibration.
  - Re-verify the 6 retained metrics still plot from the current CSV; refresh the
    metric-to-RQ plot set.
- **Stage 1 — light sim instrumentation (runs in lightweight A1).**
  - BWO byte counters for BSM + LKH rekey; `BWO_scale` sweep harness over
    `|V_j|` (parse the existing `N_rekey=log2|V_j|` log line).
  - SYB-DETECT O(|ID|²) pair-count counter.
  - Optional exact TTD onset timestamp per attacker; new CSV columns + schema bump.
- **Stage 2 — full-mode crypto (HPC).**
  - COO: wall-clock timers around TRS + FHE ops per epoch; DKG setup latency.
  - BWO_ratio full: add FHE-ciphertext + TRS-signature + evidence-tuple bytes.
- **Stage 3 — live Fabric (HPC + blockchain).**
  - FRR_revoke / FRR_demote: capture SC-Revoke + SC-Trust demotion events vs
    `is_malicious`; new CSV.
  - TCL_confirm (block submit→confirm) + TCL_reassign (revoke→reassign).

## 5. Flags to reconcile in the paper (not code)

1. **Dangling `\ref{eq:fpr}`.** The rewrite deleted the FPR subsection (and
   `eq:fpr`), but the grid-search tables (`tab:threshold-sensitivity`,
   `kl-sensitivity`, `smax-sensitivity`, `window-sybil-sensitivity`) and the
   full-mode model-selection section still cite **"FPR (Eq.~\ref{eq:fpr})"** and
   keep FPR columns. Those refs will render as `??`. **FPR is still needed for
   calibration** — either restore a one-line FPR definition (e.g. in the
   calibration section) or change those references. Do **not** delete `compute_FPR`.
2. **Two-part metrics.** FRR, BWO, TCL each have two equations → each needs both
   sub-values in the CSV and both curves in the plots.
3. **TDEE/TPE need SUMO** (`--mobility_source=1`); they emit −1 on the hardcoded
   test topology, so the ablation/baseline sweeps for these must use SUMO traces.

## 6. Recommendation
Do it on a **fresh branch off master** (`feature/metrics-11`), and land it in the
stage order above — Stage 0 is safe analytics work that can start immediately and
needs no HPC; Stages 2–3 are gated on the full-mode/Fabric integration and belong
with the HPC evaluation.
