# Paper ↔ Code Alignment — HPC Punch List

**Date:** 2026-07-03. **Branch:** `feature/metrics-11`.
**Trigger:** paper Chapter 4 was rewritten into **5 formal Experiments** (`sec:exp1`–`sec:exp5`)
with a fixed default config, **11 ablation variants AB1–AB11** (`sec:ablation`), and **11
metrics**, all evaluating the **full mode** against baselines **B1/B2/B3**. The code is still on
the older A1–A5 + B1 scheme and the lightweight path. This file maps every experiment / AB
variant / metric to the exact code knob so the HPC edits target the right things.

Legend: ✅ aligned · ⚠️ partial (reachable but not labelled / needs a split) · ❌ gap (new code)

---

## 0. Resolve in the paper FIRST (else the code targets the wrong number)

- [ ] **`s_max` per scenario is specified three incompatible ways** — `tab:set-lw`
  `TBD{100,120,130,140}`; `tab:smax-sensitivity` grid (urban 80/100/120, rural 100/120/140,
  highway 120/130/140); `tab:set-scenarios` concrete **60/90/150**. The code reads ONE
  `s_max` per scenario. Pick one set before configuring.
- [ ] **Highway propagation model contradicts itself** — §4.3 prose says **two-ray ground**,
  `tab:set-scenarios` says **Log-distance (n=3.0)**. Configure the NS-3 channel to whichever
  you keep.
- [ ] **`\ref{eq:fpr}` still dangling** in the full-mode model-selection prose
  ("FPR, Eq.~\ref{eq:fpr}") — restore a one-line FPR def or drop the ref.
- [ ] **Results/PARR prose** still says "gap between **A1** and B1" → **AB5/AB6**.
- [ ] **Map area** — tables say ≈4 km²; the density sentence in `sec:param-rationale` says
  "2 km²". Pick one (affects the 100 veh/km² claim).

---

## 1. Experiments (§4.4) → code

Default config (`tab:default-config`): ρ_a=0.40, γ=0.70, v=60 km/h, N_v=200, TL=3, urban,
**full mode**. Every experiment's "proposed method" is **full mode vs B1/B2/B3**, so the two
cross-cutting blockers below hit ALL five experiments:

- ❌ **Full mode not exercised** — default run is `routing_test=true` + `ablation_mode=1`
  (=AB5, lightweight). Full mode (GAT+LSTM ONNX, TRS/FHE, Fabric) is compiled-in but unrun.
- ❌ **B2, B3 missing** — only B1 (Ghaleb) is coded. B2 (Fed-LSTM-AE) / B3 (hTDC-AE) are
  **ML baselines → coordinate with the ML member**, do not silently own.

| Exp | Independent var | Code knob | Y-metrics | Status / extra blocker |
|---|---|---|---|---|
| **1** `sec:exp1` | ρ_a × γ (6×3) | `--attack_percentage`, `stealth_fraction_theta_s` (02_config_globals.h:307) | MCC,TTD,CDER,TDEE,TPE,PBPO | ⚠️ confirm γ has a CLI binding for {0,0.7,1.0}; needs SUMO (TDEE/TPE) + full mode + B2/B3 |
| **2** `sec:exp2` | speed {10,60,100,140} | `--maxspeed` (02_config_globals.h:71) + per-speed SUMO trace `mobility_<scen>_<spd>.tcl` | same 6 | ⚠️ trace file must exist for each speed×scenario; + full mode + B2/B3 |
| **3** `sec:exp3` | N_v {100,200,300,400}, RSU scaled | `routing_test=false` + N via CLI | MCC,TTD,CDER,PBPO,**COO,BWO_ratio** | ❌ **deferred scale-up** (16/4 test vs ~200/25 SUMO); ❌ COO/BWO absent |
| **4** `sec:exp4` | Threat Level 1–5 (σ×n_coord) | **none** | same 6 | ❌ no `threat_level`/`n_coord` knob (only attack 7 "coordinated" type) |
| **5** `sec:exp5` | 7 attack variants, isolated | `--attack_number=1..7` | MCC,TTD,CDER,TDEE/TPE,PBPO | ✅ knob exists; needs full mode + B2/B3 + SUMO |

---

## 2. Ablations AB1–AB11 (§4.1.2) → code `ablation_mode`

Code today (02_config_globals.h:167): `0=Full, 1=A1(LW-only), 2=A2, 3=A3, 4=A4(no PQ crypto),
5=A5(no-BC), 6=B1(Ghaleb LTT)`. AI sub-toggles: `--enable_gat`, `--enable_lstm_ae`
(02_config_globals.h:188). The paper's 11-way split does NOT map 1:1 — extend the selector:

| AB | Removed | Code today | Edit |
|---|---|---|---|
| **AB1** | rule signatures (ψ) | ❌ | new mode: disable TP-S1..MP-S4 scoring |
| **AB2** | HMAC + nonce | ❌ | new mode: disable HMAC gate |
| **AB3** | GAT | ⚠️ `--enable_gat=0` | wire as AB3 label |
| **AB4** | LSTM-AE | ⚠️ `--enable_lstm_ae=0` | wire as AB4 label |
| **AB5** | full AI (LW only) | ✅ mode 1 (A1) | rename A1→AB5 |
| **AB6** | TRS gate | ⚠️ half of mode 4 | split `use_pq_crypto`: TRS-off only |
| **AB7** | FHE pre-coord | ⚠️ half of mode 4 | split `use_pq_crypto`: FHE-off only |
| **AB8** | RSU 3-state lifecycle | ❌ | new mode: RSUs permanently trusted |
| **AB9** | multi-controller | ❌ | new mode: single fixed controller |
| **AB10** | blockchain (SC-Trust/Revoke) | ✅ mode 5 (A5) (04_state_globals.h:157) | rename A5→AB10 |
| **AB11** | LKH→unicast rekey | ❌ | new mode: unicast rekey path |

Net: **AB5, AB10 aligned; AB3, AB4, AB6, AB7 partial; AB1, AB2, AB8, AB9, AB11 are new.**

---

## 3. Metrics (§4.2) → producer

CSV header: 10_metrics_csv.h:959. TTD helper: analytics/compute_ttd.py.

| Metric | Scope | Producer today | Gap / stage |
|---|---|---|---|
| MCC | all-baseline | ✅ CSV `MCC` | — |
| TTD | all-baseline | ⚠️ analytics/compute_ttd.py (from beacon_log) | ok; optionally add CSV col |
| CDER | all-baseline | ✅ CSV `CDER` | — |
| TDEE | all-baseline | ✅ CSV `TDEE` (−1 w/o SUMO) | run `--mobility_source=1` |
| TPE | all-baseline | ✅ CSV `TPE` (−1 w/o SUMO) | run with SUMO |
| PBPO | all-baseline | ✅ CSV `PBPO_LW/Full` | — |
| PARR | ablation | ✅ CSV `PARR` | — |
| FRR (revoke+demote) | ablation | ❌ | Stage 3 — live Fabric |
| COO | ablation | ❌ | Stage 2 — full-mode crypto timers |
| BWO (ratio+scale) | ablation | ❌ | Stage 1–2 — byte counters + LKH sweep |
| TCL (confirm+reassign) | ablation | ❌ | Stage 3 — Fabric latencies |
| ~~FPR~~ | demoted | ✅ CSV `FPR` (keep for calibration) | drop from primary plots only |

---

## 4. Recommended HPC edit order

1. **Paper-first fixes (§0)** — 10 min, unblocks correct config.
2. **Full mode up + B1**, on SUMO → produces Exp1/Exp2/Exp5 for the proposed method
   (the 6 all-baseline metrics already exist).
3. **Ablation selector 7→11** (§2) — biggest single edit; unlocks AB1–AB11.
4. **Exp4 `threat_level` knob** (σ×n_coord), then **Exp3 scale-up** + **COO/BWO** (Stage 2).
5. **B2/B3** with the ML member; **FRR/TCL** with Fabric (Stage 3).

## 5. File index
- ablation selector: [02_config_globals.h:167](02_config_globals.h) · AI toggles `:188`
- B1 Ghaleb baseline: [08b_baseline_ltt.h](08b_baseline_ltt.h) (`--ablation_mode=6`)
- attack models (incl. attack 7 coordinated, θ_s): [06a_attack_models.h](06a_attack_models.h)
- speed / SUMO trace path: [09b_mobility_provider.h:229](09b_mobility_provider.h)
- metrics CSV: [10_metrics_csv.h:959](10_metrics_csv.h)
- full-mode fusion toggles: [06d_ai_inference.h:69](06d_ai_inference.h)
- topology / routing_test: [12_main.h:152](12_main.h) · [02_config_globals.h:36](02_config_globals.h)
- staged metric rollout: [METRICS_UPGRADE_PLAN.md](METRICS_UPGRADE_PLAN.md)
