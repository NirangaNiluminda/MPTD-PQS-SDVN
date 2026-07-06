# Paper ↔ Code Alignment — HPC Punch List

**Date:** 2026-07-03 (reconciled against the latest paper draft). **Branch:** `ml-review-fixes`.
**Trigger:** paper Chapter 4 was rewritten into **5 formal Experiments** (`sec:exp1`–`sec:exp5`)
with a fixed default config, **11 ablation variants AB1–AB11** (`sec:ablation`), and **11
metrics**, all evaluating the **full mode** against baselines **B1/B2/B3**. The code is still on
the older A1–A5 + B1 scheme and the lightweight path. This file maps every experiment / AB
variant / metric to the exact code knob so the HPC edits target the right things.

**What the latest draft changed vs this punch list:** (a) `tab:set-scenarios` now fixes
s_max=**60/90/150** and Log-distance (n=3.0) for BOTH rural and highway — matching the shipped
code and the urban/rural/highway@200 datasets; three other tables/prose remain stale (see §0).
(b) Full-mode component selection is now DONE offline — real GAT/LSTM-AE selection tables exist
(GAT MCC urban 0.4056 / rural 0.1400 / highway 0.7942); only the integrated `ablation_mode=0`
ns-3 run is still outstanding. (c) Results now report real AB5 (lightweight) MCC/PARR/CDER.

Legend: ✅ aligned · ⚠️ partial (reachable but not labelled / needs a split) · ❌ gap (new code)

---

## 0. Resolve in the paper FIRST (else the code targets the wrong number)

Status note (2026-07-03): the current paper draft **partially resolves** these, but the
resolutions are inconsistent *across tables/prose within the same draft* — the code is
already built to the `tab:set-scenarios` values (60/90/150, Log-distance both rural+highway),
so the remaining action is to fix the paper's OTHER tables/prose to match, not to re-config code.

- [ ] **`s_max` — `tab:set-scenarios` now concrete 60/90/150** (matches code + shipped
  datasets), BUT still contradicted by three other places: `tab:set-lw` `TBD{100,120,130,140}`,
  `tab:smax-sensitivity` grid (urban 80/100/120, rural 100/120/140, highway 120/130/140),
  and `sec:param-rationale` prose. **Code is correct at 60/90/150** — fix the three stale
  tables/prose in the paper to match, do NOT re-config.
- [ ] **Highway propagation — `tab:set-scenarios` now says Log-distance (n=3.0)** for BOTH
  rural AND highway, matching the shipped code (12_main.h scenario 2 = LogDistance, committed
  5b6cd92). BUT `sec:mobility-scenarios` **prose still says highway uses "two-ray
  ground-reflection model"** — stale, contradicts the table. Fix the prose → Log-distance.
- [ ] **`\ref{eq:fpr}` still dangling** in the full-mode model-selection prose
  ("FPR, Eq.~\ref{eq:fpr}") — restore a one-line FPR def or drop the ref.
- [ ] **Results/PARR prose** still says "gap between **A1** and B1" → **AB5/AB6**.
- [ ] **Map area** — tables say ≈4 km²; the density sentence in `sec:param-rationale` says
  "2 km²". Pick one (affects the 100 veh/km² claim). Note: rural map caps at ~138–151
  full-window vehicles (sparse ~2 km² Hohenwart net), so the 200-veh/scenario fairness claim
  cannot hold for rural without enlarging the map — document the rural cap or match by density.

---

## 1. Experiments (§4.4) → code

Default config (`tab:default-config`): ρ_a=0.40, γ=0.70, v=60 km/h, N_v=200, TL=3, urban,
**full mode**. Every experiment's "proposed method" is **full mode vs B1/B2/B3**, so the two
cross-cutting blockers below hit ALL five experiments:

- ⚠️ **Full mode partially exercised (offline component selection done, end-to-end sim not)** —
  the paper now carries REAL full-mode model-selection tables: `tab:gat-selection` (GAT chosen,
  per-scenario MCC **urban 0.4056 / rural 0.1400 / highway 0.7942** at FPR 0), `tab:lstmae-selection`,
  and `tab:fullmode-selected` (GAT finalised; LSTM-AE β still TBD). So the AI components ARE
  trained/selected offline. What is STILL unrun is the **integrated ns-3 full-mode run**
  (`ablation_mode=0`): default sweep is still `routing_test=true` + `ablation_mode=1` (=AB5,
  lightweight). Bring up `ablation_mode=0` (GAT+LSTM ONNX inference, TRS/FHE, Fabric) end-to-end.
- ❌ **B2, B3 missing** — only B1 (Ghaleb) is coded. B2 (Fed-LSTM-AE) / B3 (hTDC-AE) are
  **ML baselines → coordinate with the ML member**, do not silently own. (Reminder: B2/B3 must
  each be ONE global model with held-out vehicles, not per-(attack×pct) models.)

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
(02_config_globals.h:188).

**RESOLVED (C10, 2026-07-06):** new `--ablation_ab=0..11` selector (02_config_globals.h,
dispatch in 12_main.h) maps every AB onto fine-grained toggles; legacy `ablation_mode`
enum untouched. Outputs get an `_ab{N}` suffix + `ablation_ab` CSV column.

| AB | Removed | Wiring |
|---|---|---|
| **AB1** | rule signatures (ψ) | ✅ `enable_rule_signatures=false` — TP/MP flags zeroed, detectors still warm state, CP-DETECT stays |
| **AB2** | HMAC + nonce | ✅ `enable_hmac_gate=false` — Δ_HMAC gate bypassed |
| **AB3** | GAT | ✅ `g_enable_gat_cli=0` |
| **AB4** | LSTM-AE | ✅ `g_enable_lstm_ae_cli=0` |
| **AB5** | full AI (LW only) | ✅ ≡ `ablation_mode=1` |
| **AB6** | TRS gate | ✅ `enable_trs=false` — unsigned aggregate, PARR counters untouched (0/0) |
| **AB7** | FHE pre-coord | ✅ `enable_fhe=false` — plaintext ring sums, TRS still binds payload, H7 envelope intact |
| **AB8** | RSU 3-state lifecycle | ✅ `enable_rsu_lifecycle=false` — uniform-random endorsers over ALL RSUs |
| **AB9** | multi-controller | ✅ `enable_ctrl_rotation=false` — controller 0 pinned |
| **AB10** | blockchain (SC-Trust/Revoke) | ✅ ≡ `ablation_mode=5` + `skip_blockchain=true` |
| **AB11** | LKH→unicast rekey | ✅ `use_lkh_tree=false` — flat group keying, N_rekey=\|V_j\| |

Net: **all 11 variants wired.** Smoke-tested AB2/AB6/AB7/AB11 + legacy-full regression
(simTime=30, a1/p30) — see DESIGN_FLAWS_AUDIT.md §6.2 C10 resolution note.

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

1. **Paper-first fixes (§0)** — now mostly editorial: the CODE is already correct at
   60/90/150 + Log-distance; the remaining work is fixing the paper's three stale s_max tables
   and the `sec:mobility-scenarios` two-ray prose to match `tab:set-scenarios`. ~10 min in LaTeX.
2. **Full mode up + B1**, on SUMO → produces Exp1/Exp2/Exp5 for the proposed method
   (the 6 all-baseline metrics already exist). AI components already selected offline
   (GAT/LSTM-AE tables) — this step is the integrated `ablation_mode=0` ns-3 run.
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
