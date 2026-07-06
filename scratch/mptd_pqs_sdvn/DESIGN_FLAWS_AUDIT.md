# MPTD-PQS — Design-Flaw Audit (Task 1) — v2, paper-verified

**Deliverable for:** supervisor task #1 (deadline 2026-06-07)
**Author:** attack-detection / MPTD-PQS group
**Method:** paper-conformance audit. The paper is the only authority; existing code **and its comments** are treated as possibly wrong. This v2 re-run reads the paper PDF directly (§3.4.4, §3.5.2–3.5.5, §4.1) and cross-checks every claim against `file:line` — so each finding is now confirmed against the equation/figure, not inferred.
**Pages read this session:** 38–53 (signatures, LKH, Alg 1), 54–71 (Alg 2–9, fusion, crypto, consensus), 72–82 (metrics + current results). Code: `scratch/mptd_pqs_sdvn/`.

---

## 0. Executive summary

The crypto stack and the rule-based lightweight detector are in good shape and **match the paper**: the FHE-before-TRS pipeline (Alg 6, Eq 3.45–3.51), HMAC fail-fast gate (Alg 1 line 2 / Alg 4), the weighted 9-signature composite ψ (Eq 3.10–3.20), the GAT mobility-aware graph construction (Eq 3.26, built correctly inside `score_gat`), and the LKH key hierarchy (Eq 3.21–3.25) are all faithfully implemented.

The problems are concentrated in **how the full mode connects to the metrics and where the AI runs.** The single most important fact, now confirmed directly from the paper's own results section (§4.1.4–4.1.6, pp.77–79): **the paper currently reports only A1, A4, and B1 — there are no A2 / A3 / Full / B2 / B3 results at all.** That is the visible symptom of the flaws below: the full-mode AI verdict is computed but never scored (C1), and the PARR metric is wired to the wrong counter (C4, which is also why the paper shows the impossible result that A1 — a mode with *no* TRS — has PARR ≈ 0.30).

| ID | Severity | One-line | Paper authority | Verdict |
|----|----------|----------|-----------------|---------|
| C1 | 🔴 Critical | Full-mode fusion verdict Φ computed but never scored → no A2/A3/Full MCC/FPR | Eq 3.43–3.44, §4.1.4 | **✅ Resolved 2026-06-10** (resolution note below) |
| C2 | 🔴 Critical | Single global confusion matrix; no per-variant × attacker-class slicing | Eq 4.1–4.2 (p.73) | **✅ Resolved 2026-06-10** (resolution note below) |
| C3 | 🔴 Critical | TDEE/TPE: SUMO not wired by default; ρ_gt=N_Vehicles & p̂=reported pos (wrong defs) | Eq 4.5–4.6 (p.75) | **✅ Resolved 2026-07-05** (per-cell spatial TDEE, smoke-verified) |
| C4 | 🔴 Critical | **PARR measures the wrong thing** — detection-revoke proxy, not TRS aggregate rejection; correct counter unused | Eq 4.3 (p.74) | **C4a wiring ✅ Resolved 2026-07-05; C4b reachability open** |
| H1 | 🟠 High | CP-DETECT TRS-verify gate (a) is a dead no-op (callers pass nullptr) | Alg 9 line 2, Eq 3.51 | **Confirmed** |
| H2 | 🟠 High | Consensus uses a single-vehicle temporal window, not 2f+1 / f+1 over **distinct RSUs** | Eq 3.60–3.61 (p.67) | **⚠️ Partially resolved 2026-07-05** — vote counting now idempotent per (vehicle,RSU); coverage reachability still open |
| H3 | 🟠 High | GAT/AE/Fusion run per-RSU in-memory; paper runs them **at the controller via IPFS** | Alg 5 (p.59), Fig 3.9/3.11 | **Confirmed** (graph build itself OK — retracted) |
| ~~H4~~ | ⬜ Resolved | ~~B2/B3 unimplemented~~ — team swapped B2/B3 to Ercan(2022)/Sharma(2021), teammate-implemented in mptd_pqs/; paper to be updated | §4.1.1 | **Resolved 06-07** |
| ~~M2~~ | ⬜ Retracted | ~~Threshold-decrypt hardcodes t=4~~ — misread; the `4` is the field-count `len`, not the threshold (t=3,n=4 set at init) | Eq 3.54 | **Withdrawn** |
| M3 | 🟡 Medium | Several comments now contradict the code | — | Confirmed |
| M4 | 🟡 Medium | TPE uses reported pos not controller prediction; CDER fallback oracle is heuristic | Eq 4.4, 4.6 | New |
| M5 | 🟡 Medium | Paper-text defects (broken cross-refs; Fig 3.9 fusion mislabeled Eq 3.54; "compact+anonymous" TRS claim) | §3.5.3–3.5.4 | New (feeds Task 2 / report) |
| H5 | 🟠 High | No Δ_HMAC freshness window / cluster replay cache (nonce ν_i itself OK) | HMAC beacon-auth spec | **✅ Resolved 2026-07-05** (§7.1, smoke-verified) |
| H6 | 🟠 High | TRS messages lack ring nonce ν_S / Δ_TRS freshness — σ_TRS replayable | Eq trs_message/trs_fresh | **✅ Resolved 2026-07-05** (§7.1, smoke-verified) |
| H7 | 🟠 High | Plausibility envelope checks absent at Enc() and THRESH-DEC (no last-valid fallback) | Alg pq_fhe_trs l.3, thresh_dec | **✅ Resolved 2026-07-05** (§7.1; C4b attack-path reachability still open) |
| M6 | 🟡 Medium | Fusion uses bare S, not S/θ_S; θ_S never trained/loaded | Eq fusion | **New (v3, §7.2)** — methodology decision |
| M7 | 🟡 Medium | GAT standardization is live snapshot-level, not locked per-node clean stats | Eq gat_score | **New (v3, §7.2)** — methodology decision |
| M8 | 🟡 Medium | lstm_ae.py WINDOW_SIZE=20 vs deployed 10; paper table Urban L=20 stale | §model-selection | **New (v3, §7.2)** |

**Resolved & paper-correct (was suspect in May):** real PQC crypto pipeline; gated `CallSCTrust` (Alg 1 line 5); GAT graph (Eq 3.26); HMAC fail-fast (Alg 1/4); weighted ψ (Eq 3.20); LKH (Eq 3.21–3.25).

---

## 1. Critical flaws

### C1 — Full-mode AI verdict (Φ) is computed but never scored
**Paper:** Eq 3.43 `Φ_i = λ₁ψ + λ₂S + λ₃(ε/θ_ae)`, Eq 3.44 `flag = 1[Φ>Φ_th]`; §4.1.4 (results must cover A2/A3/Full for RQ3/RQ4).
**Code:** `fuse_scores()` produces `fs.anomalous`/`fs.phi` at [08:1832](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1832); it is only logged + counted into `full_flag_count` ([08:1835](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1835)). The metric driver `update_confusion_matrix(tag.GetIsPoisoned(), detected)` is fed the **lightweight** `detected` only ([08:2028](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2028)). `compute_MCC/FPR` read one global matrix `cm_TP/FP/TN/FN` ([10:541](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L541)).
**Confirmation:** the paper's results (§4.1.4–4.1.6) contain only A1/A4/B1 — exactly because full mode produces no scored decision. RQ3/RQ4 have no data.
**Fix:** keep a second confusion matrix driven by `fs.anomalous`; back-apply Φ_i to the beacons in the closing window (window carries `rw.vid[i]`, GT via `tag.GetIsPoisoned()`); log the full-mode decision per beacon for C2. Add an A1-empty / Full-populated assertion.

### C2 — No per-variant × attacker-class slicing of MCC/FPR
**Paper:** Eq 4.1/4.2, p.73 — "Reported per attack variant (trajectory/mobility) **and per attacker class** (malicious vehicle, compromised RSU, MitM, malicious controller)."
**Code:** `update_confusion_matrix(bool,bool)` has no class arg; counters are global scalars ([10:77](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L77)). `attacker_class` exists only as a CSV column ([10:115](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L115)) and the logged decision is the LW verdict.
**Fix:** key an in-memory `map<(variant,attacker_class), CM>` off the mode-appropriate decision, or log both LW and Φ decisions + class per beacon and slice in `analyze_results.py`.

---

#### ✅ Resolution — C1 + C2 (implemented 2026-06-10, build green)

A second, **full-mode** confusion matrix was added and wired to the Fusion verdict, leaving the existing lightweight matrix authoritative for A1/B1. Per-run sweep separation + explicit slice keys deliver the variant × attacker-class table for both decision layers (chosen over an in-memory 2-D map because each run injects exactly one `attack_number` → one attacker class, so the sweep *is* the slice; this matches the existing architecture and is not a simplification).

**Edits:**
- `04_state_globals.h` — `RsuBeaconWindow` gains `bool is_poisoned[IPFS_WINDOW_L]` (per-beacon GT label, Eq 4.1/4.2); `ipfs_push_and_maybe_flush(...)` gains a defaulted `is_poisoned_flag` param and stores it. Default keeps any other caller source-compatible.
- `08_detection_engine.h` (push site, ~L2735) — passes `tag.GetIsPoisoned()` so the window snapshot carries GT next to the kinematics.
- `10_metrics_csv.h` — new counters `cm_full_TP/FP/TN/FN`, `update_confusion_matrix_full(is_poisoned, full_flag)`, `compute_MCC_full()` / `compute_FPR_full()` (Eq 4.1/4.2).
- `08_detection_engine.h` (fusion loop, after `fuse_scores`) — scores `fs.anomalous` (Eq 3.45 Φ>Φ_th) against `rw.is_poisoned[i]`, **gated `ablation_mode ∉ {1,6}`** so A1/B1 leave the full matrix empty by construction (satisfies the audit's "A1-empty / Full-populated" intent). Forward-decl added at 08:40.
- `10_metrics_csv.h` (`write_mptd_results_csv` + `print_mptd_metrics`) — per-run CSV now emits explicit slice key `attacker_class` plus `cm_full_*`, `MCC_full`, `FPR_full` alongside the LW columns.

**Decision-layer → ablation mapping:** A1/B1 report LW `cm_*`/`MCC`/`FPR`; A2/A3/A4/A5/Full report `cm_full_*`/`MCC_full`/`FPR_full`. `analyze_results.py` reads by column name (`csv.DictReader`), so the inserted columns are additive — no analyzer change required; existing Table-1/2/3 outputs are unaffected.

**Build:** `./waf build` → `'build' finished successfully`, no errors/warnings in the changed files.

**Not done here (out of C1/C2 scope, tracked elsewhere):** full mode only scores when the AI models are loaded and run at the RSU window-close hook — relocating GAT/AE/Fusion to the controller via IPFS is H3; producing actual A2/A3/Full numbers depends on the ML models being trained/available (06-30 ML deadline).

### C3 — TDEE/TPE: SUMO side-channel absent by default + wrong ground-truth definitions
**Paper:** Eq 4.5 `TDEE=|ρ̂−ρ_gt|/ρ_gt`, ρ_gt = **SUMO ground-truth density**, ρ̂ = controller's **estimated** density; Eq 4.6 `TPE=mean‖p̂_i−p_i^gt‖`, p̂_i = controller's **predicted** position, p_i^gt = SUMO position.
**Code:** default `g_mobility_source=0` (hardcoded) ([02:55](scratch/mptd_pqs_sdvn/02_config_globals.h#L55)); both metrics return −1 unless `is_sumo_derived()` ([10:608](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L608)), and live TraCI is unimplemented ([09b:255](scratch/mptd_pqs_sdvn/09b_mobility_provider.h#L255)). Even with SUMO: `ρ_gt = (double)N_Vehicles` and `ρ̂ = |g_ctrl_seen_vids|` ([10:611-613](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L611-L613)) — a vehicle **count**, not a spatial density, so TDEE only responds to Sybil id-inflation, not density poisoning.
**Fix:** finish OSM+SUMO (schedule Row 3); make `sumo_trace` the eval default; define ρ_gt as spatial density (veh/segment/time-bin) and ρ̂ from the controller's learned density model; for TPE use the controller's predicted position, not the reported beacon. Smoke-test that fails if eval runs report −1.

#### ⚠️ Investigation update (2026-07-05) — infrastructure is present; only TDEE binning + eval-default remain
Re-checked against the UPDATED paper metrics spec and the actual code — the v2 "SUMO not wired" framing is **too pessimistic**:
- **SUMO ground truth IS available.** `IMobilityProvider::get_gt_position(vid)`/`get_gt_velocity(vid)` and a **spatial** `get_gt_density_in_cell(cx,cy,radius)` already exist ([09b_mobility_provider.h:91-122](scratch/mptd_pqs_sdvn/09b_mobility_provider.h#L91)). `FcdTraceMobilityProvider` (`is_sumo_derived()=true`) loads ns-2 traces, and the trace files **exist**: `mobility/mobility_{urban_60,rural_90,autobahn_150}.tcl` + `rsu_positions_{urban,rural,autobahn}.csv`.
- **TDEE is the real gap.** `compute_TDEE()` ignores the spatial `get_gt_density_in_cell` and instead uses **global counts**: ρ_gt = `N_Vehicles`, ρ̂ = `|g_ctrl_seen_vids|` ([10:704-707](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L704)). So it only reacts to Sybil id-inflation, not spatial density distortion. Fix = compute per-RSU-cell `|ρ̂_cell − ρ_gt_cell|/ρ_gt_cell` averaged over cells (and time), wiring the existing spatial GT function; requires adding **per-cell ρ̂ tracking** (today only a global distinct-vid set at [10:226](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L226)).
- **TPE is closer to correct than v2 claimed.** `compute_TPE()` dead-reckons `p̂ = p_prev + v_prev·dt` from the last (possibly poisoned) beacon vs SUMO GT — which the *updated* paper explicitly wants ("quantifying the impact of trajectory poisoning on the controller's individual path prediction model"). Remaining issue: it returns −1 unless SUMO-derived, so it needs a SUMO eval run to produce values. M4's "reported not predicted" complaint is largely obsolete under the new spec.

**Open decisions (methodology — need supervisor sign-off, not changed unilaterally):**
1. **TDEE binning scheme**: per-RSU-cell (radius = comm range) spatial density, averaged over cells and per-epoch time-bins? The paper text says "traffic density" without pinning the binning; the code's own `get_gt_density_in_cell` comment implies per-RSU-cell. This choice re-defines every TDEE number.
2. **Eval default**: switch the evaluation default to `--mobility_source=1` (SUMO) so TDEE/TPE stop returning −1 — but this **perturbs the existing hardcoded-mobility experiment baseline**, so it must be a deliberate eval-config decision, run as a separate SUMO batch rather than flipping the global default.

#### ✅ Resolution — C3 TDEE implemented & smoke-verified (2026-07-05, per approved option 2)
Per-RSU-cell **spatial** TDEE now implemented, keeping the hardcoded-mobility default untouched (SUMO runs stay a separate eval batch):
- `10_metrics_csv.h` — new per-cell sets `g_ctrl_seen_cell[MAX_RSUS]` (ρ̂: vehicle attributed to the Voronoi cell of its **reported** position, accepted beacons only) and `g_gt_seen_cell[MAX_RSUS]` (ρ_gt: vehicle attributed to the cell of its **SUMO true** position, sampled at the **same beacon instants**, Sybil-forged vids ≥ N_Vehicles excluded). Both booked inside `log_beacon_to_csv` — GT must be sampled **during** the sim because ns-3 mobility models assert (`m_lastUpdate <= now`, constant-velocity-helper.cc:84) if queried after `Simulator::Destroy()`.
- `compute_TDEE()` — per-cell mean `|ρ̂_cell − ρ_gt_cell|/ρ_gt_cell` over cells with ρ_gt>0 (Eq 4.5); still −1 when not `is_sumo_derived()`. Voronoi assignment via `nearest_rsu_for_position` (08:~3154), which uses actual placed RSU positions (12_main.h:701-711 syncs from CSV in SUMO mode).
- **Smoke test** (urban, 200 veh / 64 RSU, attack 1 @30%, simTime=30, RngRun=1): `TDEE = 0.720` (cells scored=25/64, distinct ρ̂ vids=23), `TPE = 51.144` (3116 samples), 3139 beacons. Note: simTime=8 produces **zero beacons** (warmup) — SUMO eval runs must use simTime ≥ 30 as in `run_all_scenarios.sh`.
- TPE unchanged (dead-reckoning vs SUMO GT — matches updated paper spec; M4's complaint obsolete).

### C4 — PARR is wired to the wrong counter (measures revocations, not TRS rejection)  *(new)*
**Paper:** Eq 4.3, p.74 — PARR = (poisoned RSU **aggregates** structurally blocked by **TRS threshold verification** before reaching the controller) / (total poisoned aggregates), "independent of AI detection." It isolates the **cryptographic** gate (Eq 3.51).
**Code:** `compute_PARR()` = `parr_trs_rejected / parr_poisoned_total` ([10:564](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L564)). But `parr_trs_rejected++` fires on the **lightweight detection-revoke path** — `rsu_lw.detected` + `consecutive_anomaly_count ≥ REVOKE_THRESHOLD` — at [08:2777](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2777), with **no TRS/crypto gating** and no ablation gate. The paper-correct counter `g_trs_rejected_count`, incremented only when σ_TRS verification actually fails in the crypto pipeline ([08:1212](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1212)), is **computed but never read** by `compute_PARR()`. The code comment even redefines PARR as a 3-consecutive-catch revocation rate ([10:557-562](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L557-L562)).
**Confirmation:** this is why the paper (§4.1.5) reports the impossible "A1 (lightweight, *no TRS*) PARR ≈ 0.30" — the counter fires in A1 because it is detection-driven, not TRS-driven.
**Fix:** make `compute_PARR()` use `g_trs_rejected_count` (TRS-verification failures, Eq 3.51) over total poisoned aggregates submitted; remove `parr_trs_rejected` or rename it to a separate "revocation rate" metric; gate it out of A1/B1. Re-run RQ5 — A1 PARR should then be 0.

#### ⚠️ Partial resolution — C4a done, C4b open (2026-07-05)
**C4a (counter wiring) — DONE, build green, verified.** `compute_PARR()` ([10_metrics_csv.h](scratch/mptd_pqs_sdvn/10_metrics_csv.h)) now returns `g_trs_rejected_count / (g_trs_verified_count + g_trs_rejected_count)` — the cryptographic TRS-verify gate (Eq 3.51), not the detection-revoke proxy. Both counters increment only inside `run_full_mode_crypto_pipeline` (gated `ablation_mode ∉ {1,6}` at [08:1745](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1745)), so A1/B1 report PARR = 0 by construction. The old detection-driven `parr_trs_rejected/parr_poisoned_total` ratio is retained but relabeled **RevRate** (not PARR). Smoke test 2026-07-05: A1 PARR=0.00 (was ~0.30 bogus), RevRate=0.98; A0 PARR=0.00 (0/52 aggregates rejected).

**C4b (reachability + denominator) — OPEN, needs a decision.** The RSU builds `sigma_trs` via honest `partial_sign`+`aggregate` then immediately verifies that same bundle ([08:1213-1226](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1213)) — **no attack path tampers the aggregate**, so `verify_threshold` never fails and `g_trs_rejected_count` is structurally always 0 → PARR ≡ 0 for all modes/attacks. Also, the **updated paper** (§Primary Evaluation Metrics, 2026-07-05) defines the denominator as "total poisoned aggregates **injected**" (not verified+rejected) and scopes PARR as **ablation-only: full mode vs AB6 (TRS disabled)**. To exercise PARR the sim must (i) count poisoned aggregates injected, (ii) have a compromised-RSU / MitM class produce a cryptographically-invalid aggregate that fails Eq 3.51, and (iii) expose an AB6 (TRS-off) variant. This is a threat-model change — hold for supervisor sign-off before implementing.

---

## 2. High-severity flaws

### H1 — CP-DETECT TRS-verify gate is a dead no-op
**Paper:** Alg 9 line 2 (p.68): `valid ← Verify({pk_j}, m_j, σ_TRS)` (Eq 3.51) is a mandatory hard gate; failure ⇒ `ALERT_CP(TRS_FAIL)`.
**Code:** `cp_detect_verify_trs()` returns `true` when `sigma_trs==nullptr` ([08:762](scratch/mptd_pqs_sdvn/08_detection_engine.h#L762)); all callers pass nullptr ([08:815](scratch/mptd_pqs_sdvn/08_detection_engine.h#L815)). Gate (a) never runs.
**Fix:** feed the real σ_TRS produced by `run_full_mode_crypto_pipeline` into `run_cp_detect_per_epoch` and let `verify_threshold` run; keep nullptr only for A5.

### H2 — Consensus is a single-vehicle temporal window, not distinct-RSU quorum
**Paper:** Eq 3.60 `Σ_{r_j∈R} 1[ψ_j^(i)>ψ_th] ≥ 2f+1 ⇒ Revoke`; Eq 3.61 conflict over **distinct RSUs** `Σ_{r_j} 1[σ_c conflicts E_j] ≥ f+1` (p.67).
**Code:** CP-DETECT accumulates one vehicle's temporally adjacent beacons into a per-vehicle deque ([08:718-726](scratch/mptd_pqs_sdvn/08_detection_engine.h#L718-L726), [08:834-851](scratch/mptd_pqs_sdvn/08_detection_engine.h#L834-L851)). The SC-Revoke side claims 2f+1 ([08:2782-2784](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2782-L2784)), but because each beacon physically reaches exactly one RSU in the sim topology, distinct-RSU corroboration is synthesized, not organic.
**Fix:** give vehicles overlapping coverage from ≥3 RSUs, or add an explicit RSU↔RSU evidence broadcast so the f+1/2f+1 sums run over distinct RSU IDs witnessing the same epoch.

#### ⚠️ Update (2026-07-05, v3 audit) — counting fixed on-chain; physical reachability still open
The **vote-counting semantics are now paper-correct**: SC-Revoke votes are idempotent per `(vehicle, RSU)` key (`VOTE_<vid>_<rsuID>` overwritten on-chain, [08:2845-2909](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2845)), so one RSU can never be counted twice and the 2f+1 quorum genuinely requires **distinct** RSUs. What remains open is the **topology**: non-overlapping RSU coverage means at most 2 distinct RSUs ever witness the same vehicle (< quorum 3), so completed on-chain revocation never fires organically — this is time-independent (see fix options above).

### H3 — GAT/AE/Fusion run at the wrong entity (per-RSU, in-memory) — graph build itself is OK
**Paper:** Alg 5 (p.59) "executed at the SDVN controller per sliding window"; line 2 "Retrieve beacon windows {X_i(t)} from IPFS using on-chain hashes"; submits `E_c(t)` as untrusted peer (Eq 3.59). Fig 3.9/3.11: Controller hosts GAT+AE+Fusion and pulls from the IPFS off-chain store.
**Code:** GAT+fusion run inside the per-RSU window-close hook (`rsu_id<4`) over in-memory `rsu_last_window` ([08:1758](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1758)); no IPFS retrieval for the AI path (IPFS in 06c is only the per-beacon CID commitment).
**Retraction:** the earlier "GAT graph semantics" concern is **withdrawn** — `score_gat` builds the COO edge_index with the exact Eq 3.26 predicate (dist≤R_max ∧ heading≤π/2) and appends τ_i as the 6th feature ([06d:243-287](scratch/mptd_pqs_sdvn/06d_ai_inference.h#L243-L287)). Only the *placement/entity* is wrong.
**Fix:** move the full-mode pass to a controller-side routine iterating all vehicles in V(t), retrieving windows from IPFS; submit Φ as the controller's untrusted-peer evidence (Eq 3.59). This also fixes the threat-model semantics (controller-as-untrusted-peer) and CDER attribution.

#### ⚠️ Update (2026-07-05, v3 audit) — nuance
Current code runs `AiInferenceEngine` at the **per-RSU window-close hook** over the flushed IPFS window ([08:1774](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1774), `rsu_last_window_valid[rsu_id]`), with the per-vehicle LSTM-AE ring buffer in memory ([04_state_globals.h:302]). So the *window/graph inputs* now match the paper's per-RSU-window shape, but the pass still executes in the RSU's hook rather than a controller-side routine fed by IPFS retrieval — the placement/entity gap stands.

### H4 — State-of-the-art baselines B2 and B3 are not implemented  *(new)*
**Paper:** §4.1.1 (p.72) defines three external baselines — B1 Ghaleb 2014, **B2 Vishwanath & Reddy 2026 (federated LSTM-AE)**, **B3 Somma 2025 (temporal AE w/ differential consistency loss)**. Results (§4.1.4–4.1.6) contain only B1.
**Why it's a flaw:** RQ3/RQ4 superiority claims need B2/B3 comparison; this is exactly schedule Row 3 ("State of the art implementation must be finished … connected to the simulation variables properly").
**Fix:** implement B2/B3 as toggleable baseline detectors fed the same beacon stream, scored through the same (fixed C1/C2) metric layer.

---

## 3. Medium-severity flaws

- **~~M2 — Threshold-decrypt hardcodes t=4~~ — RETRACTED.** Re-verified [08:1231](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1231): `threshold_decrypt_vec(ct, present_rsus, len, out)` — the literal `4` is the field-count `len` (decrypt 4 aggregate fields), not the threshold. The threshold (t=3, n=4) is configured at init via `init_threshold_fhe_backend(4,3,…)`. No crypto-agility violation. Finding withdrawn.
- **M3 — Stale comments** that contradict the code: σ_j^sub "PLACEHOLDER empty string" then signs ([08:2892-2929](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2892-L2929)); CP-DETECT "no-op stub returning valid=true" / "ClassicalTrsBackend any-pk" ([08:706](scratch/mptd_pqs_sdvn/08_detection_engine.h#L706), [08:749](scratch/mptd_pqs_sdvn/08_detection_engine.h#L749)); "R7e adds the ring" already wired ([08:1755](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1755)). Sweep and correct.
- **M4 — TPE/CDER oracle fidelity.** TPE accumulates reported-vs-SUMO displacement, but Eq 4.6 wants controller-*predicted*-vs-SUMO ([10:617-636](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L617-L636)). CDER's fallback `(FP+FN)/total` ([10:582](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L582)) is a beacon-error proxy, not a control-decision oracle — fine only when the downlink decision log is populated.

## 4. Paper-text defects (feed Task 2 / report revision, Row 2)  *(new — M5)*
These are in the PDF itself and will surface in the report revision:
- **Broken cross-references:** "Algorithm **??**" (p.78 §4.1.5), "Section **??**" (pp.45, 59, 63), "Equation **??**" (Fig 3.10 caption / p.48 TRS Partial Signer).
- **Fig 3.9 mislabels the Fusion Engine as Eq 3.54** (threshold key-gen); the fusion equation is **Eq 3.43**.
- **Eq 3.50 claims σ_TRS is "compact and conceals which t members signed."** Per the locked D1 decision the implemented bundle is neither compact nor anonymous (liboqs has no lattice threshold-ring combine). The paper text needs a correction note (no eval metric depends on it).
- **"seven attack scenarios"** (§4.1.4) vs the six named (TP-S1, TP-S2, MP-S1..MP-S4) / seven `attack_number` values — reconcile the count.

---

## 5. Recommended order of attack (paper-impact first)
1. **C1 + C2** — make the full-mode verdict score into a sliced confusion matrix; unblocks every A2/A3/Full result (RQ3/RQ4).
2. **C4** — repoint PARR to `g_trs_rejected_count`; fixes the RQ5 story and the bogus A1 PARR.
3. **C3 / Row 3** — OSM+SUMO traces + spatial ρ_gt + controller prediction for TPE.
4. **H3** — relocate GAT/AE/Fusion to a controller-side IPFS-fed pass.
5. **H1** — feed the real σ_TRS into CP-DETECT gate (a).
6. **H4** — implement B2/B3 SOTA baselines (Row 3).
7. **H2** — realize distinct-RSU consensus (overlapping coverage / RSU broadcast).
8. **M2–M5** — de-hardcode t, comment sweep, TPE/CDER oracle fidelity, paper-text fixes.

> Provenance: every architectural claim in v2 is tied to a paper equation/figure read this session (pp.38–82) and a verified `file:line`. The only retraction vs v1 is the GAT graph-semantics concern (graph build is paper-correct). The strongest external corroboration of C1/C4 is the paper's own results section, which — consistent with these flaws — contains no full-mode (A2/A3/Full) or B2/B3 numbers.

---

## 6. Metrics reconciliation vs UPDATED paper "Primary Evaluation Metrics" (2026-07-05)

The paper's metrics section was rewritten to an **11-metric / 4-dimension** spec (new authority). This supersedes the v2 metric assumptions. Six metrics are scored against external baselines B1–B3; five are **ablation-only** (baselines lack the mechanism). Status vs current code:

| Metric | Eq | Scope | Code status |
|--------|-----|-------|-------------|
| MCC  | mcc  | All baselines | ✅ `compute_MCC` + `compute_MCC_full` |
| TTD  | ttd  | All baselines | ❌ **NOT implemented** — no `compute_TTD`, no `t_alert`/`t_start` capture per attacker |
| CDER | cder | All baselines | ✅ `compute_CDER` (M4 oracle-fidelity caveat stands) |
| TDEE | tdee | All baselines | ⚠️ `compute_TDEE` exists but wrong ground-truth defs (**C3**) |
| TPE  | tpe  | All baselines | ⚠️ `compute_TPE` exists but reported-vs-SUMO not predicted-vs-SUMO (**C3/M4**) |
| PBPO | pbpo | All baselines | ✅ `compute_PBPO` (LW + full timing) |
| PARR | parr | **Ablation only** (full vs AB6) | ⚠️ C4a wired; denominator="total poisoned aggregates injected" + reachability open (**C4b**) |
| FRR  | frr_revoke / frr_demote | **Ablation only** (full vs AB10) | ❌ **NOT implemented** — no false-revoke/false-demote counters over honest set 𝓔_honest |
| COO  | coo  | **Ablation only** (full vs AB6/AB7 + ECDSA variant) | ❌ **NOT implemented** as per-epoch Δt_TRS+Δt_FHE split (partial timing exists in `g_fullcrypto_time_sum_ms`); no DKG-setup Δt_DKG report |
| BWO  | bwo_ratio / bwo_scale | **Ablation only** (full vs AB6/AB7/AB10/AB11) | ❌ **NOT implemented** — no byte accounting, no LKH-rekey scaling sweep |
| TCL  | tcl_confirm / tcl_reassign | **Ablation only** (full vs AB10) | ❌ **NOT implemented** — no Fabric block-confirm or post-revoke reassignment latency capture |

### 6.1 Spec-level changes to absorb
- **FPR dropped.** The paper now makes MCC the *sole* detection-quality metric ("detection-rate, F1, or FPR … redundant"). Code still emits `compute_FPR`/`compute_FPR_full` — **surplus, not wrong**; leave in CSV for diagnostics, do not report in paper tables.
- **New ablation numbering.** PARR/FRR/COO/BWO/TCL reference **AB6 (TRS disabled), AB7 (FHE disabled), AB10 (blockchain removed), AB11 (LKH replaced)**. These do NOT map to the current `ablation_mode` 0–6 enum (0=Full,1=A1…5=A5,6=B1). A mode↔AB mapping (or new toggles) is required before any ablation-only metric can be produced.
- **Metric-to-RQ mapping** is now explicit (Table tab:metric-rq); RQ5 depends on PARR/COO/BWO/TDEE, RQ6 on FRR/CDER/BWO/TCL — none of the RQ5/RQ6 ablation metrics except partial PBPO/TDEE are currently produced.

### 6.2 New pending items (feed the fix queue)
| ID | Metric | Gap | Depends on |
|----|--------|-----|-----------|
| C5 | TTD | no time-to-detect capture (t_alert−t_start per attacker) | detection-alert timestamp log |
| C6 | FRR | no false-revoke/false-demote counters over honest 𝓔_honest | SC-Revoke/SC-Trust event log + honest GT |
| C7 | COO | no per-epoch Δt_TRS + Δt_FHE split; no Δt_DKG | crypto-pipeline instrumentation |
| C8 | BWO | no byte accounting + LKH-rekey scaling sweep | message-size instrumentation |
| C9 | TCL | no Fabric confirm/reassign latency | on-chain tx timestamp capture (needs Fabric-on runs) |
| C10 | Ablation map | ~~AB6/AB7/AB10/AB11 not wired to `ablation_mode`~~ **RESOLVED 2026-07-06** — new `--ablation_ab=0..11` selector + fine-grained toggles (see below) | — |

> These are **documentation of gaps only** — no metric code was added in this pass. TTD/FRR/COO/BWO/TCL are entirely absent; TDEE/TPE exist but are C3-flawed; MCC/CDER/PBPO are sound. Recommended sequencing after C4b: C3 (TDEE/TPE correctness) → C10 (ablation map, unblocks all ablation-only metrics) → C5–C9.

**C10 resolution (2026-07-06).** New `--ablation_ab=0..11` CLI selector maps every paper variant AB1–AB11 onto fine-grained boolean toggles (`enable_rule_signatures`, `enable_hmac_gate`, `enable_trs`, `enable_fhe`, `enable_rsu_lifecycle`, `enable_ctrl_rotation`, `use_lkh_tree`, plus existing GAT/AE CLI flags) [02_config_globals.h, dispatch in 12_main.h]. The legacy `ablation_mode` 0–6 enum is untouched (batch scripts/analyzer keep working); each AB except AB5 (≡mode 1) and AB10 (≡mode 5 + skip_blockchain) forces `ablation_mode=0` = full-minus-one-mechanism. Semantics: AB1 zeroes TP/MP rule flags (detectors still warm shared state, CP-DETECT stays); AB2 bypasses the Δ_HMAC gate; AB6 skips σ_TRS sign/verify (PARR counters untouched → 0/0); AB7 sends plaintext ring sums with TRS still binding the payload and the H7 envelope intact; AB8 → uniform-random endorsers over ALL RSUs; AB9 pins controller 0 (no rotation loop); AB11 → flat group keying, per-survivor leaf rotation, N_rekey=|V_j|. Outputs carry an `_ab{N}` suffix (dataset folder + sweep CSV) and a new `ablation_ab` CSV column after `ablation_mode`. Smoke (simTime=30, a1/p30, RngRun=1, skip_blockchain): AB2 → zero per-beacon HMAC-gate logs, full crypto path intact; AB6 → sigma=0B, TRS-verify 0/0, PARR 0/0; AB7 → plaintext path ~0.45 ms/epoch (vs ~170 ms FHE), dec mean == pt mean 8.000, sigma=13909B still present; AB11 → `FLAT/unicast (AB11: N_rekey=|V_j|)` on all 5 revocations; legacy `--ablation_mode=0` run unchanged (no `[ABLATION]` banner, no `_ab` suffix).

---

## 7. v3 full-paper conformance audit (2026-07-05) — updated LaTeX vs code

Systematic mechanism-by-mechanism walk of the **complete updated paper** (threat model → LKH/DKG → LW-DETECT → GAT/LSTM-AE/fusion → PQ-FHE-TRS → SC-* / CP-DETECT → metrics/ablations) against `scratch/mptd_pqs_sdvn/` + `analytics/ml/` + `gat_detector/`. New findings get IDs **H5–H7** (high) and **M6–M8** (medium); everything checked-and-conformant is recorded in §7.3 so the supervisor deliverable shows positives, not just gaps.

### 7.1 New high-severity flaws

#### H5 — HMAC replay protection incomplete: no Δ_HMAC freshness window, no cluster nonce cache
**Paper:** beacon HMAC carries monotonic per-vehicle nonce ν_i; receiver enforces freshness window Δ_HMAC and an **RSU-cluster-level nonce cache** rejects replays across RSUs of the same cluster.
**Code:** per-vehicle monotonic nonce **exists** and keys the session KDF (`g_vehicle_nonce`, [00_lkh_keys.h:120-128, 459-490](scratch/mptd_pqs_sdvn/00_lkh_keys.h#L459)); HMAC verify is constant-time ([00:787-804]) and the timestamp is inside the MAC input ([00:771]). **Missing:** any `|t_recv − t_now| < Δ_HMAC` freshness gate at the RSU RX path ([08:1983-2004](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1983)), and any cluster-shared replay/nonce cache. A captured beacon replayed within a key epoch (same RSU or a sibling RSU in the cluster) passes the HMAC gate.
**Fix:** add Δ_HMAC check at `hmac_gate_pass`; add per-cluster `(vid → last-seen nonce/timestamp)` cache shared across the zone's RSUs.

##### ✅ Resolution (2026-07-05, build green, smoke-verified)
Two gates added inside the HMAC gate, applied **only after** `mac_ok` (an attacker cannot forge a fresh timestamp because t is MAC-covered; the cache is updated only on a full pass so forged beacons cannot poison it):
- **Freshness:** `|now − t_beacon| ≤ delta_hmac` (new config `delta_hmac=0.5 s`, CLI `--delta_hmac`; paper leaves Δ_HMAC symbolic). Reject → `[LKH-HMAC-STALE]`.
- **Cluster nonce cache:** `g_hmac_last_seen_t[LKH_MAX_VEH]` ([00_lkh_keys.h](scratch/mptd_pqs_sdvn/00_lkh_keys.h)) — beacon timestamp must be strictly greater than the last accepted one for that vehicle, shared by all RSUs (single-process sim = the paper's cluster cache). Reject → `[LKH-HMAC-REPLAY]`.
- Smoke (hardcoded urban, attack 1 @30 %, simTime=30): 0 REPLAY, 0 MAC-FAIL, 6 STALE. The 6 are honest first-contact beacons delivered ~3 s late by ns-3 ARP resolution retries — genuinely stale at delivery, correctly rejected, booked as FP (TP=0 FP=6 TN=532 FN=0). **Open knob:** `delta_hmac=0.5` introduces ~1 % honest-stale FPs from this ARP warm-up artifact; raising to 3.5 s would eliminate them at the cost of a wider replay window — flag for supervisor/eval-config decision before batch runs.

#### H6 — TRS messages have no ring nonce ν_S / Δ_TRS freshness
**Paper:** TRS-signed evidence carries ring nonce ν_S and is rejected outside freshness window Δ_TRS.
**Code:** `EvidenceMessage` serialization has a timestamp but **no ν_S field** ([06b1_trs_backend.h:841-879](scratch/mptd_pqs_sdvn/06b1_trs_backend.h#L841)); neither `verify_threshold` nor `cp_detect_verify_trs` ([08:772-803]) gates on recency. A valid σ_TRS bundle is replayable indefinitely.
**Fix:** add ν_S to the signed payload + Δ_TRS check at both RSU-side and CP-DETECT verification. Natural to land together with H1 (σ_TRS wiring).

##### ✅ Resolution (2026-07-05, build green, smoke-verified)
Implemented in the **live** TRS path `run_full_mode_crypto_pipeline` ([08_detection_engine.h](scratch/mptd_pqs_sdvn/08_detection_engine.h)):
- **trs_message:** wall-clock `t` and monotonic ring nonce `ν_S` (`g_trs_ring_nonce_issued`) are appended **inside the signed bytes** — m = (Enc(A_ring), t, ν_S, ID_S, h(S)) per the paper; a replayed bundle cannot be re-stamped without invalidating σ_TRS.
- **trs_fresh (cloud gate):** before Eq 3.51 verify: `|now − t| ≤ delta_trs` (new config `delta_trs=2.0 s`, CLI `--delta_trs`) AND `ν_S >` cloud replay cache `g_trs_cloud_last_nonce_seen`. Failure → `[TRS-FRESH-FAIL]` + σ_TRS rejected (feeds PARR numerator like any TRS reject).
- Smoke (full mode, attack 1 @30 %, simTime=30): 19/19 bundles fresh + verified, 0 FRESH-FAIL, PARR=0 as expected on the honest path.
- Note: the dead helper `evidence_sign_and_verify`/`EvidenceMessage` (06b1, **no callers**) was left untouched — fold into M3 (its "PARR counters incremented here" comment is stale too). CP-DETECT-side freshness lands with H1 when real σ_TRS flows there.

#### H7 — Plausibility envelope checks absent at both FHE boundaries
**Paper:** (i) RSU checks the plaintext aggregate against a **SUMO-derived plausibility envelope before Enc()** (Alg pq_fhe_trs line 3); (ii) at THRESH-DEC, decrypted aggregates failing the envelope are **replaced by the last valid window's value**.
**Code:** neither exists. `threshold_decrypt_vec` decrypts and returns unconditionally ([06b2_fhe_backend.h:425-465](scratch/mptd_pqs_sdvn/06b2_fhe_backend.h#L425)); no envelope/`last_valid` state anywhere in the encrypt or decrypt call sites in 08. Grep for envelope/plausibility/last_valid hits only attack-model clamping.
**Fix:** derive the envelope from SUMO stats (ties into C3's spatial GT machinery); keep a per-RSU `last_valid_aggregate`; gate both boundaries. **Interacts with C4b** — a tampered aggregate failing the envelope is one of the few natural ways PARR's numerator can fire.

##### ✅ Resolution (2026-07-05, build green, smoke-verified)
`fhe_aggregate_envelope_ok()` ([08_detection_engine.h](scratch/mptd_pqs_sdvn/08_detection_engine.h)) — scenario-derived bounds: speed ∈ [0, 1.1·max(s_max, maxspeed/3.6)]; position within the ACTUAL RSU deployment box ± 2·R_max (valid for hardcoded and SUMO layouts, since 12_main.h syncs `g_rsu_actual_pos_*` from placed positions); count ∈ [1, count_max]. Wired at both boundaries of `run_full_mode_crypto_pipeline`:
- **Pre-enc (Alg PQ-FHE-TRS):** each RSU's plaintext A_j is checked before Eq 3.46 Enc(); reject → `[FHE-ENV-PRE-REJECT]`, contribution dropped (and its vids excluded from h(S) so the signed vid-union matches the ciphertexts actually summed).
- **Post-dec (Alg THRESH-DEC):** decrypted aggregate validated using **only decrypted fields** (cloud trusts no plaintext-side state); reject → reuse `g_fhe_last_valid_mean_speed` (last valid window, per paper) or discard if no valid window exists yet → `[FHE-ENVELOPE-REJECT]`.
- Smoke (full mode, attack 1 @30 %, simTime=30): 0 envelope rejects on honest windows, 19/19 pipeline runs, dec mean == pt mean (8.000). **C4b remains open:** no attack path yet produces an out-of-envelope aggregate, so the reject branches are exercised only structurally — the compromised-RSU/AB6 threat-model change still needs supervisor sign-off.

### 7.2 New medium-severity flaws

- **M6 — Fusion omits the S/θ_S normalization.** Paper Eq: Φ = λ₁ψ + λ₂·(**S/θ_S**) + λ₃(ε/θ_ae), θ_S locked from a clean-data percentile. Code fuses **bare** `gat_score` ([06d_ai_inference.h:499-501](scratch/mptd_pqs_sdvn/06d_ai_inference.h#L499)); no θ_S is trained, stored, or loaded anywhere. Mitigant: GAT output is already sigmoid-bounded ∈[0,1] and λ₂ is SLSQP-fit to that scale, so the deployed system is self-consistent — but it does **not** match the paper equation, and the paper's θ_S-percentile calibration step has no code counterpart. Decide: implement θ_S, or amend the paper equation (feeds M5/Task 2).
- **M7 — GAT standardization is snapshot-level, not locked per-node stats.** Paper: per-node stats (x̄′_i, σ′_i) locked from a clean re-run and loaded at inference. Code computes `mu = emb.mean(dim=0)`, `sig = emb.std(dim=0)` **live per snapshot** ([analytics/ml/gat_detector.py:68-71]); no stats file exists. Under heavy attack the snapshot statistics are themselves contaminated → anomaly scores are normalized against a poisoned baseline (self-masking risk). Decide: implement locked stats, or justify snapshot normalization in the paper.
- **M8 — LSTM-AE window train/deploy inconsistency risk.** C++ deploys `LSTM_WINDOW_SIZE = 10` ([06d:125]); `analytics/ml/lstm_ae.py:17` hardcodes `WINDOW_SIZE = 20` (used by `train_lstm_ae.py`), while `train_fusion.py` reads the window from `arch_<scenario>.json` (fallback 10). The deployed/selected models are window=10 for **all** scenarios, but the paper's full-mode selection table claims Urban L=20 — consistent with the stale python constant. Fix: align `lstm_ae.py` default to 10 + correct the paper table (feeds M5).

### 7.3 Verified conformant (v3 positives)

| Mechanism | Paper spec | Evidence |
|---|---|---|
| **TRS DKG (no dealer)** | Joint-Feldman DKG, n=4, t_sign=2, group secret never assembled | [06b1:210-401] — per-member polynomials, Feldman commitments, shares only. In-process (single sim proc plays all members) |
| **FHE threshold keygen** | n+1=5 parties (4 RSU + Cloud), t_decrypt=3, no single dealer | [06b2:298-365] — chained `MultipartyKeyGen`, `ShareKeys` (t,n+1) Shamir |
| **PQ primitives** | ML-DSA-87 / OpenFHE BFV @ NIST L5 | [06b1:654-781] liboqs ML-DSA-87; [06b2:318] `HEStd_256_quantum`; real crypto when libs present |
| **λ fusion training** | λ_k≥0.05, Σ=1, SLSQP, pos-weight 2.0, Φ_th=0.5 | [analytics/ml/score_fusion.py:129-134]; [06d:68] `phi_threshold=0.5` |
| **θ_ae frozen** | median/mean+κ·MAD offline on clean, no online update | [analytics/ml/lstm_ae.py:72-91] κ=1.645; [06d:242-248] loaded once, never written |
| **GAT training** | supervised class-weighted BCE (w± = \|V\|/2\|V±\|) | [gat_detector/train.py:176-184] |
| **LW-DETECT thresholds** | ψ_th=0.09, drift 10 m/10 beacons, a_max=4.0, ω_max=0.5236, d_min=10, τ_sync=1 ms, ρ_sync=0.8 | [02_config_globals.h:217-265] — all match |
| **Attack params** | stealth ≤0.5 m, abrupt 7–12 m, stealth-prop 0.7, streak 50, ≤40 % attackers | [06a + 02:304-308, 104] — all match |
| **SC-Register** | 2f+1 RSU endorsement (f=1→3), τ_init=1.0 | [11_blockchain_setup.h:686, 299] |
| **SC-Trust vehicle EWMA** | α=0.3, τ_warn=0.5, τ_min=0.3, T_rev=3 (on-chain) | [06c:1017-1031, 849-852]; 1 Hz finalize [08:3000] |
| **RSU 3-state lifecycle** | trusted/probationary/client via m_j(t), 3f+1 floor | on-chain; ns-3 reads `GetAllRSUTrustScores` [06c:1174-1241], trusted set [11:684] |
| **Controller trust τ_ck** | directional conflict (suppression only), flag at f+1 | [06c:1144-1172]; CP threshold f+1=2 [08:756]; 1 Hz + 3 s lag [08:3042] |
| **Trust-ranked endorsers @1 Hz** | re-select top-2f+1 by trust each second | [11:617-703], `g_committee_refresh_interval=1.0` |
| **SC-Revoke distinct-quorum counting** | 2f+1 **distinct** RSUs (idempotent votes) | [08:2845-2909] — resolves the H2 counting half |
| **LKH** | per-zone key tree, rekey cost log₂\|V_j\|, zone-scoped | [00:84-183]; survivors-only rekey [08:133-176] |

### 7.4 Consolidated open-item queue (v3)

Priority order, superseding §5 where they overlap:
1. **C4b** (PARR reachability — needs supervisor sign-off; now coupled with **H7** envelope checks)
2. ~~**C10** ablation map AB1–AB11 ↔ `ablation_mode`~~ — resolved 2026-07-06 via `--ablation_ab` selector, see §6.2 resolution note
3. **C5–C9** (TTD, FRR, COO, BWO, TCL) — now unblocked by C10
4. **H3** controller-side relocation; **H1** σ_TRS wiring (only the CP-DETECT-side ν_S/Δ_TRS freshness re-check still rides with H1 — the coordinator/cloud side of **H6** landed 2026-07-05)
5. **H2** coverage reachability (overlapping RSU coverage or evidence broadcast — same root cause as the SCREVOKE quorum-unreachable note)
6. **M6–M8** (θ_S decision, GAT locked stats decision, window constant + paper table) — M6/M7 are **methodology decisions**, hold for supervisor
7. **M3/M5** comment sweep + paper-text fixes (add: Urban L=20 table row; `Eq \ref{eq:fpr}` referenced in §model-selection though FPR was dropped as a metric; fold in dead `evidence_sign_and_verify` cleanup)
8. **Eval-config decision**: Δ_HMAC=0.5 s vs 3.5 s (ns-3 ARP warm-up causes ~1% honest-stale FPs at 0.5 s — see §7.1 H5 resolution note) — hold for supervisor before batch runs

~~H5 Δ_HMAC + cluster replay cache~~ and ~~H6 ν_S/Δ_TRS (coordinator+cloud side)~~ and ~~H7 plausibility envelope~~ — all resolved 2026-07-05, see §7.1 resolution notes.
