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
| C3 | 🔴 Critical | TDEE/TPE: SUMO not wired by default; ρ_gt=N_Vehicles & p̂=reported pos (wrong defs) | Eq 4.5–4.6 (p.75) | **Confirmed** |
| C4 | 🔴 Critical | **PARR measures the wrong thing** — detection-revoke proxy, not TRS aggregate rejection; correct counter unused | Eq 4.3 (p.74) | **New / confirmed** |
| H1 | 🟠 High | CP-DETECT TRS-verify gate (a) is a dead no-op (callers pass nullptr) | Alg 9 line 2, Eq 3.51 | **Confirmed** |
| H2 | 🟠 High | Consensus uses a single-vehicle temporal window, not 2f+1 / f+1 over **distinct RSUs** | Eq 3.60–3.61 (p.67) | **Confirmed** |
| H3 | 🟠 High | GAT/AE/Fusion run per-RSU in-memory; paper runs them **at the controller via IPFS** | Alg 5 (p.59), Fig 3.9/3.11 | **Confirmed** (graph build itself OK — retracted) |
| ~~H4~~ | ⬜ Resolved | ~~B2/B3 unimplemented~~ — team swapped B2/B3 to Ercan(2022)/Sharma(2021), teammate-implemented in mptd_pqs/; paper to be updated | §4.1.1 | **Resolved 06-07** |
| ~~M2~~ | ⬜ Retracted | ~~Threshold-decrypt hardcodes t=4~~ — misread; the `4` is the field-count `len`, not the threshold (t=3,n=4 set at init) | Eq 3.54 | **Withdrawn** |
| M3 | 🟡 Medium | Several comments now contradict the code | — | Confirmed |
| M4 | 🟡 Medium | TPE uses reported pos not controller prediction; CDER fallback oracle is heuristic | Eq 4.4, 4.6 | New |
| M5 | 🟡 Medium | Paper-text defects (broken cross-refs; Fig 3.9 fusion mislabeled Eq 3.54; "compact+anonymous" TRS claim) | §3.5.3–3.5.4 | New (feeds Task 2 / report) |

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

### C4 — PARR is wired to the wrong counter (measures revocations, not TRS rejection)  *(new)*
**Paper:** Eq 4.3, p.74 — PARR = (poisoned RSU **aggregates** structurally blocked by **TRS threshold verification** before reaching the controller) / (total poisoned aggregates), "independent of AI detection." It isolates the **cryptographic** gate (Eq 3.51).
**Code:** `compute_PARR()` = `parr_trs_rejected / parr_poisoned_total` ([10:564](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L564)). But `parr_trs_rejected++` fires on the **lightweight detection-revoke path** — `rsu_lw.detected` + `consecutive_anomaly_count ≥ REVOKE_THRESHOLD` — at [08:2777](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2777), with **no TRS/crypto gating** and no ablation gate. The paper-correct counter `g_trs_rejected_count`, incremented only when σ_TRS verification actually fails in the crypto pipeline ([08:1212](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1212)), is **computed but never read** by `compute_PARR()`. The code comment even redefines PARR as a 3-consecutive-catch revocation rate ([10:557-562](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L557-L562)).
**Confirmation:** this is why the paper (§4.1.5) reports the impossible "A1 (lightweight, *no TRS*) PARR ≈ 0.30" — the counter fires in A1 because it is detection-driven, not TRS-driven.
**Fix:** make `compute_PARR()` use `g_trs_rejected_count` (TRS-verification failures, Eq 3.51) over total poisoned aggregates submitted; remove `parr_trs_rejected` or rename it to a separate "revocation rate" metric; gate it out of A1/B1. Re-run RQ5 — A1 PARR should then be 0.

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

### H3 — GAT/AE/Fusion run at the wrong entity (per-RSU, in-memory) — graph build itself is OK
**Paper:** Alg 5 (p.59) "executed at the SDVN controller per sliding window"; line 2 "Retrieve beacon windows {X_i(t)} from IPFS using on-chain hashes"; submits `E_c(t)` as untrusted peer (Eq 3.59). Fig 3.9/3.11: Controller hosts GAT+AE+Fusion and pulls from the IPFS off-chain store.
**Code:** GAT+fusion run inside the per-RSU window-close hook (`rsu_id<4`) over in-memory `rsu_last_window` ([08:1758](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1758)); no IPFS retrieval for the AI path (IPFS in 06c is only the per-beacon CID commitment).
**Retraction:** the earlier "GAT graph semantics" concern is **withdrawn** — `score_gat` builds the COO edge_index with the exact Eq 3.26 predicate (dist≤R_max ∧ heading≤π/2) and appends τ_i as the 6th feature ([06d:243-287](scratch/mptd_pqs_sdvn/06d_ai_inference.h#L243-L287)). Only the *placement/entity* is wrong.
**Fix:** move the full-mode pass to a controller-side routine iterating all vehicles in V(t), retrieving windows from IPFS; submit Φ as the controller's untrusted-peer evidence (Eq 3.59). This also fixes the threat-model semantics (controller-as-untrusted-peer) and CDER attribution.

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
