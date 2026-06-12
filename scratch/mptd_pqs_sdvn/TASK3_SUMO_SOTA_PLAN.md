# TASK 3 — OSM+SUMO Real Map · SOTA Baselines · Correct Plots

**Supervisor deadline:** 2026-06-12
**Task text:** "Get a real-world map for the simulation using OSM and SUMO (dense urban, many intersections). Finish the state-of-the-art implementation; verify SOTA is wired to the simulation variables correctly and plots are correct."
**Working rule:** the paper is ground truth; code **and comments** may be wrong — every design decision is taken from the paper §/Eq/Fig, not from what the code asserts. This doc is self-contained so it can be carried into a fresh chat.

---

## 0. Three sub-tasks

1. **OSM + SUMO real urban map** (greenfield — no OSM project exists today).
2. **Finish SOTA baselines** (B1 done in C++; B2/B3 mismatched & not integrated — see §3, likely a teammate's scope).
3. **Correct plots** (currently driven by a metric layer with known bugs — see §4).

---

## 1. What the paper requires (authority)

From §4.1.1–4.1.3 (pp.72–76), verified by reading the PDF:
- **Simulation stack:** "Experiments are conducted in NS-3 integrated with SUMO" — SUMO is mandatory.
- **Sweep variables:** penetration ρ_a ∈ {0.05, 0.10, 0.20, 0.30}; **speed regimes urban ≤30 / suburban 30–80 / highway >80 km/h**; attack duration burst <30 s and sustained drift >5 min; 4 attacker classes (malicious vehicle, compromised RSU, MitM, malicious controller); operating mode lightweight vs full.
- **Baselines:** B1 = Ghaleb 2014 [7]; **B2 = Vishwanath & Reddy 2026 [18] (federated LSTM-AE)**; **B3 = Somma 2025 [21] (temporal AE, differential consistency loss)**.
- **Metrics:** all 7 (Eq 4.1–4.7), **sliced per attack-variant × attacker-class**; TDEE (Eq 4.5) and TPE (Eq 4.6) *require* the SUMO ground-truth side-channel (ρ_gt, p_gt).
- The paper does **not** name a specific city/OSM extract — "dense urban, many intersections" is the supervisor's addition. Note the speed-regime requirement spans urban→highway, so a single dense-urban map covers only the low/medium regimes; a highway/arterial map is also needed.

---

## 2. Current state — Part 1 (SUMO/mobility)

**What works:**
- `FcdTraceMobilityProvider` ([09b_mobility_provider.h:189-217](09b_mobility_provider.h#L189-L217)) loads an ns-2 `.tcl` via `Ns2MobilityHelper`; `is_sumo_derived()` returns true so TDEE/TPE become live. Feeding a real OSM-SUMO-FCD `.tcl` is enough to satisfy Eq 4.5/4.6.
- `default_sumo_trace_path(scenario, speed)` ([09b:226-240](09b_mobility_provider.h#L226-L240)) resolves `mobility/mobility_{urban,rural,autobahn}_{speed}.tcl`.
- CLI already present: `--mobility_source` (0=hardcoded,1=sumo_trace,2=sumo_live-stub), `--mobility_scenario` (0=urban,1=rural,2=highway), `--maxspeed`.

**Gaps:**
- **No OSM project exists** — no `.osm/.net.xml/.rou.xml/.sumocfg` anywhere. The only trace, `mobility/mobility_urban_20.tcl` (17,061 lines), has round grid-like coordinates (e.g. `312.3,-1.6`) → it is a **synthetic grid, not OSM-derived**. Treat as placeholder.
- Only `urban_20` exists; suburban/highway traces for the speed regimes are missing.
- Default is `--mobility_source=0` (hardcoded) → TDEE/TPE return −1 in normal runs (audit C3).
- RSU topology is **4 RSUs in a line** (x={250,750,1250,1750}, y=480 — [08b_baseline_ltt.h:52-53](08b_baseline_ltt.h#L52-L53)), a ~2 km road. A dense urban grid needs RSUs re-placed at intersections (this also helps audit H2: overlapping coverage makes 2f+1 distinct-RSU consensus organic).
- `MOBILITY_SRC_SUMO_LIVE` (TraCI) is an unimplemented stub ([09b:254-257](09b_mobility_provider.h#L254-L257)) — fine; we use the offline `.tcl` path.

---

## 3. Current state — Part 2 (SOTA baselines) ⚠️ discrepancy

- **B1 (Ghaleb 2014 LTT)** — implemented in C++ ([08b_baseline_ltt.h](08b_baseline_ltt.h)), wired as `--ablation_mode=6`. Matches paper. ✅
- **B2 / B3** — exist only as Python in `mptd_pqs/` and implement **different papers than the draft cites**:
  - `mptd_pqs/ercan_b2_detector.py` → **Ercan et al. 2022** (kNN/RF/Stacking). Paper B2 = Vishwanath & Reddy 2026 (federated LSTM-AE).
  - `mptd_pqs/sharma_b3_detector.py` → **Sharma & Liu 2021** (SVM/kNN/NB/RF/AdaBoost). Paper B3 = Somma 2025 (temporal AE).
  - They read `analytics/results/rsu_relay_log.csv` and run their **own** cross-validation — **not integrated** into the main NS-3 sweep (which covers only MPTD-PQS + A1–A5 + B1).
- `mptd_pqs/` also contains Python reference copies of our own modules (gat_detector, temporal_autoencoder, fusion, lightweight_detector, metrics_*). Likely a teammate's analysis folder.

**RESOLVED (2026-06-07, user):** the team deliberately swapped B2/B3 to **Ercan (2022)** + **Sharma & Liu (2021)**, implemented by a teammate in `mptd_pqs/`. The **code is authoritative**; the **paper draft will be updated** to cite these (the Vishwanath&Reddy/Somma citations are stale). → not a flaw, no baseline re-implementation needed; baseline work is the teammate's scope. Our remaining job is only to make sure B1/B2/B3 are scored through the same (fixed) metric layer when they run.

---

## 4. Current state — Part 3 (plots) — CORRECTED 2026-06-07 (verified data flow)

**The plots do NOT use the C++ metrics.** Verified pipeline:
```
C++ sim → analytics/results/beacon_log.csv (raw per-beacon)
        → analytics/ml/evaluate_all.py  (loads GAT/AE, RE-computes metrics in Python for all 6 variants)
        → metrics_a{A}_p{P}_s{S}_m1.csv → sweep_summary.csv → plot_per_attack.py / plot_metrics_vs_attack_pct.py
```
So the C++ `compute_MCC/PARR/...` (10_metrics_csv.h) feed a *different, plot-unused* path. Implications:
- **C1** (full-mode verdict): `evaluate_all.py` already scores fusion per variant (line ~288). A2/A3/Full are degenerate **only because the GAT/AE ONNX models are not trained** — NOT a code bug. → blocked on model training (intentionally deferred).
- **C2** (attacker-class slice): `beacon_log.csv` already has `attacker_class`; `evaluate_all.py` just doesn't group by it → **Python fix, doable now**.
- **C4** (PARR): `evaluate_all.py` computes PARR as a **made-up proxy** (line ~87, "realistic proxy") instead of the real `trs_rejected_count` column → **Python fix, doable now**.
- **NEW (core of "plots not correct"):** `evaluate_all.py` fabricates **PARR, CDER, TDEE, TPE from proxy formulas** (functions literally commented "proxy"/"approximation") off the FN count — not the real sim-measured columns the C++ already writes (`trs_verified/rejected_count`, `ctrl_decisions_total/wrong`). 4 of 7 plotted metrics are **not measured from the simulation**.
- **C3** (TDEE/TPE): the Python proxies need SUMO ground truth → blocked on SUMO.
- Stale: `mptd_pqs/metrics_calculator.py` uses OLD pre-redesign defs (Eq 3.68/3.70/3.72; PARR=detection rate, TDEE=Σδ²) — not the sweep evaluator; ignore.

**Data-persistence gap:** `beacon_log.csv` is **truncated/overwritten every run** ([10_metrics_csv.h:105-119](10_metrics_csv.h#L105-L119)). Only `run_evaluation.sh` archives it (copies to `sweep/beacon_logs/beacon_a*.csv` before the next overwrite). **Manual single runs lose the previous run's data.**

---

## 5. The plan (ordered by dependency)

> Cross-refs: see `DESIGN_FLAWS_AUDIT.md` (C1–C4, H2) and `TASK2_CRYPTO_PLAN.md` §7.4 (evidence run). The SUMO map also unblocks the deferred crypto evidence run and TDEE/TPE.

**Step 0 — Baseline decision — RESOLVED 2026-06-07.** B2/B3 = Ercan (2022) + Sharma & Liu (2021), teammate-owned in `mptd_pqs/`; paper to be updated to match. No baseline re-implementation on our side.

**Step 1 — OSM→SUMO pipeline (the core of this task).**
1. Pick a **dense urban OSM extract** (many intersections) + a separate **arterial/highway** extract for the high-speed regime.
2. `osmconvert`/`osmfilter` → `netconvert --osm-files map.osm -o map.net.xml`.
3. Generate demand: `randomTrips.py` (+ `duarouter`) tuned per speed regime (urban ≤30, suburban 30–80, highway >80 km/h).
4. `sumo -c map.sumocfg --fcd-output fcd.xml`.
5. `traceExporter.py --fcd-input fcd.xml --ns2mobility-output mobility/mobility_{urban|rural|autobahn}_{speed}.tcl`.
6. Keep the trace **node count consistent** with the sim's vehicle count; verify `Ns2MobilityHelper` installs cleanly.
7. **Re-place RSUs** at urban intersections (replace the linear 4-RSU array); make placement config-driven.
8. Make `--mobility_source=sumo_trace` the **evaluation default**; keep hardcoded for fast smoke tests.
9. Store the SUMO project under e.g. `sumo/` (`.osm`, `.net.xml`, `.rou.xml`, `.sumocfg`, a `build_traces.sh`) so traces are reproducible.
10. **Only after** new traces verified end-to-end, remove the placeholder `mobility/mobility_urban_20.tcl`.

**Step 2 — Plot/metric fixes — NOW-DOABLE SET (no model training, no SUMO).**
These are the agreed tasks from the 2026-06-07 session. Most are in the **Python** eval/plot layer, not C++.
- [ ] **P0 — Auto-save beacon_log per run (data persistence).** In `log_beacon_to_csv` ([10_metrics_csv.h](10_metrics_csv.h)) write BOTH `beacon_log.csv` (latest, pipeline-expected) AND a permanent `analytics/results/runs/beacon_a{attack}_p{pct}_s{speed}.csv` so manual single runs never clobber prior data. *File: 10_metrics_csv.h.*
- [ ] **P1 — Real PARR (C4).** Replace the proxy `compute_parr()` with the real `trs_rejected_count`/`trs_verified_count` columns. *File: analytics/ml/evaluate_all.py.* (Caveat: sweep runs `--skip_blockchain=true`; crypto/TRS path must be ON for real counts — add a crypto-on eval profile.)
- [ ] **P2 — Real CDER.** Replace the proxy `compute_cder()` with the real `ctrl_decisions_total/ctrl_decisions_wrong` columns (Eq 4.4). *File: analytics/ml/evaluate_all.py.*
- [ ] **P3 — Attacker-class slicing (C2).** Group MCC/FPR by `attacker_class` (already in beacon_log.csv); emit per-class rows + per-class plots (paper §4.1.2). *Files: evaluate_all.py + plot_per_attack.py.*
- [ ] **P4 — Honest plotting.** Plot only variants/metrics with real signal (A1/A4/B1); mark A2/A3/Full "pending GAT/AE training" and TDEE/TPE "pending SUMO" instead of drawing proxy/degenerate values. *Files: plot scripts.*

**BLOCKED (do not attempt now):**
- **C1** full-mode A2/A3/Full plots → needs **trained GAT/AE ONNX models** (user deferring training).
- **C3** real TDEE/TPE → needs **SUMO ground truth** (Step 1).
- The C++-side audit fixes (C1/C2/C4 in 08/10) remain valid but feed a plot-unused path → lower priority.

**Step 3 — Ablation / "run part-by-part" usability (point 3).**
- Keep all toggles **orthogonal** so any variant runs on any scenario:
  - `--ablation_mode` 0=Full, 1=A1 … 5=A5, 6=B1 (+ `--enable_gat/--enable_lstm_ae` overrides).
  - `--mobility_scenario` × `--maxspeed` selects the trace; `--mobility_source=sumo_trace`.
  - `--trs_classical` for RQ5; `--attack_number`, `--attack_pct`, `--simTime`.
- Add a thin wrapper (e.g. `run_one.sh VARIANT SCENARIO SPEED ATTACK PCT`) for single runs, complementing the full `run_evaluation.sh` sweep.
- Verify the toggle matrix with a quick smoke run per variant (assert A1 full-CM empty, Full populated; A1 PARR≈0 after C4).

**Step 4 — Integrate baselines through one metric layer** (after Step 0 resolves) so B1/B2/B3 + A1–A5 + Full are all scored identically and comparably.

**Step 5 — Regenerate plots.**
- Per-attack × per-attacker-class MCC/FPR; PARR; CDER; TDEE/TPE (now live); PBPO (LW ≤100 ms; Full per W=L·T_b; TRS-vs-ECDSA).
- Verify each script reads the correct column; overlay baselines.

---

## 6. Dependency graph (quick view)

```
Step 0 (baseline decision) ──► Step 4 (baseline integration) ─┐
Step 1 (SUMO map) ──► Step 2 (metric fixes C1/C2/C4/C3) ──► Step 5 (correct plots)
Step 1 ──► (also unblocks: TDEE/TPE live, crypto evidence run [Task2 §7.4])
Step 3 (ablation/runner) runs alongside; verifies Step 2.
```

## 7. Definition of done
- Reproducible OSM→SUMO project producing urban/suburban/highway `.tcl` traces; `--mobility_source=sumo_trace` default for eval.
- RSUs placed at intersections; `Ns2MobilityHelper` install verified.
- TDEE/TPE non-negative on eval runs (no more −1).
- Metric layer fixes (C1/C2/C4) landed; A1 PARR≈0; full-mode variants produce distinct MCC/FPR.
- Any variant × scenario runnable in one command; full sweep green.
- Baselines (per Step 0 decision) scored through the same metric layer.
- Plots regenerated from corrected data, sliced per attack-variant × attacker-class, baselines overlaid.

## 8. Open questions for supervisor/team
1. B2/B3: paper's (Vishwanath&Reddy/Somma) or implemented (Ercan/Sharma)? Who owns baselines?
2. Specific OSM city/extract preference, or any dense-urban map acceptable?
3. Is the highway regime required for the urban-focused deliverable, or urban+suburban only for 12-Jun?
