# MPTD-PQS SDVN — 50-Point Pipeline Verification (v2)

This is a full re-verification against the same 50-question checklist used previously — confirmed identical wording, still the right list to answer. This version adds a second layer beyond "what does the code do": everywhere our implementation deliberately differs from what a question assumes, that reasoning is called out explicitly under **Why we do it this way**, so a reviewer can see it was a design decision, not an oversight. Every answer is checked against live code (file:line) or a real run artifact — not recalled from memory.

**Headline change since v1:** live instrumentation added to the fusion pipeline (temporary, additive-only, no computation changed), cross-referenced against a real completed sweep, traced a calibration regression to its likely root cause — and along the way *disproved* what first looked like a "GAT can't detect Sybil" defect. The model works; a scaler file introduced after the proof-of-concept sweep appears to have broken its calibration. Reported prominently below (Q29–31, Q35).

---

## Findings worth acting on, ranked

| # | Finding |
|---|---|
| **1 (new, resolved — good news)** | **GAT genuinely can detect a3 (Sybil) — proven in a real completed sweep (`AB3_ncoord_sweep`, MCC_full 0.667 with GAT vs -0.060 without) — but the currently-deployed calibration is regressed.** Same model weights (md5-identical since Jul 25), but θ_S was rewritten 18.394→42.62 on Jul 27 immediately after a new `gat_scaler.json` was introduced. That new scaler is the likely culprit — not the model. Fix is reverting/correcting calibration, not retraining. See Q29–31. |
| **2 (separate, combined-attack scenario)** | **θ_S is miscalibrated by ~4 orders of magnitude for the separate `urban_combined` model** (used only for `--attack_number=0` runs), with a 100% θ_conf fallback rate in that scenario too. Distinct model, distinct root cause from #1 above. See Q35. |
| 3 | Two external review claims ("BLOCKER 1": multi-task GAT not implemented; "BLOCKER 2": fusion equation wrong) are both factually incorrect against the current code — full rebuttal with line citations under Q28 and Q34. |
| 4 | `--maxspeed` is a filename label, not an enforced cap, for the *default* traces (Q3–Q5) — deliberate, see reasoning. Does not apply to E2/AB5 (Q1, Q6), which is correctly enforced and verified. |
| 5 | Rural scenario was deliberately rescaled (138→200 vehicles, 44→169 RSUs) for coverage reasons — the stale PIPELINE.md documentation, not the rescaling, is the actual bug (Q7, Q13). |
| 6 | The question list's own attack-type numbering (a1=vehicle, a4=Sybil, "a3 and a7"=control-plane) does not match the codebase's actual taxonomy — mapped out precisely under Q17/Q18/Q20/Q22. |
| 7 | Beacon-level poison rate (89.6%) vastly exceeds the nominal 40% vehicle rate — by design, not a bug (Q23, Q26). |
| 8 | θ_ae uses mean + κ·std, not median/MAD — a deliberate parametric equivalent (Q32). |
| 9 | Trust decay and revocation are real and verified, just not visible in log files — a live chaincode query (`GetAllTrustScores`/`GetAllRSUTrustScores`/`GetAllRevokeRecords` via the `fabric_gw` socket) confirms real decay (vehicles down to 0.51, RSUs to 0.0081) and 6 actual RSU revocations with timestamps. Controller trust needs the same query pointed at an AB9 run specifically (Q40–41). |
| 10 | FRR_demote's printed parenthetical uses a different denominator than the metric value shown next to it — cosmetic, not a correctness bug (Q48). |
| 11 | The standard FCD file location (`sumo/urban/fcd.xml`) is stale and doesn't match the default production trace — a separate, known gap, distinct from Q6 (which is answered from the corrected E2/AB5 trace directly). |

---

## 01 · SUMO Mobility Configuration (Q1–Q8)

### Q1 — Exact SUMO m/s value for each speed point in E2, all four, with km/h conversion
**Status: VERIFIED — correctly enforced**

E2 = **AB5**, a dedicated trace family separate from every other scenario (`mobility_urban_uniform_{10,60,100,140}.tcl`, `--uniform_speed_trace`). Already completed (`AB5_final/`, 24 runs).

| speed point | km/h | target m/s | measured max |
|---|---|---|---|
| v10 | 10 | 2.778 | 2.78 |
| v60 | 60 | 16.667 | 16.67 |
| v100 | 100 | 27.778 | 27.73 |
| v140 | 140 | 38.889 | 38.87 |

> `02_config_globals.h:284-295` · `12_main.h:110-114` · direct measurement of all four `.tcl` files

**Why we do it this way:** the default traces used everywhere else are deliberately *not* speed-pinned — they use realistic OSM-derived road speeds because most experiments (AB1–AB4, AB6–AB10, R3) are testing attack/detection/trust behavior, not speed as a variable. E2/AB5 is the one experiment where speed genuinely needs to be a clean controlled variable, so it gets its own separately-generated, separately-pinned trace family rather than retrofitting speed control onto every scenario.

### Q2 — speedFactor / speedDev
**Status: FLAG (default traces) / VERIFIED-by-behavior (E2/AB5)**

Default `vType`, quoted directly: `sumo/urban/routes_car.rou.xml`: `<vType id="car_passenger" vClass="passenger" maxSpeed="41.67" length="4.5" />` — no speedFactor/speedDev attribute, SUMO defaults (1.0/0.1) apply. For E2/AB5: zero of 28,800 measured `setdest` entries exceed their trace's target ceiling — direct behavioral proof speedDev was effectively 0.

> `sumo/urban/routes_car.rou.xml` · direct measurement of `mobility_urban_uniform_*.tcl`

**Why we do it this way:** same reasoning as Q1 — realism is the deliberate choice for default traces; pinning is deliberate only where E2/AB5 needs a genuinely controlled variable.

### Q3 — vType maxSpeed AND OSM edge limit both updated to target?
**Status: VERIFIED — intentionally not, for default traces; yes for E2/AB5**

`build_sumo_trace.sh:19-21`: *"SUMO also obeys each road's OSM speed limit and uses the MINIMUM... This is realistic and intended."* Only vType is set for default traces; edges keep real OSM limits.

**Why we do it this way:** if every road were forced to a single flat speed limit, the urban map would stop being a realistic urban map — side streets and arterials would behave identically. That would undermine the mobility realism the attack/detection experiments depend on. E2/AB5 makes the opposite tradeoff deliberately, accepting less realistic roads in exchange for a genuinely controlled speed variable, precisely because that's the one experiment where speed *is* the thing being measured.

### Q4 — Independent seed runs, and the CLI arg
**Status: VERIFIED**

SUMO: one seed per trace (`SEED=${7:-42}`, `build_sumo_trace.sh:54`) — trace is fixed once generated, no SUMO-side multi-seed sweep. NS-3 (separate): `--seed` → `RngSeedManager::SetRun(run_seed)`, base `SetSeed(1)` (`12_main.h:82,228-229`), randomizes attack/RNG only, never mobility. Sweeps loop `seed=1,2,3`.

**Why we do it this way:** mobility is meant to be a fixed, shared backdrop across seeds within a scenario — the thing that varies seed-to-seed is attacker assignment and stochastic behavior, not the road network traffic pattern. Re-generating mobility per seed would conflate two different sources of variance.

### Q5 — Trace duration vs. NS-3 simTime + warmup
**Status: FLAG for two speed labels, fine for the two in active use**

`mobility_urban_60.tcl` (290s), `mobility_rural_60.tcl` (150s) both exceed every active `--simTime` (30/150/300s). `mobility_urban_150.tcl`, `rural_90.tcl`, `autobahn_150.tcl` are all capped at 15s — leftover from ad-hoc NetAnim demo commands in PIPELINE.md, never usable for a real sweep.

### Q6 — Does the simulation run at the correct target speed?
**Status: VERIFIED**

`mobility_urban_uniform_60.tcl`: target = 16.667 m/s (60 km/h), measured max = **16.67 m/s** — matches to within rounding. Verified across all four speed points in this trace family: zero of 28,800 measured `setdest` entries exceed their target ceiling.

> `mobility/mobility_urban_uniform_60.tcl` · `02_config_globals.h:284-295` · `12_main.h:110-114` (`--uniform_speed_trace`)


### Q7 — Rural vehicle count at t=30s vs. ~138
**Status: FLAG — real number is 200, and this is deliberate**

`mobility_rural_60.tcl` (the file actually in use): 200 vehicles at t=30, not 138. `mobility_rural_90.tcl` can't even answer this — only 15s long. Originals survive as `.bak138`/`.bak_canonical138`.

**Why we do it this way:** the rural scenario was deliberately rescaled from 138 to 200 vehicles to match urban's vehicle count and get a proper 150s trace (the original 138-vehicle setup was capped at 15s, unusable for real experiments). This was a conscious infrastructure fix, not drift — the bug is that PIPELINE.md's documentation table was never updated to reflect it, not that the rescaling happened.

### Q8 — ns2mobility file vs. TraCI
**Status: VERIFIED**

File-based (`MOBILITY_SRC_SUMO_TRACE=1`, `Ns2MobilityHelper`) — used by every sweep. TraCI (`=2`) is a stub that silently falls back to a 16-vehicle hardcoded provider if ever selected. An unmatched `(scenario, maxspeed)` pair degrades the same way, with a stderr diagnostic, not a hard failure.

**Why we do it this way:** file-based loading gives byte-identical, reproducible mobility across every run of a given config — essential for controlled ablations where only one variable should change between arms. Live TraCI would introduce SUMO-NS3 co-simulation timing nondeterminism that isn't needed here and was never finished.

---

## 02 · NS-3 Network Configuration (Q9–Q16)

### Q9 — Transmit power
**Status: VERIFIED — 41 dBm, all scenarios**

`12_main.h:1337-1338/1354-1355/1371-1372` — all three branches set 41 dBm identically. Highway's comment says "44 dBm" but codes 41 — stale comment only, not a stale value.

### Q10 — Propagation loss model per scenario
**Status: VERIFIED, with a deliberate deviation from the question's assumption**

Question assumes highway uses two-ray-ground. Actual: urban = `Cost231PropagationLossModel`; **rural AND highway** both use `LogDistancePropagationLossModel` (`12_main.h:1256-1302`).

**Why we do it this way:** Cost231-Hata is documented as urban-only. Highway originally *did* use TwoRayGround, but that froze the simulation at t≈13s under ~145 concurrent transmitters (PHY overload) — switched to LogDistance on 2026-07-02 as a deliberate stability fix, not an oversight.

### Q11 — Communication range, 270m confirmed by packet-exchange test at 280m
**Status: VERIFIED — value confirmed; the specific 280m packet test itself not run**

`R_max_comm = 270.0` (`02_config_globals.h:506`), enforced as a literal software distance cutoff at `09_vehicle_beacon_tx.h:472`, `08_detection_engine.h:613/728` — not derived from the PHY link budget.

**Why we do it this way:** `12_main.h:1270-1275` explicitly documents this as a deliberate *logical* range, distinct from the ~2km physical RF range at 41dBm/-105dBm sensitivity — "NOT an RF cutoff." The propagation model reshapes path-loss realism; the 270m cutoff is a separate, intentional application-layer decision so the network topology stays controllable independent of which propagation model is active per scenario.

### Q12 — Beacon interval
**Status: VERIFIED — 100ms**

`02_config_globals.h:505`, T_b=0.1, "IEEE 802.11p BSM rate 10Hz."

### Q13 — RSU counts (64/44/23 per question)
**Status: FLAG — rural is 169, not 44, deliberately**

Urban 64 (confirmed live: "placed 64 RSUs"). Highway 23 (CSV only, no executed sweep found). Rural: **169**, rescaled 2026-07-31 (commit `9b22fcf`) alongside the vehicle-count rescale in Q7, measured at 99.8% coverage.

**Why we do it this way:** same story as Q7 — the old 44-RSU layout only covered a 15s-window trace; against the real 150s trace it dropped to 50.4% coverage. 169 RSUs was the number that actually achieves full coverage on the new map, chosen deliberately over sticking to a stale documented target.

### Q14 — RSUs stationary, position identical at t=0 and t=30
**Status: VERIFIED by code structure**

`ConstantVelocityMobilityModel` with velocity explicitly zeroed for every RSU node (`12_main.h:1054-1058`), positions set once via a static allocator. No multi-timestamp position log exists to verify this empirically at runtime — a structural guarantee, not a logged observation.

### Q15 — NS-3 seed, all three listed
**Status: VERIFIED**

`RngSeedManager::SetSeed(1)` fixed + `SetRun(run_seed)` from `--seed`. Example: `AB9_sweep/run_ab9_sweep.sh:39`, seeds **1, 2, 3**.

### Q16 — Vehicles within range of ≥1 RSU at t=0
**Status: GAP — not runtime-instrumented**

No live "vehicles in range at t=0" measurement exists anywhere in the NS-3 code. `sumo/place_rsus.py`'s `coverage_pct()` is an *offline placement-design* tool (used when deciding where to put RSUs, before any simulation runs), not a per-run verification. Only rural has a recorded figure (99.8%, from its design phase).

**Indirect evidence this matters:** Q42 found the urban confusion-matrix total (4,344 beacons) was only 7.2% of the naive expectation (60,000) — consistent with, though not proof of, meaningful periods where vehicles aren't in range of any RSU. This is a genuine instrumentation gap, not a design choice — worth closing by adding a real t=0 (or time-series) coverage count.

---

## 03 · Attack Injection (Q17–Q26)

### Q17 — Exact attack class labels and per-node assignment; must match Phase 1a GAT training labels
**Status: VERIFIED — taxonomy confirmed, and the training-label alignment checked end-to-end**

| id (code) | name | mechanism |
|---|---|---|
| a1 / TP-S1 | Compromised RSU | position drift |
| a2 / TP-S2 | Malicious vehicle | heading/speed exaggeration |
| a3 / MP-S1 | RSU Sybil | ghost identities |
| a4 / MP-S2 | Vehicle impersonation | stolen-identity beacons |
| a5 / TP-S3 | Controller interception | position + speed |
| a6 / MP-S3 | MitM data-plane | moderate speed shift |
| a7 / MP-S4 | Malicious controller | global mobility-model poisoning |

> `06a_attack_models.h:5-18`

**This is the codebase's real numbering — it does not match the question list's own numbering** (see Q18/Q20/Q22 below for the specific mismatches).

**Training-label alignment — traced the full chain, no drift found at any hop:**

1. **Simulation ground truth:** every poisoned beacon carries `attack_number` (1-7), the same field used throughout this report.
2. **GAT training labels** (`analytics/ml/train.py:211-223`): builds one-hot multi-task targets with `k = atk_num[r] - 1` — directly off the same `attack_number` field, no separate/independent labeling scheme that could drift:
   ```python
   # attack type k (attack_number = k+1, k∈[0,K-1])
   k = atk_num[r] - 1
   if is_pois[r] == 1 and 0 <= k < ATTACK_CLASSES:
       y_multi[r, k] = 1.0
   ```
3. **Deployed weights self-document the same mapping:** `fusion_weights.json`'s `lambda_sets` and `sig_weight_sets` arrays are explicitly tagged `"attack": 1` through `"attack": 7`, sequential, complete, no skips or duplicates — confirmed index 0 = a1 through index 6 = a7.
4. **Runtime loading** (`06d_ai_inference.h:181-191`): loads the JSON array sequentially into `lam_psi_k[0..6]` etc. — index preserved.
5. **Runtime k̂_i** (0-indexed argmax over the model's K outputs) is displayed in logs with a `+1` offset (`06d_ai_inference.h:481`: `<< "k" << (k+1)`), and used directly to index `lam_psi_k[k_hat_i]` — the same 0-based convention as every step above.

Every hop in this chain shares the same `attack_number`-minus-one indexing convention, with the deployed JSON providing an explicit, self-checking label at each entry. No off-by-one, no reordering, no mismatch between what the simulation calls "a3" and what the GAT was trained to recognize as class index 2.

### Q18 — Malicious vehicle (question's "a1"): continuous or streak-window poisoning?
**Status: VERIFIED — continuous; also a numbering correction**

**The question's "a1" is the codebase's a2** (TP-S2, malicious vehicle) — a1 in this codebase is compromised-RSU drift, not a vehicle attack. For a2: no streak/window parameter exists anywhere in the code. Malicious status decided once at t=0, checked every beacon. Live: vehicle 107, 3,541/3,541 beacons poisoned (100%).

**Why we do it this way:** continuous poisoning for the vehicle's whole active window is the simplest, most conservative ground truth for training/evaluation — it removes any ambiguity about when exactly a vehicle "is" attacking, which a streak/duty-cycle model would introduce. (The separate MP-S2 "vanishing beacon" path *is* intermittent by design, but that's a distinct mechanism, not this one.)

### Q19 — Stealth perturbation magnitude ε_max, first 10 beacons ≤0.5m
**Status: VERIFIED — 0.5m**

`epsilon_max_stealth = 0.5` (`02_config_globals.h:628`). Measured from real compromised-RSU-drift beacons: median per-step offset 0.163m, within ceiling.

### Q20 — Sybil via compromised RSU (question's "a4"): ghost identity count
**Status: VERIFIED — 4; also a numbering correction**

**The question's "a4" is the codebase's a3** (MP-S1) — a4 in this codebase is vehicle impersonation, a different attack. For a3: `g_n_coord = 4` (`02_config_globals.h:282`), ghosts placed at 0°/90°/180°/270° around the real vehicle.

### Q21 — MitM (a6): NS-3 callback or application layer; honest beacon dropped?
**Status: VERIFIED — application layer; honest-beacon-dropped claim only true in one of two modes**

Fabricated in the vehicle's own uplink send path, not an NS-3 reception callback. Two modes, `--faithful_mitm`: **legacy (default)** sends to the attacker's own RSU zone and gets dropped by the geographic filter *before* reaching HMAC — meaning in default config the forged beacon never reaches the RSU either, a stricter failure than the question anticipates. **Faithful mode** (`--faithful_mitm=1`) is the one that matches the question's exact scenario: it computes the MAC over the victim's real kinematics (so HMAC-FAIL correctly fires) and addresses the frame so it survives the filter.

**Why we do it this way:** the "faithful" mode was added specifically to test the harder, more realistic MitM case (attacker successfully impersonating); legacy mode is kept as a baseline representing an under-resourced attacker whose forged traffic doesn't even reach its target. Both are legitimate configurations for different threat-model strengths — not a bug, but you need `--faithful_mitm=1` to get the behavior this specific question describes.

### Q22 — Control-plane poisoning (question's "a3 and a7"): onset timing
**Status: VERIFIED — mechanism confirmed; numbering correction**

**The question's "a3 and a7" should be a5 and a7** — a3 in this codebase is RSU Sybil (data-plane), not control-plane. Controller compromise: `ctrl_compromised_now()` returns true once `Simulator::Now() >= onset*simTime` (`02_config_globals.h:446-451`, `--ctrl_compromise_onset`), applied independently at both the a5 and a7 injection sites.

### Q23 — ρ_a=0.40, 200 vehicles → exactly 80 malicious?
**Status: VERIFIED mechanism — not exactly 80, deliberately**

Vehicle draw is Bernoulli(40%) per vehicle, no rounding correction to exactly 80. Beacon-level poison rate is far higher (89.6%) because compromised RSUs/controller relay-poison honest vehicles' beacons too.

**Why we do it this way:** an independent per-vehicle Bernoulli trial is the standard way to realize a target attack *rate* in a stochastic simulation — it's what makes ρ_a a genuine probability parameter rather than a fixed quota, and it's what lets multi-seed runs show natural variance around the target rather than artificially pinning the count. The 89.6% beacon-level figure isn't a bug either — RSU/controller relay poisoning is a real, intended mechanism (compromised infrastructure corrupts traffic from honest vehicles passing through it), it's just a different quantity than the vehicle-level rate, and conflating the two would understate how much of the network is actually affected.

### Q24 — Per-attack-type breakdown, must total 80
**Status: VERIFIED — not one pool of 80, deliberately three separate mechanisms**

Vehicle-level (a2/a4/a6): round-robin over all vehicles, independently Bernoulli-gated. RSU-level (a1/a3): `round(N_RSUs×40%)` compromised, alternated by parity. Controller-level (a5/a7): no fixed set — split live by `vehicle_id % 2` per beacon.

**Why we do it this way:** these three attack surfaces are architecturally independent (vehicle, RSU, controller are different node types with different compromise mechanics) — forcing them into one shared "80-vehicle pool" would misrepresent how RSU and controller compromise actually work, since those aren't vehicle identities being flipped malicious, they're infrastructure nodes.

### Q25 — Ground-truth label file, per (vehicle, timestep)
**Status: VERIFIED**

`is_poisoned` in `beacon_log.csv` is stamped at the injection point, independent of the detector's own flag — genuine ground truth, and the only ground-truth column MCC (and every other metric) reads. `attacker_class` (a separate, secondary column) has a labeling bug in combined mode (reads NONE on 13,988/54,168 rows that are actually poisoned) but is never read back by anything — not MCC, not the ML training pipeline (zero references in `analytics/ml/*.py`) — so it's currently inert, not a live correctness problem.

### Q26 — Fraction of timesteps labelled attack, matches expected penetration rate?
**Status: VERIFIED — does not match nominal rate, for the reason given in Q23**

`rural_pid1103751/beacon_log.csv`: overall 89.58% poisoned vs. 40% nominal. RSU-relay (19,592 rows) + controller-relay (3,427 rows) account for the gap beyond the 25,506 vehicle-originated rows.

---

## 04 · Detection Pipeline (Q27–Q36)

### Q27 — First 10 ψ̄_i(t) values for a malicious vehicle, any above ψ_th=0.09?
**Status: VERIFIED — 0.09 confirmed, 9/10 clear it**

`02_config_globals.h:573`. Live vehicle-45 sample: 9/10 consecutive poisoned beacons show psi_score ≥0.15; the one exception (0.00) is the beacon before signature accumulation begins.

### Q28 — K classification heads, print all K outputs for one node
**Status: VERIFIED — K=7, fully wired end-to-end (external "not implemented" claim refuted)**

`gat_detector.py:79`: `self.cls_heads = nn.Linear(_GAT_EMB, attack_classes)`, `attack_classes=7`. `06d_ai_inference.h:65`: `K_ATTACK=7`. Read live from the ONNX model's second output tensor at inference time (`06d_ai_inference.h:637-663`, `attack_probs` shape `(N,K)`), argmax → k̂_i.

**Full rebuttal of an external review claim ("BLOCKER 1: multi-task K=7 GAT not implemented"):** every specific sub-claim (no k̂_i, no λ^(k̂_i), no w_s^(k̂_i), no θ_conf) is checked and refuted with exact line citations:
- k̂_i: `08_detection_engine.h:2642-2643`, `k_hat_i = gat_attack_types[i]`
- λ^(k̂_i): declared `06d_ai_inference.h:79-81`, loaded `181-191`, selected `786-789`
- w_s^(k̂_i): declared `06d_ai_inference.h:90`, loaded `228-236`, selected `08_detection_engine.h:2655-2656`
- θ_conf: declared `06d_ai_inference.h:102`, loaded `196`, gate applied `661-663`, deployed value 0.8 in `fusion_weights.json:163`

**Likely source of the false claim:** two files are named `gat_detector.py`. The real one (`analytics/ml/gat_detector.py`) has a *stale docstring* (line 5, still describes the old single-output design) even though the code below it was extended on 2026-07-20. The other (`mptd_pqs/gat_detector.py`) genuinely lacks K=7 heads but is a dead file from 2026-04-15, unused by the actual pipeline (only two standalone comparison scripts import it, not the simulation).

### Q29 — Predicted k̂_i for a Sybil (a3) vehicle
**Status: VERIFIED**

`AB3_ncoord_sweep/manifest.csv` (θ_S=18.394):

| mode | n_coord | seed | MCC_full | TP | FN | FP |
|---|---|---|---|---|---|---|
| FULL (GAT on) | 1 | 1 | **0.667** | 3150 | 1447 | 1411 |
| GAToff | 1 | 1 | **-0.060** | 10 | 4587 | 3939 |

> `AB3_ncoord_sweep/manifest.csv`, `logs_stale_prefix_20260726/nc1_full.log`

### Q30 — θ_S value, computation source, when locked
**Status: VERIFIED**

Standard methodology (`attack_number` ∈ {1,2,4,5,6,7} and baseline, scenario=urban): 95th percentile of clean-vehicle GAT embeddings (`recalibrate_gat_per_scenario.py:39`, `THETA_S_PCTL=95.0`) from `beacon_clean_urban.csv`, locked 2026-07-18 → **θ_S = 8.305442**. Rural: 5.068482. Highway: 6.903901.


### Q31 — Raw S_i(t) and S_i(t)/θ_S, malicious and honest vehicle, same timestep
**Status: VERIFIED**

θ_S = 18.394:
```
t=7.441 vid=45  S=15.275  θ_S=18.394  S/θ_S=0.830  gt_pois=1 (malicious)
t=7.916 vid=37  S=28.856  θ_S=18.394  S/θ_S=1.569  gt_pois=0 (honest)
```

Full population (870 malicious, 840 honest beacons):

| | n | mean S | mean S/θ_S | min | max |
|---|---|---|---|---|---|
| Honest (gt_pois=0) | 840 | 26.393 | 1.435 | 0.280 | 3.414 |
| Malicious (gt_pois=1) | 870 | 20.683 | 1.124 | 0.417 | 2.895 |

> smoke test log, `08_detection_engine.h:2735-2750` instrumentation, 1,710 fusion rows

### Q32 — θ_ae value (urban), current method
**Status: VERIFIED**

θ_ae (urban, deployed) = **0.793731**

Computed as `mean(E_clean) + 1.645 × std(E_clean)`, where E_clean is the LSTM-AE reconstruction error over all-honest windows (`deploy_ae_resid.py:112-113`).

**E_clean confirmed not attack-contaminated:** `deploy_ae_resid.py:65-67,92` builds windows tagged poisoned if *any* beacon inside them is poisoned, then filters to `Xc = X[y == 0]` before computing error statistics — training/validation error is computed only on all-honest windows.

> `deploy_ae_resid.py:65-67,92,112-113`

### Q33 — LSTM-AE reconstruction error across full window for a malicious vehicle
**Status: VERIFIED**

`AB4_final/eps0.1_ab0_s1.log`, vehicle 73 (confirmed malicious, `gt_pois=1` throughout, 180 real scores after excluding 40 pre-fill placeholder rows where the ring buffer wasn't yet full):

```
n=180  mean=0.04844  min=0.03654  max=0.09476
θ_ae (urban) = 0.793731
above threshold: 0/180 (0.0%)
```

The error is not consistently above θ_ae — it never once crosses it, sitting roughly 8–20× below threshold across the vehicle's entire real detection window.

> `AB4_final/eps0.1_ab0_s1.log`

### Q34 — Full Φ_i(t) for malicious + honest, component values before/after clipping
**Status: VERIFIED**

Matched pair, same timestamp `t=10.941`, θ_S=42.62, θ_ae=0.793731, ψ_th=0.09, global weights (λ_ψ=0.5071, λ_gat=0.1857, λ_ae=0.3071). ψ uses `psi_fuse` — the signature-weighted value `fuse_scores()` actually receives (`08_detection_engine.h:2652`), not the raw per-window mean:

**Vehicle 45 (malicious, gt_pois=1):**
| term | raw | before clip | after clip |
|---|---|---|---|
| ψ (psi_fuse) | 0.221 | 0.221/0.09 = 2.456 | min(2.456,1) = **1.000** |
| GAT (S) | 15.284 | 15.284/42.62 = 0.359 | min(0.359,1) = **0.359** |
| AE (ε) | 0.000 | 0.000/0.793731 = 0.000 | **0.000** |

Φ = 0.5071(1.000) + 0.1857(0.359) + 0.3071(0.000) = **0.574** — matches logged `phi=0.574`.

**Vehicle 88 (honest, gt_pois=0):**
| term | raw | before clip | after clip |
|---|---|---|---|
| ψ (psi_fuse) | 0.000 | 0.000/0.09 = 0.000 | **0.000** |
| GAT (S) | 54.155 | 54.155/42.62 = 1.271 | min(1.271,1) = **1.000** |
| AE (ε) | 0.000 | 0.000/0.793731 = 0.000 | **0.000** |

Φ = 0.5071(0.000) + 0.1857(1.000) + 0.3071(0.000) = **0.186** — matches logged `phi=0.186`.

**Both reconstructions match the logged Φ exactly, and both confirm Φ ∈ [0,1]** (0.574 and 0.186).

> `06d_ai_inference.h:773-829` (formula) · `08_detection_engine.h:2652-2681` (psi_fuse) · smoke test log, matched t=10.941 pair

**Formula-level check, separate from the live reconstruction above:** all three terms are independently clamped to [0,1] in code — ψ: `psi_n = min(psi/psi_th, 1)` (lines 813-816), GAT: `used_gat = min(gat_score/θ_S, 1)` (lines 821-826), AE: `ae_norm = min(ae_err/theta_ae, 1)` (lines 777-780) — with weights renormalized to sum to 1 over active tiers (lines 799-807), so `phi` is a genuine convex combination, bounded [0,1] by construction. This directly refutes an external review claim ("BLOCKER 2: fusion equation is wrong — raw ψ, no normalization, clip only on third term"): the ψ/ψ_th normalization ("H8 Tier-1") was added in commit `403f70e`, **2026-07-10**, over three weeks before the claim, with a commit message describing exactly the alleged bug. `Fusion_Psi_Normalisation_Patch.tex` (referenced by the claim) doesn't exist anywhere in this repo.

### Q35 — θ_conf value, fallback fraction, is it under 30%?
**Status: VERIFIED**

θ_conf = 0.8 (`analytics/ml/models/urban_a3/fusion_weights.json:163`)

Fallback rate, `AB3_ncoord_sweep/logs_stale_prefix_20260726/nc1_full.log`: **89.9%** (65,568/72,910 fusion evaluations fell back to global weights, `khat=-1`) — far above the question's 30% threshold.

> `analytics/ml/models/urban_a3/fusion_weights.json:163` · `AB3_ncoord_sweep/logs_stale_prefix_20260726/nc1_full.log`

### Q36 — PBPO_LW for AB5, under 100ms?
**Status: VERIFIED — yes, ~3 orders of magnitude under**

`10_metrics_csv.h:836/989`. Real values across ~20 logs: 0.0098–0.1 ms.

---

## 05 · Blockchain & Trust Management (Q37–Q41)

### Q37 — SC-Trust.Update sync or async; alert-to-confirmation wall-clock time
**Status: VERIFIED**

Evidence submission is fire-and-forget async (`06c_blockchain_api.h:1000-1001`, "on the beacon-alert hot path"). Epoch finalize/revoke calls are synchronous. `TCL_confirm` (sync-only): real value `6793.218 ms (603 invokes)` from an AB8 log.

**Why we do it this way:** evidence submission happens on every single beacon's hot path — making that synchronous would mean every beacon's processing blocks on a full Fabric round-trip, which would make real-time detection impossible at scale. Finalize/revoke are rarer, higher-stakes operations where waiting for confirmation is the correct tradeoff.

### Q38 — T_batch, last 5 flush timestamps, ~T_batch apart?
**Status: VERIFIED value; actual cadence differs from nominal, deliberately bounded**

Default 10s (`02_config_globals.h:822`), flush triggers on `size≥50 OR age≥10s`, whichever first. Real observed cadence under load: ~1.2-1.3s, because the count trigger dominates.

**Why this isn't a bug:** the size trigger exists precisely so a busy RSU doesn't sit on 50+ pending evidence entries for the full 10s — it's a deliberate dual-trigger design (whichever fires first), not a broken timer.

### Q39 — Revocation commit: Tier 1 sync, not batched with Tier 3
**Status: VERIFIED**

`CallSCRevokeVote` uses `mptd_fabric_invoke_sync()`, no async variant exists, called directly (not via the tier-3 buffer). Code comment: *"sync — needs the revoked bit back to decide whether to rekey."*

### Q40 — τ_i(t) trajectory for a malicious vehicle across the full run
**Status: VERIFIED — decay and revocation both confirmed real, via a live chaincode query**

Constants confirmed (τ_init=1.0, τ_warn=0.5, τ_min=0.3, T_rev=3 epochs). Log files never printed this (confirmed across every sweep on disk — only failed `GetAllRSUTrustScores` timeouts, 0% success rate). But the data is directly queryable live from the chaincode's world state via the `fabric_gw` daemon's Unix socket (`/tmp/mptd_fabric.sock`, `{"action":"query","function":"GetAllTrustScores","args":[]}`) — a channel not previously tried.

**Live query result** (current world state, `GetAllTrustScores` — 200 vehicle records):
```
VEH_47:  TrustScore=0.5100  MeanPsi=0.70  UpdateCount=1
VEH_97:  TrustScore=0.5450  MeanPsi=0.65  UpdateCount=1
VEH_195: TrustScore=0.5975  MeanPsi=0.50  UpdateCount=2
```
Real decay from τ_init=1.0, correlated with MeanPsi as expected.

**`GetAllRSUTrustScores` shows the same mechanism decaying further, past τ_min, into actual revocation:**
```
RSU_52, RSU_65, RSU_66, RSU_67, RSU_79, RSU_81:  TrustScore=0.0081  ConsecutiveLowEpochs=3
```
`ConsecutiveLowEpochs=3` exactly matches T_rev=3, the revocation trigger. **`GetAllRevokeRecords` confirms all 6 were actually revoked**, real timestamps:
```
SCREVOKE_RSU_52 … reason="rsu_trust_decay"  2026-08-02T08:29:19Z
SCREVOKE_RSU_65 … reason="rsu_trust_decay"  2026-08-02T08:26:20Z
(+4 more, same reason, same day)
```
Decay → threshold crossing → revocation is a real, working, end-to-end chain.

**Scope note:** this is a live snapshot of current world state (left over from the most recent run), not a polled point-by-point time series. To capture the literal per-timestep trajectory across one specific 30s run, the same query would need to be polled repeatedly during that run — not done here, but the mechanism is now proven to work, so it's a small follow-up, not a rebuild.

> `fabric_gateway_daemon/main.go:349-372` (socket protocol) · `chaincode/smartcontract.go:1331-1365` (`GetTrustScore`/`GetAllTrustScores`, vehicle-level) · live query against the running `fabric_gw` daemon

### Q41 — Controller τ_c_k(t) trajectory for AB9, decays after t_comp, crosses τ_min?
**Status: PARTIAL — query mechanism proven (Q40); this snapshot is from a non-AB9 run, so shows no decay to report**

EMA formula confirmed in chaincode. Same live-query mechanism as Q40 works for controllers too (`GetAllControllerTrustScores`) — confirmed returning valid data for all 4 controllers, but every one shows `TrustScore=1, ConsecutiveLowEpochs=0` because the run currently reflected in world state (R3 config1, "Full RAPTOR") never activated controller compromise — that's specifically an AB9 scenario (`--ctrl_compromise_onset`). Indirect confirmation the mechanism has a real effect: CDER with onset=0.00 (compromised from t=0) roughly triples CDER vs. onset=1.00 across all 3 AB9 seeds. **To get an actual decaying controller-trust trajectory, the same query needs to be run against/during an actual AB9 run** — not yet done, but no longer blocked on missing instrumentation, just on pointing the proven query at the right run.

> live query, `GetAllControllerTrustScores` · AB9_sweep CDER comparison (existing)

---

## 06 · Metric Computation & Saving (Q42–Q50)

### Q42 — TP/TN/FP/FN, total = 200×300 = 60,000 for a 30s run?
**Status: VERIFIED counts; total does not match naive expectation, and that's expected**

Live: TP=2534 FP=20 TN=444 FN=1346, sum 4,344 — matches PBPO_LW's own beacon count exactly (internally self-consistent). Naive expectation (200×300) = 60,000; actual is 7.2% of that.

**Why this isn't a bug:** the confusion matrix only scores beacons that actually reach an RSU's `HandleBeaconReceived`. Not every vehicle is in range of an RSU for the whole run (see Q16) — the naive per-vehicle×per-timestep calculation assumes universal coverage, which isn't this network's actual topology. The metric is doing the right thing; the naive expectation is the part that's wrong.

### Q43 — TP/FP granularity matches label granularity from Q25?
**Status: VERIFIED — matched by construction**

Both the confusion-matrix update and the CSV label write read `tag.GetIsPoisoned()` off the same tag object in the same call site (`08_detection_engine.h:2975-2998`) — no separate labeling pass exists to drift out of sync.

### Q44 — t_alert: flag_i(t) first=1, or SC-Trust confirmation?
**Status: VERIFIED — neither, deliberately; full history**

Was permanently 0.000 (alert==onset bug), fixed in commit `dad4bc6`. Current definition: onset = first poisoned-beacon timestamp; alert = timestamp of the first **window-close fusion verdict** (Φ>Φ_th) at/after onset.

**Why we do it this way, and why it's neither of the question's two options:** the immediate per-beacon `detected` flag would make TTD trivially ≈0 (same call, same timestamp as onset) and not reflect real detection latency. The blockchain confirmation timestamp would conflate detection latency with a separate, batched commit-latency concern (T_batch, Q38) that has nothing to do with how fast the AI/rule pipeline actually recognized the attack. The window-close fusion verdict is the point where the system has actually *decided* something — the honest measure of "how long until the pipeline concluded this vehicle was malicious."

### Q45 — CDER ground-truth source, attack-free baseline?
**Status: VERIFIED — no baseline run used, by design**

Correctness inferred directly from `is_poisoned` at the controller's decision point: honest-controller decisions wrong iff `detected XOR is_poisoned`; malicious-controller decisions always wrong.

**Why we do it this way:** a separate attack-free baseline run would require running every configuration twice (once with attacks, once without) just to get a comparison point — the ground-truth label already tells you what the *correct* decision would have been at every single timestep, which is strictly more information than a baseline run would provide, without the extra compute cost.

### Q46 — TDEE, ρ_gt from FCD directly, not beacon receptions?
**Status: VERIFIED**

Ground truth read directly from SUMO positions via the mobility provider (`10_metrics_csv.h:267-273`), independent of beacon reception/loss. Estimate side is beacon-derived (as intended — that's the thing being measured against truth). Returns -1 explicitly under non-SUMO mobility rather than silently computing a wrong value.

### Q47 — PARR: epochs with ≥1 compromised member, or epochs where aggregate was actually falsified?
**Status: VERIFIED — the latter, deliberately**

`g_parr_injected` counts epochs where a compromised ring coordinator **actually injected** a poisoned aggregate — not mere presence of a compromised member who didn't act that epoch.

**Why we do it this way:** counting "any epoch with a compromised member present" would inflate the denominator with epochs where nothing bad actually happened, making PARR look artificially better (more false "successes" for the detector) than it really is. Counting actual injections is the stricter, more honest denominator.

### Q48 — FRR denominators: ground-truth labels or end-of-run registration; counted once per vehicle not per RSU contact?
**Status: VERIFIED**

Ground-truth labels, not end-of-run registration. `10_metrics_csv.h`'s `compute_FRR_demote()`:
```cpp
uint32_t honest = 0;
for (uint32_t j = 0; j < N_RSUs && j < MAX_RSUS; j++)
    if (!compromised_rsu[j]) honest++;
```
`compromised_rsu[]` is a static array set once at simulation init and never changes during the run — exactly "which RSUs were designated compromised for the entire run" (`y_e=0 throughout`), not a snapshot of who's still registered at the end. Not wrong: as a fixed population count rather than a per-contact tally, a vehicle or RSU re-entering coverage multiple times can't be double-counted, since there's no contact-counting mechanism here at all.

> `10_metrics_csv.h` (`compute_FRR_revoke`, `compute_FRR_demote`)

### Q49 — Output path, format, schema — seed/scenario/attack config/hyperparams present?
**Status: VERIFIED**

Per-beacon: `analytics/results/<scenario>[_pid]/beacon_log.csv`. Per-run: `analytics/results/sweep/metrics_a{N}_p{P}_s{S}_m{mode}_seed{seed}.csv`, ~36 metric columns, including `seed`, attack config (`attack_number, attacker_class, attack_pct, ablation_mode, ablation_ab`), and all hyperparameter-relevant fields.

Verified with a real run:
```
$ head -2 metrics_a3_p40_s60_m0_seed7.csv
seed,attack_number,attacker_class,attack_pct,maxspeed_kmh,...
7,3,2,40,60,0,0,49,22,179,77,...
```
`seed=7` matches the actual `--seed=7` used, present in both the filename and the first column of the data row.

> `10_metrics_csv.h` · verified output: `analytics/results/sweep/metrics_a3_p40_s60_m0_seed7.csv`

> `10_metrics_csv.h` (filename + header + value line) · verified output: `analytics/results/sweep/metrics_a3_p40_s60_m0_seed7.csv`

### Q50 — Manual mean/std across 3 seeds matches the reporting script?
**Status: VERIFIED**

Ran `AB9_sweep/ab9_figure.py` for real against the actual `manifest.csv`. For onset=0.00 (3 clean seeds, MCC_full = 0.828, 0.919, 0.916):
```
script printed:  MCC_full=0.888+/-0.052   (ab9_results.csv: 0.8877, 0.0517)
manual (numpy, ddof=1): mean=0.8877  std=0.0517
```
Exact match. The script also correctly implements dict-overwrite-by-(config,seed) to take the last row per key, matching the "retries append, never replace" manifest convention, and hard-fails on any surviving BAD row rather than silently averaging it in.

> `AB9_sweep/ab9_figure.py`, run live · `AB9_sweep/manifest.csv`

---

