# MPTD-PQS SDVN — 50-Point Pipeline Verification

Every answer below is checked against live code (file:line) or a real run artifact (log line / CSV row) — **not** recalled from memory or inferred from documentation. Where a question can't be answered from what exists on disk, that's stated explicitly rather than guessed. Six subsystems, six independent verification passes.

**Summary:** 50 questions answered · 9 discrepancies surfaced · 4 gaps needing a fresh instrumented run · 6 subsystems audited independently.

---

## Findings worth acting on

| Qs | Finding |
|---|---|
| Q3–Q6 | **`--maxspeed` is a filename label, not an enforced cap — for the *default* traces only.** Real per-vehicle speed comes from `VEH_VMAX` engine caps + OSM road limits (SUMO takes the minimum). Measured max on `mobility_urban_60.tcl` is 29.98 m/s — 80% over the 16.667 m/s the "_60" suffix implies. This is the trace family used by AB1/AB2/AB6–AB10/R3. It does **not** apply to E2/AB5 — see Q1. |
| Q2 | **`UNIFORM_SPEED_MS`'s generation step isn't in `build_sumo_trace.sh`.** The default trace's `vType`, quoted directly from `sumo/urban/routes_car.rou.xml`, confirms no `speedFactor`/`speedDev` override — SUMO defaults apply. For E2/AB5's uniform traces, zero of 28,800 measured entries exceed their target ceiling — direct behavioral proof `speedDev` was effectively 0, even with no source vType to cite. |
| Q7, Q13 | **Rural scenario silently diverged from its documented spec.** `mobility_rural_90.tcl` was overwritten 138→200 vehicles; the paired RSU layout is now 169, not the documented 44. Originals survive only as `.bak138` / `.bak_canonical138`. |
| Q23, Q26 | **Beacon-level poison rate (89.6%) vastly exceeds the nominal vehicle rate (40%).** Compromised RSUs and the compromised controller relay-poison beacons from honest vehicles too — not captured by the vehicle-level Bernoulli draw. |
| Q31 | **Raw GAT score S_i is never persisted** — `fuse_scores()` computes it in-memory only; no column in `beacon_log.csv` carries it. |
| Q32–33 | **θ_ae is mean + κ·std (κ=1.645), not median/MAD.** No median/MAD path exists anywhere for this threshold — a framing mismatch against how the metric is usually described. |
| Q40–41 | **No RSU or controller trust trajectory is logged anywhere.** The FABRIC-EVT listener only decodes vehicle-revoke events; RSU/controller lifecycle events print as bare placeholders with no trust value. A specific "RSU_35 decayed to CLIENT at epoch 128" data point does not exist in any log or memory file — it was an unverified lead, now closed out as false. |
| Q48 | **FRR_demote's printed parenthetical uses a different denominator than the metric it's attached to.** "(2 false / 7 total demotes)" = 0.286, but the printed value is 0.053 — computed against the honest-RSU count, not the 7 shown. The metric itself is correct; the label next to it is misleading. |
| Q9 | Minor stale comment, not a bug: the highway TX-power line says "44 dBm" in its comment but codes 41 dBm — identical to every other scenario. |

---

## 01 · SUMO Mobility Configuration (Q1–Q8)

### Q1 — Exact SUMO m/s value for each speed point in E2, and the km/h conversion (all four)
**Status: VERIFIED — correctly enforced, confirmed by direct measurement**

E2 is the dedicated speed-sweep ablation (**AB5**, code comment `02_config_globals.h:284-295`: *"AB5 / E2 uniform-speed traces... confounds a SPEED sweep: v would not be a clean experimental variable"*). It runs against a **separate trace family** from every other ablation — `mobility_urban_uniform_{10,60,100,140}.tcl` — selected via `--uniform_speed_trace` (`g_uniform_speed_trace`, `12_main.h:110-114`). AB5 already completed (`AB5_final/`, 2026-07-26, 4 speeds × 2 modes × 3 seeds = 24 runs, `fig_AB5_speed_sweep.pdf/png`), and each run's log confirms the correct trace was loaded, e.g. `[MOBILITY/SUMO_TRACE] installed 200 vehicles from .../mobility_urban_uniform_60.tcl`.

Unlike the default traces (Q3–Q6), these four are genuinely speed-pinned — verified by parsing every `setdest` speed field directly out of all four files:

| speed point | km/h | target m/s (km/h ÷ 3.6) | measured max in trace |
|---|---|---|---|
| v10 | 10 | 2.778 | **2.78 m/s** |
| v60 | 60 | 16.667 | **16.67 m/s** |
| v100 | 100 | 27.778 | **27.73 m/s** |
| v140 | 140 | 38.889 | **38.87 m/s** |

Measured max matches the target ceiling to within rounding for all four points. Mean speed sits well below max (2.19–9.04 m/s, moving-vehicles-only) — expected, since intersection queueing and car-following dynamics still apply below the pinned ceiling; only the *cruise cap* is being controlled, which is correct.

**One caveat, not a correctness problem:** the script step that generates these four `_uniform` traces (`UNIFORM_SPEED_MS=<m/s>` per the code comment) does not exist in the committed `build_sumo_trace.sh` — see Q2. The output data is verified correct; the generation step just isn't reproducible from what's in git.

> `02_config_globals.h:284-295` (AB5/E2 design comment) · `12_main.h:110-114` (`--uniform_speed_trace` flag) · `AB5_final/v{10,60,100,140}_m{0,1}_s{1,2,3}.log` (24 completed runs) · direct measurement of `mobility/mobility_urban_uniform_{10,60,100,140}.tcl`

For context, the **other** thing called "speed" in this codebase — `VEH_VMAX`, the fixed per-vehicle-class engine cap used by every non-E2 scenario — is unrelated to E2 and is documented under Q3–Q6:

| class | m/s | km/h |
|---|---|---|
| car | 41.67 | 150 |
| bus | 27.78 | 100 |
| lorry | 25.00 | 90 |
| van | 33.33 | 120 |
| truck | 23.61 | 85 |

> `sumo/build_sumo_trace.sh:79-83` (VEH_VMAX array) · `02_config_globals.h:71` (default maxspeed=60)

### Q2 — speedFactor / speedDev in vType definitions
**Status: FLAG for the default traces (confirmed by direct artifact quote) — but VERIFIED-by-behavior for E2/AB5**

**Default traces** (AB1/AB2/AB6–10/R3): confirmed absent by quoting the actual live generated vType, not by an absence in git history:
```
sumo/urban/routes_car.rou.xml:  <vType id="car_passenger" vClass="passenger" maxSpeed="41.67" length="4.5" />
```
No `speedFactor`/`speedDev` attribute — `grep -c "speedFactor\|speedDev"` on this file returns **0**. SUMO's real defaults (speedFactor mean 1.0, speedDev 0.1 — ±10% per-vehicle noise) apply silently by omission, visible directly in the artifact.

**E2/AB5 uniform traces:** no surviving vType XML to quote (that intermediate step wasn't preserved — see Q1's caveat), so this is confirmed by direct behavioral measurement instead. `speedDev=0.1` is a *symmetric* random multiplier around 1.0 — if still active, some vehicles would statistically exceed the nominal target. Checked every `setdest` entry against its trace's target ceiling:

| trace | total entries | entries exceeding target |
|---|---|---|
| v10 | 7,200 | **0** |
| v60 | 7,200 | **0** |
| v100 | 7,200 | **0** |
| v140 | 7,200 | **0** |

Zero exceedances across 28,800 samples — direct evidence `speedDev` was effectively 0 for this trace family, even without the source vType XML to cite.

> `sumo/urban/routes_car.rou.xml` (direct quote, default trace) · direct measurement of all four `mobility_urban_uniform_{10,60,100,140}.tcl` files (E2/AB5) · `02_config_globals.h:283-291` (design comment, generation step not committed)

### Q3 — Does --maxspeed update OSM road edge limits too?
**Status: VERIFIED**

No — only vType maxSpeed is touched. `netconvert` imports OSM road speed limits unmodified via the standard typemap, and nothing rewrites edge speeds afterward.

> `build_sumo_trace.sh:19-21` — "SUMO also obeys each road's OSM speed limit and uses the **MINIMUM**, so 150 km/h only materialises on a road that actually allows it... This is realistic and intended."

### Q4 — Independent seed runs per scenario, and the CLI arg
**Status: VERIFIED**

**SUMO side:** one seed per trace (`SEED=${7:-42}`, positional arg 7, fed to `randomTrips.py --seed`). Each trace file is fixed once generated — no multi-seed SUMO sweep exists.

**NS-3 side (separate mechanism):** `--seed` → `RngSeedManager::SetRun(run_seed)`, with a fixed base `SetSeed(1)`. This randomizes attack/RNG behavior only, never mobility. Sweep scripts loop `seed=1,2,3` against the one SUMO trace.

> `build_sumo_trace.sh:54` · `12_main.h:82, 228-229`

### Q5 — Total trace duration vs. typical --simTime
**Status: FLAG — coverage gap**

| file | max t (s) | nodes |
|---|---|---|
| mobility_urban_60.tcl | 290.0 | 200 |
| mobility_rural_60.tcl | 150.0 | 200 |
| mobility_urban_150.tcl | 15.0 | 200 |
| mobility_rural_90.tcl | 15.0 | 200 |
| mobility_autobahn_150.tcl | 15.0 | 200 |


### Q6 — FCD mean/max speed vs. target, and >5% exceedance check
**Status: FLAG — target not enforced**

`mobility_urban_60.tcl` (the trace every AB1/AB2/AB6–10/R3 run actually loads), 58,200 setdest records: mean 3.579 m/s, **max 29.98 m/s**, min 0. Target (60 km/h) = 16.667 m/s — observed max exceeds it by **~80%**, well past the 5% exceedance threshold this check is meant to catch.

The proper check is against the SUMO FCD (floating car data) output specifically, not the converted `.tcl`. That check is currently blocked: `build_sumo_trace.sh` writes `fcd.xml` to a single shared path per regime that gets overwritten on every invocation, so no FCD file on disk today corresponds to the 200-vehicle/290s trace actually in production use — the one present in `sumo/urban/` is from an earlier, unrelated, shorter run. **Current progress: not yet resolved** — closing this properly means either archiving FCD output per-trace instead of overwriting one shared path, or regenerating a fresh FCD run against the current configuration.

> `02_config_globals.h:284-286` — "measured: mobility_urban_60.tcl has 2234 distinct speeds, max 29.98 m/s" (prior documented observation, confirms this finding independently)

### Q7 — Rural vehicle count at t=30s vs. ~138 target
**Status: FLAG — real discrepancy**

The file actually in use (`mobility_rural_60.tcl`, R3_sweep) has **200** distinct nodes at t=30, not 138, paired with 169 RSUs, not 44.

> Originals: `mobility/mobility_rural_90.tcl.bak138`, `.bak_canonical138`

### Q8 — Trace loading: ns2mobility file, or live TraCI?
**Status: VERIFIED**

File-based, via `Ns2MobilityHelper` (`MOBILITY_SRC_SUMO_TRACE=1`) — used by every sweep script. Live TraCI (`=2`) is stubbed: it prints a fallback warning and silently returns the 16-vehicle hardcoded provider if ever selected. An unmatched `(scenario, maxspeed)` pair degrades the same way — no hard failure, just a quieter run than intended.

> `09b_mobility_provider.h` (MobilitySource enum) · `12_main.h:454-460`

---

## 02 · NS-3 Network Configuration (Q9–Q16)

### Q9 — Exact transmit power
**Status: VERIFIED — 41 dBm, all scenarios**

All three scenario branches set `TxPowerStart`/`TxPowerEnd` to 41 dBm identically. The highway branch's inline comment says "44 dBm" but the coded value is still 41 — stale comment, not a stale value. An unrelated LTE backhaul PHY elsewhere uses 33 dBm; not the V2V/V2I link.

> `12_main.h:1337-1338` (urban) · `:1354-1355` (rural) · `:1371-1372` (highway)

### Q10 — Propagation loss model per scenario
**Status: VERIFIED**

Urban: `Cost231PropagationLossModel`. Rural & highway: `LogDistancePropagationLossModel` — switched away from Cost231 (documented as urban-only) and from TwoRayGround on highway (which froze the sim at t≈13s under ~145 concurrent transmitters). No startup log line confirms this at runtime — verified by code structure only.

> `12_main.h:1256-1262, 1266-1302`

### Q11 — R_max_comm — value and physical vs. logical meaning
**Status: VERIFIED — 270 m, explicitly logical**

Enforced as a literal software distance cutoff, explicitly documented as distinct from physical RF range: at 41 dBm / −105 dBm sensitivity the physical range is ~2 km, "NOT an RF cutoff."

> `02_config_globals.h:506` (R_max_comm = 270.0) · `12_main.h:1270-1275` (comment) · enforced at `09_vehicle_beacon_tx.h:472`, `08_detection_engine.h:613/728`

### Q12 — Beacon interval
**Status: VERIFIED — 100 ms**

> `02_config_globals.h:505` — T_b = 0.1 // IEEE 802.11p BSM rate 10Hz, Eq 3.9

### Q13 — RSU counts per scenario
**Status: FLAG — rural stale**

| scenario | documented | actual | evidence |
|---|---|---|---|
| urban | 64 | 64 ✓ | live log: "placed 64 RSUs" |
| highway | 23 | 23 (CSV only) | no executed sweep found |
| rural | 44 | **169** | rescaled 2026-07-31, commit 9b22fcf |

Rural was rescaled to a 200-vehicle map with a 169-RSU grid, measured at 99.8% coverage.

### Q14 — Are RSUs stationary?
**Status: VERIFIED — yes, by construction**

`ConstantVelocityMobilityModel` with velocity explicitly zeroed for every RSU node; positions set once and never reset. No multi-timestamp position log exists to verify this empirically at runtime — it's a structural guarantee, not a logged observation.

> `12_main.h:1054-1058` — "RSU nodes are stationary. Their position is already defined"

### Q15 — NS-3 random seed handling
**Status: VERIFIED**

`RngSeedManager::SetSeed(1)` fixed base + `SetRun(run_seed)` from `--seed`. Example sweep: `AB9_sweep/run_ab9_sweep.sh:39`, `for S in 1 2 3`.

> `12_main.h:82, 228-229`

### Q16 — Vehicles within range of ≥1 RSU at start
**Status: GAP — not runtime-instrumented**

No live "vehicles in range at t=0" measurement exists. `sumo/place_rsus.py`'s `coverage_pct()` — an offline placement-quality check over sampled trace positions — is the closest proxy. One real measured figure exists: rural's 169-RSU layout = **99.8% coverage**.

> `sumo/place_rsus.py:276` · `R3_sweep/run_r3_config23.sh:6`

---

## 03 · Attack Injection (Q17–Q26)

### Q17 — The 7 attack classes, and combined-mode assignment
**Status: VERIFIED**

| id | name | what it does |
|---|---|---|
| a1 / TP-S1 | Compromised RSU | position drift |
| a2 / TP-S2 | Malicious vehicle | heading/speed exaggeration |
| a3 / MP-S1 | RSU Sybil | ghost identities |
| a4 / MP-S2 | Vehicle impersonation | stolen-identity beacons |
| a5 / TP-S3 | Controller interception | position + speed |
| a6 / MP-S3 | MitM data-plane | moderate speed shift |
| a7 / MP-S4 | Malicious controller | global mobility-model poisoning |

Combined mode (`--attack_number=0`) is **not** one pool split 7 ways — three independent mechanisms operate at vehicle, RSU, and controller level respectively (detail in Q24).

> `06a_attack_models.h:5-18`

### Q18 — Continuous poisoning, or a "streak window"?
**Status: VERIFIED — continuous**

No streak/window parameter exists anywhere in the code. Malicious status is decided once at t=0 and checked every beacon. Live: vehicle — 3,541/3,541 beacons poisoned (100%). (The separate MP-S2 "vanishing"-beacon path is intermittent by design, but that's a different mechanism entirely.)

### Q19 — Stealth perturbation magnitude ε_max
**Status: VERIFIED — 0.5 m**

Measured from real compromised-RSU-drift beacons: median per-step offset 0.163 m (within the 0.5 m ceiling), cumulative walk growing to 10–120 m/run under the bounded-drift budget. Sample data came from a default combined-mode run, not an explicit a6-stealth-only run.

> `02_config_globals.h:628-632` — epsilon_max_stealth = 0.5

### Q20 — Sybil ghost identities per RSU interception
**Status: VERIFIED — 4 (g_n_coord)**

Ghosts placed at 0°/90°/180°/270° around the real vehicle, displaced by R_max_comm-scaled distance.

> `02_config_globals.h:282` · `08_detection_engine.h:3578-3646`

### Q21 — MitM (a6): NS-3 callback layer, or application layer?
**Status: VERIFIED — application layer**

Fabricated inside the vehicle's own uplink send path, not an NS-3 reception-callback intercept. Two modes gated by `--faithful_mitm`: legacy (default) sends to the attacker's own RSU zone and is dropped by the geographic filter before HMAC ever runs; faithful mode computes the MAC over the victim's real kinematics (so HMAC-FAIL correctly fires) and addresses the frame so it survives the filter. Live confirmation: the default-mode sample run has zero MitM rows reaching the log — exactly as predicted.

> `09_vehicle_beacon_tx.h:561-586`

### Q22 — Controller compromise: configurable onset time?
**Status: VERIFIED — yes, fraction of simTime**

`ctrl_compromised_now()` returns true once `Simulator::Now() >= onset*simTime`, applied independently at both the a5 and a7 injection sites, each further gated by a per-beacon Bernoulli draw.

> `02_config_globals.h:446-451` — g_ctrl_compromise_onset

### Q23 — ρ_a=0.40, N=200 → naive 80 vs. actual malicious count
**Status: FLAG — 89.6% real poison rate**

Vehicle draw is Bernoulli(40%) per vehicle — no rounding correction to exactly 80. The beacon-level rate is far higher because compromised RSUs/controller relay-poison honest vehicles' beacons too.

> ATTACK SUMMARY, r3_config3_s1.log: Trajectories received: 54168, Trajectories poisoned: 48525, **Actual poison rate: 89.582%**

### Q24 — Per-attack-type breakdown in combined mode
**Status: VERIFIED — 3 mechanisms, not 1 pool**

**Vehicle-level (a2/a4/a6):** round-robin over all vehicles by index, each independently Bernoulli-gated (~26-27 active per type at N=200). **RSU-level (a1/a3):** round(N_RSUs×40%) RSUs compromised, alternated by index parity. **Controller-level (a5/a7):** no fixed set — split live by `vehicle_id % 2` at every beacon received.

> Live class counts: honest/mislabeled 19631 · veh a2/a4: 11518 · RSU a1/a3: 19592 · ctrl a5/a7: 3427 · a6/MitM: 0 (see Q21)

### Q25 — Does is_poisoned = trustworthy per-beacon ground truth?
**Status: VERIFIED**

`is_poisoned` is stamped at the injection point, fully independent of the detector's own flag — genuine ground truth, and it's the only ground-truth column MCC (and every other metric) actually reads.


> `10_metrics_csv.h:160-192` · `09_vehicle_beacon_tx.h:239`

### Q26 — Real poisoned fraction, one beacon_log.csv
**Status: VERIFIED — confirms Q23**

`rural_pid1103751/beacon_log.csv`, N=54,168: overall **89.58%** poisoned. Of that, only 25,506 rows are vehicle-originated (capped by the 40% draw); RSU-relay (19,592) and controller-relay (3,427) contributions push the total well past the nominal rate.

---

## 04 · Detection Pipeline (Q27–Q36)

### Q27 — psi_th (rule-score threshold)
**Status: VERIFIED — 0.09**

Live vehicle-45 sample: 9/10 consecutive is_poisoned=1 beacons clear 0.09 (psi_score ≥0.15), except the very first (0.00, pre-signature-accumulation).

> `02_config_globals.h:573`

### Q28 — GAT attack-type classification heads K
**Status: VERIFIED — 7**

> `gat_detector.py:79` — cls_heads = Linear(_GAT_EMB, attack_classes); ATTACK_CLASSES default "7"

### Q29–30 — θ_S computation and per-scenario values
**Status: VERIFIED — 95th percentile, clean-vehicle embeddings**

| scenario | theta_s 
|---|---|
| urban | 8.305442 
| rural | 5.068482 
| highway | 6.903901

> `recalibrate_gat_per_scenario.py:39` — THETA_S_PCTL = 95.0

### Q31 — Raw S_i / GAT score in beacon_log.csv?
**Status: GAP — not persisted**

Confirmed absent from the CSV header. `fuse_scores()` computes it purely in-memory during fusion and never writes it out — a fresh instrumented run (CSV writer change) would be needed to get real per-beacon values.

> `06d_ai_inference.h:773-830`

### Q32–33 — θ_ae per scenario — median/MAD or mean/std?
**Status: FLAG — framing mismatch**

| scenario | theta_ae | mtime |
|---|---|---|
| urban | 0.793731 | Jul 26 |
| rural | 1.377909 | Jul 31 (retrain) |
| highway | 1.4143 | — |

**theta = err.mean() + 1.645 × err.std()** — mean + κ·std, *not* median + MAD. No median/MAD path exists anywhere for this threshold.

> `deploy_ae_resid.py` / `deploy_ae_resid_rural.py:112-114`

### Q34 — Fusion score Φ_i(t) — formula and clipping
**Status: VERIFIED**

Φ = λ₁·ψ_norm + λ₂·S_norm + λ₃·min(ε/θ_ae, 1) — each term clamped to [0,1] independently, weights renormalized over active tiers only. Bounded [0,1] by construction; no separate final clip.
Defaults λ_psi/gat/ae = 0.3/0.4/0.3 · deployed urban = 0.5071/0.1857/0.3071, threshold 0.5

> `06d_ai_inference.h:750-829`

### Q35 — theta_conf (GAT confidence gate)
**Status: VERIFIED — exists, 0.8 deployed**

Gates whether the GAT's predicted attack class is trusted: only committed if confidence ≥ max(0.5, theta_conf), else fusion falls back to global/average λ weights.

> `06d_ai_inference.h:102` (default 0.5) · deployed urban value 0.8 (fusion_weights.json)

### Q36 — PBPO_LW — under 100 ms?
**Status: VERIFIED — yes, 3 orders of magnitude under**

Real values across ~20 logs range 0.0098–0.1 ms.

> `10_metrics_csv.h:836/989` — Eq.4.7 LW

---

## 05 · Blockchain & Trust Management (Q37–Q41)

### Q37 — SC-Trust.Update — synchronous or async?
**Status: VERIFIED — async (evidence) / sync (finalize)**

Evidence submission is fire-and-forget — explicitly "on the beacon-alert hot path." Epoch finalize/revoke calls are synchronous.

> TCL_confirm = 6793.218 ms (603 invokes), reassign 4925.886 ms (37 rollovers) — AB8_sweep log
> `06c_blockchain_api.h:1000-1001, 1165-1347`

### Q38 — g_t_batch (Tier-3 batch interval)
**Status: FLAG — default 10s, real cadence ~1.2-1.3s**

Flushes on size≥50 OR age≥10s, whichever first. Under real traffic the count trigger dominates — the buffer fills before the timer elapses.

> [TIER3-BATCH-COMMIT-RSU35] flushed 50 entries... t=8.325 / t=9.620 / t=10.841 / t=12.141
> `02_config_globals.h:822`

### Q39 — Revocation: Tier 1 sync, or batched?
**Status: VERIFIED — Tier 1, synchronous**

No async variant exists for revoke votes; called directly, not via the tier-3 buffer.

> `08_detection_engine.h:3896-3905` — "sync — needs the revoked bit back to decide whether to rekey"

### Q40 — RSU trust trajectory (real run)
**Status: GAP — not logged; prior lead was false**

Constants confirmed: TauInit=1.0, TauWarn=0.5, TauMin=0.3, TRev=3 epochs default. **No per-epoch trajectory is retrievable anywhere** — the FABRIC-EVT listener only decodes vehicle-revoke events; RSU/controller lifecycle events print as bare placeholders with no trust value. The specific "RSU_35 → CLIENT at epoch 128, trust≈0.09" data point does not exist in any log or memory file — exhaustively searched and closed out as unverified/false.

> `chaincode/smartcontract.go` (constants) · listener gap at `08_detection_engine.h:337-354`

### Q41 — Controller trust (AB9 ablation)
**Status: PARTIAL — formula verified, trajectory is a gap**

Same listener gap as Q40 — zero direct trust-event matches in 250K-line sample logs. But the ablation's directional effect is confirmed indirectly via CDER across all 3 seeds: earlier compromise onset roughly triples control-plane error.

| seed | CDER @ onset=0.00 | CDER @ onset=1.00 |
|---|---|---|
| s1 | 0.607 | 0.213 |
| s2 | 0.671 | 0.342 |
| s3 | 0.621 | 0.241 |

---

## 06 · Metric Computation & Saving (Q42–Q50)

### Q42 — MCC / confusion matrix granularity
**Status: FLAG — per-beacon, but far below naive total**

Confirmed per-beacon (called once per beacon, not per-vehicle or per-window). Live: TP=2534 FP=20 TN=444 FN=1346, sum 4344 — matches PBPO_LW's own count exactly (self-consistent). But naive expectation (200 vehicles × 30s/0.1s) = 60,000 — actual is only 7.2% of that, since most vehicles are never in RSU range for the full run.

> `10_metrics_csv.h:662-672` · `08_detection_engine.h:2975`

### Q43 — is_poisoned granularity matches CM granularity?
**Status: VERIFIED — yes, by construction**

Both the confusion-matrix update and the CSV label write read `tag.GetIsPoisoned()` off the same tag in the same call site — no separate labeling pass exists to drift out of sync.

### Q44 — TTD / t_alert definition
**Status: VERIFIED — fixed, now well-defined**

Was permanently 0.000 (alert==onset bug), fixed in commit `dad4bc6`. Now: onset = first poisoned-beacon timestamp; alert = timestamp of the first **window-close fusion verdict** at/after onset — explicitly not the immediate per-beacon flag, not a blockchain confirmation time.

> TTD = 0.656 s (first alert − onset, per detected attacker mean)

### Q45 — CDER ground-truth source
**Status: VERIFIED — direct from is_poisoned, no baseline run**

Honest-controller decisions are wrong iff detected XOR is_poisoned; malicious-controller decisions always count wrong. No separate attack-free baseline comparison is used.

> CDER = 0.607 (4746/7824 wrong)

### Q46 — TDEE — is ρ_gt circular with beacon loss?
**Status: VERIFIED — no, reads SUMO truth directly**

Ground truth is read from SUMO positions directly via the mobility provider, independent of beacon reception. Estimate side is beacon-derived (as intended). Returns -1 explicitly under non-SUMO mobility rather than silently computing a bad value.

> `10_metrics_csv.h:267-273`

### Q47 — PARR denominator — actual injections, or any compromised member?
**Status: VERIFIED — actual injections only**

g_parr_injected counts epochs where a compromised ring coordinator actually injected a poisoned aggregate, not mere presence of a compromised member.

> PARR = 0.133 (2/15 rejected/injected) — explicitly distinct from the raw TRS-gate tally (2/24), which the code warns not to conflate

### Q48 — FRR_revoke / FRR_demote denominators
**Status: FLAG — misleading printed label, correct metric**

Both denominators are static ground-truth population counts (honest vehicles / honest RSUs), unaffected by coverage entry/exit. But the printed diagnostic's "(N false / M total)" parenthetical uses a *different* counter (running demote-event total) than what the metric itself divides by.

> printed: "demote 0.053 (2 false / 7 total demotes)" — 2/7 = 0.286 ≠ 0.053; the real 0.053 = 2 / honest-RSU-count

### Q49 — Output file paths, format, schema
**Status: VERIFIED**

**Per-beacon:** `analytics/results/<scenario>[_pid]/beacon_log.csv` — `sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, accel, is_poisoned, detected, sig_mask, psi_score, attack_number, attack_pct, attacker_class, gt_pos_x, gt_pos_y, gt_speed`

**Per-run:** `analytics/results/sweep/metrics_a{N}_p{P}_s{S}_m{mode}.csv` — one row, ~35 metric columns, includes attack config but **no seed column** — seed lives only in the external sweep `manifest.csv`.

### Q50 — Does aggregation correctly take last-occurrence-per-key?
**Status: VERIFIED — yes, correctly implemented**

`AB9_sweep/ab9_figure.py` documents and implements dict-overwrite-by-(config,seed) to take the last row per key, matching the "retries append, never replace" manifest convention — verified against a real 3-occurrence key resolving to its final OK row. The script hard-fails on any surviving BAD row rather than silently averaging it in.

---

*Compiled from six independent verification passes against live source (`scratch/mptd_pqs_sdvn/*.h`, `chaincode/chaincode/smartcontract.go`, `analytics/ml/*.py`) and real run artifacts under `~/Desktop/SENTINEL_experiments/*` and `analytics/results/*_pid*/beacon_log.csv`. No answer here was recalled from memory without re-checking against current disk state.*
