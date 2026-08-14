# SENTINEL Demo UI — design & build plan

**Date:** 2026-08-14
**Author:** derived from a code walk of `scratch/mptd_pqs_sdvn/`, `chaincode/`, `analytics/`
**Goal:** a browser UI that makes MPTD-PQS-SDVN legible to a viva panel *and* to
non-technical stakeholders — 7 attack types + combined mode, the multi-layer
defence (rule signatures → GAT → LSTM-AE → fusion → PQ crypto → Fabric), driven
from a laptop against this HPC box.

> **Ground rule inherited from CLAUDE.md:** never fabricate results. Every number
> the UI shows must be traceable to a CSV row, a stdout line, or a chaincode
> query. The UI is a *viewer*, not a source of truth. Anything derived or
> smoothed must be labelled as such on screen.

---

## 1. Decisions taken (confirmed with the project owner)

| decision | choice |
|---|---|
| Live vs replay | **Hybrid** — replay is the default demo path; a "Launch real run" button spawns a genuine simulation and streams its events |
| Stack | **FastAPI (Python 3.12) + React/Vite**, frontend pre-built to static assets |
| Blockchain view | **Custom ledger panel** (primary) **+ Hyperledger Explorer revived as a "raw blocks" proof tab** |
| Audience | Thesis defence panel **and** non-technical stakeholders |
| Deployment | Server runs on this HPC box; laptop connects over SSH tunnel / LAN |

---

## 2. Hard constraints (measured, not assumed)

### 2.1 The simulator is ~40× slower than real time — this drives everything

Measured on 2026-08-14 with the canonical config (`--simTime=30`, urban, 200
vehicles, 64 RSUs, `--attack_number=0`, GAT+AE on, `--skip_blockchain=true`):

```
wall clock elapsed : 600 s (killed at the 10-minute cap)
sim time reached   : t = 14.793 s   (beacons begin at t ≈ 7.0 s)
```

That is roughly **40 s of wall clock per 1 s of sim time**. The reported 300 s
runs therefore take **3–6 hours each**. Consequences:

- **Nobody can watch a full attack unfold live.** The demo's default path must
  be replay.
- A "live" button is still worth having — it proves the pipeline is real — but it
  must be scoped to **15–30 s of sim time** and framed as "watch the real
  simulator produce these events, slowly", with a progress bar and an honest ETA.
- Enabling Fabric (`--skip_blockchain=false`) is far worse: registration alone is
  **~13 min for 200 vehicles** (`SESSION_HANDOFF_2026-08-05.md:207`). Live runs
  in the demo should keep `--skip_blockchain=true` and take blockchain state from
  the **already-running** Fabric network instead.

### 2.2 Toolchain gaps on this machine

| need | status | action |
|---|---|---|
| Python 3.12 | ✅ present | — |
| `fastapi`, `uvicorn`, `pandas` | ❌ absent | `pip install --user` into a venv |
| Node.js / npm | ❌ absent (`apt` candidate 18.19.1, but `sudo` needs a password) | install **without root** via prebuilt tarball into `$HOME` (§6.1) |
| Internet | ✅ reachable | fine for `npm install` at build time |
| Docker + Fabric | ✅ **70 containers up right now**, 64 RSU peers + orderers | reuse as-is |
| Hyperledger Explorer | ⚠️ `explorer.mynetwork.com` and `explorerdb.mynetwork.com` **exited 2 weeks ago** | revive via `scratch/mptd_pqs_sdvn/explorer_fix.sh --resync` |

### 2.3 A defect to fix before the UI parses it

`analytics/results/blockchain_evidence.json` is **not valid JSON**. The
`active_controller` field is written unquoted, so when the chaincode returns an
error the file contains:

```json
"active_controller": evaluate GetActiveController: rpc error: code = Unknown desc = ...,
```

`json.load()` fails outright. Either fix the writer in `06c_blockchain_api.h` to
quote/escape the value, or have the UI fall back to live chaincode queries. **The
writer fix is the right call** — the file is evidence, and evidence that doesn't
parse isn't evidence.

---

## 3. What the codebase actually exposes (data inventory)

This is the raw material. Everything in §5 is built from these and nothing else.

### 3.1 `[FUSION-RSU*]` stdout lines — the single most valuable event

Emitted at `08_detection_engine.h:2529` on every fused per-vehicle decision:

```
[FUSION-RSU12] epoch=3 t=142.300 vid=47 psi=0.150 psi_fuse=1.000 S=24.81
  thetaS=19.74 S_over_thetaS_raw=1.257 S_over_thetaS_clamped=1.000
  ae_norm=0.412 ae_raw=13.881 dumped=0 gt_pois=1 gt_atk=2 sig_mask=17
  phi=0.673 khat=1 gatflag=1 full_anom=YES (Eq 3.46)
```

One line carries **the entire defence stack for one vehicle at one instant**:
the rule-signature score `psi`, the GAT spatial score `S` and its threshold
`thetaS`, the LSTM-AE reconstruction error `ae_raw`/`ae_norm`, the fused verdict
`phi`, the predicted attack class `khat`, and ground truth `gt_pois`/`gt_atk`.
This is what makes "show the LSTM and GAT contribution effectively" tractable —
it is already there, it just needs parsing and rendering.

⚠️ **Case trap:** `full_anom=YES` but `full_anom=no` — the case differs between
outcomes. The parser must be case-sensitive-aware or it will silently
mis-classify (this trap is documented in `RUN_CONFIG.md`).

### 3.2 `beacon_log.csv` — 18 columns, written per beacon

Path: `analytics/results[_pid<PID>]/<scenario>/beacon_log.csv`
(`10_metrics_csv.h:170`).

```
sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, accel,
is_poisoned, detected, sig_mask, psi_score, attack_number, attack_pct,
attacker_class, gt_pos_x, gt_pos_y, gt_speed
```

Two properties make it ideal for the UI:

1. **It carries both the reported pose and the ground-truth pose.** `pos_x/pos_y`
   is what the vehicle *claimed*; `gt_pos_x/gt_pos_y` is where it *actually was*.
   Drawing both and connecting them with a line is the clearest possible visual
   of trajectory poisoning — a rubber band stretching between the lie and the
   truth. No non-technical explanation needed.
2. **It is opened and closed per row** (`10_metrics_csv.h:247`), so every row is
   flushed to disk immediately. It is **fully tailable live** — no buffering
   games required.

⚠️ Ghost identities (`vehicle_id >= 10000`) have **no** backing ns-3 node, so
their `gt_*` columns are copies of the reported pose, not real ground truth.
The UI must render ghosts as a distinct class, never as "claimed vs actual".

### 3.3 The 9 rule signatures with published weights

From `08_detection_engine.h:1082`, ψ = Σ wₖ·Sₖ, threshold `psi_th = 0.09`:

| bit | signature | weight | plain-language label for the UI |
|---|---|---|---|
| 0 | TP-S1 kinematic position jump | 0.15 | "Teleported — moved further than physically possible" |
| 1 | TP-S2 heading rate deviation | 0.10 | "Turned too sharply for its speed" |
| 2 | TP-S3 acceleration bound | 0.10 | "Accelerated harder than a car can" |
| 3 | TP-S4 dead-reckoning residual | 0.15 | "Not where its own last report predicted" |
| 4 | TP-S5 cumulative drift | 0.15 | "Story has drifted from reality over time" |
| 5 | MP-S1 identity density | 0.15 | "Too many vehicles claiming to be in one place" |
| 6 | MP-S2 timing synchronisation | 0.05 | "Beacon timing doesn't match a real radio" |
| 7 | MP-S3 KL divergence | 0.10 | "Speed pattern unlike its neighbours" |
| 8 | MP-S4 transit impossibility | 0.05 | "Appeared at two RSUs it couldn't have crossed between" |

`sig_mask` in the CSV is this bitfield. **Decoding it into these nine plain
sentences is the highest-value non-technical feature in the whole UI** — it turns
an opaque anomaly score into a readable accusation.

### 3.4 Map geometry

- **64 RSUs** with exact coordinates: `mobility/rsu_positions_urban.csv`
  (`rsu_id,x,y`; also `_rural`, `_autobahn`, and E3 variants at n96/n128/n160).
- **Trace bounds**, printed at startup as `[MAP-BOUNDS]`:
  x ∈ [610.68, 2754.81], y ∈ [506.33, 2426.87] — a ~2.14 km × 1.92 km urban
  area (Shinjuku-derived).
- **Vehicle trajectories**: `mobility/mobility_urban_60.tcl` (ns-2 format,
  `$node_(N) setdest X Y SPEED`), 200 vehicles.
- **Communication range** `R_max_comm = 270 m` (`02_config_globals.h:641`) —
  draw as RSU coverage circles.

### 3.5 Pre-recorded runs (the replay corpus)

`~/Desktop/dataset_G50-mobility/` — **302 MB**, structured as
`{urban,rural,highway}/a{1..7}_p{0,20,40,60,80,100}/`. That is every attack type
crossed with every intensity, already captured. This is the replay library and
it means **the demo needs no new long runs to be usable**.

Plus, in the repo:
- `results_e1_final/e1_raw_results.csv` — penetration/intensity sweep (36 rows)
- `results_e2_final/e2_raw_results.csv` — speed regime (8 rows)
- `results_e5_final/e5_final_table.json` — SENTINEL_Full / SENTINEL_LW / B1 / B2 / B3
  per attack, with MCC ± std, TTD, CDER, PBPO
- `analytics/results/<scenario>/` — per-attack detail logs:
  `tp_s1_poison_log.csv`, `ghost_identity_log.csv`, `mitm_intercept_log.csv`,
  `controller_poison_log.csv`, `vehicle_tx_log.csv`, `rsu_relay_log.csv`

### 3.6 Blockchain — query surface already built

The chaincode has read-only functions that are, almost by accident, a perfect UI
API (`chaincode/chaincode/smartcontract.go`):

| function | feeds |
|---|---|
| `GetAllRegistrations` | identity roster + Dilithium public keys |
| `GetAllTrustScores` / `GetAllRSUTrustScores` / `GetAllControllerTrustScores` | trust decay over epochs |
| `GetAllRevokeRecords` / `GetRevokeVotes` | revocation votes reaching the f+1 quorum |
| `GetAllControllerFlags` / `IsControllerFlagged` | CP-DETECT control-plane accusations |
| `GetControllerReassignments` / `GetActiveController` | controller exclusion + failover |
| `GetEpochSubmissions` | per-epoch evidence submissions |

Writes worth surfacing as a live feed: `SCRegister`, `SCTrustSubmitEvidence`
(Eq 3.56), `SCControllerSubmitEvidence` (Eq 3.57), `CPDetectCheck`,
`SCRevokeVote` (Eq 3.65, witness window T_w = 30 s), `SCTrustFinalizeEpoch`.

### 3.7 PQ crypto layer

- **TRS**: `06b1_trs_backend.h` — t-of-n threshold ring signature; ML-DSA-87
  (CRYSTALS-Dilithium via liboqs) when `MPTD_REQUIRE_LEVEL5`, Shamir-Schnorr-P256
  otherwise. σ_TRS = Σ λⱼ(0)·σⱼ mod q (Eq 3.48).
- **FHE**: `06b2_fhe_backend.h` — **BFV** (not CKKS) on OpenFHE 1.5.1;
  aggregates `[Σspeed, Σpos_x, Σpos_y, N]` under encryption.
- **Cost metrics** already in `metrics.csv`: `COO_epoch`, `COO_trs`, `COO_fhe`,
  `COO_dkg` (ms), `BWO_ratio`, `BWO_scale`, `TCL_confirm`, `TCL_reassign`.

### 3.8 The 7 attacks, in the project's own words

| # | code | actor | what it does |
|---|---|---|---|
| 1 | TP-S1 | compromised **RSU** | rewrites vehicles' trajectories as it relays them |
| 2 | TP-S2 | malicious **vehicle** | reports a fake but physically plausible trajectory |
| 3 | MP-S1 | compromised **RSU** | injects ghost identities (Sybil); enhanced mode pre-registers Sybils with *valid* pool IDs so detection must be behavioural |
| 4 | MP-S2 | malicious **vehicle** | steals other vehicles' IDs and beacons under them |
| 5 | TP-S3 | compromised **controller** | poisons trajectories at the control plane; vehicles and RSUs are honest |
| 6 | MP-S3 | malicious **vehicle** as MitM relay | intercepts and re-broadcasts with amplified speed to breach the KL threshold (κ_th = 1.5) |
| 7 | MP-S4 | compromised **controller** | corrupts the *global* mobility model despite receiving correct data |

**Combined mode (`--attack_number=0`) is a spatial partition, not a timeline.**
All 7 run *simultaneously*, split across actors: compromised RSUs alternate
TP-S1 / MP-S1 (`06a_attack_models.h:573`); malicious vehicles round-robin over
{TP-S2, MP-S2, MP-S3} (`:474`); the controller path carries TP-S3 / MP-S4.

> **This is a storytelling problem for the demo.** A viewer expects "attack 1,
> then attack 2, then…". Combined mode gives them all seven at once, tangled
> together. The UI must therefore offer **two narrative modes**: a per-attack
> guided tour (using the single-attack recordings from §3.5) and a combined-mode
> "everything at once" view with a **filter by attack type** so a viewer can peel
> the layers apart. Do not fake a timeline that the simulator does not produce.

---

## 4. Tech stack

### 4.1 Why not OMNeT++

The user asked whether OMNeT++ would help. **It would not**, for three reasons:

1. **It is not a UI tool.** OMNeT++'s Qtenv is a *developer's* simulation
   debugger — module trees, message queues, event logs. It is aimed at the
   person writing the model, and it would confuse a non-technical viewer more
   than a blank screen would.
2. **It cannot run this model.** OMNeT++ cannot execute ns-3 code. The simulator
   is ~1 M lines of ns-3.35 headers bound to ONNX Runtime, liboqs, OpenFHE, and a
   Fabric gateway daemon. Porting to OMNeT++/Veins is a **months-long rewrite**
   with a guaranteed re-validation burden against every number in the paper —
   for zero presentational gain.
3. **The equivalent already exists and is already weak.** ns-3 ships NetAnim,
   and the project already emits `mptd_netanim_urban_a*.xml`
   (`12_main.h:2564`). It is a desktop Qt app showing coloured dots. It cannot
   show ψ/S/ε decomposition, cannot show the ledger, cannot be driven from a
   laptop over a tunnel.

A purpose-built web UI is the correct answer, and it costs a fraction of any
port.

### 4.2 The stack

```
┌─ HPC box (10.50.20.184) ──────────────────────────────────────────┐
│                                                                    │
│  ns-3 simulator ──writes──► beacon_log.csv, metrics.csv            │
│       │                     (per-row flush → tailable)             │
│       └────stdout──────────► [FUSION-RSU*] / [LW-DETECT-*] lines   │
│                                     │                              │
│  Fabric (70 containers) ◄──query────┤                              │
│       │                             │                              │
│       └──► Hyperledger Explorer :8888 (revived)                    │
│                                     │                              │
│  ┌──────────────────────────────────▼─────────────────────────┐    │
│  │ FastAPI :8000                                              │    │
│  │   /api/scenarios      catalogue of replayable runs         │    │
│  │   /api/replay/{id}    frame-indexed playback (HTTP)        │    │
│  │   /ws/live            WebSocket: tail live run events      │    │
│  │   /api/run            spawn a real short sim               │    │
│  │   /api/ledger/*       chaincode queries (cached)           │    │
│  │   /                   serves the built React bundle        │    │
│  └────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
                              │ SSH tunnel or LAN
                              ▼
                    Laptop browser — nothing installed
```

**Backend: FastAPI + uvicorn.** Python is already the project's analysis
language (`analytics/*.py`, the whole `lambda_refit_*` family), so the parsing
logic can reuse existing conventions. `pandas` for CSV slicing; `subprocess` for
`peer chaincode query` and for spawning the simulator.

**Frontend: React + Vite + TypeScript**, with:
- **deck.gl** (`ScatterplotLayer`, `LineLayer`, `PathLayer`) for the 200-vehicle
  map — GPU-accelerated, comfortable at 60 fps with this node count
- **Recharts** for time-series (φ decomposition, MCC, trust decay)
- **Zustand** for playback state
- **Tailwind** for layout

**Critical for the laptop workflow:** `npm run build` produces static assets that
FastAPI serves directly. The laptop needs **only a browser** — no Node, no dev
server, no build step at demo time.

---

## 5. The UI

Six screens. The first three are the demo; the last three are the depth a viva
panel will ask for.

### 5.1 Screen 1 — Live Network Map (the centrepiece)

The screen that runs for 90% of the demo.

```
┌────────────────────────────────────────────────────────────────────────┐
│ Scenario: Urban ▾   Attack: Combined (all 7) ▾   Intensity: 40% ▾      │
│ Defence:  ● D6 GAT+LSTM-AE   ○ D4 GAT only   ○ D1 Rules only          │
├─────────────────────────────────────────────┬──────────────────────────┤
│                                             │  DETECTION FEED          │
│      ○ ─────── ● V47                        │  ─────────────────────   │
│     truth    claim   (rubber band = lie)    │  t=142.3  V47  FLAGGED   │
│                                             │   ▸ Teleported           │
│   ◉ RSU12 ·····.                            │   ▸ Story drifted        │
│   (270m coverage)  ·                        │   φ=0.67 (thr 0.50)      │
│                                             │                          │
│      ● ● ●  honest vehicles                 │  t=141.8  V12  clean     │
│      ▲ ▲    malicious                       │  t=141.2  V88  FLAGGED   │
│      ✦ ✦ ✦  ghost identities                │   ▸ Too many IDs here    │
│      ◉ RSU   ◉ compromised RSU              │                          │
│      ■ Controller  ■ compromised            │  ── LEDGER ──────────    │
│                                             │  V47 trust 0.82→0.31     │
├─────────────────────────────────────────────┤  REVOKE votes 3/3 ✓      │
│  ◀◀  ▶  ▶▶    t = 142.3 / 300.0 s           │  RSU12 FLAGGED epoch 4   │
│  ━━━━━━━━━━━●━━━━━━━━━━━━━━━━━━━━━━━━━━━    │                          │
│  1x  5x  20x   [⚡ Launch real run]          │                          │
└─────────────────────────────────────────────┴──────────────────────────┘
```

Design notes:

- **The rubber band is the hero visual.** A hollow circle at `gt_pos_*`, a filled
  dot at `pos_*`, a line between them. When an attack starts, bands stretch
  across the map. No caption required — a non-technical viewer *sees* the lie.
  Suppress the band for ghosts (§3.2), which get their own marker.
- **Detection feed writes accusations in English**, decoded from `sig_mask` via
  the §3.3 table. This is what makes the system explicable without equations.
- **The defence toggle (D1/D4/D6) is the ablation story made physical.** Switch
  from D6 to D1 mid-replay and watch detections change. Pre-record all three arms
  for each scenario so the switch is instant.
- **Attack-type filter** for combined mode (§3.8) — check/uncheck TP-S1…MP-S4 to
  isolate one attack out of the tangle. Derived from `gt_atk` in the FUSION line
  and `attacker_class` in the CSV.
- Colour-blind-safe palette; distinguish classes by **shape as well as colour**
  (● honest, ▲ malicious, ✦ ghost, ◉ RSU, ■ controller).

### 5.2 Screen 2 — Defence Stack Inspector (the GAT/LSTM story)

Click any vehicle on the map → this panel. Directly answers "show the GAT and
LSTM contribution in an effective manner".

```
┌─ Vehicle V47 ─── ground truth: POISONED (TP-S2) ──────────────────────┐
│                                                                        │
│  LAYER 1 — Rule signatures            ψ = 0.150   (threshold 0.09) ⚠   │
│    ✓ TP-S1 Teleported            w=0.15  ████                          │
│    ✓ TP-S5 Story drifted         w=0.15  ████                          │
│    ✗ TP-S2 Turned too sharply    w=0.10                                │
│    ✗ ... (6 more)                                                      │
│                                                                        │
│  LAYER 2 — GAT (spatial graph)        S = 24.81   (θ_S = 19.74)    ⚠   │
│    Neighbourhood: 7 vehicles within 300 m                              │
│    "This vehicle disagrees with the cars around it"                    │
│    predicted attack class k̂ = 1                                        │
│                                                                        │
│  LAYER 3 — LSTM-AE (temporal)         ε = 13.88   (θ_ae = 33.69)   ✓   │
│    50-beacon window reconstruction                                     │
│    "Its recent history is self-consistent"                             │
│         ┌──── reconstruction error over time ────┐                     │
│         │              ╱╲    ╱                   │                     │
│         │  ────────╱──╲──╲──╱────── θ_ae         │                     │
│         └──────────────────────────────────────── ┘                    │
│                                                                        │
│  FUSION (Eq 3.46)                     Φ = 0.673   (threshold 0.50) ⚠   │
│    Φ = 0.507·ψ̂ + 0.186·Ŝ + 0.307·ε̂     → ANOMALOUS                    │
│    ████████████████░░░░░░░░  contribution bar, one segment per layer   │
└────────────────────────────────────────────────────────────────────────┘
```

Every number here comes from **one `[FUSION-RSU*]` line** (§3.1). The stacked
contribution bar is the answer to "which layer caught this?" — and it honestly
shows the cases where the LSTM-AE contributed nothing, which a viva panel will
respect more than a diagram where every layer always fires.

⚠️ **Label the fusion weights as attack-conditioned.** The engine loads per-attack
λ sets (`[AI-INIT] attack-conditioned lambda_sets`), so the weights shown must be
the ones actually used for that `k̂`, not the global default.

### 5.3 Screen 3 — Blockchain & Trust

```
┌─ TRUST DECAY ──────────────────┬─ REVOCATION ────────────────────────┐
│  1.0 ┤━━━━━━╲                  │  V47   votes 3/3  need f+1=2   ✓    │
│      │       ╲___              │        witness window T_w = 30 s    │
│  0.5 ┤ ─────────╲── threshold  │        → REVOKED at epoch 4         │
│      │           ╲__ V47       │                                     │
│  0.0 ┤                         │  RSU12 FLAGGED (CP-DETECT)          │
│      └─ e1  e2  e3  e4  e5     │  CTRL2 excluded → reassign CTRL0    │
├────────────────────────────────┴─────────────────────────────────────┤
│ PQ CRYPTO                                                            │
│  Ring signature  ML-DSA-87 (Dilithium, NIST L5)   t-of-n threshold   │
│  Homomorphic     BFV / OpenFHE 1.5.1  — RSUs aggregate speeds        │
│                  WITHOUT decrypting individual vehicles              │
│  Cost   COO_trs 2.4 ms · COO_fhe … · TCL_confirm …  (from metrics.csv)│
├──────────────────────────────────────────────────────────────────────┤
│ LEDGER FEED (live from Fabric)          [ Raw blocks ↗ Explorer:8888 ]│
│  ▸ SCTrustSubmitEvidence  RSU12  epoch 4   Eq 3.56                   │
│  ▸ CPDetectCheck          CTRL2  conflict                            │
│  ▸ SCRevokeVote           V47    3rd vote → quorum                   │
└──────────────────────────────────────────────────────────────────────┘
```

The custom panel carries the *meaning*; the Explorer tab carries the *proof*.
For a non-technical viewer, "the network voted and permanently recorded that this
car is untrusted" lands; a block hash does not. For the panel, the Explorer link
answers "are these real blocks?" in one click.

The FHE line is worth narrating out loud: **RSUs compute regional speed averages
without ever decrypting any individual vehicle's data.** That is a privacy claim
non-technical audiences immediately grasp.

### 5.4 Screen 4 — Attack Explainer

A card per attack (the §3.8 table), each with: a small animated schematic of the
actor and data flow, which signatures it trips, its measured MCC/TTD from
`results_e5_final/e5_final_table.json`, and a "Show me this attack" button that
loads the matching recording into Screen 1.

This is the screen that makes the demo self-guiding — a viewer can explore
without narration.

### 5.5 Screen 5 — Results & Ablation

Charts built from the existing result files (§3.5): E1 intensity sweep, E2 speed
regime, E5 SENTINEL vs B1/B2/B3 per attack, D1/D4/D6 ablation.

⚠️ **Honesty requirements, non-negotiable — these come straight from
`CLAUDE.md` and the audit:**

- Every MCC **must** display its evaluation window. The ordering D1 < D4 < D6
  holds at a **90 s** cutoff (0.8339 / 0.8432 / 0.8477) but **not at 300 s**
  (D4 falls 0.005 below D1). A chart that omits the window is misleading.
- The D4-vs-D1 gap of 0.0011 is **inside ONNX run-to-run variance (~0.007)**.
  Show error bars, or annotate it as not separable.
- FPR grows with duration: passes 0.05 at 100 s, misses by ~4× at 300 s.
  Label the FPR panel with its window.

Build these caveats into the chart components themselves so they cannot be
accidentally dropped.

### 5.6 Screen 6 — Run Console

Launch a real simulation. Flag presets that pre-fill the four documented traps
(`--routing_test=false`, `--ablation_mode=0`, `--gat_det_flag_heads=0`, and
`=0`/`=1` boolean syntax) so a mis-run is impossible from the UI. Shows the exact
command line, a progress bar keyed to sim time, a **measured ETA using the ~40×
factor**, and the live event stream.

Always pass `--per_pid_results=1` so concurrent runs cannot collide
(`RUN_CONFIG.md` documents a case where `a4_p40_m0` was found to contain all of
`a3_p40_m0`).

---

## 6. Implementation plan

### 6.1 Phase 0 — Environment (½ day)

```bash
# Node.js without root
cd ~ && curl -fsSL https://nodejs.org/dist/v20.11.1/node-v20.11.1-linux-x64.tar.xz \
  | tar -xJ && echo 'export PATH=$HOME/node-v20.11.1-linux-x64/bin:$PATH' >> ~/.bashrc

# Python env
python3 -m venv ~/demo-venv && ~/demo-venv/bin/pip install \
  fastapi uvicorn[standard] pandas websockets python-multipart

# Revive Explorer
cd $REPO/scratch/mptd_pqs_sdvn && ./explorer_fix.sh --resync
```

Also in this phase: **fix the `blockchain_evidence.json` quoting bug** (§2.3).

### 6.2 Phase 1 — Data layer (2 days)

Python modules, each independently testable against existing files:

| module | job |
|---|---|
| `parsers/beacon.py` | `beacon_log.csv` → time-indexed frames; ghost handling |
| `parsers/fusion.py` | `[FUSION-RSU*]` regex → structured events; **case-sensitive `full_anom`** |
| `parsers/sigmask.py` | bitfield → the 9 plain-language sentences |
| `parsers/metrics.py` | `metrics.csv` + `e*_final` files → chart series |
| `parsers/geometry.py` | RSU CSV + `.tcl` trace → map layers |
| `fabric/query.py` | `peer chaincode query` wrapper, cached |

**Validation gate:** parse a known run and reproduce the simulator's own printed
`MCC_full` exactly. `RUN_CONFIG.md` records that dict-keyed log parsing has
**twice** produced results contradicting the simulator by silently deduplicating
on `(rsu, t, vid)`. Add an occurrence index, and do not proceed past this gate
until the numbers match.

### 6.3 Phase 2 — Replay engine + API (2 days)

Pre-process each recording into a compact frame format (binary or Parquet) so the
laptop pulls kilobytes per second, not megabytes. Index by sim time; support
seek, variable speed, and the D1/D4/D6 arm switch.

Endpoints per §4.2. Build the scenario catalogue by scanning
`~/Desktop/dataset_G50-mobility/` and `analytics/results/`.

### 6.4 Phase 3 — Map + inspector (3 days)

Screens 1 and 2. Highest visual payoff; build first, iterate on the narrative.

### 6.5 Phase 4 — Blockchain + explainer (2 days)

Screens 3 and 4, plus the Explorer iframe/link.

### 6.6 Phase 5 — Results + run console (2 days)

Screens 5 and 6, with the honesty annotations baked into the chart components.

### 6.7 Phase 6 — Deployment & rehearsal (1 day)

```bash
# on the HPC box
cd frontend && npm run build          # → dist/, served by FastAPI
~/demo-venv/bin/uvicorn app:api --host 0.0.0.0 --port 8000

# from the laptop
ssh -L 8000:localhost:8000 -L 8888:localhost:8888 user@10.50.20.184
# then open http://localhost:8000
```

Tunnel both ports (8000 for the UI, 8888 for Explorer). LAN access to
`10.50.20.184:8000` works too if the demo network permits it — **test the actual
demo network in advance**, since venue firewalls are a classic failure.

Rehearsal checklist: full run-through on the laptop over the tunnel; verify
Fabric containers are up; confirm at least one pre-recorded scenario per attack
type loads; time the whole thing.

**Total: ~12 working days.**

---

## 7. Risks

| risk | severity | mitigation |
|---|---|---|
| Live run overruns the demo slot | **high** | Replay is the default path; live capped at 15–30 s sim time with a measured ETA shown up front |
| Fabric containers die before the demo | **high** | Health check on the dashboard; snapshot ledger state to JSON as a fallback so Screen 3 still renders |
| Network/tunnel fails at the venue | **high** | Rehearse on the actual demo network; keep a screen-recorded walkthrough as a last resort |
| Parser silently disagrees with the simulator | **high** | The Phase-1 validation gate; this has already bitten this project twice |
| Explorer won't re-sync | medium | It is the *secondary* blockchain view — the custom panel stands alone |
| deck.gl chokes on 200 vehicles + 64 RSUs | low | Well within GPU budget; fall back to Canvas 2D if needed |
| Viewer misreads combined mode as a timeline | medium | Explicit "all 7 running simultaneously" banner + attack-type filter |

---

## 8. Open items to confirm before Phase 3

1. **Recording coverage.** The `dataset_G50-mobility` corpus predates the current
   code state. Do the demo recordings need to be **regenerated with the current
   binary** (D1/D4/D6 arms × 7 attacks ≈ 21 runs × 3–6 h = a multi-day batch), or
   is the existing corpus acceptable for illustration? *Recommendation:*
   regenerate a **small set** — combined mode × 3 arms at 90 s — since 90 s is the
   window where the D1<D4<D6 ordering actually holds, and use the existing corpus
   for the per-attack tour.
2. **Basemap.** Plain coordinate grid, or a real Shinjuku street map underlay?
   A real map is far more compelling for non-technical viewers, but needs either
   an offline tile pack or internet at the venue.
3. **Rural / highway scenarios** — include in the demo, or urban only?
4. **Branding** — thesis title, university, name on a title screen?

---

## 9. What this plan deliberately does *not* do

- **No new simulator features.** The UI reads what already exists. The only code
  change proposed to `scratch/` is the JSON quoting fix (§2.3).
- **No re-derivation of metrics in the frontend.** MCC, FPR, TTD are read from
  the simulator's own output, never recomputed in JavaScript — that is how
  contradictions get introduced.
- **No smoothing or filtering of detections** to make the demo look better. The
  false positives are real and the ordering caveats are real; the UI shows them.
