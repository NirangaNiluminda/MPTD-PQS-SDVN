# MPTD-PQS — HPC Lab Run Guide

How to build and run the MPTD-PQS NS-3 (3.35) + SUMO simulation on an HPC lab
machine, drive it with the correct flags (including the **8×8 / 250 m RSU
grid**), and score it against the **3 existing baseline techniques (B1/B2/B3)**.

> Paths below assume the repo lives at the NS-3 root, e.g.
> `~/ns-allinone-3.35/ns-3.35`. Replace `$NS3` with your actual path:
> ```bash
> export NS3=$HOME/ns-allinone-3.35/ns-3.35
> cd $NS3
> ```

---

## 0. TL;DR — the one command you'll run most

```bash
cd $NS3
export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH
./waf --run "mptd_pqs_sdvn \
  --mobility_source=1 \
  --N_RSUs=64 \
  --N_Vehicles=135 \
  --skip_blockchain=true \
  --ablation_mode=1 \
  --attack_number=2 \
  --attack_percentage=20 \
  --simTime=30"
```

- `--mobility_source=1` → drive node motion from the **SUMO trace** (the `.tcl`).
- `--N_RSUs=64` → the **8×8 grid** layout (see §2).
- `--skip_blockchain=true` → this is the **lightweight / sweep** path (no Fabric).
  For the **full blockchain run** use `--routing_algorithm=4 --skip_blockchain=false`
  (BOTH required — `routing_algorithm=4` is the on-chain master switch; without it
  the ledger stays empty) and bring up the Fabric network first — the HPC node has
  Docker + Explorer + IPFS (see §1b).

Everything else is explained below.

---

## 1. Prerequisites on the HPC node

### 1a. Native C++ libraries (required to BUILD)

The project's `scratch/mptd_pqs_sdvn/wscript` links three native libs, expected
under **`$HOME/.local`** (`$HOME/.local/include` + `$HOME/.local/lib`):

| Library | Purpose | Build fails without it |
|---------|---------|------------------------|
| **OpenFHE** (≥1.5.1) | threshold-BFV FHE (Invariant 5) | yes |
| **ONNX Runtime** | GAT + LSTM-AE inference (full mode) | yes |
| **liboqs** | PQ-Dilithium (ML-DSA) TRS | yes |

These won't be in *your* `$HOME/.local` on a fresh HPC account. Options:
- Install them into `~/.local` on the HPC node (same prefix the `wscript`
  expects — then no path edits are needed), **or**
- If the cluster provides them via `module load`, load the modules and adjust
  the `-I` / `-L` paths in `scratch/mptd_pqs_sdvn/wscript` to match.

Verify before building:
```bash
ls $HOME/.local/lib/ | grep -Ei "oqs|openfhe|onnxruntime"
ls $HOME/.local/include/ | grep -Ei "oqs|openfhe|onnxruntime"
```

### 1b. Docker / Hyperledger Fabric (the blockchain layer)

The full pipeline brings up **Hyperledger Fabric in Docker**, with **Hyperledger
Explorer** (ledger UI) and **IPFS** (off-chain raw-beacon store) alongside.

> **The MPTD-PQS HPC lab node HAS Docker + Explorer + IPFS installed and running.**
> The full end-to-end blockchain run (SC-Trust / SC-Revoke / CP-Detect, RQ6
> consensus) is therefore done **on the HPC node** — this is the live-run target.

Bring the network up with the dynamic topology generator (one Fabric peer per
RSU + 5 controller-orderers — see `fabric_net/README.md`):

```bash
cd scratch/mptd_pqs_sdvn/fabric_net
./gen_network.sh all 64 5     # urban: 64 RSU peers + 5 orderers, full bring-up
```

Then run the simulation **with the blockchain enabled**, passing BOTH on-chain
flags (note `routing_algorithm=4` AND `skip_blockchain=false`):

```
--routing_algorithm=4 --skip_blockchain=false
```

> ⛓️ **`--routing_algorithm=4` is mandatory for the live run.** It is the on-chain
> master switch: `register_all_nodes()`, `initialize_blockchain()`, and the
> controller/consortium SC-evidence submits are ALL gated on `routing_algorithm==4`
> (`12_main.h:1594, 1713, 2071`), regardless of `routing_test`/`ablation_mode`. The
> default `0` ("port-based") is a routing baseline that writes nothing on-chain, so
> a run that forgets this flag completes normally but leaves `blockchain_evidence.json`
> empty and adds no Explorer records. When the gen_network is already up,
> `initialize_blockchain()` detects `peer0.rsu.example.com` and no-ops (it does not
> rebuild the legacy test-network); registration flows through the gateway daemon
> socket. See `FLAGS_REFERENCE.md` §2b.

`--skip_blockchain=true` is still used for the **training sweeps and ablation A5**
(`--ablation_mode=5`, blockchain isolation) where Fabric is intentionally bypassed
to keep the detection/mobility path fast — but it is no longer forced on HPC.

At shutdown the run writes a consolidated ledger snapshot to
`analytics/results/blockchain_evidence.json` (registrations, trust scores, the
revoke records = CRL, CP-Detect flags, and any controller reassignments). The same
committed ledger is browsable live in Hyperledger Explorer.

### 1c. Python (for the B2/B3 baselines)

```bash
python3 -m pip install --user numpy pandas scikit-learn
```
(Used by `mptd_pqs/ercan_b2_detector.py` and `mptd_pqs/sharma_b3_detector.py`.)

### 1d. ML models (only needed for full / A2 / A3 modes)

GAT + LSTM-AE ONNX models must be present:
```bash
ls analytics/ml/models/    # expect: gat_model.onnx lstm_ae_model.onnx scaler.json theta_ae.txt
```
If absent, the sim prints `[AI-INIT] ... NO` and silently falls back to
**lightweight-only** — so A2/A3/Full metrics would be invalid. For A1 / B1 runs
the models are not needed.

---

## 2. SUMO connectivity — how the trace and RSU grid are wired

**NS-3 never runs SUMO at simulation time.** SUMO is used *offline* to produce a
trajectory file; NS-3 only replays it. The chain is:

```
OSM → netconvert → urban.net.xml → gen_flow_demand.sh → routes → sumo --fcd-output
    → traceExporter.py → mobility/mobility_urban_60.tcl  ←── NS-3 reads THIS
```

What NS-3 loads at runtime (only when `--mobility_source=1`):

| Artefact | Path | Loaded by |
|----------|------|-----------|
| Vehicle trajectory | `mobility/mobility_urban_60.tcl` | `Ns2MobilityHelper` (`09b_mobility_provider.h:214`) |
| RSU positions | `mobility/rsu_positions_urban.csv` | `12_main.h:797` (RSU *i* ← CSV row *i*) |

Both files are committed, so **on HPC you do not need SUMO installed at all** for
a normal run — the `.tcl` and CSV are already in the repo.

### The RSU grid (supervisor-mandated, 2026-06-12)

`rsu_positions_urban.csv` is a fixed **8×8 = 64-RSU uniform grid, 250 m spacing**,
centred over the mobility trace. With 250 m < 300 m DSRC range, coverage is
**100 %** (every vehicle always within range of ≥1 RSU). To use it you must pass
`--N_RSUs=64` (otherwise it defaults to 4; values >`MAX_RSUS`=64 are clamped).

**Regenerate the grid CSV** (only if the trace changes — needs Python, not SUMO):
```bash
python3 sumo/place_rsus.py \
  --trace mobility/mobility_urban_60.tcl \
  --grid 8x8 --spacing 250 --range 300 \
  --out mobility/rsu_positions_urban.csv
```

**Regenerate the `.tcl` trace** (only if you change the demand — needs SUMO
installed; do this on a workstation, not HPC):
```bash
cd sumo && ./build_sumo_trace.sh        # writes mobility/mobility_urban_<speed>.tcl
```
See `sumo/PIPELINE.md` and `sumo/FLOW_DEMAND.md` for the full SUMO workflow.

---

## 3. Build on the HPC node (one-time)

```bash
cd $NS3
./waf configure          # first build, or after changing the wscript
./waf build              # compiles the project (12_main.h is large; a few min)
```

A clean build ends with the module list and **no** `error:` lines. If it fails,
it is almost always a missing lib from §1a — fix that first.

---

## 4. Running the MPTD-PQS simulation — flag reference

Always export the library path first (so the OpenFHE/ONNX/oqs `.so` files load):
```bash
export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH
```

| Flag | Meaning | Typical value |
|------|---------|---------------|
| `--mobility_source` | 0=hardcoded 16-veh, **1=SUMO trace**, 2=live TraCI (reserved) | `1` |
| `--N_RSUs` | active RSU count → **64 for the 8×8 grid** | `64` |
| `--N_Vehicles` | active vehicle count (trace has ~135) | `135` |
| `--skip_blockchain` | skip Fabric/Docker bring-up | `true` on HPC |
| `--simTime` | seconds of simulated time | `30` |
| `--ablation_mode` | variant selector (see §5 table) | `1`=A1 … `6`=B1 |
| `--attack_number` | attack signature 1–7 (TP-S*/MP-S*) | `2` |
| `--attack_percentage` | fraction of attackers (5/10/20/30) | `20` |
| `--maxspeed` | trace speed tag (selects `mobility_urban_<N>.tcl`) | `60` |
| `--enable_gat` | force GAT on/off (overrides ablation default) | `0`/`1` |
| `--enable_lstm_ae` | force LSTM-AE on/off | `0`/`1` |
| `--trs_classical` | use classical Shamir-Schnorr TRS (RQ5 PBPO baseline) | `0`/`1` |

> Headless note: never launch `sumo-gui` or NetAnim on the HPC node (no display).
> NetAnim XML is still *written* headless but is heavy and unnecessary for metric
> sweeps.

---

## 5. Running the 3 baseline techniques (B1 / B2 / B3)

The paper compares MPTD-PQS against **three existing techniques**:

| Baseline | Method | How it runs | Input file it reads |
|----------|--------|-------------|---------------------|
| **B1** | Ghaleb 2014 — LTT location/time plausibility | **inside NS-3** (`--ablation_mode=6`) | live beacons |
| **B2** | Ercan 2022 — kNN / RF / Stacking | Python, **train-then-predict** | `beacon_log.csv` (+ attack logs) |
| **B3** | Sharma & Liu 2021 — SVM/kNN/NB/RF/AdaBoost | Python, **train-then-predict** | `beacon_log.csv` (+ attack logs) |

> **Important:** the canonical B2/B3 detectors read **`beacon_log.csv`**, *not*
> `rsu_relay_log.csv` (older notes/scripts said relay log — that is wrong for the
> `*_v2`/`*_train_save`/`*_live_predict` pipeline). `beacon_log.csv` is the file
> that has the `pos_x`/`pos_y` columns the feature extractor needs. The scripts
> also read the attack-specific logs (`tp_s1_poison_log.csv`, `vehicle_tx_log.csv`,
> `ghost_identity_log.csv`) from the same folder to recover each beacon's *real*
> position for the displacement/RSSI features.

### B1 — runs inside the simulator (no training)

B1 is a rule-based C++ detector; just run the sim with `--ablation_mode=6`:

```bash
export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH
./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
  --skip_blockchain=true --ablation_mode=6 --attack_number=2 \
  --attack_percentage=20 --simTime=30"
```
B1 metrics come out of the same metric layer as MPTD-PQS (directly comparable).

### B2 / B3 — the train-then-predict workflow (ML baselines)

B2 and B3 are **machine-learning** detectors. An ML model has two phases:

1. **Train (fit + freeze)** — show the model labelled data so it learns; save it
   to disk (a `.joblib` file). Do this **once**.
2. **Predict** — load the frozen model and run it on **new** simulation output to
   get malicious/benign decisions.

> **Why two separate simulation runs?** If you train and score on the *same*
> beacons, the model has already seen the answers — accuracy is fake (data
> leakage). So: **train on RUN A, predict on a fresh RUN B.** Use different
> `--RngRun` / random seeds (or just run twice — the SUMO trace replays the same
> motion but attacker injection and channel noise differ per run).

#### Step 1 — RUN A: produce the *training* data

Run the sim for the attack scenario you want a model for, e.g. attack 2 @ 20 %:

```bash
export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH
./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
  --skip_blockchain=true --ablation_mode=1 --attack_number=2 \
  --attack_percentage=20 --simTime=30 --RngRun=1"
```
This writes `analytics/results/beacon_log.csv` (and the attack logs).

> **Regenerate the data on the 64-RSU grid.** Any `beacon_log.csv` left over from
> an older 4- or 25-RSU run is stale — the B2 detector now reads the 64-RSU grid
> positions from `mobility/rsu_positions_urban.csv`, so its RSSI/distance features
> only match a beacon log produced *with* `--N_RSUs=64`.

#### Step 2 — organise RUN A into a "datasets" folder

The trainer expects one sub-folder per scenario, named `a<attack>_p<pct>`, each
holding that run's CSVs. Copy RUN A's results into the matching folder:

```bash
mkdir -p datasets/a2_p20
cp analytics/results/beacon_log.csv          datasets/a2_p20/
cp analytics/results/tp_s1_poison_log.csv    datasets/a2_p20/ 2>/dev/null || true
cp analytics/results/vehicle_tx_log.csv      datasets/a2_p20/ 2>/dev/null || true
cp analytics/results/ghost_identity_log.csv  datasets/a2_p20/ 2>/dev/null || true
```
Repeat (re-run + copy) for every `a<attack>_p<pct>` scenario you want a model for.

#### Step 3 — train and FREEZE the models (run once)

```bash
cd $NS3
python3 mptd_pqs/ercan_b2_train_save.py  datasets  models_ercan_b2
python3 mptd_pqs/sharma_b3_train_save.py datasets  models_sharma_b3
```
- arg 1 = the datasets root from Step 2; arg 2 = where to save the frozen models.
- Each scenario produces `ercan_a2_p20_kNN.joblib`, `..._RF.joblib`,
  `..._Stacking.joblib` (+ a `_scaler.joblib`). These are the **frozen** models —
  you do not retrain them again.

#### Step 4 — RUN B: produce *fresh* data to score

Run the sim again with a **different** seed so the model is tested on data it has
never seen:

```bash
./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
  --skip_blockchain=true --ablation_mode=1 --attack_number=2 \
  --attack_percentage=20 --simTime=30 --RngRun=2"
```
This overwrites `analytics/results/beacon_log.csv` with the new run's beacons.

#### Step 5 — predict with the frozen models

```bash
python3 mptd_pqs/ercan_b2_live_predict.py \
  analytics/results/beacon_log.csv  2  20  models_ercan_b2 \
  live_results/ercan_a2_p20.csv

python3 mptd_pqs/sharma_b3_live_predict.py \
  analytics/results/beacon_log.csv  2  20  models_sharma_b3 \
  live_results/sharma_a2_p20.csv
```
Positional args: `<beacon_csv> <attack_num> <attack_pct> <models_dir> [output_csv]`.
The `<attack_num> <attack_pct>` select which frozen model to load (must match the
scenario you trained in Step 3). Each script prints the 7 evaluation metrics
(MCC/FPR/PARR/PBPO… — when the beacon log carries ground-truth `label`/`is_poisoned`
columns) and writes per-row predictions to the optional output CSV.

> **One-shot alternative (no separate train file):** `ercan_b2_detector.py` /
> `sharma_b3_detector.py` train + score in a single pass with internal
> cross-validation. That is fine for a quick number, but the **frozen-model**
> workflow above is what mirrors real deployment (train offline, predict live) and
> avoids leakage between training and scoring.

---

## 6. Full evaluation sweep (RQ1–RQ6)

`scratch/mptd_pqs_sdvn/run_sweep.sh` runs the full matrix
(attacks × percentages × speeds × modes). Before using it on HPC, edit its run
line to add `--mobility_source=1 --N_RSUs=64 --skip_blockchain=true`.

```bash
./scratch/mptd_pqs_sdvn/run_sweep.sh quick   # A1+B1, ~35 min
./scratch/mptd_pqs_sdvn/run_sweep.sh         # full matrix, ~140 min
```
Output: one CSV per run under `analytics/results/sweep/`.

---

## 7. Submitting as a batch job (SLURM example)

A heavy run (135 veh × 64 RSUs) takes many minutes per simulated second — do not
hold an interactive shell. Wrap it in `sbatch`:

```bash
#!/bin/bash
#SBATCH --job-name=mptd-pqs
#SBATCH --nodes=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=8G
#SBATCH --time=04:00:00
#SBATCH --output=mptd_%j.log

export NS3=$HOME/ns-allinone-3.35/ns-3.35
cd $NS3
export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH

# module load gcc python   # if your cluster uses environment modules

./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
  --skip_blockchain=true --ablation_mode=1 --attack_number=2 \
  --attack_percentage=20 --simTime=30"

python3 mptd_pqs/ercan_b2_detector.py
python3 mptd_pqs/sharma_b3_detector.py
```
Submit with `sbatch run_mptd.slurm`; adjust `--mem`, `--time`, modules to your
cluster.

---

## 8. Where results land

| Output | Path |
|--------|------|
| Per-beacon / relay logs | `analytics/results/*.csv` (B2/B3 read `beacon_log.csv`) |
| On-chain evidence (full run) | `analytics/results/blockchain_evidence.json` — registrations, trust scores, revoke records (CRL), CP-Detect flags, controller reassignments |
| Frozen baseline models | `models_ercan_b2/*.joblib`, `models_sharma_b3/*.joblib` |
| Baseline predictions | `live_results/*.csv` |
| Sweep metrics | `analytics/results/sweep/metrics_a{N}_p{P}_s{S}_m{M}.csv` |
| NetAnim XML (if enabled) | `analytics/results/mptd_netanim_*.xml` |

These are auto-generated and **gitignored** — copy them off the node yourself.

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `error: oqs.h / openfhe.h not found` at build | §1a — libs missing from `~/.local`; install or fix wscript paths |
| `error while loading shared libraries: liboqs.so` at run | `LD_LIBRARY_PATH` not exported (§4) |
| 0 beacons received | check `--mobility_source=1` is set and the `.tcl` + CSV use the same coordinate frame (they do by default) |
| `[AI-INIT] ... NO` but you expected full mode | ONNX models missing (§1d) — A2/A3/Full invalid; A1/B1 still fine |
| Fabric / Docker errors at start | for a full run, bring the network up first (`fabric_net/gen_network.sh all 64 5`, §1b); for a sweep/A1 run, pass `--skip_blockchain=true` |
| `beacon_log.csv not found` (B2/B3) | run the NS-3 sim first (§5 Step 1), run Python from the project root |
| B2/B3 accuracy looks impossibly perfect | you trained and predicted on the *same* run — use different `--RngRun` for RUN A vs RUN B (§5) |
| `Model not found: ..._kNN.joblib` (live_predict) | you skipped Step 3, or the `<attack_num> <attack_pct>` args don't match a trained scenario |
| Run never finishes interactively | expected — use SLURM (§7), not a login shell |

---

## 10. Quick checklist before your first HPC run

- [ ] OpenFHE + ONNX Runtime + liboqs present in `~/.local` (§1a)
- [ ] `python3 -m pip install --user numpy pandas scikit-learn` (§1c)
- [ ] `./waf configure && ./waf build` succeeds with no `error:` (§3)
- [ ] `export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH` (§4)
- [ ] run with `--mobility_source=1 --N_RSUs=64 --skip_blockchain=true` (§0)
- [ ] B1 via `--ablation_mode=6` (§5)
- [ ] B2/B3: RUN A → train/freeze (`*_train_save.py`) → RUN B → predict (`*_live_predict.py`), different seeds (§5)
