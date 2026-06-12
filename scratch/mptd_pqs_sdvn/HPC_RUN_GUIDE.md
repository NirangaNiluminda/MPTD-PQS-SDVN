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
- `--skip_blockchain=true` → no Docker/Fabric needed (see §1).

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

The full pipeline brings up **Hyperledger Fabric in Docker**. Most HPC clusters
**do not allow Docker** (rootless / Singularity only). So on HPC always run with:

```
--skip_blockchain=true
```

This skips Fabric + the REST API and runs pure detection/mobility. The
blockchain-dependent results (SC-Trust/SC-Revoke evidence, RQ6 consensus) must
be reproduced on a machine where Docker works — **not** the HPC node.

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

The paper compares MPTD-PQS against **three existing techniques**. Two run as
post-processing on the simulation's CSV; one runs *inside* the simulation.

| Baseline | Method | How it runs | Input |
|----------|--------|-------------|-------|
| **B1** | Ghaleb 2014 — LTT location/time plausibility | **inside NS-3** (`--ablation_mode=6`) | live beacons |
| **B2** | Ercan 2022 — kNN / RF / Stacking | Python post-processor | `analytics/results/rsu_relay_log.csv` |
| **B3** | Sharma & Liu 2021 — SVM/kNN/NB/RF/AdaBoost | Python post-processor | `analytics/results/rsu_relay_log.csv` |

### Step 1 — produce the shared data with a simulation run

B2/B3 read `analytics/results/rsu_relay_log.csv`, which the NS-3 run writes. Run
the sim once (any detection mode is fine for generating the log; use A1):

```bash
export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH
./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
  --skip_blockchain=true --ablation_mode=1 --attack_number=2 \
  --attack_percentage=20 --simTime=30"
```

### Step 2 — B1 (runs in the simulator)

```bash
./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
  --skip_blockchain=true --ablation_mode=6 --attack_number=2 \
  --attack_percentage=20 --simTime=30"
```
B1 metrics are emitted by the same metric layer as MPTD-PQS (directly comparable).

### Step 3 — B2 and B3 (Python, from the project root)

```bash
cd $NS3
python3 mptd_pqs/ercan_b2_detector.py     # B2 — Ercan 2022
python3 mptd_pqs/sharma_b3_detector.py    # B3 — Sharma & Liu 2021
```
Each prints the 7 evaluation metrics. They read
`analytics/results/rsu_relay_log.csv` automatically.

> The `mptd_pqs/` folder also contains newer `*_v2.py`, `*_new.py`,
> `*_live_predict.py`, `*_train_save.py` variants owned by the baseline teammate.
> The canonical scoring entry points are the two files above; use the teammate's
> variants only if they tell you to.

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
| Per-beacon / relay logs | `analytics/results/*.csv` (incl. `rsu_relay_log.csv`) |
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
| Fabric / Docker errors at start | you forgot `--skip_blockchain=true` |
| `rsu_relay_log.csv not found` (B2/B3) | run the NS-3 sim first (§5 Step 1), run Python from the project root |
| Run never finishes interactively | expected — use SLURM (§7), not a login shell |

---

## 10. Quick checklist before your first HPC run

- [ ] OpenFHE + ONNX Runtime + liboqs present in `~/.local` (§1a)
- [ ] `python3 -m pip install --user numpy pandas scikit-learn` (§1c)
- [ ] `./waf configure && ./waf build` succeeds with no `error:` (§3)
- [ ] `export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH` (§4)
- [ ] run with `--mobility_source=1 --N_RSUs=64 --skip_blockchain=true` (§0)
- [ ] B1 via `--ablation_mode=6`; B2/B3 via the two Python scripts (§5)
