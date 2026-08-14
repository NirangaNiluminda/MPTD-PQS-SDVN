# MPTD-PQS-SDVN — How to Run the Simulation

Operational guide: how to build and run the NS-3 simulation, and what each
**operating mode** and **component toggle** (crypto on/off, blockchain on/off,
full vs lightweight, per-component ablation) actually does.

All flags below are the real `--flag` names parsed in
`scratch/mptd_pqs_sdvn/12_main.h`; component meanings are from
`02_config_globals.h`.

---

## 1. Build

```bash
cd ~/ns-allinone-3.35/ns-3.35
./waf build --targets=mptd_pqs_sdvn
```
Rebuild after **any** change to a `scratch/mptd_pqs_sdvn/*.h` header
(the simulation is header-only C++).

## 2. Run skeleton

```bash
cd ~/ns-allinone-3.35/ns-3.35
LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:$HOME/.local/lib64" \
  ./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn <flags>
```

**Confirm what actually ran** — every run prints an `[ABLATION]` banner near the
top, e.g.:
```
[ABLATION] Active mode: A0  use_pq_crypto=YES  enable_gat=YES  enable_lstm_ae=YES
```
Always check this line matches what you intended.

---

## 3. Operating modes — `--ablation_mode` (the main switch)

Selects which detection/mitigation components are active. **Default is `1`
(lightweight)** — for the *full* proposed method you must pass `--ablation_mode=0`.

| `--ablation_mode` | Name | Rules+HMAC | GAT | LSTM-AE | TRS+FHE crypto | Blockchain |
|:--:|---|:--:|:--:|:--:|:--:|:--:|
| **0** | **Full (proposed method)** | ✅ | ✅ | ✅ | ✅ | ✅ (if `skip_blockchain=false`) |
| 1 | A1 Lightweight-only *(default)* | ✅ | ❌ | ❌ | ❌ | ❌ |
| 2 | A2 GAT-only | ✅ | ✅ | ❌ | ❌ | ❌ |
| 3 | A3 AE-only | ✅ | ❌ | ✅ | ❌ | ❌ |
| 4 | A4 Full, **no PQ crypto** | ✅ | ✅ | ✅ | ❌ (`use_pq_crypto=false`) | ✅ |
| 5 | A5 Full, **no blockchain** | ✅ | ✅ | ✅ | ✅ | ❌ (SC calls skipped) |
| 6 | B1 Ghaleb (2014) baseline | LTT speed + cross-RSU only | ❌ | ❌ | ❌ | ❌ |

> **Key point:** `MCC` in the metrics = the lightweight (rule) decision;
> `MCC_full` = the fused full-mode decision. Only mode 0 produces a meaningful
> `MCC_full`.

---

## 4. Encryption / PQ crypto ON vs OFF

The post-quantum pipeline is **TRS** (threshold ring signature, ML-DSA-87) +
**FHE** (threshold BFV). In full mode it is on by default.

| Goal | Flags |
|---|---|
| Full PQ crypto ON (default in mode 0) | `--ablation_mode=0` |
| Crypto OFF entirely | `--ablation_mode=4` (→ `use_pq_crypto=false`) |
| **TRS off, FHE on** (AB6) | `--enable_trs=0` |
| **FHE off, TRS still signs plaintext** (AB7) | `--enable_fhe=0` |
| Classical signing baseline (RQ5 PBPO) | `--trs_classical=1` (default 0 = PQ Dilithium) |

## 5. Blockchain ON vs OFF

Live blockchain = **Hyperledger Fabric** (permissioned). It does **not** change
MCC/FPR (it does trust/revocation), so turn it **off** for fast detection sweeps
and **on** only for the full no-bypass evidence / TCL/FRR metrics.

| Goal | Flags |
|---|---|
| **Blockchain ON** (live Fabric) | `--skip_blockchain=false --routing_algorithm=4` **+ env** `MPTD_CA_IDENTITY=0` |
| **Blockchain OFF** (fast) | `--skip_blockchain=true` |
| Full mode but skip only the SC calls | `--ablation_mode=5` |

> `MPTD_CA_IDENTITY=0` uses the pre-enrolled `User1` Fabric identity (the leased
> client-identity pool isn't enrolled). Requires the Docker Fabric network up.
> Each run wipes + re-registers all 64 RSUs on-chain (`[SC-REGISTER] … bootstrap OK`),
> ~2 s per registration.

## 6. AI detectors (GAT / LSTM-AE) — force on/off

By default GAT and LSTM-AE follow `--ablation_mode`. Override individually:

| Flag | Effect |
|---|---|
| `--enable_gat=1 / 0 / -1` | force GAT on / off / follow mode |
| `--enable_lstm_ae=1 / 0 / -1` | force LSTM-AE on / off / follow mode |

---

## 7. Per-component ablation — `--ablation_ab` (full mode minus ONE mechanism)

For the paper's AB1–AB11 study. Runs full mode (`ablation_mode=0`) with exactly
one component removed:

| `--ablation_ab` | Removes | Equivalent single toggle |
|:--:|---|---|
| 1 | Rule signatures (ψ) | `--enable_rule_signatures=0` |
| 2 | HMAC + nonce gate | `--enable_hmac_gate=0` |
| 3 | GAT | `--enable_gat=0` |
| 4 | LSTM-AE | `--enable_lstm_ae=0` |
| 5 | All AI (= mode 1 lightweight) | — |
| 6 | TRS gate | `--enable_trs=0` |
| 7 | FHE | `--enable_fhe=0` |
| 8 | RSU 3-state lifecycle | `--enable_rsu_lifecycle=0` |
| 9 | Multi-controller rotation | `--enable_ctrl_rotation=0` |
| 10 | Blockchain (= mode 5) | — |
| 11 | LKH tree (→ unicast rekey) | `--use_lkh_tree=0` |

---

## 8. Mobility, network, attack, and calibration flags

**Mobility / network**
| Flag | Meaning |
|---|---|
| `--mobility_source` | `0`=hardcoded 16-veh smoke, **`1`=SUMO trace (paper)**, `2`=SUMO-live (reserved) |
| `--mobility_scenario` | `0`=urban (Tokyo), rural / highway variants |
| `--maxspeed` | vehicle speed cap / `s_max` (km/h) |
| `--N_RSUs`, `--N_Vehicles`, `--N_Controllers` | topology size (paper: 64 / 200 / 4) |
| `--simTime` | simulation seconds (paper runs 20–30 s; each ≈ minutes of wall-clock) |
| `--RngRun` | random seed (use ≥3 different seeds, report mean±std) |

**Attack**
| Flag | Meaning |
|---|---|
| `--attack_number` | attack scenario (1=trajectory-poison, 3=Sybil, …) |
| `--attack_percentage` | attacker fraction (e.g. 50) |
| `--rsu_seed` | RSU-compromise seed (`0`=random each run — **pin it** for reproducibility) |

**Lightweight-detector calibration (sensitivity analysis)**
| Flag | Threshold | Default |
|---|---|---|
| `--psi_th` | composite alert threshold ψ_th | 0.09 |
| `--kappa_th` | MP-S3 KL-divergence κ_th | 0.10 |
| `--delta_th` | TP-S5 drift threshold (m) | 10.0 |
| `--drift_window_k` | drift observation window (beacons) | 10 |
| `--k_sybil` | MP-S1 Sybil density factor | 5.0 |

---

## 9. Common run recipes (copy-paste)

Assume you are in `~/ns-allinone-3.35/ns-3.35` with:
```bash
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:$HOME/.local/lib64"
BIN=./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn
BASE="--mobility_source=1 --mobility_scenario=0 --maxspeed=60 --N_RSUs=64 --N_Vehicles=200 \
      --attack_number=1 --attack_percentage=50 --simTime=20 --RngRun=2"
```

**A. Full system, no bypass (blockchain ON) — the evidence run**
```bash
MPTD_CA_IDENTITY=0 $BIN $BASE --ablation_mode=0 --skip_blockchain=false --routing_algorithm=4
```

**B. Full mode, fast (blockchain OFF)** — same MCC, ~5× faster
```bash
$BIN $BASE --ablation_mode=0 --skip_blockchain=true
```

**C. Lightweight only (A1)**
```bash
$BIN $BASE --ablation_mode=1 --skip_blockchain=true
```

**D. Crypto OFF full run (A4)**  /  **Blockchain OFF full run (A5)**
```bash
$BIN $BASE --ablation_mode=4 --skip_blockchain=true      # no PQ crypto
$BIN $BASE --ablation_mode=5 --skip_blockchain=true      # no blockchain
```

**E. One ablation variant (e.g. AB6 = TRS off)**
```bash
$BIN $BASE --ablation_mode=0 --ablation_ab=6 --skip_blockchain=true
```

**F. Sensitivity point (override a threshold)**
```bash
$BIN $BASE --ablation_mode=0 --skip_blockchain=true --psi_th=0.11
```

---

## 10. Where outputs go

| Output | Path |
|---|---|
| Metrics CSV (44 cols, per run) | `analytics/results/sweep/metrics_a<N>_p<P>_s60_m<mode>.csv` |
| Full-system evidence bundle | `analytics/results/PEM_evidence/run_<stamp>/` |
| Sensitivity sweep | `analytics/results/sensitivity/run_<stamp>/` |
| Live beacon log (overwritten each run) | `analytics/results/beacon_log.csv` |

The `[ABLATION]` banner + the final `MCC / MCC_full / … / TCL` block in stdout
are the authoritative record of what ran and what it produced.
