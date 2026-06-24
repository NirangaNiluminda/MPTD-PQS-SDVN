# MPTD-PQS — Command-Line Flag Reference

Every `--flag` the `mptd_pqs_sdvn` binary accepts, its default, what it does, and
the values you actually use. All flags are registered in `12_main.h` (the
`cmd.AddValue(...)` block near the top of `main()`); defaults live in
`02_config_globals.h` (and `routing_test` in `07_socket_layer.h`).

Run as:
```bash
export LD_LIBRARY_PATH=$PWD/build/lib:$HOME/.local/lib:$LD_LIBRARY_PATH
./waf --run "mptd_pqs_sdvn --flag1=value --flag2=value ..."
```
Booleans take `true`/`false`; everything else is a number.

---

## 1. The flags at a glance

| Flag | Default | Type | One-line meaning |
|------|---------|------|------------------|
| `--N_RSUs` | `4` | uint | Active RSU count. **64** for the SUMO 8×8 grid. Clamped to `MAX_RSUS=64`. |
| `--N_Vehicles` | `16` | uint | Active vehicle count. **200** for the supervisor-spec SUMO urban trace (`urban_150`); the older `urban_60` trace has 135. Clamped to capacity (`total_size`). |
| `--simTime` | `15.0` | double | Seconds of simulated time. |
| `--mobility_source` | `0` | int | **0**=hardcoded 16-veh · **1**=SUMO `.tcl` trace (paper) · **2**=live TraCI (reserved). |
| `--mobility_scenario` | `0` | int | **0**=urban · **1**=non-urban/rural · **2**=highway/autobahn. Selects the trace + RSU-CSV tag. |
| `--maxspeed` | `60` | int | Speed tag (km/h) → picks `mobility_<scenario>_<maxspeed>.tcl`. `urban_60` (135 veh) & `urban_150` (200 veh, supervisor spec — use this) exist today. |
| `--attack_number` | `1` | int | Which attack signature 1–7 (TP-S*/MP-S*). See §3. |
| `--attack_percentage` | `40` | int | % of nodes that are malicious (0–100, **avoid 100**). The "how many attackers" knob. |
| `--sybil_registration_pct` | `0` | int | Attack-3 only: % of vehicles pre-registered as Sybil at startup (0 = ghost-ID mode). |
| `--rsu_seed` | `0` | uint | RNG seed for *which* RSUs get compromised. `0` = random each run; fixed = reproducible attacker set. |
| `--ablation_mode` | `1` | int | Which variant runs. **0**=Full · **1**=A1 LW-only · **2**=A2 GAT · **3**=A3 AE · **4**=A4 no-PQ · **5**=A5 no-blockchain · **6**=B1 Ghaleb-LTT baseline. See §4. |
| `--enable_gat` | `-1` | int | Force GAT on(1)/off(0); **-1** = follow `ablation_mode`. |
| `--enable_lstm_ae` | `-1` | int | Force LSTM-AE on(1)/off(0); **-1** = follow `ablation_mode`. |
| `--trs_classical` | `0` | int | TRS scheme: **0**=PQ Dilithium/ML-DSA-87 (paper, NIST Level 5) · **1**=classical Shamir-Schnorr-P256 (RQ5 PBPO baseline). |
| `--skip_blockchain` | `false` | bool | Skip the live Hyperledger Fabric writes. **`false`** for the full blockchain run (HPC node has Docker + Explorer + IPFS). **`true`** only for training sweeps & ablation **A5** (`--ablation_mode=5`). Has effect ONLY together with `--routing_algorithm=4` (see that row + §2b). See `BLOCKCHAIN_IMPLEMENTATION.md` + `fabric_net/README.md`. |
| `--routing_test` | `true` | bool | **true** = MPTD-PQS detection mode (no SDN routing pipeline) · **false** = legacy SDN-routing experiment. See §2 — this one changes a LOT. |
| `--routing_algorithm` | `0` | int | **Two distinct jobs.** (a) When `routing_test=false`: selects the SDN link-discovery algorithm 0–5 (§2). (b) **Regardless of `routing_test`: it is ALSO the master switch for the on-chain blockchain path** — `register_all_nodes()`, `initialize_blockchain()`, and the controller/consortium SC-evidence submits are ALL gated on `routing_algorithm == 4` (`12_main.h:1594, 1713, 2071`). **For ANY live blockchain run you MUST set `--routing_algorithm=4`**, or the ledger stays empty. See §2b. |
| `--architecture` | `0` | int | 0=centralized · 1=distributed · 2=hybrid (legacy routing layer). |
| `--experiment_number` | `0` | int | Sub-experiment index (legacy routing layer; `5` triggers a special grid layout). |
| `--lambda` | `10` | int | Flow-size selector for the legacy routing/traffic generator. |
| `--qf` | `0` | int | QoS flag (legacy routing layer). |
| `--data_transmission_frequency` | `10.0` | double | Beacons/data Hz. 10 Hz → T_b = 100 ms (paper beacon interval). |
| `--link_lifetime_threshold` | `0.400` | double | Link-lifetime threshold (s) for the legacy routing optimizer. |

> **Capacity clamps** (`12_main.h`): `N_RSUs` is clamped to `MAX_RSUS = 64`,
> `N_Vehicles` to `total_size`. Asking for more just clamps with a warning.

---

## 2. `--routing_test` — the big one (true vs false)

**Default is `true`.** This single flag flips the whole binary between two
worlds, because this codebase was built on top of an older SDN link-discovery /
routing-security project (LLDP, "LDA"). MPTD-PQS detection lives in the
`routing_test=true` path.

### `--routing_test=true` (default) — MPTD-PQS detection mode ✅ use this

This is the mode for all attack-detection / metric work.

- **Topology:** enforces minimums `N_Vehicles ≥ 16`, `N_RSUs ≥ 4` (you can still
  pass larger via CLI, e.g. `--N_RSUs=64`).
- **Skips the entire SDN routing pipeline** (`12_main.h:1612 if (!routing_test)`):
  no link-discovery, no LLDP, no per-window RSA/AES/HMAC routing-key setup, no
  `routing_algorithm` run, no routing-optimization or `delta` transmission.
- **Runs:** DSRC beacon TX, the DSRC-RSU relay (Option B), and the MPTD-PQS
  detection/crypto/blockchain stack.
- **NetAnim labels** reflect the MPTD-PQS roles ("SDN CONTROLLER (MPTD-PQS)",
  management = "DSRC-RSU relay", cloud = "FHE aggregate sink").
- `--lambda`, `--qf`, `--architecture`, `--experiment_number`,
  `--link_lifetime_threshold` are **ignored** here.
- **`--routing_algorithm` is NOT ignored.** Even with `routing_test=true` (so the
  SDN link-discovery switch never runs), `routing_algorithm` still acts as the
  on-chain master switch: only `=4` triggers the blockchain path. See §2b.

### `--routing_test=false` — legacy SDN-routing experiment ⚠️ not the FYP path

- **Topology:** `N_Vehicles` / `N_RSUs` taken straight from CLI, no minimums.
- **Runs the full SDN link-discovery + crypto + routing pipeline**: `generate_F_and_E`,
  `run_optimization_link_lifetime`, the big `LDA_security` RSA/AES/HMAC setup,
  the `routing_algorithm` switch, `transmit_delta_values`, and LLDP metrics.
- This is the **old routing-security testbed**, not MPTD-PQS attack detection.
  Use it only if you specifically want to exercise that routing layer.

When `routing_test=false`, `--routing_algorithm` selects the link-discovery
algorithm:

| `routing_algorithm` | Algorithm |
|---|---|
| `0` (default) | port-based |
| `1` | normal LLDP |
| `2` | pure-crypto |
| `3` | link-guard |
| `4` | proposed LLDP |
| `5` | HELLO packets |

> **Bottom line:** for everything in the MPTD-PQS paper (the 7 metrics, the 5
> ablations, the 3 baselines) keep **`--routing_test=true`** (the default). Only
> set it to `false` if you are deliberately testing the inherited SDN-routing
> code.

---

## 2b. `--routing_algorithm=4` — the on-chain master switch ⛓️

This is the flag people forget, and forgetting it produces a **silently empty
ledger**. The entire live-blockchain path is gated on `routing_algorithm == 4`,
*independently of* `routing_test` and `ablation_mode`:

| Code site | What it does | Gate |
|---|---|---|
| `12_main.h:1594` | `initialize_blockchain()` (ensures Fabric is up) | `routing_algorithm==4 && !skip_blockchain` |
| `12_main.h:2071` | `register_all_nodes()` — boot-time SC-Register of every RSU/vehicle/controller | `routing_algorithm==4` (then `skip_blockchain` short-circuits inside) |
| `12_main.h:1713` | builds + submits the controller / consortium SC-evidence each window | `routing_algorithm==4` |

So the on-chain controls are **two nested switches**:

```
routing_algorithm==4 ?        ← is this the proposed method, which HAS a chain?
   └── skip_blockchain==false ? ← do I actually write to live Fabric, or stub it?
```

- `routing_algorithm=0` (the default, "port-based") is a **routing baseline with
  no blockchain by design** — it writes nothing on-chain no matter what
  `skip_blockchain` is. The baselines (0,1,2,3,5) are *supposed* to have no chain;
  that is part of the paper's comparison.
- `routing_algorithm=4` is the **proposed MPTD-PQS method** (routing overlay
  `run_proposed_LLDP`); it is the ONLY value that registers nodes and submits
  evidence on-chain.

**Therefore:**

| You want… | flags |
|---|---|
| metrics only, no chain (sweeps / A5) | `--routing_algorithm=0 --skip_blockchain=true` (or just omit both) |
| the proposed method, chain bypassed (clean blockchain-ablation OFF arm) | `--routing_algorithm=4 --skip_blockchain=true` |
| **the live blockchain run** (Explorer + IPFS deliverable) | **`--routing_algorithm=4 --skip_blockchain=false`** |

> **Clean blockchain ablation:** to isolate the blockchain's effect, hold the
> routing fixed at `=4` and toggle ONLY `skip_blockchain`. Comparing default `=0`
> (no chain) against `=4` (chain) confounds the routing protocol with the
> blockchain and is **not** a valid ablation.

> **`initialize_blockchain()` and the running gen_network:** when the paper-scale
> `fabric_net/gen_network.sh` network (`peer0.rsu.example.com` + 5 orderers) is
> already up, `initialize_blockchain()` detects it and no-ops — it does NOT rebuild
> the legacy `test-network`. Node registration and SC-invokes flow through the
> gateway daemon's AF_UNIX socket to that existing network. So the live-run order
> is: (1) `gen_network.sh all 64 5`, (2) start the gateway daemon, (3) run the sim
> with `--routing_algorithm=4 --skip_blockchain=false`.

---

## 3. `--attack_number` — attack signatures (1–7)

`attack_number` picks which poisoning signature is injected; `attack_percentage`
scales how many nodes/beacons it affects. (Magnitude/"drift rate" per beacon is
set by the `epsilon_*` / `theta_s` constants in `02_config_globals.h`, **not** a
CLI flag.)

| # | Signature | Threat class | Notes |
|---|-----------|--------------|-------|
| 1 | TP-S1 Location Spoofing | malicious vehicle / compromised RSU | position drift at RSU; default attack |
| 2 | TP-S2 Kinematic | malicious vehicle | |Δθ|/velocity-jump implausibility |
| 3 | TP-S3 Fabrication / Sybil | malicious vehicle | use with `--sybil_registration_pct` |
| 4 | MP-S2 Impersonation | MitM / malicious vehicle | drift on own + stolen beacons |
| 5 | (MP-S*) | — | see `06a_attack_models.h` header for the exact map |
| 6 | MP-S3 MitM data-plane | MitM / compromised RSU | moderate speed shift |
| 7 | (MP-S*) | — | see `06a_attack_models.h` header |

> The authoritative attack-number → signature map is the comment block at the
> top of `scratch/mptd_pqs_sdvn/06a_attack_models.h`. Check it before quoting a
> mapping in the report.

---

## 4. `--ablation_mode` — which variant runs (paper §4.1.1)

| Mode | Variant | GAT | LSTM-AE | PQ crypto | Blockchain | Answers |
|------|---------|-----|---------|-----------|------------|---------|
| `0` | Full | ✅ | ✅ | ✅ | ✅ | baseline |
| `1` (default) | A1 — Lightweight only | ✖ | ✖ | ✅ | ✅ | RQ2 |
| `2` | A2 — GAT only | ✅ | ✖ | ✅ | ✅ | RQ3 spatial |
| `3` | A3 — Temporal AE only | ✖ | ✅ | ✅ | ✅ | RQ3 temporal |
| `4` | A4 — Full AI, no TRS/FHE | ✅ | ✅ | ✖ | ✅ | RQ4 / PARR baseline |
| `5` | A5 — Full mode, no blockchain | ✅ | ✅ | ✅ | ✖ | RQ6 |
| `6` | B1 — Ghaleb-LTT baseline | ✖ | ✖ | — | — | SOTA comparison |

`--enable_gat` / `--enable_lstm_ae` override the GAT/AE columns when set to
`0`/`1` (default `-1` = follow the table). A2/A3/Full need the ONNX models present
(`analytics/ml/models/`), or the sim silently falls back to lightweight-only.

The **B2/B3** baselines (Ercan, Sharma) are **not** ablation modes — they are
Python post-processors run on the simulation output (see `HPC_RUN_GUIDE.md` §5).

---

## 5. Ready-to-use command recipes

**MPTD-PQS A1 on the SUMO 64-RSU grid (the standard run):**
```bash
./waf --run "mptd_pqs_sdvn --mobility_source=1 --maxspeed=150 --N_RSUs=64 --N_Vehicles=200 \
  --skip_blockchain=true --routing_test=true --ablation_mode=1 \
  --attack_number=2 --attack_percentage=20 --simTime=30"
```

**Full mode (all AI + crypto + LIVE blockchain — needs Docker + ONNX models):**
```bash
# bring the network up first:  cd fabric_net && ./gen_network.sh all 64 5
# and start the gateway daemon (see BLOCKCHAIN_IMPLEMENTATION.md), THEN:
./waf --run "mptd_pqs_sdvn --mobility_source=1 --maxspeed=150 --N_RSUs=64 --N_Vehicles=200 \
  --routing_algorithm=4 --skip_blockchain=false \
  --ablation_mode=0 --attack_number=2 --attack_percentage=20 --simTime=30"
```
> `--routing_algorithm=4` is **mandatory** here — it is the on-chain master switch
> (§2b). Without it the run completes but `blockchain_evidence.json` is empty and
> Explorer shows no new records.

**B1 SOTA baseline (Ghaleb LTT, in-sim):**
```bash
./waf --run "mptd_pqs_sdvn --mobility_source=1 --maxspeed=150 --N_RSUs=64 --N_Vehicles=200 \
  --skip_blockchain=true --ablation_mode=6 \
  --attack_number=2 --attack_percentage=20 --simTime=30"
```

**Fast smoke test (no SUMO, hardcoded 16-veh, no Docker):**
```bash
./waf --run "mptd_pqs_sdvn --mobility_source=0 --skip_blockchain=true \
  --ablation_mode=1 --attack_number=1 --attack_percentage=40 --simTime=5"
```

**Reproducible attacker set across runs** (so 20% vs 40% differ only by % ):
add `--rsu_seed=42` to fix which RSUs are compromised.

---

## 6. Quick "which flags do I actually touch?"

For the FYP detection/evaluation work you normally only vary these:

- `--ablation_mode` (which variant) · `--attack_number` (which attack) ·
  `--attack_percentage` (intensity)
- `--mobility_source=1 --maxspeed=150 --N_RSUs=64 --N_Vehicles=200` (SUMO map, supervisor spec: 200 veh + 64 RSU)
- For the **live blockchain run**: `--routing_algorithm=4 --skip_blockchain=false` (both required, §2b). For metrics-only sweeps / A5 leave `routing_algorithm=0` and pass `--skip_blockchain=true` · `--simTime`
- `--rsu_seed` for reproducibility · `--trs_classical=1` only for the RQ5 PBPO baseline

Leave `--routing_test=true`. Ignore `--lambda / --qf / --architecture /
--experiment_number / --link_lifetime_threshold` unless you are running the
inherited SDN-routing code. **Do NOT ignore `--routing_algorithm`** — set it to
`4` whenever you want on-chain records, `0` otherwise (§2b).
