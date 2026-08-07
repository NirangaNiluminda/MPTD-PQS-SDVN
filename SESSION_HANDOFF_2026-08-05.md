# SESSION HANDOFF — MPTD-PQS-SDVN
**Date:** 2026-08-05
**Branch:** `ml-review-fixes` · **Last commit:** `9eb4f34 fixes`
**Purpose:** Full context transfer to a new Claude session/account. Everything
below is *measured*, not assumed. Where a claim was later disproved it is kept
and marked, so the next session does not repeat the dead end.

---

## 0. READ THIS FIRST — the five things that cost the most time

| # | Trap | Reality |
|---|---|---|
| 1 | `routing_test` | **Defaults to `true`** ([07_socket_layer.h:16](scratch/mptd_pqs_sdvn/07_socket_layer.h#L16)). Silently disables the ENTIRE on-chain evidence pipeline. **Always pass `--routing_test=false`.** |
| 2 | `ablation_mode` | **Defaults to `1` (A1 = lightweight)** ([02_config_globals.h:216](scratch/mptd_pqs_sdvn/02_config_globals.h#L216)). `--enable_gat/--enable_lstm_ae` do **NOT** change it. Printed `MCC`/`FPR` are then LW-only and identical across arms; `CDER_full = -1`. **Pass `--ablation_mode=0` for full mode.** |
| 3 | ns-3 CLI booleans | `--flag=false` prints help and exits. Use `=0` / `=1`. (`--routing_test=false` works because it is parsed as a bool arg; when in doubt use `0`/`1`.) |
| 4 | `LD_LIBRARY_PATH` | Must be `build/lib` or the binary exits **127**. Run from `/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35`. |
| 5 | Log case sensitivity | Detection verdict is `full_anom=YES` (**uppercase**) and `full_anom=no` (**lowercase**). Case-sensitive greps silently return 0. |

**Epoch key format:** `mptd_epoch_from_ts()` returns `"E<seconds>"` (e.g. `E7`),
NOT a bare integer. Querying `GetEpochSubmissions(VEH_x, "0")` always returns
empty — this wasted a full debug cycle.

---

## 1. Environment

```
Repo          /home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN
ns-3 root     /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
              (scratch/mptd_pqs_sdvn is a SYMLINK into the repo)
Binary        build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn
Build         ./waf build --targets=mptd_pqs_sdvn -j4
```

**Build note:** a plain `./waf build` **FAILS** on an unrelated file —
`scratch/routing.cc:53 fatal error: paillier_he.h: No such file or directory`.
This is pre-existing and unrelated to our work, but it aborts before linking our
binary. **Always build with `--targets=mptd_pqs_sdvn`.**

### Fabric / blockchain

```
Gateway daemon  <ns3>/scratch/mptd_pqs_sdvn/fabric_gateway_daemon/mptd_fabric_gw
Socket          /tmp/mptd_fabric.sock
Daemon log      /tmp/mptd_fabric_gw.log      (APPEND-ONLY — always filter by date!)
Events          /tmp/mptd_fabric_events.jsonl
Peers           64 docker containers, all joined `mptdchannel`
Crypto root     <ns3>/scratch/mptd_pqs_sdvn/fabric_net/generated/organizations/
                  peerOrganizations/rsu.example.com
Wallet pool     <crypto>/users/_mptd_pool   (169 rsu*, 32 pool*, 4 ctrl*)
```

Daemon restart (env must be reproduced exactly):

```bash
kill $(pgrep -f mptd_fabric_gw); rm -f /tmp/mptd_fabric.sock
cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
env FABRIC_GW_SOCKET=/tmp/mptd_fabric.sock FABRIC_GW_CHANNEL=mptdchannel \
    FABRIC_GW_CHAINCODE=trajectory FABRIC_GW_MSP_ID=RSUMSP \
    FABRIC_GW_PEER=peer0.rsu.example.com \
    FABRIC_GW_PEER_ENDPOINT=dns:///localhost:11051 \
    FABRIC_GW_CRYPTO_PATH=<crypto path above> \
    FABRIC_GW_COMMIT_SEC=120 FABRIC_GW_CONN_DEADLINE_SEC=600 \
    FABRIC_GW_SYNC_RETRIES=1 FABRIC_GW_SUBMIT_SEC=60 FABRIC_GW_ENDORSE_SEC=60 \
    nohup .../fabric_gateway_daemon/mptd_fabric_gw >> /tmp/mptd_fabric_gw.log 2>&1 &
```

**The daemon caches one signing identity per wallet name.** Any change to wallet
key material requires a daemon restart to take effect.

---

## 2. RESOLVED: blockchain registration failure

**Symptom:** `access denied: channel [mptdchannel] creator org [RSUMSP]`, and
only 194/200 vehicles registering.

**Root cause:** `pool0`'s keystore contained **two** private keys — one stale
(`3790754f…`, mismatched) and one correct (`8c7e1cf1…`). The daemon's
`readFirstFile()` uses `Readdirnames(1)`, taking an **arbitrary unsorted**
directory entry, so it signed with the key that did not match `cert.pem`. Fabric
reports a signature mismatch as an *org-level access denial*, which is why it
looked like an MSP/channel problem.

`LeasePoolIdentity()` assigns the first free slot, so vehicle #0 always drew the
broken `pool0` — costing exactly the 6 vehicles that leased it.

**Fix applied:** stale key moved to
`<scratchpad>/keystore_backup/pool0_STALE_3790754f_sk`, daemon restarted.

**Verified:** all 205 identities now have exactly 1 key; all certs verify against
the org CA (identical SHA-256 fingerprints); `pool0` query returns OK.

**Latent bug not yet fixed:** `readFirstFile` picking an arbitrary key will
recur on any re-enroll. It should select the key matching the signcert.

### Current on-chain state (verified by live query)

```
GetAllRegistrations      -> CONTROLLER 4 | RSU 64 | VEHICLE 200 | TOTAL 268
                            RSU 0-63, VEH 6-205 (offset +6), CTRL 0-3, contiguous
GetActiveController      -> CTRL_0            (was "no active controller")
Vehicle trust records    -> 200
RSU trust records        ->  64
access denied            ->   0
Ledger reset             -> working (wipes ~513-525 keys per run)
IPFS                     -> 3286 windows off-chain / 3286 hashes on-chain
```

---

## 3. PARTIALLY RESOLVED: CP-DETECT never reaches the ledger

### What was wrong

`routing_test=true` (default) gates **three** blocks — the whole evidence chain:

| Site | Block |
|---|---|
| [08_detection_engine.h:4156](scratch/mptd_pqs_sdvn/08_detection_engine.h#L4156) | RSU ψ evidence → `SUBM_` |
| [08_detection_engine.h:2327](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2327) | controller evidence `CSUBM_` + `CPDetectCheck` |
| [08_detection_engine.h:4111](scratch/mptd_pqs_sdvn/08_detection_engine.h#L4111) | related blockchain path |

**Proof:** `[TIER3-SUMMARY] evidence_buffered=0` while RSU-side `anomalous=YES`
fired 2112×, with `enable_sc_trust=true` and `ablation_mode=1≠5`. Every
condition passed except `!routing_test`.

### Effect of `--routing_test=false` (BC3 → BC5, same config otherwise)

| Metric | BC3 (`routing_test=true`) | BC5/BC6 (`false`) |
|---|---|---|
| TIER3 evidence buffered | 0 | **2125** |
| TIER3 batches committed | 0 | **58** |
| `MCC_full` | not computed | **0.422** |
| `FPR_full` | — | 0.056 |
| `CDER` | 0.5915 | **0.099** |
| `CDER_full` | −1 | **0.334** |
| on-chain `CTRL_0` trust | 1.0 (never moved) | 0.99999999 (moved) |

### STILL BROKEN — the open problem

```
CFLAG records        : 0        <- CP-DETECT verdict never written on-chain
CTRL_0 trust         : 0.9999999921   (not meaningful decay)
CTRL_1/2/3 trust     : 1.0
MeanConflict         : 0  (all controllers)
Reassignments        : None     <- excludeAndReassignController never fires
```

…despite **3887 local CP-DETECT firings**, `flag_c=1`, and the local mirror
`g_ctrl_trust` decaying 1.0 → 0.0000.

**Disproved hypothesis (do not retry):** ghost/Sybil IDs were being submitted as
controller evidence and rejected (`VEH_<id> is not registered`, 466 txs, all 12
offenders ≥ GHOST_VID_BASE=10000, zero real vehicles). A guard was added at
[08_detection_engine.h:2343](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2343)
(`vid_i < CSUBM_GHOST_VID_BASE`). It **eliminated all rejections (466 → 0)** but
BC6's metrics came out **bit-identical to BC5** and `CFLAG` is **still 0**.
So the ghost submissions were NOT the blocker.

**Next lead:** `CPDetectCheck` computes `MeanConflict = 0`. Per Eq 3.66 the
directional conflict is `(1−flag^ctrl)·flag^rsu` — it only fires when the
controller reports *benign* while ≥ f+1 trusted RSUs flag anomaly
(**suppression**). Investigate whether the suppression write at
[08_detection_engine.h:2385](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2385)
(`if (g_combined_attack && fs.anomalous) phi_submitted = 0.0;`) actually
produces that asymmetry on-chain, and whether `SUBM_` and `CSUBM_` land under
the *same* `(vid, epoch)` key — the RSU uses `mptd_epoch_from_ts(ts)` at
[:4197](scratch/mptd_pqs_sdvn/08_detection_engine.h#L4197) while the controller
uses `mptd_epoch_from_ts(rw.timestamp[i])` at
[:2337](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2337). **If those timestamps
differ, the keys never match and conflict is structurally always 0.** This is
the single highest-value thing to check next.

---

## 4. Canonical run commands

Always from `/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35`.

### Full-mode detection run (no blockchain) — Items 3/4 style
```bash
LD_LIBRARY_PATH=build/lib build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn \
  --mobility_source=1 --mobility_scenario=0 --maxspeed=60 \
  --N_Vehicles=200 --N_RSUs=64 \
  --attack_number=0 --attack_percentage=40 --simTime=300 \
  --ablation_mode=0 --routing_test=false \
  --skip_blockchain=true --per_pid_results=1 \
  --enable_gat=1 --enable_lstm_ae=1 --seed=1
```
Arms: **D1** `--enable_gat=0 --enable_lstm_ae=0` · **D4** `--enable_gat=1 --enable_lstm_ae=0` · **D6** both `=1`.

### Blockchain run (REQUIRES all four flags)
```bash
LD_LIBRARY_PATH=build/lib build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn \
  ... --routing_test=false --ablation_mode=0 \
      --skip_blockchain=false --routing_algorithm=4 \
      --cder_credit_cp_detect=1
```
`routing_algorithm=4` gates `CallSCResetLedger()` + `register_all_nodes()`
([12_main.h:2441/2463](scratch/mptd_pqs_sdvn/12_main.h#L2441)).
`verify_location()` at [07_socket_layer.h:422](scratch/mptd_pqs_sdvn/07_socket_layer.h#L422)
is an **empty stub** — `routing_algorithm=4` is purely a blockchain-mode flag.

**Blockchain runs are strictly SEQUENTIAL** — each calls `ResetLedger` and will
wipe a concurrent run's state. Registration alone takes ~13 min for 200 vehicles.

### Control-plane isolation (a5/a7)
```bash
  --attack_number=5   (or 7)  --attack_percentage=40 --simTime=100 \
  --ctrl_compromise_onset=0.5 --cder_credit_cp_detect=1 --routing_test=false
```
`--ctrl_compromise_onset` (fraction of simTime) is required to get a *before*
window; at the default 0.0 the controller is compromised from the first beacon.

**Caveat:** single-attack runs load `models/urban/`, NOT `models/urban_combined/`
([12_main.h:357](scratch/mptd_pqs_sdvn/12_main.h#L357)). Combined mode cannot
isolate a5/a7 — they are applied to every vehicle by `vehicle_id % 2`
([:2656](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2656) / [:2718](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2718)).

### Chain query helper
```python
import socket, json
def call(req, timeout=180):
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(timeout)
    s.connect("/tmp/mptd_fabric.sock"); s.sendall((json.dumps(req)+"\n").encode())
    buf=b""
    while True:
        c=s.recv(1<<20)
        if not c: break
        buf+=c
        if b"\n" in buf: break
    s.close(); return json.loads(buf.decode().strip())
call({"action":"query","function":"GetAllRegistrations","args":[]})
```
Query fns: `GetAllRegistrations`, `GetActiveController`, `GetAllControllerTrustScores`,
`GetAllControllerFlags`, `GetControllerReassignments`, `GetTrustedControllers`,
`GetAllTrustScores`, `GetAllRSUTrustScores`, `GetEpochSubmissions(VEH_<nid>,"E<sec>")`.

### Metric extraction from logs (ground truth, ablation-independent)
```bash
awk '/^\[FUSION-RSU/ {
      gp=""; fa="";
      for(i=1;i<=NF;i++){
        if($i ~ /^gt_pois=/){split($i,a,"="); gp=a[2]}
        if($i ~ /^full_anom=/){split($i,b,"="); fa=toupper(b[2])}
      }
      if(gp=="0"){n++; if(fa=="YES") fp++} else if(gp=="1"){p++; if(fa=="YES") tp++}
    }
    END{fn=p-tp; tn=n-fp;
        num=(tp*tn)-(fp*fn); den=sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn));
        printf "FPR=%.4f recall=%.4f MCC=%.4f\n",(n?fp/n:0),(p?tp/p:0),(den?num/den:0)}' LOG
```
**Use this, not the printed summary**, whenever `ablation_mode=1` — the printed
`MCC`/`FPR` are LW-only and come out **identical for D1/D4/D6** (all 0.537/0.094),
which cannot show the ablation ordering.

---

## 5. Flag reference — defaults that matter

| Flag | Default | Note |
|---|---|---|
| `routing_test` | **true** | must be `false` for on-chain evidence |
| `ablation_mode` | **1 (A1 LW)** | `0` = full; 5 = A5 skips SC-Trust |
| `routing_algorithm` | **0** | `4` enables ResetLedger + registration |
| `skip_blockchain` | true | `false` to use Fabric |
| `enable_sc_trust` | true | |
| `g_tiered_commit` | true | batches evidence, `t_batch=10s`, `n_commit=50` |
| `g_gat_det_flag_heads` | **46** | heads 1,2,3,5 OR-ed into verdict (`eq:gat_det_flag`) |
| `g_cder_credit_cp_detect` | **false** | CP-1: credits CP-DETECT in CDER |
| `ctrl_compromise_onset` | 0.0 | fraction of simTime |
| `stealthy_control_plane` | true | |
| `N_Controllers` | 4 | |

Full flag list: `ab7_ring_n ablation_ab ablation_mode architecture attack_number
attack_percentage cder_credit_cp_detect ctrl_compromise_onset
data_transmission_frequency delta_hmac delta_th delta_trs demoted_psi_weight
drift_window_k enable_ctrl_rotation enable_fhe enable_gat enable_hmac_gate
enable_lstm_ae enable_rsu_lifecycle enable_rule_signatures enable_sc_revoke
enable_sc_trust enable_trs eps_max experiment_number faithful_mitm fhe_ring_dim
gat_det_flag_heads honest_mp_s1 kappa_th k_sybil lambda lambda_ae lambda_gat
lifecycle_gates_fusion link_lifetime_threshold maxspeed mitm_stealth
mobility_scenario mobility_source n_commit n_coord per_pid_results phi_max
poison_theta psi_th qf routing_algorithm routing_test rsu_malicious_fraction
rsu_seed rsu_t_rev rsu_trust_alpha rsu_trust_quorum seed skip_blockchain
s_max_kmh stealth_fraction stealthy_control_plane streak_sigma sybil_gat_evasive
sybil_registration_pct t_batch tiered_commit trs_classical trs_compromised_f
t_window uniform_speed_trace use_lkh_tree verbose_tx`

### Attack mapping (authoritative — [02_config_globals.h:106-112](scratch/mptd_pqs_sdvn/02_config_globals.h#L106))
| # | Paper ID | Description | Fig |
|---|---|---|---|
| 1 | TP-S1 | Malicious RSU trajectory poisoning | 3.1 |
| 2 | TP-S2 | Malicious vehicle trajectory poisoning | 3.2 |
| 3 | MP-S1 | Sybil via compromised RSU | 3.4 |
| 4 | MP-S2 | Sybil via vehicle impersonation | 3.5 |
| 5 | TP-S3 | Control-plane trajectory poisoning | 3.3 |
| 6 | MP-S3 | MitM data-plane mobility poisoning | 3.6 |
| 7 | MP-S4 | Control-plane global mobility poisoning | 3.7 |

`attack_number=0` = combined mode (`g_combined_attack=true`).
**Sir's decision (Step 3): adopt TP-S1…MP-S4 as canonical paper names, include
this table in the paper, change NO code.**

---

## 6. Status against sir's five items

### Item 1 — CP-1/CP-2 + a5/a7 · **PARTIAL**
Wiring is present: CP-1 at [:3260](scratch/mptd_pqs_sdvn/08_detection_engine.h#L3260),
CP-2 at [:966](scratch/mptd_pqs_sdvn/08_detection_engine.h#L966)/[:1001](scratch/mptd_pqs_sdvn/08_detection_engine.h#L1001).

a5 and a7 (100s, ρ=0.40, onset=0.5) — **identical control-plane numbers, which is
correct**: [:3167](scratch/mptd_pqs_sdvn/08_detection_engine.h#L3167) uses
`attack_number==5 || attack_number==7` as the same malicious-controller condition,
so they differ in data-plane poisoning only.

```
Downlink BEFORE onset : CLEAN 92932 (0.9369) | ATTACK_DETECTED 6263 | WRONG_ROUTING 0
Downlink AFTER  onset : WRONG_ROUTING 13799 (0.9984) | CLEAN 22
CP-DETECT = 5962 alerts / 11598 audited epochs, flag_c=1
local ctrl_trust  1.0 -> 0.0000
CDER = 0.030 (345/11598)   TTD = 17.56 s
```
`CDER=0.030` is **CP-1 working**, not a failure: with `cder_credit_cp_detect=1`,
`wrong = !g_flag_c_active`, so detected compromise is credited rather than
counted as error. A **matched CP-1 on/off pair is still needed** before quoting
a number (BC3 CP-1-off gave `CDER=0.5915`, but differs in other config).

**Blocking gap:** on-chain SC-Trust decay **NOT demonstrated** (§3).

### Item 2 — DQ-A1-NEW1 (θ_conf head 0 → 0.40) · **DONE, NEGATIVE**
Matched same-binary baseline vs test, 30s/ρ=0.60/seed 1:

| | θ_conf 0.80 | θ_conf 0.40 |
|---|---|---|
| routed to head 0 | 132 | 157 |
| …of which **a1** | **132** | **132** |
| …of which **honest** | **0** | **25** |
| head-0 precision | **100%** | **84.1%** |
| a1 recall / FPR / MCC | 0.7273 / 0.0139 / 0.4529 | identical |

**Zero additional a1 beacons gained; all 25 newly admitted are honest traffic
(3.47% of honest > sir's 2% reject bar).** **Recommendation: do NOT deploy.**
JSON key is **1-indexed** (`k = attack−1`) → head 0 is `"attack": 1`.
File: `analytics/ml/models/urban_combined/fusion_weights.json` (restored to
shipped state; backup in scratchpad).

### Item 3 — 300s FPR · **FAILS REQUIREMENT**
### Item 4 — D1/D4/D6 ordering at 300s · **PASSES**

Final, 300s / ρ_a=0.40 / seed 1 (from `full_anom` vs `gt_pois`):

| Arm | FPR | Recall | **MCC** |
|---|---|---|---|
| D1 | 0.1390 | 0.7204 | 0.4802 |
| D4 | 0.2047 | 0.7744 | 0.4855 |
| D6 | **0.2077** | 0.7821 | **0.4918** |

- **Ordering D6 > D4 > D1 HOLDS** ✅
- **FPR 0.2077 vs 0.05 requirement — MISSED by ~4×** ❌

**FPR is strongly time-dependent** (D6: 0.0506 @ t=111 → 0.1968 @ t=250 → 0.2077
final). The `:3882` RSU-side state-contamination fix *reduced* but did **not
eliminate** the growth. The previously reported `FPR=0.0432` was measured at
**100s and does not hold at 300s**. This is now the single largest obstacle to
sir's requirements and the residual contamination path should be hunted next.

### Item 5 — GAT retrain · **DONE (not deployed)**
Retrained model degrades a1 routing 83.2% → 48.2% and routes 6.913% of honest
traffic to head 2. Remains undeployed, per sir.

### CP-3 · **PENDING (decision made, not implemented)**
Sir chose option (a): add an RSU-view / controller-view column to
`beacon_log.csv`, document in methodology, do **not** move poisoning before
`ipfs_push`. Implementation plan: add `vantage` to `kBeaconHeader`
([10_metrics_csv.h:184](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L184)) and a
defaulted parameter to `log_beacon_to_csv` ([:160](scratch/mptd_pqs_sdvn/10_metrics_csv.h#L160));
RSU-side call sites pass `"rsu"`. Call sites: [08:3112](scratch/mptd_pqs_sdvn/08_detection_engine.h#L3112) (controller view), [08:3843](scratch/mptd_pqs_sdvn/08_detection_engine.h#L3843) (ghost/RSU view).

---

## 7. Corrections log — claims made then DISPROVED

Keep these; they prevent repeating dead ends.

1. **"MP-S2 dead-code bug is the FPR root cause"** — fix produced bit-identical
   results. The guard protects MP-S4, not MP-S2.
2. **"No controller-trust mechanism exists"** — WRONG. Fully implemented in
   `chaincode/chaincode/smartcontract.go` (`SCControllerSubmitEvidence` :1116,
   `excludeAndReassignController` :1439, `updateControllerTrust` :2461) and wired
   in C++.
3. **"ablation_mode=A1 is why on-chain evidence never flowed"** — WRONG.
   `routing_test=true` was the cause.
4. **"Ghost-ID CSUBM rejections block CFLAG"** — WRONG. Guard removed all 466
   rejections; `CFLAG` still 0 and metrics bit-identical.
5. **"3830 CSUBM reached the chain"** — WRONG. Those gateway-log lines were dated
   **2026/08/01**. The log is append-only; **always filter by date**.
6. **"0 SUBM records on chain"** — my query bug: used epoch `"0"` instead of
   `"E<sec>"`. 2125 entries had in fact committed.
7. **"BC2 registered 0 vehicles"** — WRONG, read mid-run. It finished 194/200
   vehicles + 4/4 controllers; the `pool0` bug cost exactly 6 vehicles.
8. **"D6 FPR 0.0506 is marginal"** — interim value at 37% of the run. Final is
   0.2077, a clear miss.

---

## 8. Immediate next steps (priority order)

1. **Find why `CPDetectCheck` computes `MeanConflict = 0`.** Prime suspect: the
   RSU (`ts`) and controller (`rw.timestamp[i]`) may derive **different epoch
   keys**, so `SUBM_`/`CSUBM_` never share a `(vid, epoch)` and conflict is
   structurally 0. Verify by dumping both epoch strings for one vehicle.
2. **Hunt the residual FPR growth** (0.05 → 0.21 over 300s). Compute FPR in time
   windows and per attack type to localise the contamination path.
3. Matched CP-1 on/off pair for a clean CDER delta.
4. Implement CP-3 vantage column.
5. Add a post-registration assertion that queries the chain and prints
   expected-vs-actual per role (would have caught 194/200 immediately).
6. Fix `readFirstFile` to select the keystore key matching the signcert.

## 9. REVIEW THREAD — sir's instructions and our replies

### 9.1 Prior rounds (present on disk in repo root)

Read these for the full history; do not re-derive their conclusions.

> **WARNING (2026-08-05):** these files are **UNTRACKED in git** (`git status`
> shows them as `??`), as is this handoff. They exist on disk only. They are not
> protected by version control — do not `git clean`, and back them up before any
> branch switch or checkout.

| Doc | Covers |
|---|---|
| `RESPONSE_TO_REVIEW_2026-08-03.md` | round 1 |
| `RESPONSE_TO_REVIEW_ROUND2/3/4_2026-08-03.md` | rounds 2–4 |
| `RESPONSE_TO_REVIEW_ROUND5/6_2026-08-04.md` | rounds 5–6 |
| `RESPONSE_TO_REVIEW_ROUND7_CRITICAL3_2026-08-04.md` | round 7 (critical 3) |
| `RESPONSE_DQ_NEW1-3_2026-08-04.md` | DQ-NEW1..3 |
| `RESPONSE_STEPS1-3_2026-08-04.md` | Steps 1–3 (Fixes A/B/C) |
| `RESPONSE_WHY_D6_BELOW_D4_2026-08-04.md` | D6<D4 root cause (λ_ae feasibility) |
| `RESPONSE_MCC_IMPROVEMENT_2026-08-05.md` | MCC 0.4225→0.5121 via `eq:gat_det_flag` |
| `RESPONSE_ACTIONS1-2_2026-08-05.md` | Actions 1 & 2 |
| `RESPONSE_13_DIAGNOSTICS_2026-08-05.md` | DQ-FPR1-3, DQ-A1-1/2, DQ-MCC1, DQ-VAR1-7 |
| `RESPONSE_STEPS1-4_2026-08-05.md` | Steps 1–4 |
| `MPTD_DIAGNOSTIC_REPORT_2026-08-01/02.md` | diagnostics |

Earlier handovers: `HANDOVER.md`, `HANDOVER_2026-07-22.md`, `AB3_HANDOFF.md`,
`AB4_HANDOFF.md`, `TODO_TTD_FIX.md`, `EVALUATION_GUIDE.md`, `HOW_TO_RUN.md`.

### 9.2 Sir's LATEST letter — verbatim (NOT in any other file)

> Good progress. The RSU-side state contamination fix is the most important
> result of this round — FPR dropping from 0.2272 to 0.0432 is real and correctly
> traced. However five items remain unresolved before final experiments. Read
> everything carefully.
>
> **Decisions on open questions**
>
> **Step 3 — Use Option 1. Align the paper to the code.**
> The TP-S1 through MP-S4 naming is already unambiguous, maps 1:1 to figures, and
> requires no code risk. The silent-failure risk from swapping fitted weight
> arrays is real and exactly the class of bug this engagement has spent weeks
> fixing. Update the paper's variant table to use
> TP-S1/TP-S2/TP-S3/MP-S1/MP-S2/MP-S3/MP-S4 as canonical names with the mapping
> table from your recommendation included as a table in the paper. Do not touch
> any code.
>
> **CP-3 — Use option (a). Document the vantage point difference, do not change
> the threat model.**
> The two-vantage-point architecture is correct and reflects the real threat
> model. Add a column to beacon_log.csv marking whether each row is RSU-view or
> controller-view, and document this in the paper's methodology. Do not move the
> poisoning before ipfs_push.
>
> **Five outstanding items — complete in this order**
>
> **Item 1 — Complete CP-1 and CP-2 immediately**
> CP-DETECT fires 93,079 times and its verdict is discarded. Wire g_flag_c_active
> into CDER computation and into SC-Trust controller trust decay. After wiring,
> run a dedicated a5/a7 test (ρ_a=0.40, 100s, only a5 and a7 active) and report:
> CDER before and after controller compromise onset, time-to-first-CP-DETECT-flag,
> and whether SC-Trust controller trust score decays after repeated CP-DETECT
> firings. This is required before the paper can claim controller-compromise
> detection.
>
> **Item 2 — Run DQ-A1-NEW1**
> Lower θ_conf for head 0 (a1 weight set) only to 0.40 and run D6 at 30s/ρ_a=0.60.
> Report: a1 routing fraction to own weight set, a1 recall, honest FPR, overall
> MCC. The students identified this as the correct lever — test it and report the
> numbers. Do not deploy without measured evidence.
>
> **Item 3 — Run 300s/ρ_a=0.40 with RSU-side fix applied**
> The FPR fix was only measured at 100s. Run the full 300s condition and report
> MCC, FPR, per-type recall. The 0.05 FPR requirement must be confirmed at 300s
> before it can be claimed.
>
> **Item 4 — Run D1/D4/D6 at 300s/ρ_a=0.40 with all fixes**
> The cumulative ordering D6 > D4 > D1 is only verified at 30s/ρ_a=0.60. Run all
> three arms at 300s and report MCC for each. This is required to confirm the
> ordering holds at the paper's primary evaluation condition.
>
> **Item 5 — GAT retrain decision**
> Do not deploy the Step 4 retrained model. It makes a1 routing worse
> (83.2% → 48.2%) and the root cause is a corpus→runtime generalisation gap, not
> a training quality problem. The θ_conf fix in Item 2 is the correct lever. The
> retrained model improves five of seven heads but degrades the most important
> one — defer redeployment until after Item 2 is measured and the net impact is
> understood.
>
> **Send in this order**
>
> First: CP-1 and CP-2 wiring results with a5/a7 CDER measurement.
> Second: DQ-A1-NEW1 result (θ_conf=0.40 for head 0).
> Third: 300s FPR and D1/D4/D6 ordering at 300s.
>
> Do not start final experiments before all three are confirmed.

### 9.3 Our answers to that letter (as of this handoff)

**NOT YET SENT.** Sir's required send order begins with Item 1, which is
incomplete — writing the document now would mean either claiming something
unproven or leading with a gap. Finish the epoch-key check (§8.1) first.

| Item | Answer to give | Evidence |
|---|---|---|
| **1** | Wiring done; a5/a7 measured; **on-chain trust decay NOT achieved** — `CFLAG=0`, `MeanConflict=0`. Must be reported as unresolved, not as working. | §3, §6 |
| **2** | **Negative result.** θ_conf=0.40 gains **0** extra a1 beacons and admits **25 honest** (3.47% > sir's own 2% bar); head-0 precision 100%→84.1%; MCC/FPR/recall unchanged. The students' *diagnosis* (head-0 routing is the bottleneck) is right; this *lever* is not the fix. | §6 |
| **3** | **Requirement NOT met.** FPR 0.2077 at 300s vs 0.05 target. Must also correct the premise of sir's opening line: the `0.0432` he calls "real" was a **100s** measurement and does not survive to 300s. | §6 |
| **4** | **Ordering CONFIRMED at 300s**: 0.4918 > 0.4855 > 0.4802. | §6 |
| **5** | Agreed, retrained model stays undeployed. Note Item 2 did not rescue it, so the a1-routing problem remains open. | §6 |

**Additional disclosures owed to sir (do not omit):**
1. `ablation_mode` defaults to **A1**; printed `MCC`/`FPR` in all prior logs are
   **lightweight** and identical across D1/D4/D6 (0.537/0.094). All D-arm numbers
   in this handoff were recomputed from `full_anom` vs `gt_pois`.
2. "Only a5 and a7 active" **cannot** be done in combined mode (applied to every
   vehicle by `vehicle_id % 2`), so a5/a7 were run as single-attack runs, which
   load `models/urban/` not `models/urban_combined/` — not directly comparable to
   the combined-mode arms.
3. a5 and a7 produce **identical** control-plane numbers by design
   ([:3167](scratch/mptd_pqs_sdvn/08_detection_engine.h#L3167) treats 5 and 7
   identically); they differ only in data-plane poisoning.
4. CP-DETECT count is **3887–5962** in our runs, not 93,079 — configuration
   dependent.

### 9.4 Standing instructions from the user (carry these forward)

- **Never fabricate results.** Verify every claim by live run or direct code/data
  inspection.
- When a claim looks wrong, **find the root cause** rather than assume.
- **Correct earlier claims openly** when disproved (see §7).
- Validate proposed fixes on **held-out/full-duration** data, not just the
  condition that made them look good.
- When the user asks "give me the tail cmd", output **only** the exact command as
  plain text.
- Verify state carefully before destructive actions.
- Report outcomes faithfully — if a test fails, say so with the output.

## 10. Artefacts

Scratchpad (session-local, will not persist):
`/tmp/claude-1001/-home-sdvn-mobility-flooding-Niranga-MPTD-PQS-SDVN/42ad9abc-b50e-48e5-a8a0-f709b9d1f263/scratchpad/`

Key logs: `PF_D1|D4|D6_300s.log` (Items 3/4), `ITEM1_a5|a7_100s_onset50.log`,
`ITEM2_theta0_040_D6_30s_rho60.log` + `ITEM2_BASELINE_theta0_080_...`,
`BC3_30s_keyfix.log` (routing_test=true), `BC5_30s_routingtest_false.log`,
`BC6_30s_ghostfix.log`, `keystore_backup/pool0_STALE_3790754f_sk`.

**Copy anything needed out of the scratchpad before the session ends.**

Uncommitted work on `ml-review-fixes`: the ghost guard at
[08_detection_engine.h:2343](scratch/mptd_pqs_sdvn/08_detection_engine.h#L2343)
(compiled into the 18:13 binary, verified to remove all rejections, but did not
fix `CFLAG` — keep or revert as you prefer).
