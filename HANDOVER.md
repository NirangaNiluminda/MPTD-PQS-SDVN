# SENTINEL/AEGIS — Session Handover (2026-07-29 ~07:40)

Handover to a fresh Claude Code session on the **same machine** (previous account hit its limit).
Read this fully, then read the memory index at
`~/.claude/projects/-home-sdvn-mobility-flooding-ns-allinone-3-35/memory/MEMORY.md` — it has the deeper per-topic history.

Previous handover (2026-07-22, now stale) archived as `HANDOVER_2026-07-22.md`.

- Project root / git repo: `/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN`
  (symlinked into the ns-3 tree as `scratch/mptd_pqs_sdvn`)
- ns-3 tree: `/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35`
- Experiment outputs: `/home/sdvn_mobility_flooding/Desktop/SENTINEL_experiments/`

---

## 0. TL;DR — state right now

| Thing | State |
|---|---|
| **AB9 sweep** | **RUNNING**, 13/15 done. Do NOT restart. |
| **AB9 retry watcher** | **ARMED** (PID 904249), waiting for `AB9_SWEEP_DONE`. |
| **AB11** | **DONE** — bug found + fixed + verified + figure made. |
| **ns-3 binary** | **STALE** — does not contain the AB11 fix. Rebuild after AB9. |
| **Fabric / Explorer / IPFS** | All UP and healthy. |
| AB1, AB2 (300 s) | Complete (30 runs each). |
| AB8 | Deliberately NOT swept — see memory. |

**The one action that must not be forgotten:** rebuild the ns-3 binary once AB9 +
retries finish (§3).

---

## 1. AB9 — RUNNING, do not touch

Ablation "multi-controller architecture removed". X = controller compromise onset
`t_comp/T_sim ∈ {0.00, 0.25, 0.50, 0.75, 1.00}`, combined attack ρ_a=0.40, 3 seeds, 30 s, on-chain.

- Runner: `Desktop/SENTINEL_experiments/AB9_sweep/run_ab9_sweep.sh`
- Monitor:
  ```bash
  tail -f ~/Desktop/SENTINEL_experiments/AB9_sweep/progress.txt
  column -s, -t ~/Desktop/SENTINEL_experiments/AB9_sweep/manifest.csv
  ps -C mptd_pqs_sdvn -o pid,etime,cmd          # authoritative process list
  ```
- ~50–70 min per run. On-chain runs are **SERIAL by necessity** — concurrent sims
  contend for Fabric endorsement and corrupt each other's registration.

### The validation gate — read this before trusting any row

`manifest.csv` has a `gate_ok` column. `OK` means RSU 64/64, VEH ≥195/200, CTRL 4/4.
Anything else is `BAD(rsu=..,veh=..,ctrl=..)` and means **partial Fabric registration,
which silently corrupts every metric in that run**. Never plot a BAD row.

3 rows failed the gate (all `rsu=0,veh=0,ctrl=0` — total registration failure):
`onset=0.75/seed1`, `onset=0.25/seed2`, `onset=1.00/seed2`.

### The retry watcher (already armed — don't launch a second one)

`AB9_sweep/retry_ab9_bad.sh`, **PID 904249**, is sleeping until `AB9_SWEEP_DONE`
appears in the manifest, then re-runs every `(onset,seed)` pair that has no `gate_ok=OK`
row, up to 2 attempts. Retry logs get a `.rN` suffix; new rows are **appended**.

> **The figure script must take the LAST `gate_ok=OK` row per (onset,seed) pair** —
> not the first, and not a plain average, or the BAD rows will poison the means.

Check it's alive with `pgrep -af retry_ab9_bad`. It ends by writing `AB9_RETRY_DONE`.

### Expected result

The 12 good rows so far show the intended monotone decay:

| onset | CDER (s1 / s2 / s3) |
|---|---|
| 0.00 | 0.607 / 0.671 / 0.621 |
| 0.25 | 0.598 / — / 0.613 |
| 0.50 | 0.464 / 0.548 / — |
| 0.75 | — / 0.442 / — |
| 1.00 | 0.213 / — / — |

`MCC_full` is near-flat (~0.83–0.92) **by design** — vehicle/RSU attacks a1–a4/a6 run
regardless of controller state, so CDER carries the signal. Don't treat flat MCC as a bug.

---

## 2. AB11 — COMPLETE (finished this session)

Spec: "LKH replaced with unicast key distribution", X = |V_j| ∈ {40, 80, 120, 160, 200}.

### Run it as a standalone micro-benchmark, NOT a full NS-3 sim

A t=30 NS-3 run **structurally cannot** produce AB11. Both blockers measured:
- Max zone population is **< 16** — zero `Zone grown` events across all 64 zones in a
  real 200-vehicle run (200 veh ÷ 64 RSUs ≈ 3/zone). Spec needs 40–200 in ONE zone.
- **`BWO_scale = 0`** on-chain — every `SCRevokeVote` returns `endorse error: Aborted`,
  so `lkh_rekey_on_revoke()` is never reached. (Chain-OFF runs DO fire: AB10 logs show 1–63.)

### The bug that was found and fixed

Both branches of `lkh_rekey_on_revoke()` pushed **every survivor** into
`g_lkh_affected_members`, and `send_lkh_rekey_to_vehicles()` unicasts one RekeyTag per
entry (incrementing `BWO_scale`). So the LKH arm transmitted |V_j| packets — identical to
the unicast ablation arm. The spec's own acceptance test ("measured LKH should track
log₂|V_j|") **failed**; the log₂ number existed only as a return value and a `printf`.

Fix, in `00_lkh_keys.h` + `08_detection_engine.h`:
- New `LkhNodeRekeyMsg` / `g_lkh_node_rekey_msgs`; `lkh_zone_rekey_path_ex(z, slot, t,
  emit_msgs)` emits ONE message per rotated path node, carrying K'_v wrapped under both
  child keys (`lkh_wrap_key` = XOR with a KDF keystream bound to node index + time).
- `lkh_zone_rekey_path()` kept as a non-emitting wrapper, so benign handoff is unchanged.
- LKH branch no longer rotates survivors' leaf keys (correct LKH semantics), so
  `g_lkh_affected_members` stays empty and nothing is unicast.
- 08 broadcasts the node messages; the bottom-level message deliberately omits `ct_path` —
  that IS the forward-secrecy cut excluding the revoked vehicle.

### Measured after the fix

| \|V_j\| | LKH | unicast | ratio | LKH airtime | unicast airtime |
|---|---|---|---|---|---|
| 40 | 6 | 39 | 6.5× | 1.58 ms | 10.27 ms |
| 80 | 7 | 79 | 11.3× | 1.84 ms | 20.80 ms |
| 120 | 7 | 119 | 17.0× | 1.84 ms | 31.34 ms |
| 160 | 8 | 159 | 19.9× | 2.11 ms | 41.87 ms |
| 200 | 8 | 199 | 24.9× | 2.11 ms | 52.40 ms |

LKH column == `ceil(log₂|V_j|)` **exactly** at every point; unicast == |V_j| − 1.

### Files

`Desktop/SENTINEL_experiments/AB11_bench/`
- `ab11_lkh_bench.cc` — links the PRODUCTION `00_lkh_keys.h` via a 4-symbol shim
  (`ns3::Ipv4Address`, `MAX_RSUS`, `use_lkh_tree`, `g_first_vehicle_node_id`). No ns-3,
  no Fabric. Build:
  `g++ -O2 -std=c++17 -I<scratch/mptd_pqs_sdvn> -o ab11_lkh_bench ab11_lkh_bench.cc` (~2 s).
- `ab11_results.csv`, `ab11_figure.py`, `fig_AB11_lkh_vs_unicast.png/.pdf`
- `verify_lkh_delivery()` replays the receiver side (sibling + path subtrees recover K',
  revoked vehicle cannot, survivor leaf keys untouched). 0 failures in 200 runs.
  **Negative controls confirmed 100/100 detection** for a corrupted ciphertext and for a
  forged forward-secrecy break — the check is not vacuous.

### Caption caveat

Panel (b) airtime is an **analytical projection** from the measured message counts
(6 Mbps, 72 B headers, 40 µs preamble, 58 µs DIFS) — *not* an NS-3 channel measurement.
Say so in the paper caption.

---

## 3. ⚠️ PENDING: rebuild the ns-3 binary

The AB11 source fix is in, but the **binary is stale** (built 2026-07-28 19:41; the fix
landed 07-29). I deliberately did not rebuild: the AB9 runner launches `$BIN` fresh per
run, so rebuilding mid-sweep would split the sweep across two different binaries.

**Also pending in the same rebuild (added 2026-07-29 ~08:20):** AB7 ring-size sweep
support. `--ab7_ring_n=N` now overrides the TRS/FHE signing-ring size n (was hardcoded
`4` at both `init_trs_backend`/`init_threshold_fhe_backend` call sites in
`11_blockchain_setup.h`). Threshold t is held FIXED at 3 for every n (sir's call:
matches the value already hardcoded at n=4, the 2f+1 BFT-quorum convention used
elsewhere — NOT the theoretical t_sign=f+1=2 that only ever lived in AB6's PARR
forgery-probability model). `n=3` is rejected at CLI-parse time (BFT bound n≥3f+1=4 at
f=1). Default (`--ab7_ring_n` unset) is byte-identical to every prior run. **Not yet
build-verified** — needs the same post-AB9 `./waf build` this section already calls for.
See [[project-ab7-ring-size-sweep]] memory for the full ring/threshold discussion.

Source is already syntax-checked clean. **After AB9 + retries finish (`AB9_RETRY_DONE`):**

```bash
cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
./waf build -k --targets=mptd_pqs_sdvn      # -k: scratch/routing.cc is pre-broken, ignore it
```

Blast radius of the AB11 fix: `BWO_scale` changes **only in chain-OFF runs** (AB10 shows
1–63 msgs). BWO is not an AB10 panel, so **no completed sweep's headline metrics move.**
Blast radius of the AB7 change: zero when `--ab7_ring_n` is unset (every existing sweep
uses the hardcoded-4 default path) — new code, additive only.

**Once built, before any AB7 full sweep:** smoke-test at `--simTime=30` across all five
`--ab7_ring_n ∈ {4,6,8,10,12}` points first (per sir's instruction) — confirm
`[CRYPTO/TRS] ready (n=N t=3 ...)` and `[CRYPTO/THFHE] ready (... parties=N+1 t=3 ...)`
print the right n at each point, and that COO_epoch/trs/fhe/dkg and BWO_ratio come back
sane (no −1, no crash) at n=12 before committing to the full 5-point sweep.

---

## 4. Build / run basics + gotchas

- Build: `./waf build -k --targets=mptd_pqs_sdvn` (NOT `./waf --run`). `-k` is required —
  `scratch/routing.cc` is pre-broken and unrelated.
- Run:
  ```bash
  export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:$HOME/.local/lib64"
  export MPTD_CA_IDENTITY=0 MPTD_FABRIC_SOCK_TIMEOUT_SEC=550
  ./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn <flags>
  ```
  `MPTD_CA_IDENTITY=0` uses the User1 fallback and is what unblocked on-chain runs — keep it.
- Always launch long runs with `setsid nohup ... &`. Foreground calls die at the 2-min tool timeout.

**Gotchas that have cost real time:**
- `$!` after `setsid` returns the *wrapper* PID, not the binary. Use
  `ps -C mptd_pqs_sdvn -o pid,cmd | grep <flag>`.
- `pkill -f <pattern>` **self-matches the invoking shell**. Use `pkill -x` /
  `kill $(pgrep -x ...)`. `pkill -f "attack_number=0"` is especially dangerous.
- Sim stdout is **block-buffered** — logs lag reality and truncate at the same `[LKH] RSU`
  spot every run. That is NOT a hang. Verify progress with READ-ONLY ledger queries.
- **Never issue ledger writes while a sim is running** — manual `ResetLedger` probes cause
  `PHANTOM_READ_CONFLICT` against the sim's startup reset. Read-only queries are fine.

---

## 5. Infrastructure — all UP, verified 2026-07-29 07:40

| Component | State |
|---|---|
| Fabric peers | 64/64 up (`peerN.rsu.example.com`) |
| Orderers | 5/5 up |
| Chaincode | `trajectory_ccaas` up (CCAAS container) |
| Gateway daemon | `mptd_fabric_gw` PID 2151565 |
| Explorer | `explorer.mynetwork.com` + `explorerdb` up 25 h, healthy |
| IPFS | `ipfs daemon` PID 3663848 — **API on port 5002** (NOT the default 5001), gateway 8081. Sim confirms 388 windows uploaded per run. |

**`gen_network.sh` fix (do not regress):** `cmd_all()` was missing a `cmd_down` call, which
left 60/64 peers on stale June-17 volumes with an old CA — this caused a whole night of
intermittent registration failures. `cmd_all` now runs `cmd_down` first, and `cmd_down`
excludes `explorer*|*explorerdb*|*ccaas*` from the network-wide force-remove (Explorer was
deleted 3× by that sweep).

**Chaincode changes require an image rebuild + CCAAS container restart** with
`CHAINCODE_ID` / `CORE_CHAINCODE_ID_NAME` = the package ID from the deploy log
(e.g. `trajectory_1.0:a2c5d549...`).

---

## 6. Git state — 9 UNCOMMITTED files, do NOT `git checkout`

HEAD = `70269e2` "blockhain bug fixes". Modified and unstaged:

```
chaincode/chaincode/smartcontract.go
scratch/mptd_pqs_sdvn/00_lkh_keys.h          ← AB11 fix
scratch/mptd_pqs_sdvn/02_config_globals.h
scratch/mptd_pqs_sdvn/04_state_globals.h
scratch/mptd_pqs_sdvn/06a_attack_models.h
scratch/mptd_pqs_sdvn/06c_blockchain_api.h
scratch/mptd_pqs_sdvn/08_detection_engine.h  ← AB11 fix
scratch/mptd_pqs_sdvn/11_blockchain_setup.h
scratch/mptd_pqs_sdvn/12_main.h
```

These hold the AB11 fix, the TCL_reassign 3-bug fix, the AB8/AB9 opt-in knobs, and the
Fabric retry hardening. **Discarding them loses several sessions of work.**

New opt-in CLI flags (all default to preserving prior behaviour, so every earlier sweep
stays bit-identical): `--rsu_malicious_fraction`, `--lifecycle_gates_fusion`,
`--demoted_psi_weight`, `--rsu_trust_quorum`, `--ctrl_compromise_onset`.

---

## 7. Open decisions for sir

1. **AB8** — 3 of 4 spec panels have zero ablation signal (fusion never reads RSU trust
   state) and ~29 % of demotions punish HONEST RSUs at 30 s. Options: run at 300 s
   (~10× cost, physically correct), report at 30 s with the geometry limitation stated,
   or reduce scope. See `project_ab8_quorum_horizon_limit`.
2. **`TCL_reassign = -1`** is now a *characterised design property*, not a bug — Eq(ctrl_trust)
   divides conflict by ALL ~16 assigned RSUs while ~1 observes, needing c > 0.70 against a
   measured c ≈ 0.0013 (540× gap). Does this warrant a design change?
3. **T_w accumulation fix** in the chaincode (`epochWithinWindow`) — make it default-on?
   It currently applies to all on-chain runs with lifecycle enabled.
4. **ρ_a semantics** (~87 % effective poison rate in combined mode) — carried over unresolved
   from the 2026-07-22 handover.

---

## 8. Standing preferences (from sir's feedback)

- **No explanatory notes or text boxes inside plots.** Explanation belongs in the LaTeX
  caption. Avoid redundant plotted series.
- Verify rather than infer — sir asks for rigorous proof, not plausible reasoning. Two
  theories were wrong this week until re-checked against the design doc / measurement.
- Baselines must be ONE global model with held-out vehicles, never per-(attack × pct) models.

---

## 9. Memory files

`~/.claude/projects/-home-sdvn-mobility-flooding-ns-allinone-3-35/memory/MEMORY.md` is the
index (loaded automatically each session). Most relevant to current work:

- `project_ab11_lkh_message_accounting.md` ← this session
- `project_ab8_quorum_horizon_limit.md`
- `project_tcl_reassign_suppression_fix.md`
- `project_fabric_partial_registration_cascade.md` ← the validation-gate rationale
- `project_ab10_metrics_validity.md`
