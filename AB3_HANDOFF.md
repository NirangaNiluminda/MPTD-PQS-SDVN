# AB3 (GAT ablation, Sybil-via-compromised-RSU) — progress & decision log

**Status (2026-07-27):** root cause diagnosed and fixed at the mechanism level (both the
stale GAT calibration and the fusion-weight cap). `--lambda_gat` needs proper offline
calibration before the real n_coord sweep is run. Do not run the full sweep yet — see
§5 Open items.

---

## 1. What triggered this

Before running the full AB3 sweep (`n_coord ∈ {1,2,5,10,20}`, Sybil attack
(`attack_number=3` = "sir's a4", Sybil-via-compromised-RSU), ρ_a=0.20 fixed, GAT
disabled vs enabled), a t=30s sanity check was run to confirm the Sybil attack is
actually detectable, since detection code had been touched since the last known-good
run and the behaviour was no longer certain.

## 2. Diagnostic runs (all ρ_a=0.20, n_coord=4, `--skip_blockchain=1`, simTime=30s)

| # | Config | MCC_full | TP/FN (Full) | Finding |
|---|--------|----------|--------------|---------|
| A | legacy Sybil (no `--sybil_gat_evasive`), Full | 0.0000 | 0/200 | ghosts never routed to GAT at all in legacy mode; rule threshold (`honest_mp_s1`, forced on for attack 3) needs ~10 IDs/RSU, n_coord=4 never reaches it |
| B | evasive Sybil, Full, stale θ_S=18.394 | 0.0000 | 0/79 | GAT sees the ghosts but is saturated — no discrimination |
| C | evasive, standalone-GAT (`ablation_mode=7`, decides on raw `S>θ_S`), stale θ_S | ~0 (degenerate) | 79/0 but FP=237/237 | GAT flags **everything**, clean or poisoned — pure scale mismatch, not "attack too subtle" |
| D | evasive, standalone-GAT, **locked-stats model swapped in** | **0.3305** | 79/0, FP=159/TN=78 | recalibration alone fixes standalone discrimination |
| E | evasive, **true Φ-fusion**, locked-stats model | 0.0000 | 0/79 | recalibration alone does **not** fix fusion mode |
| F | evasive, Φ-fusion, GAT **disabled** (`ablation_ab=3`), locked-stats model | 0.0000 | 0/79 | **byte-identical to E** — proves GAT's marginal contribution to fused MCC is exactly zero even when perfectly calibrated |
| G | evasive, Φ-fusion, locked-stats model, **`--lambda_gat=0.7`** | **0.3305** | 79/0, FP=159/TN=78, TTD=0.898s | fusion-weight override fixes true Full mode too |

## 3. Two independent root causes (both confirmed, both now addressed)

**(i) Stale GAT calibration.** `analytics/ml/models/urban_a3/gat_model.onnx` was a
symlink to the old shared `models/urban/gat_model.onnx`, with `theta_s.txt=18.394`
calibrated against that model's embedding scale. Live in-sim GAT scores (both clean and
poisoned beacons) were coming out at 30,000–144,000 — several orders of magnitude off
θ_S — so GAT could not discriminate anything (run C: 100% TPR *and* 100% FPR).

A retrained, locked-clean-stats model already existed in the repo
(`analytics/ml/lock_stats_ab3.py` → `analytics/ml/models/urban_a3_trained/`,
`theta_s.txt=7.667544`) but had never been deployed to the path the sim actually loads.

**(ii) Fusion-weight cap (independent of (i), NOT fixed by recalibration alone).**
`Φ = λ_psi·ψ + λ_gat·GAT_norm + λ_ae·AE_norm`, decision = `Φ > Φ_th (0.5)`. Deployed
`λ_gat=0.1857` (global) — and every per-attack k-set caps out at 0.3 — so GAT can
**never** single-handedly cross Φ_th. The evasive Sybil (`--sybil_gat_evasive`) is
*deliberately* engineered so ψ and the LSTM-AE stay ~0 (plausible kinematics, no
temporal signature) — GAT is meant to be the sole discriminator by design (see the
`g_sybil_gat_evasive` comment block in `02_config_globals.h`) — but the deployed λ
weights structurally prevent that. Runs E vs F prove it: GAT on vs GAT off gave
byte-identical fused output.

Per-attack λ-sets (`k1..k7`) can't fix this either: `k_hat` is `-1` on every decision
(the multi-task attack-type head collapses at deploy — same caveat already documented
for the AB4/`lambda_ae` fix), so the global triple is always what's applied regardless
of attack.

## 4. Changes made this session

**(a) Model swap (reversible, currently live):**
```
analytics/ml/models/urban_a3/gat_model.onnx : ../urban/gat_model.onnx  →  ../urban_a3_trained/gat_model.onnx
analytics/ml/models/urban_a3/theta_s.txt    : 18.3940                  →  7.667544
```
Original state is preserved untouched at `analytics/ml/models/urban_a3.bak/` (a
pre-existing backup, dated 2026-07-24 — not created by this session, just confirmed
intact). Revert with:
```bash
cd analytics/ml/models/urban_a3
rm gat_model.onnx && ln -s ../urban/gat_model.onnx gat_model.onnx
echo "18.3940" > theta_s.txt
```

**(b) New `--lambda_gat` CLI override**, mirroring the existing `--lambda_ae` (AB4)
mechanism exactly. Rescales `{psi, ae}` to `1-lambda_gat` keeping their ratio, sets
`lambda_gat` directly. Files touched:
- `scratch/mptd_pqs_sdvn/02_config_globals.h` — new `double g_lambda_gat_cli = -1.0;`
- `scratch/mptd_pqs_sdvn/12_main.h` — new `cmd.AddValue("lambda_gat", ...)`
- `scratch/mptd_pqs_sdvn/06d_ai_inference.h` — rescale block, symmetric to the
  `lambda_ae` block immediately above it

Verified (run G, `--lambda_gat=0.7`): weights rescaled `(0.5071, 0.1857, 0.3071) →
(0.186846, 0.7, 0.113154)` (psi:ae ratio preserved), and **true Φ-fusion mode** now
gives `MCC_full=0.3305`, `TP=79/79` (100% recall), `TTD=0.898s` — up from 0.0000/0/79
FN with the same attack configuration before the flag.

Build: `cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35 && ./waf build
--targets=mptd_pqs_sdvn` — clean, no errors.

## 5. Open items

1. ~~`--lambda_gat` value is not yet calibrated.~~ **RESOLVED 2026-07-27.** Calibrated
   with `lambda_refit_ab3.py` (same held-out protocol as `lambda_refit_ab4.py`: fit on
   seeds 1+2, validate on unseen seed 3, all at n_coord=4, `--sybil_gat_evasive=1`,
   `--ablation_mode=0`).

   - Grid search over λ_gat ∈ [0.20, 0.95] is a **clean step function**: MCC=0.0000 for
     every λ_gat ≤ 0.475, then a flat plateau at **MCC=0.3215 (train) from λ_gat=0.500
     straight through to 0.950** — i.e. once GAT's saturated score can cross Φ_th at
     all, the exact weight above that doesn't matter.
   - **Held-out seed 3** (never touched during fitting): `FULL MCC=0.3124, recall=1.000,
     FPR=0.558` vs `AB3 (GAT-off) MCC=0.0000, recall=0.000` → **dMCC = +0.3124**. GAT's
     contribution is real and reproduces out-of-sample, not an artifact of overfitting
     to 2 seeds.
   - Sanity check passed: at the **deployed** λ_gat=0.1857 (no override), held-out
     dMCC=+0.0000 — exactly reproduces the in-sim runs E/F byte-identical result.
   - **λ_gat=0.500 is the boundary value** (sits exactly on Φ_th=0.5) — risky to deploy
     at the exact edge (floating-point ties). **Recommended value: `--lambda_gat=0.7`**
     — comfortably inside the validated plateau, and it's exactly what run G already
     verified in-sim (`MCC_full=0.3305, TP=79/79, TTD=0.898s`), so the offline
     calibration and the in-sim result agree.
   - **Caveat to flag in any writeup:** FPR=0.558 (held-out) / 0.671 (run G, FP=159 of
     TN+FP=237) is high — at this operating point GAT-boosted fusion catches 100% of
     the evasive Sybil but also flags ~56-67% of clean beacons. That's an acceptable
     (even expected) operating point for an ablation designed to prove GAT's marginal
     contribution exists, but **not** a value to promote to the deployed global
     `fusion_weights.json` — it's scoped to this ablation only via the CLI override,
     never touches the JSON on disk.
   - Script: `lambda_refit_ab3.py` (repo root). Calibration data:
     `<scratchpad>/CAL_a3_nc4_s{1,2,3}.log` (not committed — regenerate via the
     3-seed loop in §6 if needed).

2. **The sweep command must include `--sybil_gat_evasive=1`.** Without it, ghosts are
   never routed to GAT regardless of any weight/calibration fix (see run A). Note
   `--honest_mp_s1` is already auto-forced to true for `attack_number==3`
   (`12_main.h:199`), so it doesn't need to be passed explicitly, but
   `--sybil_gat_evasive=1` does.
3. **Decide whether the model swap in §4(a) becomes permanent** (i.e. re-point the
   symlink for good, or keep `urban_a3_trained/` as a separate opt-in path) versus
   reverting once calibration work is done through a follow-up retrain. Not yet
   decided — currently live as a working state.
4. **Blockchain/Fabric wallet issue is separate and explicitly untouched.** The Fabric
   wallet at `scratch/mptd_pqs_sdvn/fabric_net/generated/gw_shim/users/_mptd_pool/` is
   empty — blockchain-ON runs reject 100% of beacons for every attack type (0/4 RSUs
   register). Per instruction, this was left alone; AB3 runs should continue using
   `--skip_blockchain=1`, which the user confirmed is fine for this ablation.

## 6. Repro command (current state — lambda_gat=0.7 is the calibrated recommendation)

```bash
cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
export LD_LIBRARY_PATH=$(pwd)/build/lib:$LD_LIBRARY_PATH
./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn \
  --routing_algorithm=4 --routing_test=true --attack_number=3 --attack_percentage=20 \
  --n_coord=4 --ablation_mode=0 --sybil_gat_evasive=1 --lambda_gat=0.7 \
  --simTime=30 --per_pid_results=1 --skip_blockchain=1
```

To regenerate the calibration data from scratch (3 seeded runs, ~10min each):
```bash
for s in 1 2 3; do
  ./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn \
    --routing_algorithm=4 --routing_test=true --attack_number=3 --attack_percentage=20 \
    --n_coord=4 --ablation_mode=0 --sybil_gat_evasive=1 --seed=$s \
    --simTime=30 --per_pid_results=1 --skip_blockchain=1 \
    > CAL_a3_nc4_s${s}.log 2>&1
done
python3 /home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN/lambda_refit_ab3.py
```

## 7. Smoke test — n_coord=1 and n_coord=20 (DONE, 2026-07-27)

Both run with `--lambda_gat=0.7 --sybil_gat_evasive=1 --ablation_mode=0
--attack_number=3 --attack_percentage=20 --seed=1 --simTime=30 --skip_blockchain=1`,
same as n_coord=4 (run G) for direct comparison:

| n_coord | MCC_full | TP/FN | FP/TN | FPR | TTD | psi nonzero (rule fired)? |
|---|---|---|---|---|---|---|
| 1  (`SMOKE_nc1.log`)  | 0.4454 | 200/0 | 158/87 | 0.645 | 0.899s | 0/445 — never |
| 4  (run G)            | 0.3305 |  79/0 | 159/78 | 0.671 | 0.898s | 0/79 — never |
| 20 (`SMOKE_nc20.log`) | 0.3221 |  23/0 |  56/31 | 0.644 | 0.894s | 0/110 — never |

**Finding 1 — the RSU-collision confound (§5 item 3 worry) did NOT materialize.**
`psi=0.000` on every single logged fusion decision at n_coord=20, identical to
n_coord=1. Rules never fire; GAT stays the sole discriminator across the whole tested
range even on the 4-RSU toy topology. This specific risk is retired.

**Finding 2 — MCC_full is NOT monotonic in n_coord on this topology**, and probably
can't be made to look monotonic here. It peaks at n_coord=1 (0.445) and is roughly flat
from 4→20 (0.33→0.32); recall is 100% and FPR holds steady (~0.64-0.67) throughout. What
actually shrinks with n_coord is the raw number of completed fusion decisions (445 → 79
→ 110 total scored across the 30s window) — more ghost UDP traffic at higher n_coord
congests the shared CSMA channel, so fewer beacons finish their IPFS/fusion window at
all before the sim ends. That's a **network-congestion artifact of the tiny
16-vehicle/4-RSU dev topology**, not the "coordination stresses GAT's spatial-relational
detector" effect the paper's n_coord variable is meant to isolate — at this scale there
isn't enough spatial room for n_coord to matter the intended way.

## 8. Real-topology validation (2026-07-27) — CRITICAL: toy-topology fix does NOT transfer

Per §7's own recommendation, ran the AB4-style validation-first protocol on the paper's
real topology (`--mobility_source=1 --mobility_scenario=0 --maxspeed=60 --N_Vehicles=200
--N_RSUs=64`, `--attack_number=3 --attack_percentage=20 --n_coord=4 --ablation_mode=0
--sybil_gat_evasive=1 --lambda_gat=0.7 --simTime=300 --seed=1 --skip_blockchain=true`)
before committing to the 10-run sweep. **Result: catastrophic failure, do not proceed to
the sweep with the current calibration.**

| | LW/rules-only | Full/Fusion (GAT on, toy-calibrated) |
|---|---|---|
| MCC | -0.0351 | **-0.209** |
| TP/FP/TN/FN | 110/3878/64655/4510 | 2662/**67008**/866/475 |
| FPR | 0.057 | **0.987** |
| TTD | — | 3.42s |

Attack itself is healthy (6.3% poison rate, non-degenerate, poisoning starts at t=7s,
13/64 RSUs compromised matching ρ_a=0.20 — no sign of AB4's "late trace entry" problem).
**The detection side breaks**: Full/Fusion flags 98.7% of everything.

**Root-cause mining (from the raw `S=` column already logged in this run, no rerun
needed):**
```
clean   n=67874  p50=113,080  p95=143,916
poison  n=3,137   p50=144,246  p10=2.94  min=2.94
```
Clean and poison raw GAT scores are **statistically indistinguishable at the bulk/median
level** (both ~110K-144K) — this is not a threshold-calibration problem; no single θ_S
can separate these. Two compounding causes:

1. **Graph-size embedding blowup.** GAT embedding norms scale with the graph's node
   count. The locked-stats mu/sigma baseline (`urban_a3_trained/`) was built from
   toy-scale (16-vehicle) graphs; 200-vehicle RSU-window graphs produce systematically
   much larger embedding magnitudes, swamping any relational-anomaly signal in a
   near-uniform scale shift.
2. **Ground-truth/detection-unit mismatch.** At attack 3, the intercepted *real*
   vehicle's beacon is labeled `poisoned=true` for provenance, but its own kinematics
   are never altered — it genuinely looks clean. The actual anomaly is the *separately
   injected ghost* beacon (different vid). The ~10% tail scoring S≈2.94 (near-zero — the
   opposite direction from "anomalous") is almost certainly those ghosts, scored in
   their own small relayed graph. But the confusion matrix's ground truth is keyed to
   the real vehicle's node, not the ghost's — so even a working ghost-anomaly signal
   doesn't necessarily flip the metric being measured.

**Confirmation — does removing GAT fix it?** Yes, cleanly. Same topology/attack, 30s
(shorter — just for a fast confirmatory read), `--ablation_ab=3` (GAT fully out of
fusion, no `--lambda_gat` needed since the term is renormalized away):

| | Full (GAT on) | GAT off (`ablation_ab=3`) |
|---|---|---|
| MCC_full | -0.209325 | **+0.0717** |
| FPR_full | 0.987 | **0.0041** |
| TP/FP/TN/FN | 2662/67008/866/475 | 10/10/2450/500 |
| TTD | 3.42s | 16.0s |

GAT (under the toy-scale calibration) isn't merely failing to contribute at real scale —
it's **actively destructive**: it floods fusion with false positives, taking MCC from
mildly-positive-but-weak (rules alone, 2% recall, TTD=16s — not great either, but not
harmful) to solidly negative. Logs: `AB3_REAL_VALIDATE_nc4.log` (Full, 300s),
`AB3_REAL_GAToff_30s.log` (GAT-off, 30s) in the scratchpad dir (not committed).

### ρ_a=0.60 comparison (2026-07-27) — does more attacker density help?

Same real topology, 30s, `--attack_number=3 --n_coord=4 --seed=1`, but
`--attack_percentage=60` instead of 20:

| | ρ_a=0.20 (baseline) | ρ_a=0.60 |
|---|---|---|
| Full (GAT on) MCC_full | -0.209 (300s run) | **+0.170** |
| Full FPR_full | 0.987 | 0.710 |
| Full TP/FP/TN/FN | 2662/67008/866/475 | 1139/907/370/200 |
| GAT-off MCC_full | +0.0717 (30s) | **-0.0021** |
| GAT-off FPR_full | 0.0041 | 0.0078 |
| GAT-off TP/FP/TN/FN | 10/10/2450/500 | 10/10/1267/1329 |

**Full mode's MCC_full does improve at higher ρ_a — but this is very likely a base-rate
artifact, not evidence the calibration issue is fixed.** GAT is still flagging most
things almost indiscriminately (FPR=0.71, still high, just less catastrophic than 0.987).
At ρ_a=0.60 a much larger share of the vehicle population is genuinely poisoned, so the
same near-constant-positive behavior produces more *correct* positives purely because
there's more to be right about — not because GAT started discriminating clean from
poisoned any better. The underlying diagnosis in §8 (clean/poison raw S bulk-
indistinguishable) is unaffected by ρ_a; this doesn't change the recommended next steps.

**GAT-off got worse, and in an odd way: TP is exactly 10 at both ρ_a=0.20 and ρ_a=0.60**
— identical absolute count despite poison volume growing ~2.6x (630→1645). That's not
"rules catch a stable fraction," it's rules catching a near-*fixed number* of events
regardless of how much attack is present, which suggests whatever triggers rule-based
`full_anom=YES` here is capped by something unrelated to poison rate (e.g. a fixed
number of RSU-window density-overflow events) rather than scaling with the actual
attack. Worth a closer look before relying on GAT-off as a stable baseline at real scale.

**Verdict for the user's question:** no, raising ρ_a does not fix the real-topology
detection problem — it changes the operating point (base rate) in a way that flatters
Full mode's summary MCC while FPR stays high (71%), and it doesn't move the needle on
GAT-off's underlying (apparently rate-insensitive) recall. The §8 root cause and
recommended next steps stand regardless of ρ_a.

### CORRECTED root cause (2026-07-27, supersedes the graph-size theory above)

The "graph-size blowup" theory above turned out to be wrong (N is a **fixed 10-beacon
window**, `WINDOW_L_BEACONS=10` in `04_state_globals.h:294` — never varies with topology
size; confirmed 7297/7297 calls at N=10 in the real-topology run and 54/54 at N=10 in the
toy-topology calibration run). The actual cause is much simpler and needs **no retrain**:

**`analytics/ml/models/urban/scaler.json` — shared by GAT and the LSTM-AE — was
overwritten on 2026-07-26 07:03 by an unrelated AB4/LSTM-AE fix**, repurposing it for
dead-reckoning *residual* features (`res_x, res_y, dspeed, dheading, accel`; tiny
near-zero stats: mean≈0.04, scale≈0.32). GAT's runtime code (`06d_ai_inference.h:527-533`)
still z-scores **absolute** `pos_x, pos_y, speed, heading, accel` through this now-
incompatible scaler. `models/urban_a3/scaler.json` is a **symlink** to `../urban/scaler.json`
(made 2026-07-24, before the break) so it silently inherited the corruption.

Timestamps confirm the sequence: `urban_a3_trained/gat_model.pt` was trained
**2026-07-25 13:19** (a day before the scaler broke) — using the then-correct
absolute-position scaler. The backup `urban/scaler.json.bak_pre_resid` (saved
2026-07-26 07:01, 2 min before the overwrite) has the original absolute-position stats:
mean=[1755.2, 1390.6, 6.13, 0.51, -0.05], scale=[545.3, 494.1, 6.50, 1.70, 7.34] — which
closely matches this real topology's actual position range (measured from
`beacon_log.csv`: pos_x mean=1704, pos_y mean=1380).

**Direct proof** — z-scoring the same real `beacon_log.csv` data with each scaler:
```
WRONG (currently deployed, residual-fitted):  |z| mean=1712.9   max=7989.7
CORRECT (bak_pre_resid, absolute-fitted):      |z| mean=0.483   max=23.3
```
Feeding absolute positions through a scaler fit on tiny residual deltas produces z-scores
in the thousands, uniformly, regardless of attack status — this alone fully explains the
observed clean/poison score collapse in §8. **The GAT weights themselves are very likely
fine** (trained the day before the corruption); this is a scaler-wiring bug, not a model
or scale-transfer problem.

**Broader-impact flag (not this task's scope, but worth surfacing):** any OTHER Full-mode
GAT run on the shared `urban` scenario since 2026-07-26 07:03 is equally exposed.
`analytics/datasets/urban/a1_p55_m0` postdates the break and looks like it could be
another session's Full-mode (`m0`) result on this same scenario — flag it to whoever owns
that work.

### Recommended next steps — fix the scaler wiring, no retrain needed

1. **Give GAT its own scaler, separate from the LSTM-AE's.** They now have genuinely
   different, incompatible feature representations (absolute position vs. residual
   dead-reckoning delta) — sharing one `scaler.json` between them is the bug. Concretely:
   add a second scaler path to `AiEngine::init()` (currently one shared `scaler_path` for
   both — see `12_main.h`'s `g_ai_engine.init(gat_path, lstm_ae_path, scaler_path, ...)`),
   or at minimum stop symlinking `urban_a3/scaler.json` to the shared file and instead
   copy `urban/scaler.json.bak_pre_resid`'s absolute-position stats into a GAT-dedicated
   file that `06d_ai_inference.h`'s `score_gat()` reads.
2. **Cheap validation first (seconds, not hours):** re-run the offline z-score check
   above but through the actual trained GAT ONNX (`urban_a3_trained/gat_model.onnx` or
   the locked-stats version) on `beacon_log.csv` from the completed 300s run, confirm
   clean vs. poison raw S now separates sensibly with the corrected scaler — no ns-3
   re-run required for this step.
3. **Only then** re-run the real 300s in-sim validation (same command as §8) to confirm
   MCC_full recovers without the false-positive flood, before returning to §7's n_coord
   sweep question.
4. The ground-truth/detection-unit caveat from the superseded theory (real vehicle's own
   node looks clean; the ghost node is the actual anomaly) may still matter for recall —
   worth checking after the scaler fix, but it's no longer the primary suspect for the
   MCC collapse.

## 9. Superseded — do not use for the real sweep

§§1-7 (toy 16-vehicle/4-RSU topology work: model swap, `--lambda_gat` calibration,
n_coord=1/4/20 smoke tests) are retained for the mechanism/plumbing record — the
`--lambda_gat` CLI flag itself is correct and reusable — but **the calibrated value
(0.7) and the swapped model do not transfer to the real topology** per §8. Do not launch
the n_coord sweep with these values on the real 200v/64RSU topology.

That move to the real topology has now happened (§8) — it did NOT show a clean n_coord
trend question yet, because detection itself is broken there first. See §8's numbered
next steps before returning to the n_coord sweep question at all.
