# SENTINEL/AEGIS — Session Handover (2026-07-22 ~08:00)

Handover to a fresh Claude Code session on the **same machine**. Read this fully, then check the memory files (see bottom) — they have the deeper history.

Project root: `/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN` (this is the git repo, symlinked into the ns-3 tree as `scratch/mptd_pqs_sdvn`).
ns-3 tree: `/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35`.

---

## 0. TL;DR — what's happening right now

An **AB1 ablation sweep is RUNNING** (detached, survives session end). It's the SENTINEL detection-paper ablation "AB1: rule signatures removed", swept over ρ_a at 300s on the combined attack.
- Sweep loop PID (bash): `pgrep -f ab1_sweep_300s.sh`
- Current sim: `ps -C mptd_pqs_sdvn -o pid,etime,args`
- **3/30 runs done** as of handover. ~2.5 h/run → full sweep ~75 h.
- **Do NOT restart it.** Just monitor. If it dies, see §4 to resume.

---

## 1. Build / run basics

- Build: `cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35 && ./waf build --targets=mptd_pqs_sdvn` (NOT `./waf --run`).
- Run: `LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:$HOME/.local/lib64" ./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn <flags>`
- Current binary built **2026-07-21 21:39** (has all the changes below). git HEAD `c3e3cd1` but **6 .h files are UNCOMMITTED** (see §3) — do not `git checkout` them or you lose the combined-mode + recalibration work.
- Sim runs are slow: ~2.5 h at simTime=300 / 200 vehicles. **Always launch via `setsid nohup ... &` + `run_in_background`**, never foreground (2-min tool timeout kills it).
- **GOTCHA:** `pkill -f "attack_number=0"` self-matches your own shell command AND can kill the real sim. Use `ps -C mptd_pqs_sdvn` for the authoritative process list.

---

## 2. THE BIG CONTEXT — combined-attack mode + GAT recalibration

sir split the work into two papers: **SENTINEL** (detection) + **AEGIS** (mitigation). Current focus = SENTINEL ablation study (AB1–AB5).

### 2a. Combined-attack mode (`--attack_number=0`) — BUILT + VALIDATED
sir's ablation default = "combined attack" = **all 7 attack types active in ONE run** (so TPE from TP attacks + TDEE from MP attacks both come from one run). The sim had no such mode; I built it. 3 planes, per-entity dispatch:
- **Vehicles** a2/a4/a6 — partitioned round-robin (`g_veh_attack[]`, `veh_atk()` in 02_config_globals.h; assigned in declare_attackers 06a).
- **RSUs** a1/a3 — `declare_compromised_rsus` fires for combined, partitions across a1/a3 (`g_rsu_attack[]` in 04_state_globals.h). Poisoning at 08:3220 (a1) / 08:3291 (a3), honest-beacon guard.
- **Controller** a5/a7 — 08:1968 (a7, even veh) / 08:2028 (a5, odd veh), honest-beacon guard; CP-DETECT gates 08:730 / 08:2779.
Validated: all 7 fire, CP-DETECT=843, no crash, all metrics present. **CAVEAT: effective poison rate ~87% at ρ_a=0.40** because each plane runs at pct=40 independently (see §5 open Q1).

### 2b. GAT anti-informative on combined — RESOLVED (this was the hard part)
On the combined attack, the AB1 ablation (rule signatures off) first gave **MCC_full = −0.058 (NEGATIVE)** — the GAT+AE scored CLEAN beacons as more anomalous than POISONED. Root cause = TWO things:
1. **θ_S mis-calibration.** The rule signatures (`sig_mask`) are a GAT INPUT feature (06d GAT_FEATURE_DIM=16 = 5 kin + tau + psi + 9 sig bits). In the combined graph, even clean beacons sit at high GAT-S (in-sim clean≈20, poisoned≈385). θ_S=8.31 (single-attack) saturated the GAT. **Recalibrated θ_S=55.9** (95th %ile of clean IN-SIM S). ⚠️ Calibrate from the **in-sim FUSION-log S values**, NOT an offline ONNX recompute (offline gave wrong-scale S=309).
2. **Architectural coupling (interpretation-b, sir's call).** AB1 used to zero the sig flags → killed `sig_mask` in the GAT input → lobotomized the GAT. FIX: AB1 now **keeps sig_mask/ψ feeding the GAT input**, only removes the rule TIER's OWN detection (LW decision + ψ fusion term `psi_fuse=0` at 08:2448). Edits at 08:1029 + 08:2448.

Result: **AB1 MCC_full −0.058 → +0.224** (positive, below full-mode 0.689) = valid ablation.

**Separate combined calibration** lives in `analytics/ml/models/urban_combined/` (θ_s.txt=55.867, θ_ae.txt=1.3834, fusion_weights.json = balanced 0.51/0.19/0.31; ONNX+scaler symlinked to the untouched `urban/`). Code auto-loads it when `attack_number==0 && scenario urban` (12_main.h ~210, `g_combined_attack`). **The single-attack `models/urban/` is untouched — single-attack runs are unaffected.**

### 2c. Honest finding (claim-level, flag to sir)
A λ re-fit showed the optimal combined fusion is **ψ 0.90 / GAT 0.05 / AE 0.05** → on the combined mix, **ψ (rule signatures) carries ~90% of detection; GAT+AE add little** even recalibrated. I did NOT apply that λ (it collapses AB1) — reverted to balanced 0.51/0.19/0.31. This is a real finding: GAT+AE may be strong on SPECIFIC single attacks (E5) but weak on the combined mix. **Worth flagging to sir before publishing the ablation.**

---

## 3. UNCOMMITTED code changes (do not lose!)

6 files in `scratch/mptd_pqs_sdvn/`, all uncommitted (git HEAD c3e3cd1):
- `02_config_globals.h` — `g_combined_attack`, `g_veh_attack[]`, `veh_atk()`; attack_scenario_name[0]="COMBINED"; `g_verbose_tx`.
- `04_state_globals.h` — `g_rsu_attack[]`.
- `06a_attack_models.h` — combined branch in declare_attack_states + declare_attackers + declare_compromised_rsus.
- `08_detection_engine.h` — RSU a1/a3 + controller a5/a7 combined gates; CP-DETECT gates; **interpretation-b at 08:1029 + 08:2448**.
- `09_vehicle_beacon_tx.h` — `veh_atk()` at injection/EnforceRealism/a4/a6 gates; `g_verbose_tx` gating of [DSRC-TX]/[LL-SEL].
- `12_main.h` — `g_combined_attack=(attack_number==0)`; `--verbose_tx` flag; urban_combined path-select.
**Recommend committing these** (user hasn't asked yet — ask first). Also new tools in repo root: `recalibrate_combined.py`, `refit_lambda_combined.py`.

---

## 4. Monitor / resume the AB1 sweep

- Manifest: `~/Desktop/SENTINEL_experiments/AB1_sweep_300s/manifest.csv` (mode, rho_a, seed, wall_s, completed, exc, veh, rows, **eff_poison_pct**, MCC_full, PBPO, TTD).
- Progress log: `/tmp/claude-1001/-home-sdvn-mobility-flooding-ns-allinone-3-35/66f1db89-.../scratchpad/ab1_sweep_300s.out` (may be under a different session-id dir now — search for `ab1_sweep_300s.out`).
- Sweep script: same scratchpad dir, `ab1_sweep_300s.sh`. Structure: `for s in 1 2 3: for p in 5 10 20 30 40: for ab in 0 1`. Seed-1 curve first (~24h), then seeds 2,3. Total 30 runs.
- **If it dies:** the script is idempotent-ish (overwrites manifest). To resume without redoing, edit the loops to skip completed (mode,rho_a,seed) rows already in manifest, OR just relaunch and let it redo. Relaunch: `setsid nohup bash <scratchpad>/ab1_sweep_300s.sh > <scratchpad>/ab1_sweep_300s.out 2>&1 &`.
- Results so far: FULL MCC_full 0.59→0.68 (rises with ρ_a); AB1 ~0 at ρ_a=5 (−0.009), expected to rise toward ~0.2 at ρ_a=40. eff_poison ≈ 2–2.5× nominal ρ_a (confirms per-plane inflation → x-axis relabel with effective %).

---

## 5. OPEN DECISIONS (need sir / user — do not resolve unilaterally)

1. **ρ_a semantics ("87% question").** Combined runs pct=40 per-plane → ~87% effective poisoning at ρ_a=0.40, not 40%. User leaned "ρ_a should be OVERALL". Current sweep measures `eff_poison_pct` so the x-axis can be relabeled honestly (no redo). Approach A (split budget across planes so effective≈ρ_a) is ~1h to implement if sir wants true overall-ρ_a. Affects AB1, E1, E4.
2. **GAT+AE contribution** (§2c) — flag to sir that they're ~5% weight on combined; better evidenced by per-attack E5.
3. Duration: ablation runs at **300s** (needed so LSTM-AE window L=50 warms up; 30s under-represents it). Confirmed with user.

---

## 6. NEXT STEPS (SENTINEL ablation, after AB1 sweep)

Per sir's directive (each AB has a default point + an X-sweep; see the pasted plan in memory):
- **AB2** (HMAC off): sweep ρ_MitM, MitM attack ONLY (not combined). Report MCC/TTD/CDER. Flag `--ablation_ab=2`.
- **AB3** (GAT off): sweep n_coord{1,2,5,10,20}, Sybil a4 only, ρ_a=0.20. **Needs `--n_coord` flag WIRED (not done).**
- **AB4** (LSTM-AE off): sweep ε_max{0.1..0.5}, TP a1 only, ρ_a=0.20. **Needs `--ε_max` flag WIRED (not done).**
- **AB5** (full AI off = lightweight only): sweep speed v{10,60,100,140}, combined. Report ALL 6 metrics. **Needs the 4 SPEED TRACES generated (not done).** This is the headline "Detection Infeasible Zone" ablation; unaffected by GAT recalibration (no AI runs).
- Then SENTINEL experiments E1–E5 (E5 = per-attack table vs baselines B1/B2/B3 — the Step-1 deliverable sir wants first). E5 was paused earlier (a1 3 seeds done at 300s: MCC_full 0.665/0.684/0.610) — resumable at `~/Desktop/SENTINEL_experiments/E5_perattack_300s/`.

---

## 7. Key paths & memory
- Experiments output: `~/Desktop/SENTINEL_experiments/` (AB1_sweep_300s/, E5_perattack_300s/, VAL_300s/, config.txt).
- Combined calibration: `analytics/ml/models/urban_combined/`.
- 300s KEEP_IN trace: `ns-3.35/mobility/mobility_urban_60.tcl` (200 veh, 290s). 30s backup: `.bak30s`.
- Baselines scorer: `faithful_baselines_eval.py` (SENTINEL=full pipeline vs B1/B2/B3, all from beacon_log).
- **Memory files** at `/home/sdvn_mobility_flooding/.claude/projects/-home-sdvn-mobility-flooding-ns-allinone-3-35/memory/` — read `MEMORY.md` index first, especially: `project_combined_attack_mode.md`, `project_gat_ae_antiinformative_combined.md`, `project_keepin_300s_trace.md`, `project_sig_weights_change12.md`.

## 8. Standing constraints (from user/sir)
- Paper is ground truth. Do NOT edit .tex files (give values + line numbers; user edits Overleaf).
- Do NOT ad-hoc tune to "win"; report outcomes honestly (the ψ-dominant finding is an example — surfaced, not hidden).
- Never weaken/misconfigure baselines.
- Commit only when the user explicitly asks.
