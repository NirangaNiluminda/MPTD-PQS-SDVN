# AB4 (LSTM-AE ablation) — Handoff for a parallel Claude chat

**Purpose:** Work AB4 in a *separate* chat while another chat finishes AB3. Read this
top-to-bottom; it is self-contained. Do **not** touch AB3 artifacts (see §7).

---

## 1. Project in one paragraph
ns-3.35 SDVN simulator for the **SENTINEL** detection paper (MPTD-PQS). Detection =
lightweight rule signatures (ψ) → **GAT** (spatial anomaly, score S) → **LSTM-AE**
(temporal anomaly, window L=50 urban) → fusion φ = λ_ψ·ψ + λ_gat·gat + λ_ae·ae > 0.5.
Ablations remove one mechanism and measure the drop. **AB4 removes the LSTM-AE.**

- Repo (edit source here): `/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN`
- Source headers: `scratch/mptd_pqs_sdvn/*.h` (symlinked into the ns-3 tree)
- ns-3 build tree: `/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35`
- Binary: `ns-3.35/build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn`
- Build: `cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35 && ./waf build --targets=mptd_pqs_sdvn`
  (a sibling `scratch/routing.cc` is broken/missing `paillier_he.h` — the `--targets`
  flag skips it; a bare `./waf build` will fail on routing.cc, which is fine to ignore.)
- Python venv (ML/plots): `/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN/gat_detector/.venv/bin/python`

## 2. How to run a sim (ALWAYS detached)
```bash
cd /home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:$HOME/.local/lib64"
BIN=./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn
setsid nohup $BIN --mobility_source=1 --mobility_scenario=0 --maxspeed=60 \
  --N_Vehicles=200 --N_RSUs=64 --skip_blockchain=true --stealthy_control_plane=true \
  --verbose_tx=false --attack_number=<N> --attack_percentage=<pct> --simTime=300 \
  --seed=<s> --per_pid_results=1 --ablation_mode=0 --ablation_ab=<AB> \
  > /path/to/log 2>&1 &
```
- **AB4 = `--ablation_ab=4`** (LSTM-AE removed; fusion renormalizes ψ+gat). FULL = `--ablation_ab=0`.
- Output dir: `analytics/datasets/urban/a{attack_number}_p{pct}_m0[_ab4]/metrics.csv` + `beacon_log.csv`.
- **MCC/TTD/CDER/PBPO come from `metrics.csv`** (in-memory per-process → always valid).

## 3. CRITICAL operational rules (learned the hard way)
1. **Never `pkill -f`** — it self-matches the running command and can kill real sims. Kill by explicit PID.
2. **Always launch sims detached** (`setsid nohup … &`); a 2-min tool timeout will otherwise kill foreground sims. Even a 30s sim takes ~10-15 min wall (per-beacon ONNX inference).
3. **`--per_pid_results=1`** isolates the live results dir per PID. WITHOUT it, concurrent sims share `analytics/results/urban/beacon_log.csv` and **clobber each other's beacon_log** (MCC stays valid, but per-beacon analysis is garbage). Use it whenever you'll inspect beacon_log.
4. **`metrics.csv` is keyed by attack/pct/mode ONLY (not PID/seed)** — two runs with the same (attack, pct, ab) overwrite each other's `a{N}_p{pct}_m0[_ab]/metrics.csv`. Archive between runs, or run them non-overlapping.
5. **The KEEP_IN urban trace populates gradually** — vehicles enter the scored region late (attack-3 poison didn't start until t=158s!). **Short sims (30s/100s) can show 0 attack activity.** Use `--simTime=300` for anything involving detection, and check the `ATTACK SUMMARY` "Actual poison rate" > 0 before trusting a run.
6. Machine: 32 cores, 62 GB RAM, ~7 GB swap. ~2.3 GB RSS/sim. 10-wide concurrent 300s sims swap-thrash (each takes 3-4.5h); solo they take ~15-40 min. Check `free -g` before launching many.

## 4. What AB4 must show + the attack to use
AB4 removes the **LSTM-AE = the TEMPORAL detector**. To demonstrate it's essential, use
an attack that is a **temporal anomaly the AE catches but ψ-rules and GAT miss**:
a smooth **gradual drift over time** (e.g. speed/position slowly diverging), staying
under the per-beacon kinematic gates so ψ stays silent, and spatially plausible so GAT
stays quiet. The AE (trained on normal temporal windows) flags the abnormal *sequence*.

- **HANDOVER note:** AB4 was speced as "sweep ε_max{0.1..0.5}, attack a1, ρ_a=0.20", where
  `ε_max` (stealth step bound) controls drift subtlety. There is an `epsilon_max_stealth`
  config (`02_config_globals.h`, default 0.5) exposed via **`--eps_max`** — verify the CLI is
  wired (`grep -n eps_max scratch/mptd_pqs_sdvn/12_main.h`); if not, wire it like the other AddValue flags.
- **Known bug to fix first:** earlier AB4 gave **zero TP** (no poisoned beacons scored) —
  same class as attack-3's under-poisoning. Root cause pattern: attacker-selection gating +
  late trace entry. **Before sweeping, run ONE 300s run and confirm the ATTACK SUMMARY shows
  a non-trivial "Actual poison rate" (aim ~10-20%) and `distinct poisoned vehicles > 1`**
  (awk the beacon_log col9). If it's ~0.7%/1 vehicle, the attack is degenerate → fix the
  attacker gating in `06a_attack_models.h declare_attackers()` (attack-3's fix was: for the
  relevant mode, drop an over-restrictive AND-gate so the full `attack_percentage` draw poisons).

## 5. The deliverable (mirror AB1/AB2 exactly)
Sir wants each ablation as a **3-panel figure** vs attacker ratio **ρ_a on {0,0.2,0.4,0.6,0.8,1.0}**,
mean ± std over **3 seeds**, error bars, panels **(a) Detection quality [MCC], (b) Detection
latency [TTD (s)], (c) Per-beacon overhead [PBPO_Full (ms)]** (AB2 used CDER for panel c — check
which sir wants for AB4). Style: blue = "SENTINEL (full)", orange = "AB4 (…removed)", direct
line labels, x-axis "Attacker penetration ρ_a".

- **Reuse the plot scripts** in the scratchpad (`plot_ab1_final.py`, `plot_ab2_3panel.py`) — copy and change dir/labels.
- **TTD is NOT reliable from metrics.csv** (in-sim TTD is 0 for many points). Use the **offline
  fusion extraction**: pair each vehicle's first `gt_pois=1` FUSION beacon (onset) with its first
  `full_anom=YES` (alert), timestamped via the enclosing `[IPFS-STORE] … t_start=`. See
  `scratchpad/ab2_offline_ttd_grid.sh` / `ab1_ttd_highpts.sh` as templates.
- **If AB4 uses the COMBINED attack (attack_number=0)**, note the "87% question": nominal ρ_a
  inflates per-plane (nominal 0.6 ≈ 85% effective poison, 1.0 = 100% = degenerate MCC=0). For a
  single-attack AB4 this doesn't apply. Compute effective rate = (TP+FN)/total from the confusion matrix.
- Sweep grid you likely need: reuse existing {0.05,0.1,0.2,0.3,0.4} if present, add missing
  {0,0.6,0.8,1.0}. Look in `~/Desktop/SENTINEL_experiments/` for prior AB4 sweep dirs/manifests.

## 6. Ablation dispatch reference
`12_main.h` "C10" block maps `--ablation_ab` 1..11 onto fine-grained toggles. AB5≡legacy
mode 1, AB10≡legacy mode 5, everything else forces `ablation_mode=0`. **AB4 → LSTM-AE disabled.**
Confirm by grepping: `grep -n "ablation_ab" scratch/mptd_pqs_sdvn/12_main.h` and reading the switch.

## 7. DO NOT TOUCH (AB3 chat owns these)
- `analytics/ml/models/urban_a3/`, `urban_a3_trained/`, `urban_a3.bak/` (AB3's GAT model — being swapped/retrained live)
- `scratch/mptd_pqs_sdvn/06a_attack_models.h` **case 3 / sybil_gat_evasive** and the
  `declare_attackers()` attack-3 gate (AB3 just modified these). If AB4 needs to edit
  `declare_attackers()`, coordinate — add a *separate* branch for AB4's attack, don't alter the attack-3 lines.
- Any running sim with `--attack_number=3 --sybil_gat_evasive=1` (AB3's).
- Recently added, safe to rely on (already built into the binary): `--per_pid_results`,
  `--honest_mp_s1`, `--tiered_commit/--t_batch/--n_commit` (blockchain Tier-3, no effect on detection).

## 8. First 3 concrete steps for the AB4 chat
1. `grep -n "ablation_ab" scratch/mptd_pqs_sdvn/12_main.h` → confirm AB4 disables the LSTM-AE; identify AB4's intended attack_number.
2. Run ONE 300s FULL run of that attack; check `ATTACK SUMMARY` poison rate + distinct poisoned vehicles > 1. Fix the attacker gating if degenerate (§4).
3. Once well-posed: run FULL vs AB4 (`--ablation_ab=0` vs `=4`) at ρ_a=0.2, 300s, confirm **MCC(FULL) > MCC(AB4)** and the AE actually contributes; then sweep the ρ_a grid × 3 seeds and build the 3-panel figure (§5).

Good luck — verify the poison rate first; that was the single biggest time-sink on AB3.
