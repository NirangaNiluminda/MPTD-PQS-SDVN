# MPTD-PQS-SDVN — project context

Auto-loaded every session. Keep it short; put detail in the linked files.

## What this is

NS-3 + SUMO simulation of an SDVN mobility/trajectory-poisoning detection
framework (rule signatures + GAT + LSTM-AE + PQ crypto + Hyperledger Fabric),
with a LaTeX paper in `report/`. Branch `ml-review-fixes`.

## Paths

```bash
NS3=/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
REPO=/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN
BIN=$NS3/build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn
```

**Source headers live in `$REPO/scratch/mptd_pqs_sdvn/`, not under `$NS3`.**
Build with `cd $NS3 && ./waf build --targets=mptd_pqs_sdvn`.

## Before running ANYTHING

Read **[RUN_CONFIG.md](RUN_CONFIG.md)** — canonical command, all 84 CLI flags with
defaults, why each unused flag is unused, and the full trap list. The four that
have cost the most time:

| trap | detail |
|---|---|
| `routing_test` defaults **true** | declared in `07_socket_layer.h:16`, not a config header. Pass `--routing_test=false`. |
| `ablation_mode` defaults **1** | mode 1 is AB1, not full. Pass `--ablation_mode=0`. |
| `gat_det_flag_heads` defaults **46** | the GAT OR-path is ON unless you pass `=0`. |
| ns-3 booleans | need `=0`/`=1`; a bare `--ring_detect` does nothing. |

Confirm what actually reached the process: `tr '\0' ' ' < /proc/<pid>/cmdline`.

`RUN_CONFIG.md` is **generated** — never edit it by hand:

```bash
python3 tools/dump_run_config.py           # regenerate
python3 tools/dump_run_config.py --check   # exit 1 if stale or a flag is undocumented
```

Flag names and defaults are parsed from source; the "why" lives in
`tools/flag_rationale.json`. **Add an entry there whenever you add a CLI flag** —
`--check` fails until you do.

A tracked pre-commit hook enforces this. **On a fresh clone, enable it once:**

```bash
git config core.hooksPath tools/hooks
```

Without that one command the hook is inert — `core.hooksPath` is local config and
does not survive cloning.

## Ground rules (from the project owner, non-negotiable)

- **Never fabricate results.** Verify every claim with a live run or by reading
  code/data. If it hasn't been measured, say so.
- **When something looks wrong, find the root cause** — don't assume.
- **If shown wrong, correct it openly** and move on.
- Deploy or promote nothing without explicit go-ahead.

## Current state (2026-08-07)

300 s combined-attack run, seed 1, rho_a 0.40, urban — simulator-printed:

| arm | MCC_full | FPR_full |
|---|---|---|
| D1 (no ML) | 0.763 | 0.064 |
| D4 (GAT) | 0.758 | 0.090 |
| D6 (GAT+AE) | 0.766 | 0.095 |

Ordering **D1 < D4 < D6 holds at a 90 s cutoff** (0.8339 / 0.8432 / 0.8477) but
**not at 300 s** (D4 falls 0.005 below D1). Any reported MCC must state its
evaluation window. `psi_cond_floor` eliminated D4's true-positive loss entirely
(158 -> 0); the residual gap is false positives, concentrated in 13 vehicles.

## Dead ends — do NOT retry

| attempt | why it failed |
|---|---|
| Fix A model (`urban_ghostk2_posfix`) | S is anti-informative in-sim: clean p50 0.935 > real-poison 0.900 > ghost 0.000. Offline AUC 0.677 does not transfer. MCC collapsed to 0.036. |
| `pop_anomalous_writes` | starves history, FPR 0.535 |
| `identity_binding` (Fix 1) | -0.124 MCC, 40% of rejections honest |
| GAT retrain for ghosts | S structurally blind — ghosts are 4/5 of nodes so they define the mean; the head flags the VICTIM 95% of the time |

**Deployed model must stay reverted:** `gat_model.onnx -> ../urban/gat_model.onnx`,
`theta_s = 19.74`, `theta_ae = 33.693885`. Verify before every run.

## Key documents

| file | contents |
|---|---|
| [RUN_CONFIG.md](RUN_CONFIG.md) | generated flag reference + traps + canonical run |
| [CODE_AUDIT_VS_PAPER_ITEMS_2026-08-07.md](CODE_AUDIT_VS_PAPER_ITEMS_2026-08-07.md) | code-vs-paper audit of all ~28 modelling items |
| [HANDOFF_2026-08-07.md](HANDOFF_2026-08-07.md) | session handoff, root-cause narrative |
| `report/main.tex` | the paper (may lag Overleaf — check before editing) |

## Known code/paper mismatches

Details in the audit. The ones that bite: GAT input is **16** features (5
kinematic + tau + psi + 9 signature bits), not the 6 the paper claims;
`psi_th` is 0.09 in code vs 0.05 in the paper; `R_MAX_GRAPH` is 300 m vs the
paper's 270 m; theta_ae is mean+1.645*std in code vs median+kappa*MAD in the paper.
Attack-variant numbering is `k = attack_number - 1` for k_hat, and the paper's
Section~\ref{sec:exp5} variant list is misordered against
`02_config_globals.h:143-149`.
