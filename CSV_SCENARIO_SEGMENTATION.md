# Per-Scenario CSV Segmentation (live-sim outputs)

Branch: `feature/csv-scenario-segmentation`. Single file changed:
`scratch/mptd_pqs_sdvn/10_metrics_csv.h`.

## Problem (before)

Every live-sim CSV was written to a **fixed** path under `analytics/results/` and
**truncated each run**. So running the three SUMO scenarios back-to-back
(`--mobility_scenario=0` urban, `=1` rural, `=2` highway) made each run **overwrite**
the previous one — you ended up with only the last scenario's data. The per-run
archive (`analytics/results/runs/beacon_a<atk>_p<pct>_s<speed>.csv`) was keyed by
attack/pct/speed, **not** by scenario, so files could still collide and didn't say
which scenario produced them.

## Change (after — option A: per-scenario folders)

A small helper derives the scenario from the existing global `mobility_scenario`
(0=urban, 1=rural, 2=highway — same selector used for the model paths in
`12_main.h`) and every live-sim CSV is written under
`analytics/results/<scenario>/`:

```cpp
static inline const char* mptd_scenario_name();   // "urban" | "rural" | "highway"
static inline std::string mptd_results_dir();     // NS3_ROOT "/analytics/results/<scenario>/"
```

### New output layout

```
analytics/results/<scenario>/
    beacon_log.csv                       # per-beacon rows (main ML training data)
    tp_s1_poison_log.csv
    ghost_identity_log.csv
    mitm_intercept_log.csv
    rsu_relay_log.csv
    vehicle_tx_log.csv
    unregistered_beacon_log.csv
    controller_poison_log.csv
    runs/beacon_a<atk>_p<pct>_s<speed>.csv   # permanent per-run archive

analytics/datasets/<scenario>/a<atk>_p<pct>/    # committable dataset snapshot
    beacon_log.csv + attacker-specific detail + metrics
```

`<scenario>` ∈ `{urban, rural, highway}`.

## How to run the three scenarios (HPC)

Pass a different `--mobility_scenario` per run (with `--mobility_source=1` for the
SUMO trace); each run self-segregates into its own folder — no manual moving:

```
./waf --run "mptd_pqs_sdvn --mobility_source=1 --mobility_scenario=0 ..."   # → analytics/results/urban/
./waf --run "mptd_pqs_sdvn --mobility_source=1 --mobility_scenario=1 ..."   # → analytics/results/rural/
./waf --run "mptd_pqs_sdvn --mobility_source=1 --mobility_scenario=2 ..."   # → analytics/results/highway/
```

## Important: downstream readers need the new path

The canonical `analytics/results/beacon_log.csv` **no longer exists** — it is now
`analytics/results/<scenario>/beacon_log.csv`. Scripts that read the old fixed path
must be updated to take a scenario (or glob the per-scenario folders):

- `global_heldout_eval.py`
- `analytics/demo_task1.py`
- `analytics/run_evaluation.sh`
- `analytics/ml/generate_scenario_data.sh`
- `analytics/ml/train.py`
- `analytics/ml/evaluate_all.py`

(These are not changed in this commit — update them when wiring the per-scenario
eval on the HPC.)

## Deliberate scope decisions

- **No schema change.** The scenario is conveyed by the **folder**, not a new
  column, so existing column-position parsers keep working once pointed at the new
  path. (If a `scenario` column is wanted later, it's an additive follow-up.)
- **Sweep summary left as-is.** `analytics/results/sweep/metrics_a<N>_p<P>_s<S>.csv`
  is a per-run *summary* tied to the sweep harness and already keyed by
  attack/pct/speed; segmenting it would change the harness contract, so it was not
  touched here.

## Build note
Pure path-construction change (string concatenation through `mptd_results_dir()`);
no new dependencies. Verified `mobility_scenario` is in scope —
`simulation.cc` includes `02_config_globals.h` (where it is defined) before
`10_metrics_csv.h`. Not compiled here (NS-3 waf build runs on the HPC).
