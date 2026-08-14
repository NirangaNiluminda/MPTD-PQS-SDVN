# TODO — TTD instrumentation fix (apply AFTER the current AB2 300s pair finishes)

Status: **diagnosed, not applied.** Do not apply while a sweep is running — a rebuild
swaps the binary. AB1's 30 runs are already complete and unaffected.

## Symptoms

1. `metrics.csv` → `TTD` column is **0.000 in all 30 AB1 runs** (both FULL and AB1).
2. `beacon_log.csv` is **byte-identical between FULL and AB1** (verified by md5 on
   `a0_p40_m0_s1` vs `a0_p40_m0_ab1_s1`), so its `detected` column cannot measure any
   ablation, and offline TTD computed from it is meaningless.

## Root cause (single, shared)

The `detected` variable used at `08_detection_engine.h:2732` is **not the mode-specific
fusion decision**. It is the immediate/lightweight-style flag, which fires on the same
beacon regardless of `--ablation_ab`. Two consequences:

- **beacon_log**: the `detected` column is identical across modes.
- **TTD**: at `08_detection_engine.h:2726-2729` the onset and alert timestamps are both
  assigned inside the *same* call with the *same* `t_now`:

  ```c
  if (tag.GetIsPoisoned() && g_ttd_first_poison[vi] < 0)
      g_ttd_first_poison[vi] = t_now;
  if (detected && g_ttd_first_poison[vi] >= 0 && g_ttd_first_alert[vi] < 0)
      g_ttd_first_alert[vi] = t_now;     // alert == onset  =>  TTD = 0
  ```

  So whenever the first poisoned beacon is also `detected`, alert − onset = 0. Because
  that flag fires immediately in both modes, `compute_TTD()` averages ~0 everywhere.

`compute_TTD()` itself (`10_metrics_csv.h:825-834`) is **correct** — it is fed bad
timestamps. Do not "fix" it.

## Proposed fix

Set the TTD *alert* timestamp from the **fusion decision**, not from the per-beacon flag —
i.e. the same `full_flag` that produces `MCC_full` and the `[FUSION-...] full_anom=` log line.

- Alert site: the fusion block around `08_detection_engine.h:2500-2512`, where both
  `vid_i` and `full_flag` are in scope. Add roughly:

  ```c
  // C5 TTD: alert timestamp must come from the FUSION decision so the metric
  // responds to the ablation (AB1 removes psi; AB3/AB4 remove GAT/AE).
  int vi = (int)vid_i - (int)g_first_vehicle_node_id;   // VERIFY this mapping
  if (full_flag && vi >= 0 && vi < total_size &&
      g_ttd_first_poison[vi] >= 0 && g_ttd_first_alert[vi] < 0)
      g_ttd_first_alert[vi] = Simulator::Now().GetSeconds();
  ```

- Remove/replace the alert assignment at `08:2728-2729` (keep the **onset** assignment —
  onset is ground truth and correctly mode-independent).

- **Verify `vid_i`'s index space** before writing. `lkh_veh_idx()` subtracts
  `g_first_vehicle_node_id`; the fusion path may already carry a 0-based vehicle index.
  A wrong base silently lands timestamps in the wrong slot — exactly the bug the comment
  at `08:2722` says was fixed once already (`the old hardcoded -2 landed the onset/alert
  timestamps in wrong (often OOB) slots -> TTD~0`).

- Separately (lower priority): make `beacon_log.csv`'s `detected` column carry the
  mode-specific decision, or add a second column, so the CSV is self-sufficient.

## Validation after applying

1. Rebuild: `./waf build --targets=mptd_pqs_sdvn`.
2. Run one short FULL and one short AB1 (combined, rho_a=0.40, simTime=60).
3. Expect `metrics.csv` TTD: FULL ~1 s, AB1 >5 s (the AE window floor L=50 x T_b=0.1 = 5 s).
   Both still 0.000 => the mapping is wrong; re-check `vi`.
4. Confirm `beacon_log.csv` md5 now **differs** between the two modes.

## Consistency caveat (important for the paper)

AB1's published TTD was recovered **offline from the retained run logs**
(`[FUSION-...]` decisions timestamped by the enclosing `[IPFS-STORE-...] t_start`),
at epoch-window granularity (~0.2 s). Values: FULL 1.094 +/- 0.955 s,
AB1 13.879 +/- 9.100 s.

Once the in-sim fix lands, AB2-AB5 will report TTD at **per-beacon** granularity from
`metrics.csv`. That is a finer resolution than AB1's. Before mixing them in one table,
either:
 - re-derive AB1's TTD from the fixed binary (needs a re-run — not recommended), or
 - state the granularity difference explicitly in the caption.

Extraction script that recovered AB1's TTD (reusable if needed):
`<scratchpad>/extract_ttd_all.sh` -> writes `/tmp/ab1_ttd_fusion.csv`.
