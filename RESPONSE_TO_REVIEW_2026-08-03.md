# Response to Review — 2026-08-03


---

## CRITICAL ISSUE 1 — GAT spatial score discrimination (Q31)

**Verdict: stale finding, already resolved before this review; not a current defect.**

The raw numbers cited (870 malicious / 840 honest beacons, mean S/θ_S 1.124 / 1.435, θ_S=18.394) are accurate — they match our own instrumentation exactly. But the diagnosis built on top of them is stale, and the fix it asks for was already done and validated.

1. **"Both populations clip to 1.0, GAT contributes identically" — not what the data shows.** Only 13.8% of malicious and 13.1% of honest beacons actually exceed S/θ_S=1 and clip. The other ~86% of both classes retain their raw, unclipped value. A mean above 1.0 doesn't imply the population clips — it reflects a heavy-tailed distribution with a minority of high outliers.

2. **"θ_S=18.394 vs 8.305, two values for the same scenario" — they're not the same scenario.** 8.305 (`models/urban/`) and 18.394 (`models/urban_a3/`) are two different models. This is intentional and documented in code: `12_main.h:345-351` explains that 8.305 is known too low for the a3/Sybil attack specifically ("~70x too low... saturates the GAT term for 43% of CLEAN beacons"), and `urban_a3` exists precisely to correct that. Recomputing with 8.305 reapplies the value the codebase already identified as wrong for this case.

3. **"GAT's value comes entirely from k̂_i routing, not S_i" — checked directly, this is backwards.** In the same 1,710-row dataset, k̂_i is valid (routes to attack-conditioned weights) in only 1.2% of rows (20/1710). The other 98.8% use the global λ weights, meaning S_i is contributing directly through λ_gat·(S/θ_S) almost the entire time.

4. **The decisive finding: this data is from a ~6-hour transitional window, not the current system.** `urban_a3`'s model was swapped to a newly retrained encoder at 2026-07-27 08:04. A scaler bug (GAT fed inputs normalized for dead-reckoning residuals instead of absolute position) was found and fixed at 13:56 the same day, and θ_S was recalibrated to match at 14:14 — recorded with timestamps and file provenance in `AB3_HANDOFF.md` §8-9. The smoke test behind this issue used θ_S=18.394, correct only for the old model — meaning it ran in the ~6-hour gap after the model swap but before recalibration caught up.

Since 14:14 that day, deployed θ_S has been **42.62**, calibrated against the corrected scaler, validated with real in-sim data (`AB3_HANDOFF.md` §8, 300s run):
```
clean  S: p50=10.05  p90=17.07  p95=21.09  max=62.80
poison S: p50=29.13  p25=17.65  p10=12.09  min=4.27
```
Poison p50 (29.13) is clearly above clean p50 (10.05) — correct direction, real separation. MCC_full improved -0.209 → 0.520, FPR dropped 98.7% → 2.1%, confirmed at both 30s and 300s.

**Status: resolved prior to this review.** No further recalibration needed for `urban_a3`.

---

## CRITICAL ISSUE 2 — LSTM-AE contribution (Q33, Q34)

**Verdict: the specific claim (vehicle 73) is accurate but badly non-representative. The full population shows the AE clearly works and scales with attack magnitude.**

Malicious-population reconstruction error, across all 5 seeds per level (θ_ae=0.793731):

| ε_max | mean ε | max ε | % of malicious beacons exceeding θ_ae |
|---|---|---|---|
| 0.1 | 0.801 | 11.44 | 15.7% |
| 0.2 | 0.893 | 11.50 | 17.0% |
| 0.3 | 1.124 | 12.58 | 22.3% |
| 0.4 | 1.381 | 12.18 | 40.1% |
| 0.5 | 1.640 | 14.29 | 56.2% |

Clean, monotonic dose-response — more detections as injected drift increases, exactly what a working, drift-sensitive LSTM-AE should produce. Max error at every level is well above θ_ae (11-14×), not below it as the letter's one example suggests.

**Why vehicle 73 looked broken:** at ε_max=0.1 (vehicle 73's run), only 15.7% of malicious beacons cross θ_ae — vehicle 73 was one of the other 84.3%, at the weakest/stealthiest setting in the sweep. Expected behavior for a subtle attack, not evidence the mechanism never fires.



---

## CRITICAL ISSUE 3 — Attack-conditioned weights fallback rate (Q35)

**Verdict: the 89.9% figure is real and stands. The root cause is not what the letter proposes, and a full fix is not yet complete — reporting honestly rather than overclaiming.**

**θ_conf = 0.8. Fallback = 89.9%** (65,568/72,910), independently reproduced this session at 89.9-98.1% under corrected test conditions. Exceeds the stated 30% bar — **unreliable, confirmed.**

**Both of the letter's proposed fixes were tested directly and do not work:**
- *Lower θ_conf to 0.5/0.6/0.7:* tested on 1,030 real evaluations — fallback stayed at exactly 98.1% at θ_conf = 0.8, 0.5, 0.4, and 0.3. The confidence distribution is bimodal (a few scores >0.8, everything else at exact 0); there's no mass in the 0.3–0.8 range for a lower threshold to capture.
- *Softmax-temperature calibration:* wrong mechanism (independent sigmoid heads, not a temperature-scaled softmax) — but more importantly, a calibration fit on real (confidence, ground-truth) pairs showed the ranking itself is backwards in the tested sample (0% of poisoned nodes clear even θ=0.1, while ~2.5% of clean nodes do). Calibration is a monotonic rescaling; it cannot fix a ranking that's already inverted at the source.

**Major process finding:** every test in this investigation (three retrain attempts, multiple live checks) was initially run with the default `N_RSUs=4` ("toy topology") instead of `--N_RSUs=64`, which the codebase's own `AB3_HANDOFF.md:191-192` documents as required for this scenario. Under the wrong topology, the classifier showed **exact** `0.00000000e+00` confidence on literally every evaluation — indistinguishable from a dead model. Correcting the topology (`--N_RSUs=64`), the **same original, untouched, deployed model** immediately produced real confidence (up to 0.999) and real attack-type routing (`khat=2` firing). **The model was never broken; the test harness was misconfigured.**

**Root cause of the remaining ranking problem (why some clean nodes score higher than poisoned ones), traced to a genuine code bug and a labeling-scope gap:**
- Found and fixed a real bug: ghost (Sybil) vehicle IDs are `≥10000`, but the per-vehicle `psi`/`sig_mask` accumulator arrays are fixed-size, `total_size=256`, indexed directly by vid — guarded by `if (v < total_size)` to prevent memory corruption. That guard is correct and necessary; the gap was that ghosts had no alternate tracking path, so they were always silently fed `psi=0, sig_mask=0` into GAT. Fixed with a bounded `unordered_map` for the ghost-ID range, mirroring the existing real-vehicle logic (accumulate / read / reset).
- Testing after the fix showed **no change** — because in the default (legacy) a3 configuration actually exercised, the `gt_pois=1` ground-truth label attaches to the **real vehicle whose identity was cloned**, not to a separate ghost entry. That real vehicle's own kinematics are genuinely clean (it isn't lying about anything), so the classifier correctly finds nothing wrong with it. The actual fabricated ghost data, per the codebase's own documentation, doesn't reach the GAT/fusion scoring path at all in legacy mode.
- Tried the documented fix for this (`--honest_mp_s1=1 --sybil_gat_evasive=1`, meant to route ghosts into scoring while evading rule-signatures) — confirmed via live test that ghost vids still never appear in the scored window even with these flags and the array-bounds fix in place. **This remains open**: the evasive-mode wiring needs further tracing (does the ghost-creation code path even call the beacon-window ingestion function for fabricated ghosts?) before this can be closed.

**Status: partially resolved.**
- Fixed: a real memory-safety-adjacent bug (ghost psi/sig_mask never tracked).
- Confirmed: the model itself is not broken; test configuration was the primary cause of the "dead classifier" appearance.
- Open: why ghosts still don't reach the scoring path under evasive mode, and by extension, the true fallback rate under a configuration where the actual attacker identity gets scored. Until that's traced, the 89.9%/98.1% fallback figures should be treated as accurate but reflecting **the victim-relabeling gap**, not necessarily the ceiling of what's achievable once ghosts are properly scored.

---

## CRITICAL ISSUE 4 — Urban beacon coverage (Q42, Q16)

Step 1 result:

Instrumented a diagnostic that logs every vehicle's distance to its nearest RSU at t=15s, using the same R_max_comm=270m threshold. Ran against the urban scenario (200 vehicles, 64 RSUs, --attack_number=0 --attack_percentage=40 --simTime=20 --seed=1):


[COVERAGE-DIAG] t=15s vehicles_within_270.0m_of_any_RSU=200/200 (100.0%)
[COVERAGE-DIAG] RSU spread:     x[821.0,2571.0]  y[568.2,2318.2]
[COVERAGE-DIAG] vehicle spread: x[760.5,2614.8]  y[637.0,2311.5]
All 200 of 200 vehicles are within range of at least one RSU at t=15s. RSU and vehicle spatial extents overlap closely (~1,750m × 1,750m for both) — RSUs are not clustered in a subregion while vehicles roam elsewhere. Geometric coverage is complete.

This rules out RSU placement as the cause of the low confusion-matrix count. The same run's actual beacon total confirms the gap persists regardless: TP=1455 FP=12 TN=257 FN=624 (total 2,348), vs. naive expectation of 40,000 (200 vehicles × 20s / 100ms) — ~5.9%, consistent with the original 7.2% finding at 30s

---

## CRITICAL ISSUE 5 — Default MitM (a6) attack visibility (Q21)



`--faithful_mitm` already exists as a runtime flag in the codebase (implemented in a prior session, alongside combined-attack mode and a TTD instrumentation fix). The letter's recommendation — add `--faithful_mitm=1` to every a6 run — is actionable as stated.and when we run the atatack we can add the flag always. the issue is resoleved.

---

## RECONCILIATION 1 — ψ_th (0.09 vs 0.05)

This is a decision, not a bug: pick one value and make code and paper match. No technical blocker either way — deferring the choice to you, since it affects every downstream threshold-sensitivity comparison in the paper. Recommend keeping the code's current 0.09 (already used across every completed sweep to date) and updating the paper's table.
---

## RECONCILIATION 2 — Rural scenario parameters (200/169 vs 138/44)

Also a decision, not a bug. The 200/169 configuration was a deliberate change (matching urban density, extending trace duration) documented in this project's own rural setup notes. Recommend updating the paper's simulation-settings table to 200 vehicles / 169 RSUs and removing the 138/44 description, since reverting the code would discard the rural sweep work already completed and validated against 200/169 (R3 configs 1-4, MCC_full up to 0.86).

---

## RECONCILIATION 3 — ρ_a=0.40 → 89.6% poisoned beacons (Q26)

 Recommend the paper explicitly define ρ_a as a vehicle/actor-level compromise rate, with a stated caveat that beacon-level poisoning intensity is higher for relay-based attack types due to propagation through the compromised relay — matching the letter's suggested resolution.

---

## DESIGN GAP — E4 Threat Level sweep (Q18)

**Verdict: the letter is only half-right. `n_coord` already exists.**

Confirmed directly in code:
```
02_config_globals.h:282:  int g_n_coord = 4;
12_main.h:140:            cmd.AddValue("n_coord", ..., g_n_coord);
```
Already wired into the attack model ("the number of coordinated Sybil identities a compromised RSU fabricates per intercepted vehicle") and already used in a completed historical sweep (`AB3_ncoord_sweep/manifest.csv`, n_coord = 1, 2, 5 tested). **The letter's claim that n_coord does not exist is incorrect.**


Verified the existing historical sweep's topology directly: all 6 logs (`nc1/nc2/nc5 × full/gatoff`) confirm `N_RSUs=64 N_Vehicles=200` — the correct configuration. **That data does not need to be re-run; it's trustworthy as-is.** 

---
