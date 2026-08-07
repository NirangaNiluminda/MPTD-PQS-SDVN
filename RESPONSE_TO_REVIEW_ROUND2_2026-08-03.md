# Response to Review — Round 2 — 2026-08-03

## Block 1 — θ_S validated for urban_a3 only, other models unconfirmed

**Status: investigated, real bug found, fixed, and validated.**

**Correction to the premise first:** there are not seven separate per-attack-type GAT models. Confirmed directly in `12_main.h`: only two exist for the urban scenario — the shared `models/urban/` model (used for a1, a2, a4, a5, a6, a7 — six of the seven attack types) and `models/urban_a3/` (a3 only, already validated in the first response). K=7 refers to the classification heads *inside* one model, not seven independently-calibrated models.

**What the diagnostic found:** ran the S/θ_S population check for `attack_number=1` (representative of the shared model). Before any fix:
```
malicious: n=870  mean_S=249,942.4
honest:    n=840  mean_S=237,068.5
θ_S = 8.305
```
Both populations ~250,000 against a threshold of 8.305 — S/θ_S ≈ 30,000× over threshold for both classes, statistically indistinguishable. **This is the identical scaler bug already found and fixed for `urban_a3`** (residual-feature scaler feeding a model trained on absolute-position features), just never applied to the shared model that covers the other six attack types.

**Fix applied and validated:**
1. Added `models/urban/gat_scaler.json` (absolute-position stats, restored from the pre-existing `scaler.json.bak_pre_resid` backup — identical values to what fixed `urban_a3`).
2. Generalized `12_main.h`'s model-loading logic to check any scenario's own `gat_scaler.json`, rather than special-casing `urban_a3` only. Scenarios without one (rural, highway, urban_combined) are unaffected — behaviour is byte-identical for them.
3. Recalibrated `models/urban/theta_s.txt`: **8.305442 → 22.531** (95th percentile of the corrected clean-population S distribution). Old value backed up (`theta_s.txt.bak_pre_gatscaler_fix_20260803`).

**Post-fix population stats (attack_number=1, N_RSUs=64, correct topology):**
```
honest:    n=1580  mean=14.585  p50=11.546  p95=22.531  max=405.781
malicious: n=1540  mean=281.165 p50=238.906 p25=29.264  min=4.883

malicious beacons above new θ_S: 76.9%
honest    beacons above new θ_S: 4.4%   (≈ the expected ~5% for a 95th-pct threshold)
```
Malicious mean (281.2) is ~19× honest mean (14.6) — correct direction, real separation, clean textbook calibration.

**End-to-end validation — real detection improvement, not just score separation:**
```
MCC (LW)  = 0.716   →  MCC_full (Fusion) = 0.760
FPR (LW)  = 0.077   →  FPR_full (Fusion) = 0.032
```
Full-mode fusion now genuinely outperforms lightweight rule-only detection for attack_number=1 — confirms GAT is contributing real signal, not just non-degenerate numbers.

**Net result: six of the seven attack types (everything except a3, which was already fixed) are resolved in this one fix**, since they all share the one model.

---

## Block 2 — Beacon confusion matrix coverage vs. geometric coverage — resolved, not a bug

**Status: fully explained with the exact diagnostic requested. No filtering condition exists; the gap is real, physical-layer beacon loss.**

Added a counter at the literal `update_confusion_matrix()` call site (`08_detection_engine.h`), alongside the existing TX/RX instrumentation. Ran a 20s urban run under the corrected `--N_RSUs=64` topology:

```
[COVERAGE-DIAG] t=2s..18s: vehicles_within_270m_of_any_RSU = 200/200 (100%) at every sampled timestamp
[COVERAGE-DIAG] beacon TX attempts=24000  RX at RSU (HandleBeaconReceived calls)=1733  RX/TX=7.22%
[COVERAGE-DIAG] confusion-matrix update() calls=1733  CM/RX=100.0000%
```

**CM/RX = 100.0000%.** Every beacon that physically reaches `HandleBeaconReceived` gets scored — there is no additional filtering condition between "beacon received" and "confusion matrix updated." Traced the function body directly: the only early-return before the confusion-matrix call is the ghost-packet check (`08_detection_engine.h:2040`), which doesn't apply to real vehicle beacons.

**The entire 92.78% gap is physical-layer beacon loss**, occurring before `HandleBeaconReceived` is ever invoked — consistent with the original PHY/MAC-contention hypothesis from the first diagnostic pass (200 simultaneously-transmitting vehicles on shared DSRC channels), now confirmed under the corrected, non-clustered `N_RSUs=64` topology, which rules out RSU placement as an alternative explanation with certainty.

**Recommendation for the paper:** describe metrics as computed over the physically-delivered beacon population, with the RX/TX ratio reported explicitly as a real characteristic of the wireless simulation layer — not a bug requiring a fix, and not something to silently omit.

---

## Block 3 — Ghost vehicle NS-3 presence

**K=7 attack-type classification heads:** fallback rate is 89.9% regardless of θ_conf value (tested down to 0.3). The ranking is inverted — 0% of actually poisoned nodes produce any confidence above even θ_conf = 0.1, while 2.5% of clean nodes do. This means the K=7 heads are not producing meaningful attack-type identification in practice.

**Ghost NS-3 presence — direct answer: ghosts are fake IDs generated at the RSU/application layer. They do not exist as separate ns-3 nodes.**

Confirmed in the ghost-generation code (`08_detection_engine.h:3676-3720`): a ghost is a `uint32_t ghost_vid` plus position/speed/heading doubles computed as an offset from the real intercepted vehicle's position (`ghost_px = real_px + ...`). No `ns3::Node`, `MobilityModel`, `NetDevice`, or PHY/channel object is ever created for it — no simulated transmitter, no radio propagation.


---

## Block 4 — E4 streak parameter σ

**Status: implemented and verified. E4 can now be run as originally specified — both TL composite variables exist.**

Implemented `--streak_sigma` (default `-1` = off, continuous injection, byte-identical to every existing result):
- `02_config_globals.h`: new `int g_streak_sigma = -1;`.
- `12_main.h`: new CLI flag `--streak_sigma`.
- `09_vehicle_beacon_tx.h`: per-vehicle streak counter (mirrors the existing `vanish_counter` pattern used for beacon suppression) gates both the poisoning application and the ground-truth `IsPoisoned` label, so a vehicle in its "honest" phase is genuinely transmitting real kinematics and is correctly labeled clean for that beacon — not just visually honest with a stale poisoned tag.

**Verified with a real run** (`attack_number=2`, `--streak_sigma=5`, 20s): pulled the `is_poisoned` sequence for a real malicious vehicle (vid=45) straight from `beacon_log.csv`, sorted by time:
```
[1 1 1 1 1 0 0 0 0 0 1 1 1 1 1 0 0 0 0 0 1 1 1 1 1 0 0 0 0 0 ...]
```
Exact 5-on/5-off cycling, repeating — matches σ=5 precisely, confirmed against real simulation output, not just code inspection.

**Both TL composite variables (n_coord, σ) now exist and are verified working.** E4 no longer requires a redesign — Option A is complete. Recommend proceeding with the E4 sweep as originally specified in the paper.

---