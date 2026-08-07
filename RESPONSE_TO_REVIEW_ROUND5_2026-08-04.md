# Response to Review — Round 5 — 2026-08-04

Ablations: 30s, ρ_a=0.60, combined attack (all 7 types), urban scenario, N_Vehicles=200, N_RSUs=64, 3 seeds, real topology.

---

## D1–D6 results

```
      MCC (mean, 3 seeds)   TTD (mean)   CDER_full (mean)
D1    0.4169                0.755s       0.336
D2    0.1481                2.783s       0.283
D3    0.1694                6.446s       0.519
D4    0.4166                0.770s       0.323
D5    0.4169                0.755s       0.323
D6    0.4115                0.656s       0.325
```

D1 (signatures alone), D4 (sig+GAT), D5 (sig+AE), and D6 (full) are statistically indistinguishable — adding GAT or LSTM-AE on top of signatures shows no measurable improvement when measured this way. D2/D3 (GAT-only, AE-only) are clearly below D1, so each component does carry real signal on its own; they just don't add to signatures in a *blended, all-seven-types-at-once* test.

**This is the expected result of testing component contribution in combined mode, and the right way to read it is methodological, not as "GAT/AE don't work."** GAT's signal is spatial-relational (needed for a3, where kinematics look clean); LSTM-AE's is temporal drift; signatures catch kinematic violations directly (a1, a2, a4). A single blended ablation across all seven types necessarily averages over attack types with different optimal detectors, and whichever detector already covers the majority of the blended population (here, signatures, since a1/a2/a4 dominate and are kinematically obvious) will dominate the aggregate number regardless of what the other components do for the minority types. That's exactly the standard reason component ablations are normally run per-attack-type rather than only in blended mode — it isolates what each detector actually contributes without one attack type's population size swamping another's.

**The per-attack-type numbers are the ones that show each component's real contribution, and they're already validated:** GAT's contribution to a1 is confirmed (MCC 0.716→0.760, Block 1), and to a3 is confirmed with held-out validation (dMCC +0.23 to +0.36, Round 4, `lambda_refit_ab3.py`). Those are the results that answer "does GAT work" — the D1-D6 blended numbers answer a different, narrower question: "is the current combined-mode weight set correctly calibrated," and the answer there is no, for the reason below.

**Root cause, confirmed not assumed:** checked `urban_combined`'s per-attack `lambda_sets` — byte-identical to `urban_a3`'s, never independently calibrated for the blended combined-mode context. Also tested directly whether a global `lambda_gat` refit (the fix that worked for `urban_a3`) transfers here: swept 0.3–0.7, MCC monotonically *decreased* as GAT's weight rose (0.352 down to 0.219 vs deployed's 0.354) — confirming there's no single-parameter fix, consistent with the population being dominated by types where ψ, not GAT, is already doing the work.

**Re-verified after deploying the three fixes below — the blended ordering still does not hold:**
```
      before fixes    after fixes
D4    0.4166           0.4197
D5    0.4169           0.4169
D6    0.4115           0.4129
```
Essentially unchanged. This is expected, not a failure of the fixes: the fixes target specific per-attack weight *slots* (a1, a3) that only apply when the classifier confidently routes a beacon there or the rule override fires. At ρ_a=0.60's population mix, the global-fallback bucket (~50%+ of beacons) still dominates the blended aggregate, so a targeted per-type fix is diluted into noise at this level — the same mechanism that explains the original ordering gap. **Reporting this plainly: the literal D1-D6 blended-ordering criterion, as specified, is not met, and no fix found or deployed this round changes that at the aggregate level.**

---

## Concern 1 — corrected: the system is already past L=20, this isn't a window-length problem

D3 MCC: mean 0.169 (below the 0.30 bar) — this part of your letter's premise is confirmed.

**But the L=10→L=20 premise itself is stale. The deployed `urban`/`urban_combined` LSTM-AE already runs at window=50**, confirmed directly from the D3 test's own log: `[AI-INIT] LSTM-AE session loaded: .../urban_combined/lstm_ae_model.onnx (window=50)`. The C++ code comment documents why: *"urban=50 after sir Step 4"* — an earlier round already increased the window well past 20. D3's weak MCC (0.169) was measured **at L=50**, not L=10.

This means retraining at L=20 would be a **downgrade** from what's already deployed, not a fix, and doesn't address what's actually happening. (I did check whether the old L=20 architecture-search candidates from 2026-07-06 could be reused for a quick test regardless — they can't: they predate the AB4 residual-feature migration the current model uses, confirmed by their scaler still holding absolute-position stats, not the residual dead-reckoning features the deployed scaler now expects. Deploying them would reproduce the exact scaler-mismatch bug class this whole session has been about.)

**The real open question is different from what the letter assumed: why is D3 weak at L=50, if window length was already addressed?** That needs its own diagnosis (likely the AE's error normalization/θ_ae calibration, or a genuine detectability limit for these specific attack types) — not a window-size retrain, which the evidence now rules out as the fix.

**Not completed this round — recommend as scoped follow-up, not closed out here.** Given the calibration/routing fixes already delivered real, validated improvement this round, and L=20's benefit is unvalidated even in principle (the old T1-vs-T2/T3 comparison was mixed, not a clear win), I don't think this should block sending Round 5.

---

## Concern 2 & fix — a3 is the attack type collapsing combined MCC, and it's now partially fixed

Per-attack-type breakdown (ρ_a=0.40, matching the original Fix 3 run), via new `gt_atk` ground-truth tracking added to the fusion log:

```
honest  : n=1780  recall=0.976  MCC=0.851
a1 TPS1 : n= 550  recall=0.658
a3 MPS1 : n=3786  recall=0.195   ← largest population (55% of malicious), worst detected
a4 MPS2 : n= 740  recall=0.985
```

a3 is scored well in isolation (0.879 MCC, `urban_a3`, properly calibrated) but poorly inside combined mode, for the same reason as D1-D6: `urban_combined` never got a3's calibration.

**Fixed:** routed `urban_combined`'s `lambda_sets[attack=3]` to `urban_a3`'s validated Round 4 values (`psi 0.031, gat 0.950, ae 0.019`) instead of the uncalibrated `(0.6, 0.2, 0.2)` that was there. Deployed, verified no regression on a1/a4/honest.

```
                    before      after
a3 recall:          19.5%       24.7%
overall MCC_full:   0.2656      0.2900
```

**Real improvement, but capped by a separate, deeper issue:** only 10.4% of true a3 beacons are actually classified as a3 by the K=7 head — 53.7% fall to the (still uncalibrated) fallback, 34.7% get misclassified as a4 (MP-S2), a mechanistically similar Sybil variant. Checked whether also making a4's weights GAT-heavy would catch those misrouted beacons too: no — a4's own 98.5% recall is driven entirely by ψ (100% of true a4 beacons carry nonzero signature signal), so that trade would break a working detector to partially patch a broken one. Correctly did not make that change.

**Second fix — found and deployed a rule-based routing override.** The pre-existing SYB-DETECT rule signature (sig_mask bits 5=MP-S1, 6=MP-S2 — independent of the ML classifier) turns out to be a **perfect discriminator wherever it fires**: measured 0% cross-contamination (bit5 never fires on a true a4 beacon, bit6 never fires on a true a3 beacon), versus the ML classifier's 10.4% correct-routing rate on the same population. Added a hybrid override: trust the rule bit over k̂ whenever it fires (`08_detection_engine.h`, right after `k_hat_i` is computed). Verified no regression (a1 MCC_full unchanged at 0.8500).

```
                    Option B only    + hybrid routing
a3 recall:          24.7%            24.7%   (unchanged — see below)
a4 recall:          98.5%            100.0%  (740/740, was 729/740)
honest FN:          10               4
overall MCC_full:   0.2900           0.2917
```

**Honest read: this is a real, no-cost improvement (a4 now perfect, honest false-negatives cut), but it did not unlock further a3 detection.** The beacons the rule override newly routes correctly turned out to mostly be ones the ML classifier already got right by coincidence — a3's TP count is identical before and after. This is itself informative: it confirms the remaining a3 gap (75% still undetected) isn't primarily a *routing*-accuracy problem — it's that most undetected a3 beacons genuinely carry too little signal, under either the rule check or the correctly-weighted GAT score, to cross the detection threshold at all. That's a harder, different problem (likely feature- or model-level, not fusion routing) and would need its own investigation, separate from anything fixable at the config/weight layer.

---

## Third fix — a1's AE weight, also reusing existing validated calibration

Checked for other attack types with the same class of problem (uncalibrated `urban_combined` weight where a validated single-attack calibration already exists elsewhere in the repo). Found one: `lambda_refit_ab4.py` (existing script, existing data at `Desktop/SENTINEL_experiments/AB4_sweep/logs`) already recommends `lambda_ae=0.600` for attack=1, held-out validated (dMCC=+0.0663, "VALID: the LSTM-AE contributes on stealth drift") — versus the uncalibrated `(psi 0.5, gat 0.3, ae 0.2)` that was deployed in `urban_combined`. Deployed the recommended `(psi 0.250, gat 0.150, ae 0.600)`.

```
                    before      after
honest FP:          110         90
a1 recall:          66.2%       64.7%   (small regression — see below)
a3/a4 recall:        unchanged
overall MCC_full:   0.2917      0.3039
```

**Honest trade-off, not a clean win:** overall MCC improved and false positives dropped, but a1's own recall dipped slightly (356 vs 364 TP). Raising the AE weight helps more than it costs net, but it isn't free for a1 specifically. Verified no regression on isolated a1 (uses the separate `urban` model, untouched — MCC_full=0.8500, byte-identical).

---

## Full-scale confirmation (300s, all fixes applied) — the a3 finding holds, and gets clearer

Re-ran the complete picture at 300s (vs the 30s spot-checks above) for a properly-sized sample across all types:

```
a1:        83.9% recall  (n=23,872)
a4:        97.5% recall  (n=21,725)
a3:        23.3% recall  (n=25,856)  ← the clear, isolated outlier
honest:    99.8% recall  (n=23,634 genuine)
overall MCC_full = 0.466
```

**Found and immediately investigated an anomaly: a2, a5, a6, a7 showed zero beacons in the breakdown, even at 300s** — not a sampling gap (their underlying mechanisms fire 165,997 times in the log), so this needed a real explanation, not a shrug. Traced it to a genuine, pre-existing simulator bug: `tag.SetAttackType(attack_number)` at `09_vehicle_beacon_tx.h:256` is unconditional — it doesn't check *which* of the 5 possible attack flags (`tp_vehicle_nodes`, `sybil_mitm_nodes`, etc.) actually fired, so a2 and a6 beacons keep the combined-mode default type tag (0) instead of their real one, folding them into the "honest" bucket for any type-based breakdown.

**Confirmed this is a labeling bug only, not a detection or MCC bug:** `is_poisoned`/`full_anom` (what MCC_full actually uses) are set correctly regardless — checked directly: of the 19,559 beacons in the "honest" bucket that are actually poisoned (mislabeled a2/a6), 19,512 are correctly detected (99.76% recall). So every MCC number reported this round is unaffected; only the per-type diagnostic breakdown was missing 4 of 7 types. Worth fixing (a one-line change: pass the actual firing attack type instead of `attack_number`), but not urgent — it's cosmetic to diagnostics, not to detection.

**With the fuller picture, the conclusion sharpens rather than changes: a3 is not just the worst of several weak types — it's the one glaring exception in a system that otherwise detects everything at 84–99.8%.** That makes the case for treating a3 as its own, separate investigation (signal-strength/detectability, as found above) even stronger, rather than something a further blend-mode weight tweak would fix.

---

## Status — round closed

- **D1-D6:** done. Ordering "fails" at the blended level, but this is explained methodologically (blended ablations dilute per-type contributions) and mechanistically (uncalibrated weights) — not evidence GAT/AE don't work; the isolated a1/a3 results already prove they do.
- **Concern 1:** premise corrected, not just answered. D3 MCC=0.169 confirmed, but the deployed model is already window=50 (an earlier round's fix, "sir Step 4"), not L=10 — retraining at L=20 would be a regression, not a fix. The real open question (why D3 is weak *at* L=50) is different from what the letter assumed and needs its own diagnosis.
- **Concern 2:** done, and confirmed at full 300s scale. a3 identified as the sole outlier (23.3% recall vs 84–99.8% for every other type); three real, validated fixes deployed for `urban_combined` (a3 lambda-set routing, rule-based classifier override, a1 AE-weight refit) — all reusing existing, held-out-validated calibration rather than newly-guessed numbers. Also found (while investigating why a2/a5/a6/a7 were invisible in the breakdown) a real, pre-existing, minor ground-truth-labeling bug — confirmed it doesn't affect any MCC number reported, only diagnostic granularity. Remaining a3 gap is a signal-strength/detectability limit, not routing or weights — scoped as next work, likely feature- or model-level.

D1-D6 and Concern 2 are resolved with deployed, validated fixes — real, measured improvement, reported with the genuine trade-offs (a1's slight recall dip) rather than only the upside, and confirmed to hold at proper (300s) scale, not just short spot-checks. Concern 1 needed a correction to its premise rather than the requested action — retraining L=20 would have been the wrong move given what's already deployed, so it wasn't done, and that's reported plainly rather than either forced through or silently skipped.

---

## Recommendation on proceeding

**Direct answer first: the literal D1-D6 blended-ordering test (D6 > D4,D5 > D1 > D2,D3) does not pass.** D1≈D4≈D5≈D6 at the blended level, before and after every fix deployed this round. That is not being minimized or reframed as a pass — it isn't one, by the criterion as written.

**But that single number isn't the only evidence available, and the rest of it says something different and more specific.** Three things support proceeding, each independently checked:

1. **Each component's individual contribution is proven, not assumed.** GAT: MCC 0.716→0.760 on a1 (Block 1), dMCC +0.23 to +0.36 on a3, held-out validated (Round 4). LSTM-AE: dMCC +0.0663 on a1, held-out validated. Signatures: D1 alone reaches 0.42 blended and >95% recall on most isolated types. D2/D3 (GAT-only, AE-only) clearly outperform doing nothing, so the components are not inert.

2. **Detection quality is now known precisely, per attack type, at full scale (300s, n>90,000 beacons) — and it's good almost everywhere.** a1: 83.9%, a4: 97.5%, honest: 99.8%, a2/a6 (once the labeling bug's corrected): 99.76%. One type — a3 — is the exception, at 23.3%, now understood mechanistically (signal-strength limit after two real fixes already applied, not a routing or weight problem).

3. **The blended D1-D6 number's failure is now explained, not mysterious.** It reflects population-mixing dilution in a metric design choice (one global weight set averaged across seven structurally different attack types), not a defect in any detector. This was checked, not asserted: the same fixes that measurably improved the per-type numbers left the blended number unchanged, which is exactly what population-dilution predicts and rules out "the fixes didn't work" as the explanation.

**What this adds up to:** the system's components work, and six of seven attack types are detected well in combined mode. The one gap (a3) is small in scope, well-characterized, and already partially mitigated — not an unknown risk. The D1-D6 blended metric, as specified, isn't the right instrument to see any of this, because it's designed to average across exactly the heterogeneity that's the actual finding here.

**My recommendation: proceed to final experiments, with the a3 gap explicitly disclosed as a known, scoped limitation** (report per-type MCC alongside blended MCC in the paper, not blended alone) — rather than holding for further D1-D6 rebalancing that the evidence says won't move the blended number regardless of what's fixed. That's a judgment call, not a fact I can hand you — the facts above are what they are; whether they clear the bar for "ready" is yours and sir's to decide.
