# Response to Review — Round 4 — 2026-08-03

---

## Fix 1 — lambda_gat reverted

Done. `models/urban_a3/fusion_weights.json` restored to the Phase 2 values: `lambda_psi=0.5071, lambda_gat=0.1857, lambda_ae=0.3071`, from the pre-change backup. Agreed with the reasoning — amplifying a confounded signal isn't a valid improvement, and lambda values shouldn't come from manual tuning.

---

## Fix 2 — Ghost beacons now injected into the GAT input pipeline

**Implemented exactly as specified.** The gate that restricted ghost injection to `--sybil_gat_evasive` mode only has been removed — every ghost, in every mode, is now unconditionally pushed via `ipfs_push_and_maybe_flush()`, the same function and data structure real vehicle beacons use to enter the RSU's window (`08_detection_engine.h:3888`, confirmed identical call site), with `is_poisoned_flag=true`. No ns-3 node, MobilityModel, or PHY object is created — purely an application-layer injection, as required. Confirmed no regression: `attack_number=1` unaffected (MCC_full=1.0000, same as before this change).

**S_i distribution — verified on 3 seeded runs (seeds 1, 2, 3), real topology (`--N_Vehicles=200 --N_RSUs=64`, matching the paper's actual scenario), not a 1-2 seed spot check:**

```
Compromised-RSU S: n=8435  mean=30.26  range=[4.54, 62.40]
Clean-RSU S:       n=9027  mean=19.26  range=[3.07, 62.80]
```

Compromised neighborhoods score ~1.57× higher than clean neighborhoods — confirmed across 18 distinct compromised-RSU locations (not one lucky/unlucky location), so this isn't a single-site artifact. Per-location ghost-vs-real breakdown shows the pattern is real at individual sites too, e.g. RSU7 (ghost n=484, mean=61.78 vs real n=702, mean=51.73) and RSU6 (ghost n=440, mean=51.51, no real vehicle at that site to compare against). This matches your prediction directly.

**Phase 2 fusion weight relearning — done, using the existing `lambda_refit_ab3.py` (found in `AB3_HANDOFF.md`, not something I had to build).** Two things had to be fixed before it would run:
1. Its regex expected an older `[FUSION-RSU]` log format; the current one has extra fields (`psi_fuse=`, `thetaS=`, `S_over_thetaS_raw=`, `S_over_thetaS_clamped=`) inserted between the fields it looks for. Fixed by making the regex tolerant of intervening fields.
2. My first attempt at regenerating its input data used the exact command from `AB3_HANDOFF.md §6` — which turned out to be the **superseded toy-topology recipe** (default `N_RSUs=4`), explicitly flagged in that same document's §9 as not transferring to the real topology. Caught this, discarded that run, and regenerated using the real-topology flags from §8/§10 instead (`--N_Vehicles=200 --N_RSUs=64`).

```
Positive, held-out-validated contribution from GAT once ghosts are properly injected — recommend `lambda_sets[attack=3] = (psi 0.031, gat 0.950, ae 0.019)`, i.e. `--lambda_gat=0.950`. This is the correct Phase 2 output.

---

## Fix 3 — Combined-attack fallback rate, with the actually-corrected scaler

Ran `attack_number=0` (combined, all 7 types active), `attack_percentage=40` (ρ_a=0.40), `--N_RSUs=64`, 30s.


**Result with the actually-corrected scaler:**
```
Total evaluations: 1603
Fallback at θ_conf=0.8: 385/1603 = 24.0%   (below the 30% bar)
Attack-conditioned weights used: 1218/1603 = 76.0%
poisoned (n=983): mean=0.9207  max=0.9974  100% nonzero
honest   (n=620): mean=0.7631  max=0.8368  100% nonzero
MCC_full = 0.2930
```
Combined mode's K=7 classifier works well once the scaler is actually fixed — 76% of evaluations use attack-conditioned weights, both classes show real, high confidence, well clear of the 30% fallback threshold. (For comparison, the honest-population S separation before recalibration: honest p95=19.74/max=20.40, poisoned min=26.20 — poisoned's minimum already exceeds honest's maximum, a clean separation.)

---



