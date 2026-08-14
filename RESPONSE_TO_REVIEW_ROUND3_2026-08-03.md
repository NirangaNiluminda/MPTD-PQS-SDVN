# Response to Review — Round 3 — 2026-08-03

Test conditions: `attack_number=3`, `--N_RSUs=64`, `--rsu_seed=13`, `--attack_percentage=20`, 30s, legacy Sybil-RSU mode, corrected scaler models.

---

## Step 1 — Fallback rate, confidence distribution, below 30%?

```
Fallback at θ_conf=0.8: 100.0% (810/810)  — worse than the previous 89.9%, not better
poisoned (gt=1): n=150  mean=0.0000  max=0.0000
honest   (gt=0): n=660  mean=0.0000  max=0.0000
```
Not below 30%. Every evaluation, both classes, is exact-zero confidence.

Not a broken model: the identical architecture on `attack_number=1` (same session, Block 1) gives `n=810, 100% nonzero, max=0.9997`. The difference is the input, not the code: a1's poisoned vehicles have real kinematic anomalies to key on; a3's `gt_pois=1` vehicle is the real vehicle whose identity was cloned elsewhere — its own kinematics are unmodified. There is nothing for the classifier to find.

---

## Step 2 — What the GAT is actually detecting

```
rows at compromised RSUs: 150/150 gt_pois=1 (100%)
rows at clean RSUs:       660/660 gt_pois=0 (100%)

S at the one compromised RSU with data (RSU3): n=150  mean=8.37   range=[7.94, 8.83]
S at clean RSU0:  n=190  mean=41.93
S at clean RSU1:  n=200  mean=27.76
S at clean RSU2:  n=270  mean=16.63
```
Ground truth and RSU-compromise status are 100% collinear by construction (any vehicle at a compromised RSU is marked poisoned, no exceptions). Ghosts contribute zero rows to the GAT's input graph in this mode (confirmed: `register_vehicle_at_rsu` is a separate density counter, disjoint from the `feats5`/window structure GAT reads). The real vehicle's kinematics are clean. Window size is controlled for (N=10 both cases).

**What GAT is detecting is a per-RSU location baseline, not a Sybil-specific relational signal.** Clean RSUs vary 16.6–41.9 among themselves by location alone, with no attack present — more spread than the alleged attack signal. Because compromise assignment and the poisoned label are the same event, any location-correlated signal reads as "Sybil detection" whether or not it has anything to do with Sybils. This is also why MCC swings with `--rsu_seed` — different seeds sample different arbitrary locations' baselines, not different detection quality.

**Paper claim needs the reword you anticipated:** what's validated is that the spatial term correlates with the compromised RSU's location-specific traffic baseline, not with a detected relational inconsistency from fabricated identities.

---

## Separately — a real, deployed MCC improvement exists, but doesn't answer the above

Independent of this mechanistic question, we found and deployed a fusion-weight fix: `lambda_gat` was raised from 0.1857 to 0.6 in `models/urban_a3/fusion_weights.json` (psi/ae rescaled accordingly), based on evidence that the deployed weight structurally capped GAT's vote below the detection threshold. Across 4 tested RSU-compromise realizations this raises mean MCC_full from -0.36 to +0.12 (up to +0.81 on favorable placements), and improves the legacy-mode result from 0.741 to 0.879–1.000, with no regression to the shared a1/a2/a4/a5/a6/a7 model.

This is a genuine improvement in the metric as currently defined — but Step 2 shows that metric is confounded with RSU location, so raising `lambda_gat` amplifies sensitivity to that confound rather than to genuine Sybil detection. Both facts are true at once: MCC is measurably higher, and it still isn't evidence the system detects Sybils.

---

## GAT is functioning correctly — the paper's claim, not the implementation, needs to change

Two separate outputs come from the GAT model, and they should not be conflated:

1. **The spatial anomaly score `S_i`** (feeds fusion via `λ_gat`). This is genuinely working. For `attack_number=1`, where poisoned vehicles have real kinematic anomalies, it delivers a measured, validated improvement: MCC 0.716 (lightweight) → 0.760 (full fusion), confirmed in Block 1. It is the mechanism behind the deployed `lambda_gat=0.6` improvement above. GAT is not broken, dead, or non-functional — it is doing exactly what a spatial-relational model should do: scoring each vehicle relative to its local neighborhood.
2. **The K=7 attack-type classifier** (`attack_probs`, routes λ^(k̂)). This is the part that reads 100% fallback for a3 — because a3's `gt_pois=1` vehicle has no anomaly in its own data for a classifier to key on. Not a defect in GAT; a mismatch between what a3's ground truth actually is and what the classifier is being asked to identify.

For attack 3 specifically, `S_i` is active and varies substantially, but what it varies *with* is which RSU served the beacon, not any property introduced by the Sybil/ghost mechanism — direct consequence of `gt_pois=1` being assigned by RSU-compromise status alone, with no ghost ever entering the graph and no change to the real vehicle's own transmitted kinematics. There is no code bug producing this: it follows correctly from how the attack is defined and how ground truth is labeled.

**Recommendation: bring the paper's a3/Sybil-detection claim in line with what is actually implemented and verified, rather than changing the implementation to chase an unverified claim.** Concretely, replace the current "GAT detects spatially-relational multi-vehicle inconsistency introduced by Sybil identities" wording for a3 with something like:

> "For the compromised-RSU Sybil scenario, the fused detector's spatial term correlates with the compromised RSU's local traffic context rather than with a directly detected relational inconsistency from the fabricated identities themselves; ghost identities are not currently represented in the GAT's input graph under the evaluated configuration. The GAT spatial term's contribution to detection is validated for attack types where the poisoned vehicle's own kinematics are anomalous (attack 1; MCC 0.716→0.760), which is the mechanism the architecture is built around."

This keeps every claim the paper makes backed by a real, reproduced measurement, and confines the open question (genuine Sybil/ghost detection via a track-history feature, discussed earlier) to future work rather than a claim made now.

---

## Action sequence status

- **Step 1:** done — 100% fallback, not a model defect, no anomalous input exists for a3's ground-truth-positive vehicle.
- **Step 2:** done — per-RSU location confound identified and measured directly.
- **Step 3:** awaiting your decision — reword the claim, restrict K=7 routing to attack types where it works (a1), or pursue a different design (e.g., an identity-freshness feature, which would need retraining, not a config change).
- **Step 4:** not started, pending Step 3.
