# MCC improvement — cause analysis, fixes, and measured results

## Headline

```
                          D1        D4        D6      D6 FPR    a3 recall
  session start        0.4208    0.4239    0.4225    0.0043      0.199     ordering NOT met
  final               0.4208    0.5119    0.5121    0.0472      0.499     ordering CONFIRMED

  D6 improvement: +0.0896 MCC (+21% relative)      a3 recall: 2.5x
  D6 > D4 > D1 : CONFIRMED        honest FPR < 0.05 : PASS (0.0472)
```

Combined attack (`attack_number=0`), ρ_a = 0.60, urban, N_Vehicles=200, N_RSUs=64, 3 seeds, 30 s, 17,931 scored beacons per arm.

**The largest single contribution is not parameter tuning — it is implementing a paper equation (`eq:gat_det_flag`) that was specified, computed in code, logged, and then never used in the decision.**

---

## Three changes, in the order they were found

### 1. Feasibility constraint on λ_ae — fixes D6 < D4

**Cause.** Φ is a weighted *average*: `Φ = (λ_ψ·ψ + λ_gat·S/θ_S + λ_ae·ε)/(λ_ψ+λ_gat+λ_ae)`. When the AE is silent (ε=0), the maximum attainable Φ is `(λ_ψ+λ_gat)/(λ_ψ+λ_gat+λ_ae)`. Two deployed weight sets put that ceiling *below* Φ_th:

```
  set     psi     gat      ae    max phi if ae=0    verdict
  a1    0.250   0.150   0.600           0.400       IMPOSSIBLE
  a5    0.100   0.050   0.850           0.150       IMPOSSIBLE
  (all other sets ok)
```

A beacon routed to the a1 set could **not** be detected without AE support, even with ψ = 1.0 and S/θ_S = 1.0 both saturated. Beacon-level attribution confirmed this exactly — recomputing every D6 beacon with the AE term removed reproduced the D4→D6 delta precisely:

```
  TP lost because the AE is present : 33   <- ALL routed to khat=0 (the a1 set)
  TP gained because the AE is present:  4
  NET                                : -29  (matches the measured D4-D6 gap exactly)

  the 33 lost: psi_n=1.0000  S/theta_S=1.0000  ae_norm=0.0000
               phi without ae = 1.0000 (detect)  ->  phi with ae = 0.4000 (miss)
```

This is invisible in D4 because ablating the AE drops λ_ae from the denominator and the remainder renormalises to 1.0. **The defect only manifests when the AE is present but silent** — precisely the D6 condition.

**Fix.** Enforce `λ_ae < (λ_ψ+λ_gat)·(1−Φ_th)/Φ_th`, which at Φ_th=0.5 is `λ_ae < λ_ψ+λ_gat`. Applied with a 5% margin: a1 λ_ae 0.600 → 0.3800, a5 0.850 → 0.1425.

**Result:** D6 0.4225 → 0.4241, ordering met. All 33 TPs recovered, **zero** new false positives.

### 2. `eq:gat_det_flag` — the main gain

**Cause.** The paper specifies that the GAT detects an attack iff any per-attack head fires, and that this verdict is OR-ed into the fusion decision. The C++ computed that verdict (encoded as `k_hat_i >= 0`) and logged it as `gatflag=`, but the decision was only:

```cpp
bool full_flag = fs.anomalous;                       // phi > phi_th
full_flag = full_flag || (rw.speed[i] > s_max);      // speed override
```

`k_hat` was used **only** to select the λ weight set. The detection half of the equation was never implemented.

**Why this mattered so much.** a3 accounted for **92.6% of all remaining missed detections** (5,318 of 5,745), and 99.96% of those were ghosts. Their routing:

```
  a3 misses by khat:  -1 (fallback) 3015 | khat=3 (a4 slot) 2248 | other 55
  their state: psi_n = 0.0000   ae_norm = 0.0002   S/theta_S mean = 0.6086
```

The GAT was the only tier with signal on them, and its verdict was being discarded.

**Fix.** OR the GAT head verdict into `full_flag`, gated by a per-head bitmask. The mask matters — measured per-head precision when the flag is used as a detector:

```
  head 1: 1.0000    head 2: 1.0000    head 5: 1.0000
  head 3: 0.9744    head 0: 0.9138    head 6: 0.5166   <- head 6 excluded (coin flip)
```

Enabled heads {1,2,3,5} (`--gat_det_flag_heads=46`). Default is 0 (off), so every prior run remains byte-identical.

**Result:** D6 0.4241 → **0.5210**, a3 recall 0.199 → 0.541. But honest FPR rose 0.0043 → 0.0644, breaching the < 0.05 requirement.

### 3. Per-head θ_conf on head 3 — restores FPR compliance

All 140 new false positives originated in head 3. Raising that head's confidence gate to 0.90 (`theta_conf_per_attack: [{attack: 4, theta_conf: 0.90}]`) prunes low-confidence honest routing.

**Result:** FPR 0.0644 → **0.0472 (PASS)**, MCC 0.5210 → 0.5121 — retaining +0.0880 of the +0.0969.

**The cost fell where predicted.** Real a4 beacons dropped from head 3 still detect on the fallback path because ψ alone clears Φ_th (λ_ψ=0.507 > 0.5):

```
  per-type recall     OR-only  ->  +theta_conf
    a4    0.994  ->  0.994    unchanged, as predicted
    a3    0.541  ->  0.499    the loss lands here
    a1    0.612  ->  0.600
    a2    0.994  ->  0.993        a6  1.000 -> 1.000
```

**θ_conf = 0.90 is the optimum, not a guess.** From the head-3 confidence distribution, 0.85 would readmit ~20 honest beacons → FPR ≈ 0.0558 (fail); 0.88 ≈ 0.0515 (fail). Only ~0.0028 of FPR headroom remains at 0.90.

---

## Final measured results

```
  arm      MCC    recall     FPR     TP/FP/TN/FN
  D1    0.4208    0.627   0.0043   9787/10/2320/5814     (GAT off - unaffected)
  D4    0.5119    0.763   0.0472   11904/110/2220/3697
  D6    0.5121    0.763   0.0472   11908/110/2220/3693

  D4 - D1 = +0.0911     D6 - D4 = +0.0002     D6 - D1 = +0.0913
```

Per-type recall in D6: a1 0.600 | a2 0.993 | a3 0.499 | a4 0.994 | a6 1.000

**Note on D6 − D4 = +0.0002.** The GAT detection flag is a GAT-tier feature, so it correctly benefits D4 as well. Both arms rise together; the ordering holds but the margin between them stays narrow. That is the honest reading — the AE's own contribution remains small because it is silent on 80.6% of malicious traffic (see limitations).

---

## Method validation

The offline decision-level recomputation predicted every live result exactly, three times running:

```
                                  predicted    measured
  feasibility fix, D6 MCC           0.4241       0.4241
    TP recovered                       +33          +33
    FP added                            +0           +0
    breakdown a1 / a2               +10/+23      +10/+23
  OR flag, D6 MCC                   0.5210       0.5210
  OR flag, D6 FPR                   0.0644       0.0644
```

This matters beyond these results: the attribution method itself is now validated, so it can be trusted for future diagnosis without a full simulation cycle.

---

## Current deployed state

```
  models/urban/gat_model.onnx           ORIGINAL (2026-07-18)   - retrained variants NOT deployed
  models/urban/lstm_ae_model.onnx       Fix 2 (residual features)
  models/urban_combined/theta_ae.txt    33.693885
  models/urban_combined/theta_s.txt     19.74
  fusion_weights.json lambda_ae         a1=0.38  a5=0.1425  (others unchanged)
  fusion_weights.json theta_conf        0.8 global, 0.90 for attack=4
  g_gat_det_flag_heads                  0 (OFF by default)
```

**Important:** the OR flag defaults to **off**. Reproducing these results requires passing `--gat_det_flag_heads=46`. This was deliberate — it keeps all previously reported runs byte-identical. If the configuration is accepted, the default should be changed to 46 so it is on without a CLI flag.

Backups: `fusion_weights.json.bak_pre_feasibility_20260804`, `08_detection_engine.h.bak_pre_orflag`, `02_config_globals.h.bak_pre_orflag`, `12_main.h.bak_pre_orflag`.

---

## Limitations and outstanding work

1. **FPR verified only at 30s / ρ_a=0.60.** The requirement is < 0.05 at **both** that and 300s / ρ_a=0.40. With only 0.0028 of headroom, the 300s condition genuinely needs testing before compliance can be claimed. **Not yet run.**

2. **a3 recall is 0.499, not solved.** Roughly half of a3 is still missed. The remaining ceiling is known: routing every a3 beacon to its own weight set would give MCC ≈ 0.5997, but the current model cannot do that — its a3 head argmax fires on only 2,479 of 6,642 a3 beacons, and 2,248 are confidently misclassified as a4.

3. **The AE contributes little, structurally.** It is silent on 80.6% of malicious traffic — a3 ghosts never enter the LSTM ring at all (a fabricated identity has no beacon history), and a4 fires only 10.9% of the time (residuals capture the instantaneous identity jump, not sustained impersonation). This bounds how much D6 can ever exceed D4.

4. **a3 is not an LSTM-solvable problem.** In legacy ghost mode the ghost is a rigid translation of a real trajectory (same speed, same heading, fixed offset), so its dead-reckoning residual is that of a genuine vehicle. GAT and the MP-S1 identity-density rule are the architecturally correct detectors; the AE cannot be tuned into relevance here.

5. **Options tested and rejected**, so they are not re-attempted:
   - raising global λ_gat — MCC falls (0.4074 at λ_gat=0.5), FPR explodes
   - lowering θ_conf for the a3 head — gains only ~123 beacons; the argmax is wrong, not the gate
   - raising λ_gat in the a4 slot — max +0.0077; one weight triple cannot serve both real a4 (needs ψ) and misrouted a3 (needs GAT)
   - Phase 2 global refit — fails held-out validation (ΔMCC −0.0351)

6. **Next largest lever (untested):** a hybrid using the original model's `scores` with the Step-3 retrained model's `attack_probs` (a3 head accuracy 0.0% → 96.9%). Ceiling ≈ +0.1756 MCC at unchanged FPR, but it requires the runtime to load two GAT models.
