# Why D6 is still lower than D4 — cause found, fix applied, ordering now met

**Answer: it is not statistical dilution. Two of the seven attack-conditioned weight sets are arithmetically degenerate — they make detection impossible when the AE is silent, regardless of how strongly the signature and GAT tiers fire.**

**The fix is deployed and measured live. The cumulative ordering requirement is now satisfied:**

```
                     D1        D4        D6       D6 - D4
  before fix       0.4208    0.4239    0.4225     -0.0014    ordering NOT met
  after  fix       0.4208    0.4239    0.4241     +0.0002    D6 > D4 > D1  CONFIRMED
```

Live measurement, combined attack (`attack_number=0`), ρ_a = 0.60, 3 seeds, 30 s, 17,931 scored beacons per arm. **False positives unchanged at 10** — the recovery costs nothing in precision.

I want to be straight about the margin: **+0.0002 is small.** The ordering is genuinely met and the mechanism is fully understood, but this is not a decisive separation, and the reason is explained in "Why D6 ties rather than clearly wins" below.

---

## The measurement

D6 loses exactly 29 net true positives versus D4 (D4 TP=9852, D6 TP=9823), with false positives identical (10 each). To attribute those precisely, I recomputed every D6 beacon's verdict with the AE term removed and the remaining weights renormalised — same beacons, same run, only the AE's participation changed. This reproduces the −29 exactly:

```
  TP LOST because the AE is present : 33
  TP GAINED because the AE is present:  4
  NET                                : -29   (matches the D4→D6 delta exactly)
```

**Every one of the 33 lost beacons is a real vehicle (zero ghosts), and every one is routed to k̂ = 0 — the a1 weight set.** Their component values, averaged:

```
  psi_n     = 1.0000    <- signature tier firing at maximum
  S/theta_S = 1.0000    <- GAT tier firing at maximum
  ae_norm   = 0.0000    <- AE contributing nothing
  phi WITHOUT ae = 1.0000   -> detected
  phi WITH    ae = 0.4000   -> missed
```

These are beacons where **both** working detectors fire at full strength, and the system still misses them.

## The cause

Φ is a weighted average: `Φ = (λ_ψ·ψ + λ_gat·S/θ_S + λ_ae·ε) / (λ_ψ + λ_gat + λ_ae)`. When the AE is silent (ε = 0), the maximum attainable Φ is `(λ_ψ + λ_gat) / (λ_ψ + λ_gat + λ_ae)`. If that ceiling sits below Φ_th, detection is arithmetically impossible.

Checking every deployed weight set against Φ_th = 0.5:

```
  set        psi     gat      ae    psi+gat    max phi if ae=0    verdict
  global   0.507   0.186   0.307      0.693              0.693    ok
  a1       0.250   0.150   0.600      0.400              0.400    IMPOSSIBLE
  a2       0.550   0.050   0.400      0.600              0.600    ok
  a3       0.031   0.950   0.019      0.981              0.981    ok
  a4       0.600   0.200   0.200      0.800              0.800    ok
  a5       0.100   0.050   0.850      0.150              0.150    IMPOSSIBLE
  a6       0.750   0.050   0.200      0.800              0.800    ok
  a7       0.450   0.450   0.100      0.900              0.900    ok
```

**The a1 set has λ_ψ + λ_gat = 0.400 < Φ_th = 0.500.** A beacon routed there cannot be detected without AE support, even with ψ and GAT both saturated at 1.0. The a5 set is worse still (0.150), though it is not exercised in this scenario.

This is also exactly why the defect is invisible in D4: when the AE is ablated, λ_ae is dropped from the denominator and the remaining weights renormalise to sum to 1 — so 0.25/0.40 + 0.15/0.40 = 1.0 and the beacon detects normally. **The bug only manifests when the AE is present but silent**, which is precisely the D6 condition.

## The fix, and what it achieves

The general feasibility condition is `λ_ae < (λ_ψ + λ_gat)·(1 − Φ_th)/Φ_th`, which at Φ_th = 0.5 reduces to **λ_ae < λ_ψ + λ_gat**. Applying it with a 5% margin (holding the ψ:GAT ratio fixed, capping only λ_ae):

```
  a1: lambda_ae 0.600 -> 0.380   (psi+gat = 0.400)
  a5: lambda_ae 0.850 -> 0.143   (psi+gat = 0.150)
```

Result — all 33 lost true positives are recovered, with **no** increase in false positives:

```
  ALL 3 SEEDS        MCC        TP/FP/TN/FN
    D6 current     0.4225
    D6 repaired    0.4241       9856/10/2320/5745
    D4 bar         0.4239
    -> repaired D6 beats D4 by +0.0002

  HELD-OUT seed 3    MCC        TP/FP/TN/FN
    D6 current     0.5278
    D6 repaired    0.5298       2839/0/1110/1486
    D4 bar         0.5298
    -> exactly tied with D4
```

**So the repair removes the AE's harm, but does not make D6 decisively better than D4 — it makes them essentially equal.** I would rather state that plainly than present +0.0002 as a win.

## Live confirmation — deployed and re-measured

The constraint was applied to `fusion_weights.json` (a1: λ_ae 0.600 → 0.3800; a5: 0.850 → 0.1425) and D1/D4/D6 re-run from scratch. Load-time verification in every run confirms combined-attack mode and the repaired sets:
```
  [AI-INIT] combined-attack calibration -> models/urban_combined/
  [RSU-SELECTION] attack=0  pct=60%  compromising 38/64 RSUs
  [AI-INIT] lambda_sets: k1=(0.25,0.15,0.38) ... k5=(0.1,0.05,0.1425) ...
```

**Measured result:**
```
  arm      MCC    recall     FPR     TP/FP/TN/FN
  D1    0.4208     0.627   0.0043   9787/10/2320/5814
  D4    0.4239     0.631   0.0043   9852/10/2320/5749
  D6    0.4241     0.632   0.0043   9856/10/2320/5745

  D4 - D1 = +0.0031     D6 - D4 = +0.0002     D6 - D1 = +0.0033
  ORDERING D6 > D4 > D1 : CONFIRMED
```

**The offline attribution predicted this exactly — every figure.** That is worth stating, because it validates the analysis method itself, not just this one result:
```
                              predicted     measured
  repaired D6 MCC               0.4241       0.4241
  true positives recovered         +33          +33   (9823 -> 9856)
  false positives added              +0           +0   (10 -> 10)
  breakdown: a1                    +10          +10   (416 -> 426)
             a2                    +23          +23   (671 -> 694)
```

Per-type recall, before → after:
```
  a1   0.514 -> 0.526      a2   0.960 -> 0.993
  a3   0.199 -> 0.199      a4   0.994 -> 0.994      a6   1.000 -> 1.000
```
Only a1 and a2 change, which is exactly right — they are the types routed to the repaired a1 slot. a3/a4/a6 are untouched, confirming the fix is surgical and introduces no side effects elsewhere.

## Why D6 ties rather than clearly wins

Because the AE's upside is genuinely small on this population: it gained only 4 true positives. Per the Step 1 measurements, the AE is silent on **80.6% of malicious beacons**:

- **a3 (6,642 beacons):** 86.1% have `ae_norm` exactly 0, because 5,349 of them are ghosts and ghosts never enter the LSTM ring at all — a fabricated identity has no beacon history to build a temporal window from (`lstm_ring_push_resid`, `08_detection_engine.h:3953`).
- **a4 (5,930 beacons):** only 10.9% reach `ae_norm` = 1.0; residuals capture the instantaneous jump at an identity switch, not sustained impersonation (Step 2).

The AE fires strongly only on a1/a2/a6 — 19.4% of malicious traffic. There is little headroom for it to add, so once its artificial penalty is removed, D6 converges to D4 rather than surpassing it.

## Recommendation

1. **The feasibility constraint is deployed and confirmed live** (backup: `fusion_weights.json.bak_pre_feasibility_20260804`). This is a structural correction — it removes an arithmetic impossibility — not a fitted parameter, so it does not carry the overfitting risk that sank the earlier refit attempts. It recovers 33 TP and adds 0 FP, on held-out data and in live measurement alike. Say the word if you want it reverted.
2. **Make it a hard constraint in Step 4.** Phase 2 optimisation must enforce `λ_ae < λ_ψ + λ_gat` for every weight set, otherwise the search can re-enter the infeasible region. This should be a bound on the simplex, not a post-hoc check.
3. **Set expectations for the ordering requirement.** With this fix, D6 ≥ D4 holds but only just. A decisive D6 > D4 requires the AE to contribute on a3 or a4, and for a3 that is structurally impossible as currently designed — ghosts have no time series to reconstruct. If a strict D6 > D4 margin is required, the realistic route is giving the AE signal on a4 (sustained-impersonation features rather than instantaneous residuals), not further weight tuning.
