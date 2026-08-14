# Thirteen diagnostics — answers

**Headline findings:**

1. **The 300 s false positives are not spread across honest traffic — they are 5 vehicles.** Top-5 vehicle IDs produce 91.3% of all FPs; one vehicle has FPR = 1.0000. 69.7% of FPs land on vehicles whose identity is actively being forged by a4 attackers.
2. **a1's low recall is a routing failure, not an AE failure.** Only 10.1% of a1 beacons reach the a1 weight set; 26.2% are misrouted to the a3 set whose λ_ae = 0.019 nulls the AE entirely.
3. **a5 and a7 produce zero scored beacons at every configuration, for two independent structural reasons.** One is by explicit design in the code.
4. **The code↔paper variant mapping does not match your list** — a1 is malicious *RSU*, not malicious *vehicle*.

---

# Issue 1 — 300 s FPR root cause

## DQ-FPR1 — false-positive breakdown by source (OR flag OFF, 300 s / ρ_a=0.40)

```
  total honest = 23634    false positives = 3703    FPR = 0.1567

               source    count    share
            psi alone     1765    47.7%
            GAT alone     1086    29.3%
     combination only      852    23.0%

  mean term contribution across all FPs:
    psi term = 0.3458
    GAT term = 0.3951      <-- DOMINANT
    AE  term = 0.1876
```

**By count the signature tier fires most often (47.7%), but by magnitude the GAT term is dominant (0.3951).** The AE contributes least on both measures.

Signature bits on those FPs: TP-S5 70.7%, TP-S4 68.2%, TP-S1 67.6%, MP-S4 67.6%, TP-S2 27.4%, TP-S3 26.4%, MP-S1 26.5%, **MP-S2 22.4%**, MP-S3 1.4%.

So MP-S2 accounts for 830 of 3,703 — 22.4%, matching your arithmetic. The remaining ~2,870 come predominantly from the **TP-S1/S4/S5 kinematic signature cluster**, which fires together on the same beacons.

## DQ-FPR2 — concentrated or uniform?

**Emphatically concentrated.**

```
  distinct honest vehicle IDs scored     : 27
  distinct honest vehicle IDs in FP set  : 19

     vid      FP   honest beacons   per-vid FPR
     196    1011             1073        0.9422
     191     918             1146        0.8010
      98     622              622        1.0000     <-- every beacon flagged
     202     453              868        0.5219
     195     375             1339        0.2801
      32      40              541        0.0739
     154      35             2337        0.0150
     205      31             1377        0.0225
     171      30              646        0.0464
     173      30              876        0.0342

  top-5  = 91.3% of all FPs
  top-10 = 95.7% of all FPs
```

**Five vehicles produce 91.3% of the false positives.** This is identity-specific contamination, not global miscalibration. Note also that only **27 distinct honest vehicles are ever scored** at this condition — the honest population reaching the detector is far smaller than the 120 honest vehicles in the simulation.

## DQ-FPR3 — are the top-FP vehicles impersonation targets?

**Yes — and this confirms your hypothesis.**

```
     vid      FP    forged as   same RSU?   time overlap?
     196    1011           a4          no             YES
     191     918           a4          no             YES
      98     622           a4          no             YES
     202     453            -           -               -
     195     375            -           -               -

  FPs on vehicles that ARE impersonation targets: 2581/3703 = 69.7%
```

The three worst offenders are all a4 impersonation targets with confirmed temporal overlap between the forged beacons and their own flagged beacons. **69.7% of all false positives are the detector correctly reacting to a real impersonation signal, scored as an error because the victim's own beacon carries `gt_pois = 0`.**

The RSU differs because a4 forges the victim's ID at the *attacker's* location, which is served by a different RSU — that displacement is itself part of the signal.

**Answer to "where are the other 2,870 coming from":** not from a global miscalibration. ~69.7% are impersonation victims; the mechanism is the TP-S1/S4/S5 kinematic cluster firing on victims whose kinematic state is being contradicted by forged beacons under their own identity.

---

# Issue 2 — a1

**Correction first, because it changes the premise.** Your letter describes a1 as *"trajectory poisoning via htis malicious vehicle"*. In the code, **a1 = TP-S1 = malicious *RSU* trajectory poisoning**. Malicious *vehicle* trajectory poisoning is **a2 (TP-S2)**. See DQ-VAR4.

## DQ-A1-1 — component values for missed a1 beacons (30 s / ρ_a=0.60, where recall = 0.600)

```
  a1 beacons = 810   detected = 486   MISSED = 324   recall = 0.600

  for the 324 missed:
    psi_n      mean = 0.0000   p50 = 0.0000     <-- signatures completely silent
    S/theta_S  mean = 0.4562   p50 = 0.3520
    ae_norm    mean = 0.6720   p50 = 1.0000     <-- the AE IS firing
    phi        mean = 0.2895   p50 = 0.3654   p90 = 0.4460   max = 0.4928

    phi in [0.35, 0.45] (just below threshold) : 150/324 = 46.3%
    phi < 0.10 (nowhere near)                  : 70/324  = 21.6%
```

**The AE is working — `ae_norm` p50 = 1.0000, fully saturated.** The problem is that ψ contributes exactly zero and Φ lands just under threshold for nearly half the missed beacons (max = 0.4928, within 0.008 of firing). These are not undetectable; they are marginally under-weighted.

## DQ-A1-2 — a1 routing breakdown

```
  khat=-1  (GLOBAL FALLBACK)   284   35.1%   lambda = (psi 0.507, gat 0.186, ae 0.307)
  khat= 2  (a3 weight set  )   212   26.2%   lambda = (psi 0.031, gat 0.950, ae 0.019)
  khat= 6  (a7 weight set  )   130   16.0%   lambda = (psi 0.450, gat 0.450, ae 0.100)
  khat= 0  (a1 weight set  )    82   10.1%   lambda = (psi 0.250, gat 0.150, ae 0.380)
  khat= 3  (a4 weight set  )    72    8.9%
  khat= 1  (a2 weight set  )    30    3.7%

  of the MISSED a1:  khat=-1 : 194     khat=6 : 130
```

**Only 10.1% of a1 beacons reach their own weight set.** Your dilution hypothesis is correct and worse than stated:

- 35.1% fall to global fallback (λ_ae = 0.307 instead of 0.380)
- **26.2% are misrouted to the a3 set, where λ_ae = 0.019 — the AE is effectively switched off**
- Every one of the 324 missed beacons is either in fallback (194) or the a7 set (130). **Not a single beacon routed to the a1 set was missed.**

a1's recall is therefore bounded by classification accuracy, not by AE quality.

---

# Issue 3 — blended MCC

## DQ-MCC1 — MCC excluding a3 ghosts (300 s / ρ_a=0.40, OR flag OFF)

```
  a3 ghost beacons = 20795   detected = 1113   ghost recall = 0.054

  blended MCC, ALL beacons        = 0.4831    TP/FP/TN/FN = 66483/3703/19931/23829
  blended MCC, a3 GHOSTS EXCLUDED = 0.7789    TP/FP/TN/FN = 65370/3703/19931/4147
  delta = +0.2958
```

**0.7789 — below the 0.80 threshold you set, but close.** Excluding ghosts removes 19,682 of 23,829 false negatives (82.6% of all misses), which quantifies the ghost problem precisely: ghosts are the overwhelming majority of what the system fails to detect.

The residual gap from 0.7789 to 1.0 is not ghosts — it is the 3,703 false positives (concentrated in 5 impersonation victims, per DQ-FPR2/3) and the remaining 4,147 non-ghost misses.

---

# Variant coverage (DQ-VAR1 – DQ-VAR7)

## DQ-VAR1 — a5/a7 scored-beacon count, and exactly where they are dropped

```
  gt_atk values EVER observed, 300 s / rho_a=0.40 (113,946 beacons):
     gt_atk=0 : 23634      gt_atk=1 : 23172     gt_atk=2 :  6828
     gt_atk=3 : 25856      gt_atk=4 : 32589     gt_atk=6 :  1867
     gt_atk=5 : ZERO       gt_atk=7 : ZERO
```

**Confirmed: zero scored beacons for a5 and a7.** The attacks *do* execute — 17,789 `[TP-S3-CTRL]` and 25,002 `MP-S4` events — but never reach the confusion matrix. Two independent causes:

**Cause 1 — the attack applies a null transformation by design.** `stealthy_control_plane = true` is the default (`02_config_globals.h:184`). In `08_detection_engine.h:2709` (a5) and `:2647` (a7):

```cpp
if (stealthy_control_plane) {
    fake_px  = real_px;      // unchanged
    fake_py  = real_py;      // unchanged
    fake_spd = real_spd;     // unchanged
}
```

The code comment is explicit: *"the vehicle→RSU beacon is left plausible (unchanged) so beacon-level detectors (Ercan/Sharma/ψ) are blind… Only CP-DETECT's controller-vs-RSU consensus catches it."* Observed output confirms it:

```
[TP-S3-CTRL] controller corrupted V37 pos(2341.860,1142.856)→(2341.860,1142.856) spd 15.860→15.860
```

Position and speed identical. **The beacon is not modified at all.**

**Cause 2 — the tagging happens after the detection window is filled.** `SetIsPoisoned(true)` / `SetAttackType(5)` *are* called (`:2745-2746`), but:

```
  HandleBeaconReceived()        spans lines 2473 - 3337   (a5 gate :2709, a7 gate :2647)
  ipfs_push_and_maybe_flush()   called at  line 3947      (a LATER function, past :3338)
```

The RSU scoring window is populated at `:3947` with `(int)tag.GetAttackType()` from the **RSU-side path**, which runs before the controller-side poisoning in `HandleBeaconReceived`. So the window records the pre-poisoning tag: `gt_atk = 0`, `gt_pois = 0`.

**Consequence:** a5/a7 beacons are scored as **honest**, and contribute to the honest population and its false-positive count.

## DQ-VAR2 — per-variant MCC (ρ_a=0.40, 30 s, D6)

```
  variant        TP    FP     TN     FN   recall      MCC
  a1 TP-S1      380   140   1100    170    0.691   0.5874
  a2 TP-S2        0   140   1100      0      n/a   UNDEFINED
  a3 MP-S1     1715   140   1100   2071    0.453   0.3038
  a4 MP-S2     1106   140   1100      4    0.996   0.8838
  a5 TP-S3        0   140   1100      0      n/a   UNDEFINED
  a6 MP-S3      170   140   1100      0    1.000   0.6975
  a7 MP-S4        0   140   1100      0      n/a   UNDEFINED
```

**Important distinction on a2.** a2 shows zero beacons *at this specific configuration and seed only*. It is present at other conditions — 699 beacons at 30 s/ρ_a=0.60 and 6,828 at 300 s/ρ_a=0.40. Its absence here is sampling, not structural. **a5 and a7 are absent at every configuration tested**, which is structural.

## DQ-VAR3 — TTD per variant

```
  variant        onset   1st detect        TTD
  a1 TP-S1       7.225        7.225      0.000 s
  a2 TP-S2         n/a        never     INFINITY   (no beacons at this config)
  a3 MP-S1       7.023        7.060      0.037 s
  a4 MP-S2       7.225        7.225      0.000 s
  a5 TP-S3         n/a        never     INFINITY   (no beacons exist, any config)
  a6 MP-S3       7.941        7.941      0.000 s
  a7 MP-S4         n/a        never     INFINITY   (no beacons exist, any config)
```

Where a variant is detectable, detection is effectively immediate (0.000–0.037 s).

## DQ-VAR4 — code ↔ paper mapping, and the mismatch

Verbatim from `02_config_globals.h:106-112`:

```
  1 = TP-S1 : Malicious RSU trajectory poisoning            (Fig 3.1)
  2 = TP-S2 : Malicious vehicle trajectory poisoning        (Fig 3.2)
  3 = MP-S1 : Sybil via compromised RSU                     (Fig 3.4)
  4 = MP-S2 : Sybil via vehicle impersonation               (Fig 3.5)
  5 = TP-S3 : Control-plane trajectory poisoning            (Fig 3.3)
  6 = MP-S3 : MitM data-plane mobility pattern poisoning    (Fig 3.6)
  7 = MP-S4 : Control-plane global mobility model poisoning (Fig 3.7)
```

Mapping to the variant list in your letter:

```
  your #1 trajectory poisoning via malicious vehicle   -> code a2   (NOT a1)
  your #2 trajectory poisoning via compromised RSU     -> code a1   (NOT a2)
  your #3 trajectory poisoning via malicious controller-> code a5
  your #4 Sybil via compromised RSU                    -> code a3
  your #5 Sybil via vehicle impersonation              -> code a4
  your #6 MitM                                         -> code a6
  your #7 control-plane poisoning                      -> code a7
```

**a1 and a2 are transposed relative to your ordering.** Every per-variant result in the paper depends on this alignment, and Issue 2 of your letter was written against a1 = "malicious vehicle" when the code's a1 is malicious RSU.

## DQ-VAR5 — does a5 inject at the beacon layer?

**No. It operates only above the beacon layer, and in the default configuration it does not modify the beacon at all.** Two reasons, both above (DQ-VAR1): `stealthy_control_plane = true` sets `fake = real`, and the controller-side tagging in `HandleBeaconReceived` occurs after the RSU window is filled.

**The paper's claim that the system detects controller-compromise attacks is not supported by the beacon-path simulation.** The code's own design intent is that CP-DETECT — controller-vs-RSU consensus — is the mechanism for a5/a7, not the beacon detectors. In this run `CP-DETECT` appears once.

## DQ-VAR6 — how does a7 manifest at the RSU beacon-window level?

**It does not.** a7 (`:2647`) follows the identical stealthy branch: `fake_spd = real_spd`, `fake_hdg = real_hdg`, `shift = 1.0`. No beacon content transmitted by any vehicle or RSU is changed. Its effect is confined to controller-side decisions (the downlink continues issuing `WRONG_ROUTING`).

**There is no signal the RSU beacon-window pipeline could use to detect a7.** Any per-variant detection claim for a7 based on the beacon path is unsubstantiated.

## DQ-VAR7 — per-variant beacon counts in `beacon_log.csv`

```
  rows = 1029  (combined mode, rho_a=0.40, 30 s)
  attack_number column : {0: 1029}          <-- global config value, not per-beacon
  attacker_class column: {2: 648, 4: 142, 1: 108, 0: 95, 3: 36}
```

`beacon_log.csv` stores the **global** `attack_number` (0 in combined mode), so it cannot report per-variant counts directly. The per-variant label lives in `attacker_class`:

```
  class 1 = MALICIOUS_VEHICLE     (a2, a4)   : 108
  class 2 = COMPROMISED_RSU       (a1, a3)   : 648
  class 3 = MITM                  (a6)       :  36
  class 4 = MALICIOUS_CONTROLLER  (a5, a7)   : 142
```

**a5/a7 beacons are not zero in `beacon_log.csv` — there are 142 of them.** This is because `log_beacon_to_csv` is called at `:3103`, *inside* `HandleBeaconReceived` and *after* the a5/a7 poisoning, so it sees the tagged beacon. But `ipfs_push` at `:3947` runs in the earlier RSU-side function and records the same beacons as honest.

**The two logs disagree with each other.** `beacon_log.csv` says 142 controller-attack beacons; the detection pipeline says zero. This inconsistency should be resolved before any per-variant claim is published.

---

# Summary of what these thirteen answers establish

1. **The 300 s FPR is not a global calibration problem.** It is 5 vehicles, 91.3% of FPs, 69.7% of them impersonation victims being correctly flagged and scored as errors.
2. **a1 is limited by routing, not by the AE.** The AE saturates (ae_norm p50 = 1.0) on the beacons that are missed; only 10.1% of a1 reaches its own weight set, and no beacon that was correctly routed was missed.
3. **Excluding ghosts, MCC is 0.7789** — the ghost problem accounts for 82.6% of all missed detections.
4. **a5 and a7 cannot be detected by the beacon pipeline, by design.** The stealthy default applies a null transformation, and the controller-side tag never reaches the detection window. Any paper claim of beacon-path detection for these two variants is unsupported.
5. **The code↔paper variant mapping is transposed for a1/a2** and must be corrected before per-variant results are published.
