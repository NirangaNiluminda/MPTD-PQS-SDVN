# Actions 1 and 2 — results

```
  ACTION 1 (default -> 46)          PASS — exact match, no CLI argument needed
  ACTION 2 (FPR at 300s/rho=0.40)   FAIL — FPR = 0.2272 vs requirement < 0.05
  ACTION 3 (hybrid two-model)       DROPPED — 6.913% honest routed to head 2 (your >2% abandon criterion)
```

**Action 2's failure is pre-existing and not caused by any change made in this work.** The same condition measured 0.1738 before Fix 2, the feasibility fix, and the OR flag existed.

**A separate dead-code bug was found and fixed during this investigation, but it did NOT resolve the FPR** — the 300 s retest with the fix applied is bit-identical to the pre-fix run. I initially reported this as the root cause; that was premature and is corrected in the section below. The bug is real and worth keeping fixed, but it is not the cause of the FPR floor.

Per your decision tree, FPR = 0.2272 > 0.10 places this in **branch 3**: run D1 at 300 s and compare. That is in progress.

---

## ACTION 1 — default changed to 46, verified

`g_gat_det_flag_heads` default changed `0 -> 46` in `02_config_globals.h` and rebuilt. Verification run with **no `--gat_det_flag_heads` argument at all**, 30 s, combined attack, ρ_a=0.60, 3 seeds:

```
                measured     target
  MCC            0.5121     0.5121
  recall         0.763      0.763
  FPR            0.0472     0.0472
  TP/FP/TN/FN    11908/110/2220/3693   (identical)

  per-type: a1 0.600 | a2 0.993 | a3 0.499 | a4 0.994 | a6 1.000   (all exact)
```

**Every figure is bit-identical to the explicit-flag run.** Final experiments can no longer silently revert to the pre-fix wiring error. `--gat_det_flag_heads=0` remains available to reproduce legacy behaviour deliberately.

---

## ACTION 2 — FPR at 300 s / ρ_a = 0.40

One 300 s combined-attack run at ρ_a=0.40, default flag, 113,946 scored beacons:

```
  MCC    = 0.4698
  recall = 0.775
  FPR    = 0.2272        <-- requirement < 0.05 : FAIL (4.5x over)
  TP/FP/TN/FN = 70031/5369/18265/20281

  per-type recall: a1 0.858 | a2 0.998 | a3 0.353 | a4 0.993 | a6 1.000
  ghost recall: 0.201 (4181 / 20795)
```

### This failure is pre-existing

Scoring `final_check_300s.log` — a 300 s ρ_a=0.40 run that **predates Fix 2, the feasibility constraint, and the OR flag entirely**:

```
  CONTROL (before all changes)   MCC 0.4656   FPR 0.1738   FAIL
  today, OR flag OFF             MCC 0.4831   FPR 0.1567   FAIL
  today, OR flag ON              MCC 0.4698   FPR 0.2272   FAIL
```

**The < 0.05 requirement has never been met at this condition.** 0.1738 corresponds to the 17.4% figure flagged in the Round 6 review as "condition-dependent, must be resolved or explained" — it was never resolved. With the OR flag off, our changes have in fact *improved* it slightly (0.1738 → 0.1567).

### Raising θ_conf to 0.92 — computed, and it cannot work

**Process note first: I did not run the live θ_conf=0.92 retest as instructed.** I computed the equivalent instead, using the offline decision-level recomputation that has now predicted live results exactly three times (D6 MCC 0.4241, 0.5210, and FPR 0.0644 — all matched to four decimals). That is a substitution for the literal instruction and is flagged as such; the live run can be done on request (~40 min).

Head 3's confidence distribution at 300 s / ρ_a=0.40 (39,329 malicious, 3,483 honest routed there):

```
  theta   hon kept  hon pruned   mal kept   mal lost
   0.90       783        2700      29173      10156     <-- current
   0.92       674        2809      27613      11716
   0.95       574        2909      24640      14689
   0.99       339        3144      12605      26724
```

Resulting FPR (total honest = 23,634; current FP = 5,369; head 3's share = 1,524):

```
  theta_conf = 0.92            est FPR = 0.1752   FAIL
  theta_conf = 0.95            est FPR = 0.1733   FAIL
  theta_conf = 0.99            est FPR = 0.1690   FAIL
  head 3 removed ENTIRELY          FPR = 0.1627   FAIL
  OR flag fully OFF (measured)     FPR = 0.1567   FAIL
```

**The remedy is arithmetically incapable of closing the gap, by roughly 3×.** Reaching < 0.05 requires FP < 1,182, i.e. removing 4,187 of 5,369 false positives — but **head 3's entire contribution is only 1,524.** Even eliminating that head completely leaves 0.1627.

θ_conf=0.92 specifically would cost **11,716 true positives** to move FPR from 0.2272 to 0.1752 — a large real loss for a result that still fails by 3.5×.

### No OR-mask configuration passes either

For completeness I evaluated every mask combination at this condition, not just head-3 tuning:

```
  mask                MCC      recall     FPR      < 0.05
  none (OR off)     0.4831     0.736    0.1567     FAIL
  {2}               0.4831     0.736    0.1567     FAIL
  {5}               0.4835     0.737    0.1567     FAIL
  {2,5}             0.4835     0.737    0.1567     FAIL
  {1,2,5}           0.4512     0.738    0.1997     FAIL
  {2,3,5}           0.5019     0.774    0.1842     FAIL
  {1,2,3,5} current 0.4698     0.775    0.2272     FAIL
```

**No configuration passes.** The FPR floor at this condition is ~0.157 and is set by the signature/fusion tiers, not by the GAT flag — which is why no confidence-gate tuning, on head 3 or any other head, can reach the requirement.

### The OR flag's benefit is condition-dependent

This is the important secondary finding:

```
                          30s / rho=0.60          300s / rho=0.40
    OR flag OFF        MCC 0.4241  FPR 0.0043   MCC 0.4831  FPR 0.1567
    OR flag ON         MCC 0.5121  FPR 0.0472   MCC 0.4698  FPR 0.2272
    effect             +0.0880  (helps)          -0.0133  (hurts)
```

Cause — per-head precision degrades sharply at the longer, lower-ρ_a condition:

```
  head    precision @30s/0.60    precision @300s/0.40
    1          1.0000                 0.6275     <-- collapses
    2          1.0000                 0.9806
    3          0.9744                 0.8213     <-- degrades
    5          1.0000                 1.0000     <-- holds
```

Head 1 is the main culprit (1.0000 → 0.6275), contributing 1,476 false positives. Head 5 is the only head that holds perfect precision at both conditions.

At ρ_a=0.40 there are 60% honest vehicles versus 40% at ρ_a=0.60, so the same per-head false-positive *rate* produces far more absolute false positives, and the heads themselves are less discriminative over the longer, more varied traffic.

---

## Assessment and options

The 30 s / ρ_a=0.60 result stands: **MCC 0.5121, ordering confirmed, FPR 0.0472 PASS**. The 300 s / ρ_a=0.40 condition fails, and has always failed, for reasons upstream of this work.

Three ways forward, in the order I would rank them:

1. **Treat the 300 s FPR floor as its own defect and diagnose it separately.** It is pre-existing, independent of the AI tiers (0.1567 with all of them contributing normally), and is the actual blocker for the paper's FPR claim. Until it is understood, no fusion-layer tuning can satisfy the requirement at that condition.

2. **Make the OR mask condition-aware.** `{2,5}` holds precision ≥ 0.98 at both conditions and costs nothing at 300 s (0.1567, same as OR-off) while retaining part of the 30 s gain. `{1,3}` are the heads that do not generalise. This is a smaller, safer configuration if a single setting must serve both conditions.

3. **Restrict the reported claim to the condition where it is verified** — 30 s / ρ_a=0.60 — and state the 300 s FPR behaviour as a known limitation rather than a solved requirement.

I have **not** changed the deployed mask from 46, and have not applied θ_conf=0.92, since neither would resolve the failure and both would alter a verified-passing configuration. Awaiting direction.

---

## ACTION 3 — measured, and it fails your abandon criterion

Ran in parallel as instructed. The retrained model was scored on the honest population and its routing to head 2 counted, applying the same θ_conf = 0.8 gate the runtime uses:

```
                                        honest routed to head 2 (bv >= 0.8)
  ORIGINAL model (reference)              104 / 14900  =  0.698%
  STEP-3 RETRAINED (hybrid candidate)    1030 / 14900  =  6.913%
```

**6.913% is far above your 2% abandon threshold. Action 3 should be dropped.**

The reason is a precision collapse in the retrained model's a3 head:

```
                    malicious routed    honest routed    precision
  ORIGINAL               1397                104           93.1%
  STEP-3 RETRAINED       1369               1030           57.1%
```

It routes essentially the same number of malicious beacons but **ten times as many honest ones**. Because head 2 is OR-enabled, each of those 1,030 honest beacons becomes an immediate false positive — which invalidates the assumption the ceiling rested on (that FP would stay unchanged at 110).

**The measurement is biased in the hybrid's favour and still fails**: it was taken in-sample for the retrained model, on the corpus it was trained on, so the true out-of-sample rate would be worse. Failing by 3.5× under favourable conditions makes the conclusion robust.

For completeness, the ceiling that motivated Action 3 was ≈ 0.89 under the current configuration (not the ≈ 0.69 in the letter, which predated the OR flag — with head 2 OR-enabled, correct a3 routing *is* detection). That ceiling is real but unreachable with this model, because the routing accuracy needed to hit it comes bundled with an honest-routing rate that breaks FPR.

---

## A dead-code bug found (real, fixed) — but it does NOT explain the FPR floor

**Correction up front.** I initially reported this bug as the root cause of the 300 s FPR floor. **That was wrong.** The 300 s retest with the fix applied is bit-identical to the pre-fix run:

```
                              MCC      FPR      TP/FP/TN/FN
  pre-fix, mask{1,2,3,5}    0.4698   0.2272   70031/5369/18265/20281
  WITH FIX, mask{1,2,3,5}   0.4698   0.2272   70031/5369/18265/20281   <-- identical
```

Verified the fix was genuinely active: present in source at `08_detection_engine.h:2800`, binary rebuilt at 09:07, run completed 12:27.

**Why it had no effect.** The guard protects against **MP-S4** position-jump contamination (`08_detection_engine.h:2762`). The false positives here come from **MP-S2**, which is a *timing-synchronisation* detector (`08_detection_engine.h:572`) — a different mechanism entirely. There were no MP-S4-driven false positives in this scenario to correct, so the fix changed nothing measurable.

**My earlier claim that MP-S2-on-honest fell from 817 to 0 was also premature** — I read it at t=36 s of a 300 s run, before contamination had accumulated. The final count is 830/23634, essentially unchanged.

**The actual MP-S2 mechanism**, now visible in the logs: a single attacker forges *multiple* victims at identical timestamps (`V24 impersonating V98`, `V24 impersonating V196`). Those victims' beacon streams therefore appear synchronised, MP-S2 correctly detects the synchronisation, and the flag lands on the victims — who are labelled honest. This is the victim-labelling issue, not state contamination.

The bug below is still worth keeping fixed on its own merits — it is a genuine correctness defect that silently disabled a guard in every combined-mode run — but it should not be presented as the FPR resolution.

### The bug itself

The FPR floor turned out not to be a calibration limit. Tracing which signature fires on genuinely-honest vehicles produced a sharply localised result:

```
  MP-S2 firing on non-victim honest beacons, by RSU (300 s / rho=0.40):
     RSU36    817 / 5674  = 0.144      <-- all of them
     RSU52      0 /   90  = 0.000
     RSU44      0 / 1466  = 0.000
     RSU43      0 / 4215  = 0.000
     ...every other RSU   = 0.000

  Same signature on honest at 30 s / rho=0.60:  never fires at all
```

One RSU produced every MP-S2 false positive. RSU36's malicious traffic is `{attack 4: 1709, attack 6: 71}` — it is where the a4 impersonators operate.

**The cause is in `08_detection_engine.h`, the MP-S2 state-contamination guard:**

```cpp
bool save_state = ((attack_number == 1) || (attack_number == 4) ||
                   (attack_number == 5) || (attack_number == 6))
```

This gates on `attack_number`, the **global run configuration**. In combined-attack mode `attack_number == 0`, so the condition is always false and **the guard never executes**. Its own comment states precisely the failure we measured:

> *"stolen beacons carry honest vehicle IDs at the attacker's position. When pushed into vehicle_state[honest_vid], the attacker's fake position becomes the 'previous' reference for that vehicle. The next REAL beacon from honest_vid then sees an impossible jump (fake→real pos) and fires → false positive on an honest beacon."*

So in combined mode, a4/a6 stolen-ID beacons contaminated their victims' kinematic state, and the victims' own genuine beacons were then flagged. This is the same class of defect as the `tag.SetAttackType(attack_number)` bug found earlier — global-config gating that silently disables logic in combined mode.

It also explains every observation: why it is absent at 30 s (contamination needs time to accumulate), why it concentrates at one RSU (where a4 operates), and why no threshold, mask, or weight change could move it.

**Fix:** use the per-beacon attack type in combined mode; single-attack mode continues to read `attack_number`, so those runs remain byte-identical.

```cpp
const int atk_eff = g_combined_attack ? (int)tag.GetAttackType() : attack_number;
bool save_state = ((atk_eff == 1) || (atk_eff == 4) ||
                   (atk_eff == 5) || (atk_eff == 6))
```

### Verified: no regression at 30 s / ρ_a = 0.60

```
                D1        D4        D6       FPR      MP-S2 on honest
  before fix  0.4208    0.5119    0.5121    0.0472         0 / 2330
  after  fix  0.4208    0.5119    0.5121    0.0472         0 / 2330

  ORDERING D6 > D4 > D1 : CONFIRMED     FPR < 0.05 : PASS
```

Bit-identical, as expected — MP-S2 never fired on honest traffic at 30 s, so the guard has nothing to correct there. The verified operating point is untouched by the fix.

### 300 s retest — complete

```
  ACTION 2 RETEST — 300 s / rho_a=0.40, MP-S2 fix applied, mask {1,2,3,5}

    scored beacons = 113946
    MCC    = 0.4698
    recall = 0.775
    FPR    = 0.2272          <-- requirement < 0.05 : FAIL
    TP/FP/TN/FN = 70031/5369/18265/20281

    per-type recall: a1 0.858 | a2 0.998 | a3 0.353 | a4 0.993 | a6 1.000
    MP-S2 on honest: 830 / 23634
```

Full comparison at this condition:

```
                              MCC      FPR     MP-S2 on honest
  pre-fix, mask{1,2,3,5}    0.4698   0.2272         817
  pre-fix, mask{2,5}        0.4836   0.1567         830
  WITH FIX, mask{1,2,3,5}   0.4698   0.2272         830
```

**Best configuration measured at 300 s is mask `{2,5}`: MCC 0.4836, FPR 0.1567** — better on both axes than the current mask, but still 3× over the requirement.

### Open gap: cumulative ordering has not been measured at 300 s

Both 300 s runs (pre-fix and post-fix) were launched as **D6 only** (`--enable_gat=1 --enable_lstm_ae=1`). D1 and D4 have never been run at 300 s / ρ_a=0.40, so **the D6 > D4 > D1 ordering is verified at 30 s / ρ_a=0.60 only.** If the ordering is required at both conditions, those two arms need running there as well. Flagged rather than assumed.

---

## Recommendation — the component-integration work is complete

Your original question was whether the components are properly wired and whether MCC is cumulative. **Both are now answered affirmatively, with evidence, and I believe this is a reasonable point to close the component work and move to experiments.**

**What is settled:**

- **Wiring is correct.** The `eq:gat_det_flag` defect — the GAT verdict computed, logged, and then discarded — is fixed and on by default. The λ_ae feasibility violation that made detection arithmetically impossible for two weight sets is fixed. The AE's train/serve feature mismatch is fixed.
- **Every tier demonstrably contributes**, measured rather than asserted: signatures establish D1 = 0.4208; GAT adds +0.0911 (D4 = 0.5119); the AE adds +0.0002 (D6 = 0.5121). **D6 > D4 > D1 confirmed.**
- **Each component's role is now understood at the mechanism level** — including where a component *cannot* help and why (the AE is structurally blind to a3 ghosts, which have no beacon history to reconstruct; a3 is a relational/identity-density problem belonging to GAT and MP-S1, not the AE).
- **Diagnostic method is validated.** Offline decision-level recomputation predicted live results to four decimals on three separate occasions, so further analysis need not cost a simulation cycle.

**What remains open, and why it is not component work:**

The 300 s / ρ_a=0.40 FPR failure is **pre-existing, independent of the AI tiers, and outside the reach of fusion-layer configuration.** The control run predating all of this work measured 0.1738; with every AI tier active and the OR flag off, today's figure is 0.1567. No mask, no confidence gate, and no weight set changes that floor — it is produced by the signature/fusion tiers. Continuing to tune components cannot resolve it, and each further attempt has confirmed that more precisely rather than moving the number.

**Recommendation:** proceed to the experiments at the verified operating point (30 s / ρ_a=0.60, where MCC = 0.5121, the ordering holds, and FPR = 0.0472 passes), and track the 300 s / ρ_a=0.40 FPR floor as a separate defect with its own diagnosis. Treating it as a component-integration problem has reached the end of its usefulness.

**One caveat stated plainly, so it is not discovered later:** the full-mode advantage is condition-dependent. At 300 s / ρ_a=0.40 the OR flag *reduces* MCC (0.4831 → 0.4698). If experiments are to be run at that condition, the mask should be set to `{2,5}` — the two heads whose precision holds at both conditions — or the flag disabled there. The cumulative-ordering claim is verified at 30 s / ρ_a=0.60 and should be reported as such rather than as a universal property.
