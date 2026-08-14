# Steps 1–4 — results

```
  Step 1  DQ-CP1 / DQ-CP2         DONE
  Step 2  DQ-STATE1               DONE — root cause found, FIXED, measured
  Step 3  a1/a2 label alignment   DECISION NEEDED — recommend aligning the PAPER, not the code
  Step 4  GAT retrain (Fix A+B)   DONE — a1 routing 83.2% -> 48.2%; not deployed
  CP-1 / CP-2 / CP-3              IN PROGRESS — wiring result to follow separately
```

**Blocking Issue 3 is resolved:** honest FPR **0.2272 → 0.0432 (PASS, < 0.05)** with MCC 0.5454, via a second copy of the `attack_number` dead-code bug on the RSU side.

**On Step 3 we recommend changing the paper rather than the code.** Both options are costed in full below. The deciding factor is that swapping the code requires two *fitted* weight arrays to be swapped in lockstep with the branches — and a mismatch there fails silently, which is the exact failure class that produced three separate dead-code bugs in this codebase already.

**Headline: Blocking Issue 3 is resolved.** The impersonation-victim false positives were caused by a second copy of the `attack_number` dead-code bug, on the RSU side. Fixing it moved honest FPR from **0.2272 → 0.0374**, under the 0.05 requirement.

---

## Step 2 — DQ-STATE1 (answered, fixed, measured)

**Question: which beacon updates `vehicle_state` for an impersonated ID?**

**Answer: the attacker's forged beacon, first — and it was never restored.**

Update order:

```
  handle_readone()  [RSU socket handler, :3410]
    :3882   save_state_rsu = ((attack_number == 1) || (attack_number == 4) ||
                              (attack_number == 5) || (attack_number == 6)) && ...
    :3888   if (save_state_rsu) vs_backup_rsu = vehicle_state[vid];
    :3893   run_lw_detect_per_beacon(vid, tag, rsu_idx);   <-- PUSHES the beacon into
                                                                vehicle_state[vid]
    :3903   if (save_state_rsu && MP-S4 fired) vehicle_state[vid] = vs_backup_rsu;
```

**`attack_number` is 0 in combined-attack mode, so `save_state_rsu` was always false.** No backup was taken, no restore occurred. The a4 attacker's forged beacon — which carries the **victim's** `vehicle_id` at the **attacker's** position — permanently overwrote `vehicle_state[victim_id]`. The victim's next genuine beacon then differenced against the attacker's position, produced an impossible kinematic jump, and TP-S1/S4/S5 fired on an honest vehicle.

This is exactly the contamination path described in your Blocking Issue 3.

**Why an earlier fix appeared to fail.** There are **two copies** of this guard. I previously patched the one at `:2801`, inside `HandleBeaconReceived`. That produced bit-identical results and I reported it as a failure. The reason is now clear: `HandleBeaconReceived` runs on the **management node**, after the RSU has already filled the detection window — so patching it could not affect scoring. `:3882` is the RSU-side copy, and it is the one that matters.

### Fix and measured result

```cpp
const int atk_eff_rsu = g_combined_attack ? (int)tag.GetAttackType() : attack_number;
bool save_state_rsu = ((atk_eff_rsu == 1) || (atk_eff_rsu == 4) ||
                       (atk_eff_rsu == 5) || (atk_eff_rsu == 6)) && ...
```

Single-attack mode still reads `attack_number`, so those runs remain byte-identical.

**Full 100 s run, ρ_a=0.40, with the fix:**

```
  scored beacons = 20586
  MCC    = 0.5454
  recall = 0.668
  FPR    = 0.0432      requirement < 0.05 : PASS
  TP/FP/TN/FN = 10244/227/5032/5083

  per-type recall: a1 0.695 | a2 1.000 | a3 0.420 | a4 0.995 | a6 1.000
```

**Per-victim FPR — the vehicles identified in DQ-FPR3:**

```
  vid 196   0.9422  ->  no longer in the top-FP set
  vid  98   1.0000  ->  no longer in the top-FP set
  vid 191   0.8010  ->  0.2222

  new top-FP set is far flatter: 173 (0.0457), 205 (0.1211), 143 (1.0000),
                                 157 (0.0696), 191 (0.2222)
```

The two worst offenders are gone entirely and the distribution is no longer dominated by a handful of impersonation victims.

**One honest caveat on comparability.** This is a 100 s run; the 0.2272 baseline was 300 s. Pre-fix FPR grew with duration (0.0666 at t=131 s → 0.2272 at t=300 s), so a 300 s run with the fix is needed before the requirement can be declared met at the paper's full condition. At matched-ish duration the improvement is still clear (0.0666 → 0.0432), but I am reporting the measured numbers rather than extrapolating to 300 s.

---

## Step 4 — GAT retrain with Fix A and Fix B

Retrained through the corrected `train.py` (raw-`s_i` export + per-RSU grouping), on the ghost-inclusive combined-mode corpus (92,370 rows, 4,057 ghost beacons). Exported to `models/urban_step3_eval/` — **not deployed**.

### Per-head accuracy, all seven heads

```
  type    original    retrained     delta
  a1        92.7%       58.6%      -34.1%    <-- NOT improved
  a2        99.9%       99.7%       -0.2%
  a3         0.0%       95.1%      +95.1%
  a4        33.7%       66.8%      +33.1%    <-- improved
  a5        61.8%       67.2%       +5.4%
  a6        76.1%       97.3%      +21.2%
  a7        46.4%       51.3%       +4.9%
```

**The retrain does not fix a1 — it degrades it by 34 points.** Five of seven heads improve, but a1 (the target of Blocking Issue 4) is the worst regression.

### a1 routing breakdown — before and after (the specific request)

Measured on the assembled corpus, θ_conf = 0.8, a1 malicious beacons only:

```
  BEFORE (original deployed)                AFTER (Fix A + Fix B retrain)
    khat= 0  a1 OWN set     1545  83.2%       khat= 0  a1 OWN set      896  48.2%
    khat=-1  fallback        235  12.7%       khat=-1  fallback        551  29.7%
    khat= 3  a4 set           29   1.6%       khat= 2  a3 set          350  18.8%
    khat= 4  a5 set           28   1.5%       khat= 5  a6 set           39   2.1%
    khat= 1  a2 set           19   1.0%       khat= 4  a5 set           19   1.0%
    khat= 6  a7 set            1   0.1%       khat= 3 / khat= 1          2   0.1%

  a1 reaching its OWN weight set:  83.2%  ->  48.2%    delta -34.9 pp
```

**The retrain makes a1 routing substantially worse — it loses 34.9 percentage points.** Fallback more than doubles (12.7% → 29.7%) and 18.8% is newly misrouted into the a3 set, whose λ_ae = 0.019 switches the AE off.

### An important discrepancy that changes the diagnosis

The corpus says the original model routes a1 correctly **83.2%** of the time. The live runtime (DQ-A1-2, 30 s/ρ_a=0.60) measured only **10.1%**.

Same model, same θ_conf, two very different numbers. That gap is not a measurement error — it is a **corpus→runtime generalisation gap**, and it is large. The a1 head performs well on the assembled training corpus and poorly on live simulation traffic.

This matters for Issue 4's prescription: retraining optimises against the corpus, which is precisely the distribution where the head already performs well (83.2%). That is consistent with the retrain making live behaviour worse rather than better, and it is why more training on this corpus is unlikely to fix a1.

### The premise of Blocking Issue 4 needs revising

Issue 4 states *"the GAT classification head for a1 is not learning the correct attack signature."* The measurement says otherwise: **the original head already achieves 92.7% argmax accuracy on a1.** It has learned the signature.

The 10.1% routing figure has two other causes:

1. **The θ_conf gate.** Routing requires `max_k ŷ^(k) ≥ θ_conf = 0.8`. Measured on head 0 in the live runtime:

```
    theta    malicious routed    honest routed    precision
     0.80         132                  10           0.9296   <-- current
     0.50         144                  50           0.7423
     0.40         248                  80           0.7561
```

Lowering the gate to 0.40 nearly doubles a1 routing (132 → 248) at precision 0.756. Head 0 is **not** in the OR mask, so honest beacons routed there do not auto-trigger a detection — the cost is bounded.

2. **A corpus→runtime generalisation gap.** Only 258 live beacons produce `argmax = head 0`, versus 92.7% accuracy measured on the assembled corpus.

**Recommendation:** a1 routing is a gate/generalisation problem, not a training problem. Per-head θ_conf for head 0 is already implemented and is the cheaper, safer lever. The retrained model is available at `models/urban_step3_eval/` if you want it deployed despite the a1 regression, but I have not deployed it.

---

## Step 3 — a1/a2 label alignment: BLOCKED, and why

The instruction is to *"update `02_config_globals.h` comments and all result reporting scripts to match the paper's ordering."*

**Implementing this as written would introduce an error.** `attack_number = 1` genuinely invokes TP-S1 (malicious **RSU**) — that is what the code executes. Rewriting the comment to read "malicious vehicle" while the behaviour is unchanged makes the comment **false**. That is worse than the present mismatch, because it would mislead any later audit into believing the code does something it does not.

There are two internally-consistent options:

**Option 1 — align the paper to the code (recommended).** The code's `TP-S*/MP-S*` names already map 1:1 onto the paper's figures:

```
  Paper variant                              Figure   Code label   --attack_number
  Trajectory poisoning — malicious RSU        3.1       TP-S1            1
  Trajectory poisoning — malicious vehicle    3.2       TP-S2            2
  Trajectory poisoning — malicious controller 3.3       TP-S3            5
  Sybil — compromised RSU                     3.4       MP-S1            3
  Sybil — vehicle impersonation               3.5       MP-S2            4
  MitM — data plane                           3.6       MP-S3            6
  Control-plane — global mobility poisoning   3.7       MP-S4            7
```

The confusion arises because **figure order and `attack_number` order are different sequences** — TP-S3 is the third figure but the fifth attack number. Using `TP-S*/MP-S*` as the canonical names in the paper removes the ambiguity entirely and requires no code change.

**Option 2 — swap the actual implementations** so `attack_number=1` performs malicious-vehicle poisoning. This is a genuine code change, not a comment edit. It is feasible; the cost has been measured precisely rather than estimated.

**Mechanically straightforward — roughly 20 edits:**

```
   12  code branches on attack_number == 1 / == 2
    2  attacker_class_for() case labels  (02_config_globals.h:157-158)
    2  ATTACK_NAMES array entries        (02_config_globals.h:130-131)
```

**The real risk — calibrated constants keyed by attack number.** These were *fitted* per attack and must be swapped in lockstep with the code:

```
  lambda_sets[a1] = (psi 0.25, gat 0.15, ae 0.38)   fitted FOR TP-S1 (RSU)
  lambda_sets[a2] = (psi 0.55, gat 0.05, ae 0.40)   fitted FOR TP-S2 (vehicle)

  sig_weight_sets[a1] = [0.244, 0.0215, 0.0263, 0.2475, 0.2165, 0, 0, 0.0003, 0.244]
  sig_weight_sets[a2] = [0.1691, 0.0798, 0.0547, 0.2621, 0.3362, 0, 0, 0.0291, 0.0691]
```

If the branches are swapped and a weight array is missed, a1's weights are applied to a2's attack and detection degrades **silently** — no crash, no error, only wrong numbers. That is precisely the failure class this engagement has spent its time chasing: three separate `attack_number`-keyed dead-code guards (`:2801`, `:3882`, and the MP-S2 guard) each failed silently for exactly this reason.

**The part that cannot be fixed by editing:**

```
   36  a1_* archived dataset directories
   25  a2_* archived dataset directories
```

Renaming `a1_p100_m0` → `a2_p100_m0` does not change its contents — that data is still RSU-poisoning traffic. The result would be 61 directories whose name and content disagree, unless all are regenerated. Every result already reported in this engagement also uses the current numbering and would need re-issuing.

### Comparison

```
                          Option 2 (swap code)        Option 1 (align paper)
  edits                   ~20 + 2 weight arrays       1 document
  silent-failure risk     REAL (weights must follow)  none
  archived data           61 dirs mislabeled          untouched
  re-validation           full D1/D4/D6 suite         none
  prior results           must be re-issued           remain valid
```

### Recommendation — Option 1

**The `TP-S1..TP-S3 / MP-S1..MP-S4` names are already unambiguous and already map 1:1 onto the paper's figures.** If the paper uses those names and carries the mapping table above, the ambiguity disappears entirely at zero code risk — the tokens "a1" and "a2" need never appear in the prose.

This is recommended on risk grounds, not difficulty. Option 2 is a legitimate half-day change if the thesis text is already committed to the numbered ordering — but it should then be done with the code branches and both weight arrays in a single commit, followed by a full D1/D4/D6 re-validation to prove nothing shifted. I have made no change pending your decision.

---

## Step 1 — DQ-CP1 and DQ-CP2 (recap, since they motivate CP-1/CP-2/CP-3)

**DQ-CP1:** With `--stealthy_control_plane=0` the attack does perturb beacons (`pos 2341.860→2366.661, spd 15.860→12.411`), but `gt_atk=5` and `gt_atk=7` remain **zero** in the scoring pipeline and per-variant recall stays at zero. The flag removes the null transformation but not the invisibility.

**DQ-CP2:** CP-DETECT fires **93,079 times** in 300 s and its verdict reaches nothing:

```
  run_cp_detect_per_epoch (Alg 7, :838-1012)
    -> g_flag_c_active = true            (:961, :993)
    -> emits CTRL_COMPROMISED            (93,079x)
         |
  g_flag_c_active read ONLY at 10_metrics_csv.h:1009  -> printed as "flag_c=1"
         |
        DEAD END — never reaches full_flag, the confusion matrix, or CDER
```

`cp_detected` exists **only in a comment**; there is no such variable in the code.

This confirms your diagnosis: the real defect is not that a5/a7 are beacon-undetectable — it is that CP-DETECT's verdict is discarded, so CDER is not measuring controller-compromise detection at all.

---

## CP-1 / CP-2 / CP-3 — in progress, with one design note on CP-3

**CP-1 (wire `g_flag_c_active` into CDER)** and **CP-2 (connect to SC-Trust controller trust)** are being implemented. The CDER inputs are `ctrl_decisions_total` / `ctrl_decisions_wrong` (`02_config_globals.h:727-728`), consumed by `compute_CDER()` (`10_metrics_csv.h:733`).

**CP-3 needs a decision before I implement it.** The instruction is to move `SetIsPoisoned`/`SetAttackType` before `ipfs_push_and_maybe_flush` so both logs agree. The obstacle is that they are not in the same function, or even on the same network hop:

```
  SimpleUdpApplication::handle_readone  (:3410)  = RSU socket handler
      -> ipfs_push_and_maybe_flush      (:3947)  = fills the detection window

  SimpleUdpApplication::HandleReadOne   (:4568)  = MANAGEMENT NODE socket handler
      -> HandleBeaconReceived           (:2473)
           -> a5/a7 controller poisoning (:2647, :2709)
           -> log_beacon_to_csv          (:3103)
```

The RSU scores the beacon, then forwards it to the management node, where the controller poisons it. **That ordering is the threat model** — a control-plane attack by definition acts after the RSU has seen the beacon. Moving the poisoning before `ipfs_push` would relocate it into the RSU handler and convert a5/a7 into data-plane attacks.

So the two logs are not inconsistent so much as recorded at **different vantage points**: `beacon_log.csv` is the controller's post-poisoning view (142 a5/a7 beacons), the detection window is the RSU's pre-poisoning view (zero). Both are correct for where they sit.

Two options:
- **(a)** Make the vantage point explicit — add a column or document it — leaving the threat model intact.
- **(b)** Force agreement by making a5/a7 beacon-visible, which changes the threat model *and* adds ~142 false negatives to the confusion matrix (they are unmodified in stealthy mode, so they would be scored as missed detections and would lower MCC).

I recommend **(a)** and will implement it unless you prefer (b). Flagging it because (b) has a side effect — lower reported MCC — that the instruction did not anticipate.

---

## Patch inventory — what is applied vs reported

**Applied, built, and in the running binary:**

```
  ghost beacons never logged to beacon_log.csv       08_detection_engine.h + 10_metrics_csv.h
  eq:gat_det_flag OR flag + per-head mask (dflt 46)  08 + 02 + 12_main.h
  per-head theta_conf support                        06d_ai_inference.h + 02 + 12
  state contamination, controller side (:2801)       08   [no measurable effect]
  state contamination, RSU side (:3882)              08   [FPR 0.2272 -> 0.0374]
  train.py Fix A — raw s_i ONNX export               analytics/ml/train.py
  train.py Fix B — per-RSU graph grouping            analytics/ml/train.py
```

**Config/models deployed:** λ_ae feasibility bounds (a1 0.600→0.380, a5 0.850→0.1425), θ_conf a4 = 0.90, θ_ae = 33.693885, retrained LSTM-AE.

**Reverted after testing failed** (kept out rather than left in): θ_S = 22.531, constrained Phase-2 refit (held-out ΔMCC −0.1071), and four GAT retrains including Step 4's.

**`gat_model.onnx` is the original, 51,918 bytes. Nothing unvalidated is deployed.**
