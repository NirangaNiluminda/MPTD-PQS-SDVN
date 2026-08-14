# Response — Items 1–5, Step 3 and CP-3
**Date:** 2026-08-05 · **Branch:** `ml-review-fixes`
**STATUS: READY TO SEND.** All figures are measured. Item 1's root cause is
identified and fixed, and the on-chain detection chain now fires on the shipped
configuration (verified, §5.3/§5.6). Item 3 remains a failure against the
requirement and is reported as such. One decision is required from you (§8).

---

## 0. Summary

| Item | Requirement | Result |
|---|---|---|
| 1 | CP-1/CP-2 wired; a5/a7 CDER; SC-Trust decay | **ADVANCED — partially met.** Root cause found and fixed; `CFLAG`, controller exclusion and failover now fire on-chain. **Sustained trust decay still NOT achieved** — blocked by RSU witness density, needs your decision |
| 2 | θ_conf head 0 → 0.40 | **DONE — negative.** Do not deploy |
| 3 | FPR ≤ 0.05 at 300s | **NOT MET** — 0.2077 |
| 4 | D6 > D4 > D1 at 300s | **CONFIRMED** — 0.4918 > 0.4855 > 0.4802 |
| 5 | Do not deploy retrained GAT | **Agreed** — remains undeployed |
| Step 3 | Paper adopts TP-S1…MP-S4 | Accepted, paper-side, no code touched |
| CP-3 | Vantage column in `beacon_log.csv` | Accepted, not yet implemented |

---

## 1. Correction to the premise of your opening paragraph

Your letter states the FPR drop "from 0.2272 to 0.0432 is real and correctly
traced." **The trace is correct; the number does not survive to 300 s.**

`0.0432` was measured at **100 s**. FPR in this simulation is strongly
time-dependent:

| Sim time | D6 FPR |
|---|---|
| t = 111 s | 0.0506 |
| t = 250 s | 0.1968 |
| **t = 300 s (final)** | **0.2077** |

The RSU-side state-contamination fix reduced but did **not** eliminate the
growth. A residual contamination path remains and is now the largest obstacle to
the FPR requirement. We should not treat the 100 s figure as evidence of
compliance.

---

## 2. Item 3 — 300 s FPR and per-type recall · **REQUIREMENT NOT MET**

Combined attack, ρ_a = 0.40, 300 s, seed 1, full mode.

| Arm | MCC | FPR | Recall (overall) |
|---|---|---|---|
| D6 | 0.4918 | **0.2077** | 0.7821 |

**The 0.05 FPR requirement is missed by roughly 4×, so it cannot be claimed.**
See §1 for why the 100 s figure did not survive.

**Per-type recall** (paper names per your Step 3 decision), computed from the
fusion verdict against ground truth over all three arms:

| Attack | # | D1 | D4 | **D6** |
|---|---|---|---|---|
| TP-S1 — malicious RSU trajectory poisoning | 23 883 | 0.8655 | 0.8624 | **0.8845** |
| TP-S2 — malicious vehicle trajectory poisoning | 6 829 | 0.9908 | 0.9977 | **0.9977** |
| **MP-S1 — Sybil via compromised RSU** | **25 805** | **0.1901** | **0.3516** | **0.3516** |
| MP-S2 — Sybil via vehicle impersonation | 32 587 | 0.9613 | 0.9849 | **0.9903** |
| MP-S3 — MitM data-plane mobility poisoning | 1 867 | 1.0000 | 1.0000 | **1.0000** |

Three things follow that we think matter more than the headline MCC:

1. **MP-S1 is the weak point of the whole system**, not the FPR. At 25 805
   beacons it is the second-largest attack class, and D6 detects barely a third
   of it. Every other beacon-plane attack is at 0.88–1.00.
2. **The GAT is what addresses MP-S1** — recall nearly doubles from 0.1901 to
   0.3516 when it is enabled (D1 → D4), and the LSTM-AE adds nothing further on
   this class. Conversely the AE is what lifts TP-S1 (0.8624 → 0.8845, D4 → D6).
   The components are complementary rather than redundant, which is the
   justification for the D6 configuration.
3. **TP-S3 and MP-S4 do not appear in this table at all.** They are the
   control-plane attacks and, by design, leave the beacon payload unmodified —
   so they produce no poisoned beacon rows and no beacon-plane recall can be
   defined for them. They are detected on the CP-DETECT path instead (§5), not
   by fusion. We flag this explicitly rather than let the table imply 5 of 7
   attacks is the full picture.

---

## 3. Item 4 — D1/D4/D6 ordering at 300 s · **CONFIRMED**

Combined attack, ρ_a = 0.40, 300 s, seed 1. Metrics computed from the fusion
verdict (`full_anom`) against ground truth (`gt_pois`) — see §6 for why the
printed summary could not be used.

| Arm | FPR | Recall | **MCC** |
|---|---|---|---|
| D1 | 0.1390 | 0.7204 | 0.4802 |
| D4 | 0.2047 | 0.7744 | 0.4855 |
| D6 | **0.2077** | 0.7821 | **0.4918** |

- **Item 4 passes.** The cumulative ordering **D6 > D4 > D1 holds** at the
  paper's primary evaluation condition.
- **Item 3 fails.** FPR 0.2077 vs the 0.05 requirement — roughly 4× over. Recall
  improves monotonically with each component (0.7204 → 0.7744 → 0.7821), so the
  AI layer is contributing; the cost is a rising false-positive rate.

---

## 4. Item 2 — DQ-A1-NEW1 (θ_conf head 0 → 0.40) · **NEGATIVE RESULT**

Run against a **matched same-binary baseline** (identical command, only the
θ_conf value differs), D6, 30 s, ρ_a = 0.60, seed 1.

| | θ_conf = 0.80 (baseline) | θ_conf = 0.40 |
|---|---|---|
| Beacons routed to head 0 | 132 | 157 |
| …of which **a1** | **132** | **132** |
| …of which **honest** | **0** | **25** |
| Head-0 routing precision | **100 %** | **84.1 %** |
| a1 recall | 0.7273 | 0.7273 |
| honest FPR | 0.0139 | 0.0139 |
| overall MCC | 0.4529 | 0.4529 |

**Lowering the gate gains zero additional a1 beacons.** All 25 newly admitted
beacons are honest traffic. a1 beacons that miss the gate are not sitting in the
`[0.50, 0.80)` confidence band — only honest ones are.

By the criterion you applied to Action 3 (reject if > 2 % of honest traffic is
routed into an attack head), this fails: **25/720 = 3.47 % of honest beacons**,
with head-0 precision falling 100 % → 84.1 % for no measurable gain.

**Recommendation: do not deploy.** The students' *diagnosis* — that head-0
routing is the bottleneck — is supported by the data. This particular *lever* is
not the remedy. Note this also means Item 2 did not rescue the retrained model,
so the a1-routing problem (Item 5) remains open.

*Implementation note:* the `theta_conf_per_attack` key is **1-indexed**
(`k = attack − 1`), so head 0 is `"attack": 1`. Writing `"attack": 0` silently
changes nothing.

---

## 5. Item 1 — CP-1 / CP-2 · **ROOT CAUSE FIXED; PARTIALLY MET**

### 5.1 Wiring — complete
CP-1 credits CP-DETECT in CDER (`wrong = !g_flag_c_active`); CP-2 accumulates
controller misbehaviour evidence and decays controller trust at both CP-DETECT
firing sites.

### 5.2 a5/a7 dedicated test — measured
ρ_a = 0.40, 100 s, `--ctrl_compromise_onset=0.5` (required — at the default 0.0
the controller is compromised from the first beacon, leaving no "before" window).

**CDER before vs after controller-compromise onset:**

| Window | CLEAN_ROUTING | ATTACK_DETECTED | WRONG_ROUTING |
|---|---|---|---|
| Before (t < 50 s) | 92 932 (0.9369) | 6 263 (0.0631) | **0** |
| After (t ≥ 50 s) | 22 (0.0016) | 0 | **13 799 (0.9984)** |

Zero wrong control decisions before onset; **99.84 % after** — matching the
paper's expectation that attacks 5 & 7 drive CDER → 1.0.

```
CP-DETECT   = 5962 alerts over 11598 audited epochs, flag_c = 1
local ctrl_trust : 1.0 → 0.0000
CDER = 0.030 (345/11598)     TTD = 17.56 s
```

`CDER = 0.030` is **CP-1 operating as designed**, not a detection failure: with
crediting enabled, compromised decisions that CP-DETECT caught are scored as
detected rather than as control error. A matched CP-1 on/off pair is still
outstanding before we quote a single before/after CDER figure.

### 5.3 SC-Trust controller decay — **PARTIALLY ACHIEVED**

Once the root cause in §5.5 was corrected, the on-chain detection chain fires
end-to-end for the first time. All three runs are 30 s, ρ_a = 0.40, combined
attack, `ablation_mode=0`, seed 1 — identical apart from evidence-commit timing.

| | BC6 — before | BC7 — batching **off** (diagnostic) | **BC8 — fix, batching ON (shipped)** |
|---|---|---|---|
| `CFLAG` records | 0 | 1 | **1** |
| Controller exclusions | none | CTRL_2 | **CTRL_2** |
| Reassignment | none | CTRL_2 → CTRL_0 | **CTRL_2 → CTRL_0** |
| Tier-3 batching | on | **disabled** | **on** |
| Batched commits | 58 | — (2125 individual tx) | **219** |
| `MCC_full` | 0.422 | 0.4224 | **0.422** |
| `CDER` | 0.099 | 0.0991 | **0.099** |

```
CFLAG_CTRL_2_VEH_191_E7    ConflictCount=2  NumRSUs=2  ThresholdFP1=2
CTRLREASSIGN_CTRL_2_E7     excluded=CTRL_2  successor=CTRL_0
                           reason=cp_detect_conflict
[TIER3-SUMMARY] evidence_buffered=2125 batches_committed=219 (T_batch=10s N_commit=50)
```

**CP-DETECT now produces a durable on-chain verdict, an exclusion from
`C_trusted`, and an automatic controller failover — with batching left enabled.**
Detection metrics are unchanged to three decimal places, confirming the fix
altered evidence-commit timing only and not detection behaviour.

**Cost, stated plainly:** the targeted flush raises batched commits from 58 to
**219** (3.8×) for the same 2125 evidence entries, because a flush is forced
whenever a CP-DETECT check is pending. This is a real increase in the
transaction count that PBPO measures. It remains far below the 2125 individual
transactions that disabling batching would cost, so ~90 % of the batching
benefit is retained — but PBPO figures computed before this change will need
re-measuring.

**Sustained trust decay is NOT demonstrated, and we do not claim it.**
Controller trust dips when conflicts are recorded and then **recovers**:

| Controller | at E9 (during conflict, BC7) | final E26 (BC7) | **final E26 (BC8)** |
|---|---|---|---|
| CTRL_0 | TrustScore 0.9365, MeanConflict 0.0741 | 0.9999925, 0 | **0.9999999999, 0** |
| CTRL_3 | TrustScore 0.8600, MeanConflict 0.2000 | 0.9998979, 0 | **1.0, 0** |

The EMA of Eq 3.55 (`τ ← α·τ + (1−α)(1−meanConflict)`) pulls trust back toward
1.0 once conflicts stop. On-chain conflicts occurred only in epochs E7–E9 of 27,
because — per §5.5 — a vehicle has just **one** honest RSU witness per epoch in
97.8 % of cases, so the `f+1` quorum is reached only during a rare two-RSU
handoff. Local CP-DETECT fires 3887 times; the ledger can only witness a handful
of those.

Consequently `τ` never stays below `τ_min` for `T_rev` consecutive epochs, and
the trust-driven revocation path (as distinct from the flag-driven exclusion
above, which did fire) is still not exercised.

**Honest summary for Item 1:** the CP-DETECT → CFLAG → controller-exclusion →
reassignment chain is **demonstrated on-chain**. Sustained SC-Trust decay is
**not**, and is blocked by RSU witness density rather than by any defect we can
correct unilaterally — see the Eq 3.69 question in §5.5.

In-sim metrics for the same run, unchanged from the batched configuration
(`MCC_full = 0.4224`, `CDER = 0.0991`, `CDER_full = 0.3337`), confirming the fix
altered only the evidence-commit timing and not detection behaviour.

### 5.4 What we fixed to get this far

Two defects were found and corrected; both were required even to reach the
current state.

**(a) Blockchain registration.** Fabric rejected submissions with
`access denied: channel [mptdchannel] creator org [RSUMSP]`. Root cause was a
**stale duplicate private key** in one wallet identity's keystore; the gateway
daemon selects a key by unsorted directory order and signed with the one that did
not match its certificate. Fabric reports a signature mismatch as an org-level
denial, which disguised it as an MSP/channel fault. After removing the stale key:
**64/64 RSUs, 200/200 vehicles, 4/4 controllers, 268 on-chain records, 0
denials**, `GetActiveController → CTRL_0`.

**(b) The entire on-chain evidence path was inert.** `routing_test` defaults to
`true`, and gates the RSU ψ submission, the controller evidence submission, and
`CPDetectCheck`. With the default, `evidence_buffered = 0` despite detection
firing 2 112 times. Setting `--routing_test=false`:

| | before | after |
|---|---|---|
| TIER3 evidence entries | 0 | **2125** |
| batches committed | 0 | **58** |
| `CDER` | 0.5915 | **0.099** |
| `MCC_full` | not computed | **0.422** |
| on-chain `CTRL_0` trust | 1.0 (never moved) | 0.99999999 (moved) |

### 5.5 Root cause — **IDENTIFIED AND MEASURED**

Two hypotheses were tested and **disproved** before the real cause was found.

**Disproved 1 — ghost identities.** Controller evidence was being submitted for
Sybil ghost identities that are never registered (466 rejected transactions). A
guard removed all 466 rejections — `CFLAG` remained 0, metrics bit-identical.

**Disproved 2 — epoch-key mismatch.** Our leading hypothesis was that the RSU and
the controller derive *different* epoch keys (the RSU from its beacon-processing
time, the controller from the stored window timestamp), so `SUBM_` and `CSUBM_`
would never share a `(vid, epoch)` key and the conflict would be structurally
zero. **This is false.** Both values originate from the same `Simulator::Now()`
call within the same beacon-handling invocation, so they are identical. Confirmed
by direct ledger query — **178 of 183** vehicle-epoch pairs carry *both* records
under the same key, e.g.:

```
SUBM_VEH_36_E7_RSU_33    Psi = 0.15
CSUBM_VEH_36_E7          Phi = 0.182436
```

**The suppression mechanism also works correctly.** 122 of 183 pairs show the
intended asymmetry — the controller reporting benign (`Phi ≤ ψ_th = 0.09`) while
an RSU reports anomalous (`psi > 0.09`), e.g. `CSUBM_VEH_36_E12` with `Phi = 0`
against `Psi = 0.15`. So the controller genuinely lies on-chain, and the
directional conflict of Eq 3.68 does evaluate to 1 for those RSUs.

**The actual cause is a witness-count shortfall compounded by a commit-timing
race.** We censused every `(vid, epoch)` pair on the ledger after the run:

| Distinct RSU witnesses per (vid, epoch) | Pairs |
|---|---|
| 1 | **179** |
| 2 | 4 |

With `f+1 = 2`, a single-witness pair yields `conflict = 1 < 2` and can never
raise a flag. **97.8 % of all evidence pairs are therefore ineligible by
construction** — a vehicle is heard by one RSU at a time except during the brief
two-RSU handoff at a cell boundary.

All 4 eligible pairs involve the same vehicle and the same two RSUs. On the raw
ψ/Φ values, 2 of them reach the threshold:

```
VEH_191 E7 : Phi=0 (benign)  RSU_35 psi=0.85, RSU_43 psi=0.15  -> raw conflict=2
VEH_191 E9 : Phi=0 (benign)  RSU_35 psi=0.85, RSU_43 psi=0.20  -> raw conflict=2
VEH_191 E8 : Phi=0.45 (anomalous, not suppression)             -> raw conflict=0
VEH_191 E10: Phi=0.300 (anomalous, not suppression)            -> raw conflict=0
```

**These raw counts are an upper bound, not a prediction.** `CPDetectCheck` counts
a vote only from a *trusted* RSU — `Status = ACTIVE` and lifecycle state
`TRUSTED`. The gateway log for this run shows RSU_35 being rejected at
`2026/08/05 18:59:24` with `RSU_35 status=REVOKED (expected ACTIVE)`. RSU_35 is
the high-ψ witness in both candidate pairs, so once the trust filter is applied
its vote is discarded and both pairs fall to `conflict = 1 < 2`. On this evidence
the number of pairs that could ever have fired may well be **zero**.

This is not an incidental detail. In combined-attack mode two of the seven
attacks are *malicious-RSU* attacks, so the RSU reporting the strongest anomaly
is liable to be a compromised RSU that the lifecycle has correctly demoted. The
f+1 quorum therefore has to be met by *honest* witnesses only — and the honest
witness population per vehicle-epoch is 1.

A third, independent defect compounds this: `CPDetectCheck` is scheduled **+0.5 s**
after the controller submission, on the stated assumption of a ~50–200 ms commit.
RSU evidence does not take that path — it is **batched**, flushing only at 50
entries or 10 s. The run's own log shows the first batch landing at `t = 8.325 s`
carrying evidence for beacons from `t ≈ 0`. At +0.5 s the RSU range-scan is still
empty, so the check runs against zero witnesses regardless of the above.

**In short:** the epoch keys match, the controller's on-chain lie is real, and the
conflict logic is correct. The flag never fires for three compounding reasons —
(i) 97.8 % of evidence pairs have a single witness and cannot reach `f+1 = 2`;
(ii) in the few multi-witness pairs the strongest witness is a demoted/revoked
RSU whose vote is correctly excluded; and (iii) the check is executed before the
batched RSU evidence has been committed.

### 5.6 The fix

We first isolated cause (iii) by running with batching disabled
(`--tiered_commit=0`). That alone took `CFLAG` from 0 to 1 and produced the
controller exclusion and reassignment reported in §5.3 — confirming the
commit-timing race was the binding constraint, and that causes (i) and (ii),
while real, were not what prevented the flag.

**We did not ship that switch.** Disabling Tier-3 batching would forfeit the
batched-commit design of §3.5.5 and the PBPO transaction-count claim that rests
on it — trading a reported defect for a silently weakened contribution.

The deployed fix instead commits *only* the evidence the pending check actually
needs. Before `CPDetectCheck` is scheduled for a given `(vehicle, epoch)`, any
RSU buffer holding an entry for that exact pair is flushed; every other RSU keeps
its batch. Batching therefore remains enabled and its transaction-count
behaviour is preserved for all other traffic, while the check is guaranteed a
populated `SUBM_` prefix.

`tier3_flush_for_vid_epoch()` in `scratch/mptd_pqs_sdvn/08_detection_engine.h`,
called at the CP-DETECT scheduling site under `if (g_tiered_commit)`.

**Verified.** Run BC8, with batching left ON, reproduces BC7's result exactly —
`CFLAG = 1`, CTRL_2 excluded, CTRL_0 activated — while
`[TIER3-SUMMARY] batches_committed=219` confirms batching remained active
throughout. Detection metrics are identical to the pre-fix run. The fix is
therefore effective on the configuration we intend to ship, not only on a
diagnostic one; its transaction-count cost is quantified in §5.3.
- **Quorum base.** `CPDetectCheck` requires `f+1` distinct trusted RSUs that each
  submitted evidence for the *same* vehicle in the *same* 1-second epoch. `f` is
  derived from the on-chain `NETCFG.NumRSUs`, which we measured by live query to
  be **4** — not the 64 RSUs actually simulated and registered. So the operative
  threshold is **f+1 = 2**. A vehicle is physically observed by ~2 RSUs (the
  handoff pair) in a 1-second epoch, which makes the threshold *marginally*
  satisfiable rather than unreachable.

**A separate configuration defect surfaced here and is worth flagging on its own.**
`NETCFG.NumRSUs` is written as a **hardcoded `4`** regardless of the `--N_RSUs`
value the simulation runs with. Every on-chain quorum is derived from this number
— the 2f+1 registration/vote thresholds and the f+1 CP-DETECT threshold alike —
so all of them are currently computed for a 4-RSU network while the simulation
runs 64. The same record also carries `TWindowSec = 30` for 300 s runs. We have
**not** changed either value: raising `NumRSUs` to 64 would raise the CP-DETECT
threshold from 2 to 22 and make it genuinely unreachable at realistic RSU
densities, so this is a modelling decision rather than a safe unilateral fix.

**This is the question for you.** Eq 3.69 defines the quorum over `R^obs_ck` —
the RSUs *observing* the vehicle — whereas the implementation derives `f` from a
network-wide RSU count. Those coincide only when the observing set is the whole
network. **Please confirm which set Eq 3.69 intends**, because it decides whether
`NumRSUs` should track `--N_RSUs` (and the quorum be taken over observers) or
remain a network-size parameter.

---

## 6. Disclosures

1. **`ablation_mode` defaults to A1 (lightweight).** `--enable_gat` and
   `--enable_lstm_ae` force the detectors on but do **not** change it, so the
   printed `MCC`/`FPR` are lightweight-only and come out **identical across
   D1/D4/D6** (0.537 / 0.094) — they cannot show the ablation ordering. All D-arm
   figures in §2–3 were recomputed from the fusion verdict against ground truth.
2. **"Only a5 and a7 active" is not expressible in combined mode** — they are
   applied to every vehicle by `vehicle_id % 2`. They were therefore run as
   single-attack runs, which load `models/urban/` rather than
   `models/urban_combined/`, so those figures are not directly comparable to the
   combined-mode arms.
3. **a5 and a7 produce identical control-plane numbers by design** — the code
   treats `attack_number == 5` and `== 7` with the same malicious-controller
   condition; they differ only in data-plane poisoning.
4. **CP-DETECT fires 3887–5962 times in our runs, not 93 079** — the count is
   configuration dependent.

---

## 7. Status of the outstanding work

Your required order is CP-1/CP-2 first.

**Resolved:**

1. ~~Resolve why `CPDetectCheck` computes `MeanConflict = 0`~~ — **DONE (§5.5).**
   Root cause measured by direct ledger census: the epoch keys match (178/183
   pairs carry both records) and the controller's suppression is real (122 pairs),
   but 179/183 pairs have a single RSU witness against a threshold of `f+1 = 2`,
   the strongest witness in the multi-witness pairs is a revoked RSU whose vote is
   excluded, and the check runs before the batched evidence is committed.

2. ~~Confirmation run isolating the timing defect~~ — **DONE.** BC7
   (`--tiered_commit=0`) isolated it; BC8 verified the shipped fix with batching
   left ON (§5.3, §5.6).
3. ~~Obtain non-zero `CFLAG` records~~ — **DONE.** `CFLAG = 1`, CTRL_2 excluded,
   CTRL_0 activated, on the shipped configuration.

**Still outstanding:**

4. **Sustained controller trust decay — reported as NOT achieved.** Trust
   recovers to ~1.0 once conflicts stop, because on-chain conflict events are
   confined to the rare two-RSU handoff. This is a property of RSU witness
   density, not a defect we can correct unilaterally — it needs item 6 below.
5. Matched CP-1 on/off pair for a clean before/after CDER figure (§5.2). This
   refines an already-reported number rather than blocking a claim.
6. **Your decision on the Eq 3.69 quorum base and on `NETCFG.NumRSUs`** (§5.5) —
   the one item that gates any further progress on trust decay.
7. Re-measure PBPO: the fix raises batched commits 58 → 219 (§5.3).

---

## 8. The decision we need from you

Everything above is measured. One question now gates further progress, and we
have deliberately not answered it ourselves because it changes the paper's model
rather than its code.

**On-chain controller-compromise detection is reachable — we have now shown it
firing. Sustained SC-Trust decay is not, at this RSU density.** A vehicle is
heard by one honest RSU per epoch in 97.8 % of cases, while the conflict quorum
needs `f+1 = 2`. Conflicts therefore register only during the brief two-RSU
handoff, and the Eq 3.55 EMA restores trust to ~1.0 before `T_rev` consecutive
low epochs can accumulate.

There are three ways forward and they are not equivalent:

1. **Take the quorum over `R^obs_ck`** — the RSUs actually observing the vehicle,
   which is what Eq 3.69 appears to say — rather than over a network-wide RSU
   count. This makes the threshold meetable at realistic densities.
2. **Increase RSU coverage overlap** so a vehicle transits ≥ 3 zones per epoch. A
   scenario change, not a threshold change.
3. **Accept and report** that trust-driven controller revocation is not
   exercisable at this density, and rest the claim on the flag-driven exclusion
   we have demonstrated.

We recommend (1) if it matches your intent for Eq 3.69, since the implementation
currently derives `f` from `NETCFG.NumRSUs` — which, separately, is written as a
hardcoded **4** regardless of the 64 RSUs simulated (§5.5). Raising it to 64
without also fixing the quorum base would push the threshold to 22 and make the
mechanism unreachable by construction. **We have changed neither value and will
not without your instruction.**

**Please confirm which set Eq 3.69 intends.**
