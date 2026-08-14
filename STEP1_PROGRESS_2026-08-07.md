# Step 1 progress — Fix B (per-RSU vehicle_state)

**02:20, 2026-08-07** · branch `ml-review-fixes` · **provisional — control arm still running**

## Status

| item | state |
|---|---|
| Fix B implemented (`vehicle_state[MAX_RSUS][total_size]`) | ✅ 46 access sites, builds clean |
| 300 s D6 with Fix B **ON** | ✅ **complete** |
| 300 s D6 **control**, same seed | 🔄 running, ETA ~05:15 |
| Full Step 1 report (ON vs control) | after control completes |

Implemented **flag-gated** (`--per_rsu_vehicle_state`, default OFF) rather than as an
outright replacement, so the control arm is the *same binary, same seed, one
variable*. Otherwise any change could be attributed to the rebuild rather than to
Fix B.

## Your pass condition 1 — vid=98: **MET, decisively**

| | FP | clean beacons | **FPR** |
|---|---|---|---|
| before | 622 | 622 | **1.0000** |
| **with Fix B** | **43** | 622 | **0.0691** |

A 93% reduction. vid=98 no longer appears in the top-6 FP vehicles at all. This is
exactly the cross-RSU contamination you identified — RSU 19 writing forged
kinematics that RSU 44 later read as vid 98's baseline — and per-RSU isolation
removes it.

## Your pass condition 2 — the t≈160/190 step: **NOT met**

FP-vs-time, 20 s bins, Fix B ON:

| bin | FPs |
|---|---|
| 120–140 | 101 |
| 140–160 | 111 |
| **160–180** | **293** |
| **180–200** | **390** |
| 200–220 | 451 |
| 220–240 | 562 |
| 240–260 | **673** |
| 260–280 | 449 |
| 280–300 | 293 |

The escalation after t≈160 s is still there, and still climbing. **Fix B did not
remove it.**

### Why — the remaining FPs are different vehicles

| vid | FP | clean | FPR |
|---|---|---|---|
| 196 | 640 | 1083 | **0.5910** |
| 191 | 608 | 1147 | 0.5301 |
| 202 | 470 | 868 | 0.5415 |
| 129 | 408 | 1292 | 0.3158 |
| 154 | 338 | 2337 | 0.1446 |
| 157 | 324 | 2432 | 0.1332 |
| *98* | *43* | *622* | *0.0691* |

vid 202 (arrives t≈164) and vid 196 (arrives t≈193) are the vehicles whose arrival
times define the step, and they still carry FPR 0.54 and 0.59. So **their false
positives are not caused by cross-RSU contamination** — Fix B makes that
mechanism structurally impossible, and they persist regardless. A second,
distinct mechanism is producing them, and it is now the dominant FPR source.

## Headline metrics (provisional)

| | MCC_full | FPR_full |
|---|---|---|
| pre-fix 300 s D6 (earlier binary) | 0.5252 | 0.2150 |
| **Fix B ON** | **0.557** | **0.152** |

FPR down ~29% relative, MCC up ~0.032. **Treat as provisional** until the
same-seed control lands (~05:15) — the 0.5252/0.2150 figures come from a
different binary, so part of the delta could be the rebuild.

## Note on your Fix A one-liner — it will not work

```python
self.score_scale = torch.nn.Parameter(torch.clamp(self.score_scale, min=0.01))
```

- In `__init__`: `score_scale` initialises to **1.0**, so the clamp is a **no-op**
  and training still drives it negative.
- In `forward` (as you suggested): this **rebinds** `self.score_scale` to a new
  Parameter each pass. The optimizer holds a reference to the original object, so
  it keeps updating a tensor the forward pass no longer uses, and
  `Parameter(clamp(...))` detaches it from the autograd graph. **Training breaks
  silently.**

Implemented the projected-gradient equivalent instead — same intent, preserves the
optimizer state and the graph:

```python
opt.step()
with torch.no_grad():
    model.score_scale.clamp_(min=0.01)
```

The run now prints the final `score_scale` and its polarity, so the constraint is
verifiable rather than assumed.

## Method note

All per-beacon figures above are **fusion-tier**, parsed from the `[FUSION-RSU*]`
log lines. The parser was validated bit-exactly against the simulator's own
confusion matrix on a control run (TP=3951, FP=70, TN=1180, FN=1725,
MCC 0.499, FPR 0.056). This matters because `beacon_log.csv`'s `detected` column
is the **rule-tier** flag, not fusion — the earlier per-RSU FPR table was limited
by exactly that.

## Next

Control arm completes ~05:15, then the full ON-vs-control Step 1 report. Per your
instruction, Step 2 measurement/deployment has **not** started. The Fix A
constrained retrain is queued to train overnight, but it deploys nothing and runs
no D1/D4/D6 — that waits on your review of Step 1.
