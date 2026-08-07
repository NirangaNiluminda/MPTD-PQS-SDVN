# GAT retraining: a prerequisite you should see before Step 1

**Date:** 2026-08-06 · **Branch:** `ml-review-fixes`
**Status:** nothing deployed has changed. `--ghost_batch` is **default OFF**; all
previously reported MCC/FPR numbers stand unaltered.

---

## 0. A correction to my own recommendation

I recommended the GAT retrain, and cited *median S/θ_S = 0.392* as evidence that
"real spatial signal is present." **You approved it on that basis. That evidence
was not sound, and I found out after you approved.**

That figure was the GAT scoring an **isolated single node**. It says nothing
about relational signal, because at the time of measurement there were no
relations in the graph to measure. I am flagging this before Step 1 rather than
letting it surface as an unexplained failure at your Step 4 gate.

Your Steps 1–6 are still the right plan. Two things must happen first, and one
of them changes what Step 1 will find.

---

## 1. Your ring specification is exactly right — confirmed by measurement

Before anything else: I measured the ghost geometry in the corpus against your
Step 2 description ("four fabricated identities at approximately 135 m offset,
correlated headings, correlated positions"):

| your specification | measured | agreement |
|---|---|---|
| ring radius ≈ 135 m | adjacent-pair p50 = **190.9 m** = 135·√2 = 190.92 | exact |
| — | opposite-pair p95 = **270.0 m** = 2 × 135 | exact |
| correlated headings | median \|Δheading\| = **0.0000 rad** | exact |

The ring is a four-point square of radius 135 m about the victim, with
identical headings. **The pattern you asked the GAT to learn is genuinely
present in the data.** That is the good news, and it is why the plan is worth
completing rather than abandoning.

---

## 2. Step 0 — the ring was being destroyed before the GAT saw it

Ghost beacons were **force-flushed individually**, so each was scored alone in a
single-node graph. Every property in your Step 2 is a *relation between ghosts* —
none of them can exist in a graph with one node.

Implemented `--ghost_batch` (`08_detection_engine.h:3959`), verified on a 30 s run:

| ghost-window composition | before | **after** |
|---|---|---|
| 1 beacon (ring invisible) | **74.8 %** | **0 %** |
| ≤ 2 beacons | 98.3 % | 0 % |
| **4–5 beacons (ring intact)** | ~0.3 % | **100 %** (97.1 % at 5, 2.9 % at 4) |
| non-ghost RSU windows | 10 | **10 — unchanged** ✅ |

The ring now reaches the model. Normal RSUs are untouched.

---

## 3. Step 1 — the corpus check fails, in two separate ways

You asked me to confirm the ghost rows are present with `attack_number=3`.
**They are not present at all**, and where they do exist they carry the wrong
label.

| | rows | ghost rows (vid ≥ 10000) | ghost label |
|---|---|---|---|
| `beacon_train_master.csv` — **the file the trainer reads** (`train.py:37,39`) | 72 919 | **0** | — |
| `beacon_train_master_ghostcorpus.csv` — **nothing reads this** | 92 370 | **4 057** | `attack_number=0` |

Two consequences:

1. The trainer's corpus contains **zero ghost beacons.** Its 521 poisoned rows
   are all real vehicles, and all 72 919 rows are labelled `attack_number=3` —
   so the a3 "Sybil" model was trained without a single fabricated identity in
   its input.
2. The ghost rows that do exist (4 057 rows, 56 ghost IDs, 11 RSUs) are labelled
   `attack_number=0` (combined mode). Your Step 2 relabel to k=2 is therefore
   **required and substantive**, not the formality it reads as.

**Step 1 needs an added action: point the trainer at the ghost corpus**, or merge
the ghost rows into the master. This is a one-line change but it must be an
explicit decision, not something I make silently.

---

## 4. A deeper blocker: the current model cannot express the pattern

I scored the deployed `urban_combined` GAT on RSU-windowed graphs built from the
ghost corpus, and measured **within-window** discrimination (pooled statistics
are misleading here — they are dominated by between-window scale).

AUC 0.50 = no signal. Both output channels, both compositions:

| graph composition | S — within-window AUC | bv (heads) AUC | S constant across all nodes |
|---|---|---|---|
| natural corpus windows (~8/10 ghosts) | **0.529** (p50 0.500) | 0.527 | 22.8 % of windows |
| **live post-`ghost_batch`** (4 ghosts + 1 real, N=5) | **0.512** (p50 0.500) | 0.503 | **73.8 % of windows** |

Ghosts rank *above* real vehicles in only 37 % of windows — i.e. slightly worse
than a coin toss. And in three-quarters of live-composition windows **S is
literally identical for every node**, so it cannot separate anything.

**Mechanism, and it is not a weights problem.** At deploy, 10 of the 16 input
dimensions (`psi_score` + 9 `sig_mask` bits) are zero for every node, and `tau`
is a constant 1 — this is documented in `train_ab3_gat_v4_nopsi.py`'s own
header. Eleven of sixteen inputs are constant. The five that vary
(`pos_x, pos_y, speed, heading, accel`) are, by construction, nearly identical
across a tight 135 m ring with identical headings. The embeddings converge, and
`S_i = ‖(e_i − μ)/σ‖` then normalises away whatever shift the ring shares.

This is why I want your Step 4 gate kept exactly as you wrote it: it is the check
that would catch this if the retrain fails to fix it.

**Note on θ_S.** On ghost-bearing windows the current θ_S = 19.74 is exceeded by
85.7 % of ghosts *and 99.6 % of clean nodes*. It is not discriminating; it is
saturating — the failure mode you warned about.

---

## 5. A leakage risk in Step 3 — please rule on this

Ghosts are separable on **marginals alone**, and one of those marginals is a
pipeline artifact rather than a physical property:

| feature | ghost | real |
|---|---|---|
| `sig_mask == 0` | **100.0 %** | 77.9 % |
| `psi_score` (mean) | 0.000 | 0.063 |
| speed p50 | 0.030 | 4.880 |

`sig_mask == 0` for **100 %** of ghosts is a perfect one-way indicator. A
classification head given `sig_mask` in its input will learn *"no rule signature
⇒ ghost"* — which is not the ring, and not a property of the attack. It is a
consequence of ghosts bypassing the rule tier.

**This is the same class of error as the Fix 2 verbatim label leakage** I flagged
earlier, and it would produce an impressive-looking result that does not
generalise.

**Recommendation:** run Step 3 on `train_ab3_gat_v4_nopsi.py`, which already
zeroes `psi` and `sig_mask` during training. It was written for a related reason
(those dims are zero at deploy), and it happens to close this leak as well.

I would also flag that **48 % of ghost beacons have speed exactly 0** — a
stationary Sybil is easier to detect than a realistic one. Whether to make the
ring mobile is a threat-model decision for you, not something I should change
unilaterally; but the detection rates we report will be optimistic if it stays.

---

## 6. Revised plan

| step | status |
|---|---|
| **0 (new)** — ghost graph batching | ✅ implemented + verified (§2), default OFF |
| **1** — confirm ghost rows in corpus | ❌ **failed** — 0 rows in trainer's file (§3); needs corpus decision |
| **2** — label ghosts as k=2 | required, currently `attack_number=0` |
| **3** — retrain with Fix A + Fix B | recommend on the `v4_nopsi` base (§5) |
| **4** — S/θ_S distribution check | **your gate — keep it** (§4 shows why) |
| **5** — per-variant regression ≤ 0.05 | your gate, unchanged |
| **6** — deploy + 300 s D1/D4/D6 | after both gates pass |

## 7. What I need from you

1. **Corpus:** point the trainer at `beacon_train_master_ghostcorpus.csv`, or
   merge its ghost rows into the master? (I recommend merging, so the model keeps
   the non-ghost attack classes it currently handles.)
2. **Leakage:** confirm Step 3 runs with `psi`/`sig_mask` zeroed. If you want them
   retained, please say so explicitly — I would then report the result as
   contingent on a feature the attacker could trivially change.
3. **Stationary ghosts:** document as a fidelity limitation, or make the ring
   mobile and re-measure?

Nothing further will be deployed until you rule on 1 and 2. `--ghost_batch`
remains off by default, so the ordering (D6 0.5252 > D4 0.5185 > D1 0.4794) and
the reported FPR are unaffected by anything in this document.
