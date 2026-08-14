# Code-vs-paper audit against the modelling items — 2026-08-07

**Scope:** all ~28 items, both sides. Code side verified against source, model
JSON artefacts, and live process command lines. Paper side verified against the
supplied `main (10).tex`.

**Method:** read-only. No new simulations were run.

**Legend:** ✅ already correct in the paper — no patch needed · ⚠️ present but
wrong — needs correction · ❌ documents behaviour disabled in the reported runs ·
🆕 confirmed absent — write from scratch

---

## §A — Corrections that change the content of the patch

These seven change the technical substance, not the wording. Each is a
code-vs-paper mismatch confirmed on both sides.

### A-1 ⚠️ F4 — the quoted weight vector is the wrong attack class (proven)

F4 states k̂=4's signature-weight set is
`[0.0045, 0, 0, 0, .3275, .2836, .3844, 0, 0]`. **It is not.** The loader indexes
positionally with `k = attack_number − 1` (`06d_ai_inference.h:194-204`;
explicit for θ_conf at `:240`, `int k = (int)atk_f - 1`).

| k̂ | attack class | variant | sig weight vector |
|---|---|---|---|
| 3 | 4 | MP-S2 | `[0.0045, 0, 0, 0, .3275, .2836, .3844, 0, 0]` |
| **4** | **5** | **TP-S3** | **`[0.001, 0.9921, 0.001 ×7]`** |

The arithmetic settles it. The logged collapse was `psi_fuse 0.1770 → 0.0020`:

- global `[0.0976, 0, 0, .1685, .2018, .2214, .231, 0, .0797]`, bits 0 and 8 →
  0.0976 + 0.0797 = **0.1773** ✓ (logged 0.1770)
- attack **5** weights, same bits → 0.001 + 0.001 = **0.0020** ✓ exact
- attack **4** weights → smallest non-zero entry 0.0045, so **0.0020 is
  unreachable**

The sink is **k̂=4 = attack class 5 = TP-S3**, whose set puts 99.21% of its mass
on bit 1 while the lost beacons carry bits 0 (TP-S1) and 8 (MP-S4). Writing F4
against MP-S2 makes the worked example non-reproducible and collides with G3,
which concerns a genuinely different slot (head 3 = attack 4 = MP-S2).

### A-2 ⚠️ F1 — the equation is right; the ablation arms are not covered

`eq:fusion` in the paper matches the code exactly for full mode, including
`min(·,1)` on all three terms and ψ normalisation by ψ_th. **F1 needs no change
to the equation itself.**

The gap is renormalisation. The code computes
(`06d_ai_inference.h:894-901`):

```
lp = enable_rule_signatures ? λψ^(k̂) : 0     lg = use_gat ? λgat^(k̂) : 0
la = use_ae ? λae^(k̂) : 0                    sum_w = lp + lg + la
                       λ̃ = λ / sum_w
```

In full mode this is ~a no-op (0.5071+0.1857+0.3071 = 0.9999). In the ablation
arms it is not. The paper **does** document it for AB3 and AB4 ("the remaining
fusion weights … are renormalized to sum to one within each attack-class set")
but **not for AB5**, which is exactly where it matters most: with GAT and AE both
off, `sum_w = 0.5071` and **λ̃ψ = 1.0**, so AB5's rule is `min(ψ̄/ψ_th,1) > 0.5`
— a pure rule detector at an effective threshold of ψ_th/2. Confirmed deliberate
in code (`12_main.h:418-420`).

### A-3 ⚠️ F2 — ψ̄ is in the paper, but with the wrong denominator

The paper already defines ψ̄ in three places (`tab_notations`, the `eq:fusion`
preamble, and `alg:full_detection` line 4), all as `(1/L)Σ_{l=1}^{L} ψ_i(t_l)`.
So F2's "confirm it appears" = **yes**.

But the code computes (`08_detection_engine.h:2291-2292`):

```
psi_i = last_psi_per_vehicle[vid] / psi_cnt_per_vehicle[vid]
```

— the mean over the beacons **actually received** from that vehicle in the
window, a count that varies per vehicle per window and is never reliably L. The
denominator must be `n_i(t) ≤ L`, defined as the received count.

**Three different window lengths are in play and the paper uses one symbol for
all of them:**

| | value | source |
|---|---|---|
| detection window (ψ̄, LW) | **10** | `04_state_globals.h:364` `WINDOW_L_BEACONS` |
| LSTM-AE window, deployed | **50** | read from ONNX shape, `06d_ai_inference.h:415` |
| LSTM-AE window, paper | 10 / 20 | `tab:set-fullmode-ai` says 10; `tab:fullmode-selected` says urban 20 |

`LSTM_WINDOW_SIZE = 10` at `:305` is a stale fallback — its comment ("all
window=10") is out of date.

### A-4 ⚠️ A1 — feature set wrong on both sides, and the GAT is not 6-dimensional

The paper describes the AE input as raw beacon tuples (`eq:ta_input`,
`eq:bsm`) — absolute positions. A1 is right that this needs correcting. The code
(`04_state_globals.h:617-647`) computes:

```
rx  = Δx − s·T_b·cos(θ)      ry  = Δy − s·T_b·sin(θ)     (dead-reckoning residuals)
dsp = s − s_prev             dhd = wrap(θ − θ_prev) ∈ (−π, π]
                    → lstm_ring_push(vid, rx, ry, dsp, dhd, ac, tau)
```

Two corrections to A1 as drafted:

1. **Feature 5 is raw acceleration, not Δaccel.** `ac` passes straight through;
   there is no `ac − ac_prev`. Four of six features are residuals, one is
   absolute, one is constant (A3).
2. **The residual fix is LSTM-AE only.** `score_gat()` still consumes absolute
   pos_x/pos_y/speed/heading/accel via a separate `gat_scaler_`
   (`06d_ai_inference.h:821-830`). Stating "features are residuals, not absolute
   positions" without naming the model is wrong for the GAT.

**Separately — the GAT feature dimension in the paper is wrong.**
`tab:set-fullmode-ai` says *"Input feature dimension d = 6 (position x,y, speed,
heading, accel., trust)"*. The code says:

```c
constexpr int GAT_FEATURE_DIM = 7 + GAT_SIG_BITS;   // = 16
// [5 kinematic (scaled), tau (raw), psi (raw), sig_mask bits 0..8 (raw 0/1)]
```

The GAT consumes **16** features including ψ and all nine signature-mask bits.
This is architecturally significant: the GAT is fed the rule tier's output as
input. It also affects AB1 — the code comment at `08_detection_engine.h:2385`
confirms that under AB1 "sig_mask/ψ still feed the GAT input" while only the ψ
*fusion term* is removed. `LSTM_FEATURE_DIM = 6` does match the paper.

### A-5 ⚠️ A2 — the paper's θ_ae formula is a different estimator

Paper `eq:ta_threshold`: **θ_ae = median(E_clean) + κ·MAD(E_clean)**.
Code (`analytics/ml/lstm_ae.py:10,21`): **θ_ae = μ_ε + 1.645·σ_ε**, `KAPPA = 1.645`.

These are not the same estimator — median/MAD vs mean/std. A2's requested
correction is therefore necessary, not cosmetic. κ is also inconsistent three
ways: `tab:set-fullmode-ai` says **3**, `tab:kappa-sensitivity` selects **2**
(urban), the code uses **1.645**.

The deployed value **θ_ae = 33.693885** (`theta_ae.txt`) appears nowhere in the
paper.

### A-6 ⚠️ C3 — the paper's quorum equation uses the wrong base and a fixed threshold

Sir's C3 asks whether `R^obs_ck` is aligned. It is **not**, in two ways.

Paper `eq:ctrl_flag`: `Σ_{r_j ∈ 𝓡} conflict_j(t) ≥ f + 1` — sums over the **full**
RSU set 𝓡, with f fixed (f=1 → threshold 2). Note `eq:ctrl_trust` *does* use
`R^obs_ck`, so the paper is internally inconsistent between the two.

Code (`smartcontract.go:1688`): `f := fByzantine(len(seenRSU))` over the
per-epoch observed set. Because `fByzantine(n) = 0` for n < 4, and the measured
witness distribution is **179 single-witness pairs against 4 with two**, the
effective threshold is **1 almost everywhere**, not 2.

The code's own comment (`:1679-1687`) flags the consequence: one trusted RSU can
unilaterally flag and exclude a controller, and TP-S1/MP-S1 are malicious-RSU
attacks. If the paper claims f+1 Byzantine tolerance on this path, that claim
does not hold at the observed witness counts.

### A-7 ⚠️ Threshold values that disagree with the code

| quantity | paper | code | source |
|---|---|---|---|
| ψ_th | 0.05 (`tab:set-lw`, `tab:threshold-sensitivity`) | **0.09** | `02_config_globals.h:685` |
| R_max (GAT edge) | 270 m everywhere | **300 m** | `06d_ai_inference.h:307` `R_MAX_GRAPH` |
| Φ_th | 0.5 / **0.5108** / **0.40** (three values, see §F) | 0.5 | `fusion_weights.json`, `:74` |

R_max is the one to watch: the paper derives the 270 m figure from the 41 dBm
transmit power and uses it for RSU spacing rationale, but `eq:edge_def1`'s graph
radius in code is 300 m. Either the paper's edge definition needs its own
symbol, or the code needs changing.

---

## §B — Items documenting behaviour disabled in the reported runs

All three are real, working code. None was active in the D1/D4/D6 runs.

| item | mechanism | default | in the reported runs |
|---|---|---|---|
| **G4** | `gat_or_path_min_phi` Φ-floor of 0.60 | `0.0` (`02_config_globals.h:71`) | ❌ the OR-path itself was **disabled** — runs passed `--gat_det_flag_heads=0`; the default is `46` (`:520`). No OR-path detections exist to floor. |
| **S3** | `--ghost_batch` ring batching | `false` (`:403`) | ❌ never set. |
| **C1** | flag_c credited to CDER | `g_cder_credit_cp_detect = false` (`:861`) | ❌ never set; `08_detection_engine.h:3558` takes the `wrong = true` branch throughout. |

G4 cannot be written as drafted: a floor on a path that never fires is not a
false-positive control, and the FP reduction G4 credits to the floor was obtained
by disabling the path outright. Each needs a decision — describe as
available-but-disabled, or re-run with it enabled.

---

## §C — Items already correct in the paper (no patch needed)

Checking these first saves writing patches that duplicate existing text.

| item | where it already appears |
|---|---|
| **F1** (equation form) ✅ | `eq:fusion` — all three terms, `min(·,1)`, ψ/ψ_th normalisation. Only the renormalisation gap of A-2 remains. |
| **F2** (ψ̄ defined) ✅ | `tab_notations`, `eq:fusion` preamble, `alg:full_detection` line 4. Denominator wrong (A-3). |
| **F3** (clipping justification) ✅ | `eq:fusion` preamble states it almost verbatim: *"this clipping makes Φ a genuine weighted average in [0,1], giving Φ_th = 0.5 the principled interpretation of at least half the weighted evidence signals attack."* **No patch needed.** |
| **F5** (feasibility constraint) ✅ | `eq:fusion` text and `tab:pipeline-settings` weight constraints both carry λ₃ < λ₁+λ₂. See caveat below. |
| **G1** (multi-task GAT) ✅ | `eq:gat_cls` shows per-head ŷ_i^(k); `eq:gat_loss` shows the K-task sum. The two Overleaf patches are applied. |
| **G2** (conditioned weights) ✅ | λ^(k̂) in `eq:fusion`, w_s^(k̂) in `eq:psi_score`, K=7 sets for both in `tab:pipeline-settings`. |
| **P2** (rural parameters) ✅ | `tab:set-scenarios` already shows rural **200 vehicles / 169 RSUs (13×13)**. Already updated — **no action needed.** |

**F5 caveats.** (i) The paper states λ₃ < λ₁ + λ₂, which is only the Φ_th = 0.5
special case; the artefact's constraint is the general
`λ_ae < (λ_ψ + λ_gat)·(1 − Φ_th)/Φ_th` — worth carrying since Φ_th is tunable.
(ii) Sir asks that the two repaired sets be documented in
`tab:pipeline-settings`; **they are not** — the table has the constraint but no
values. Both repairs are confirmed in `fusion_weights.json`: a1 λ_ae
0.600 → 0.380, a5 0.850 → 0.1425. All seven sets satisfy the bound; a1 and a5 sit
at exactly a 5% margin, so the "5% margin" in F5 is real.

**G3 — partly present, with a broken cross-reference.** The per-head mechanism is
documented (`tab:pipeline-settings` confidence-gate row, and the `eq:flag`
follow-up text). Two problems: the **values are absent** (code: global
θ_conf = 0.8, `theta_conf_per_attack = [{attack: 4, θ_conf: 0.9}]`, applied at
`06d_ai_inference.h:211`), and `tab:pipeline-settings` promises *"per-head
selected values and fallback rates reported in
Section~\ref{sec:fullmode-sensitivity}"* — **that section contains no such
table.** Dangling forward reference; a reviewer will check it.

---

## §D — Confirmed absent from the paper (write from scratch)

Verified by search of the full LaTeX. Code spec given so the patch can be written
directly.

**F4 — psi_cond_floor** 🆕 `psi_fuse = max(ψ_conditioned, ψ_global)`,
`08_detection_engine.h:2419`. Write against **TP-S3 (attack class 5)** per A-1.

**A3 — τ_i hardcoded** 🆕 `TAU_DEFAULT = 1.0f` (`06d_ai_inference.h:308`); both
LSTM call sites pass literal `1.0f` (`08_detection_engine.h:4222, 4472`). The
paper currently implies the opposite — `tab:set-fullmode-ai` lists "trust" as a
live GAT feature. Documenting it as a limitation is correct.

**S1 — deterministic Sybil ring test** 🆕 Absent; `SYB-DETECT` currently has only
MP-S1/S2/S4. **Every parameter in sir's description matches the code**
(`02_config_globals.h:88-93`): `tol_t = 0.05 s`, `tol_hd = 0.05 rad`,
`r_min = 60 m`, `r_max = 250 m`, `r_cv = 0.25`, `min_members = 3`. Centroid
exclusion confirmed at `08_detection_engine.h:1195-1197` — a beacon is flagged
only if `|r_self − mean| ≤ 0.25·mean` inside the band, so the victim at r≈0 can
never be flagged. **One detail to add:** the group gate is `n < min_members + 1`
(`:1177`), so the co-temporal/co-heading group needs **≥4** beacons (3 ring
members + victim) before radii are computed.

**S2 — ghost injection into the GAT graph** 🆕 `GHOST_VID_BASE = 10000`, pushed
through the same RSU receive path (`08_detection_engine.h:4176, 4234-4235`).
Note ghost LSTM-AE scoring is deliberately **not** extended to ghosts unless
`--ghost_ae` is set (default false, `:394`).

**V1 — per-RSU vehicle state** 🆕 `g_vs_cur_rsu = (int)rsu_id` binds every
`vehicle_state` access in the call to the receiving RSU
(`08_detection_engine.h:1218`). Sir's proposed sentence is accurate as written.

**C2 — targeted pre-flush** 🆕 `tier3_flush_for_vid_epoch()`
(`08_detection_engine.h:107-119`) flushes only buffers holding an entry for that
exact `(vid, epoch)`, leaving other batches intact. Sir's sentence is accurate.
The paper's Tier-3 description currently mentions only `T_batch`/`N_commit`.

**C4 — controller floor** 🆕 `cTrustedFloor = 1`; exclusion refused when
`nActive − 1 < 1` (`smartcontract.go:1490-1500`). The paper documents the RSU
floor (`|R_trusted| ≥ 3f+1`) but has no controller equivalent. Worth adding that
the CFLAG is still written, so detection is preserved and only exclusion is
withheld — the floor does not suppress the detection metric.

**P1 — DSRC delivery rate** 🆕 Absent. The paper states no RX/TX ratio anywhere.
(I cannot verify the 7.22% figure without a run — see §H.)

**P3 — ρ_a definition** 🆕 The beacon-level statement is absent, and the paper's
existing definition **disagrees with sir's**: Experiment 1 defines ρ_a as *"the
fraction of total network nodes (vehicles and RSUs combined) that are malicious"*,
whereas P3 calls it the vehicle-level compromise rate. That needs resolving
before the patch. Measured beacon-level poisoning on the current `final/D1` log:
**79.16%** (87,554 / 110,600 fusion decisions), matching the 79.5% already on
record — **not 89.6%**.

**AB1/AB2 — ablation methodology** 🆕 partly present. AB3/AB4 already state
λ=0 + renormalisation. Missing: the methodological statement that
`ablation_mode=0` (full scoring) is used throughout with components zeroed as
passive substitutes; the GAT substitutes (`S_i = 0`, `k̂ = −1`, OR-flag off);
and renormalisation for **AB5**. AB2 as drafted is asymmetric — it describes
GAT-off as "S_i = 0" but AE-off as "renormalized"; the code treats both
identically.

---

## §E — Attack-variant mapping errors (P4) — affects every per-variant result

P4 asks that a1–a7 be replaced by TP-S\*/MP-S\* names. Two problems, and the
second is serious.

**E-1: the paper still uses a1–a7 in at least four places** — `fig:exp5` caption,
the `eq:fusion` feasibility text ("attack classes a1 and a5"), §res-exp5 prose
("a5, a7"), and §raptor-r4 ("{a₁, a₂, a₄, a₆}" / "{a₃, a₅, a₇}").

**E-2: the existing a1–a7 mappings are wrong.** Code ground truth
(`02_config_globals.h:143-149`):

| code | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|
| **actual** | TP-S1 malicious **RSU** | TP-S2 malicious **vehicle** | MP-S1 Sybil via RSU | MP-S2 Sybil via impersonation | TP-S3 control-plane | MP-S3 MitM | MP-S4 control-plane global |
| `fig:exp5` caption | malicious **vehicle** ✗ | compromised **RSU** ✗ | Sybil via RSU ✓ | Sybil via impersonation ✓ | TP via controller ✓ | MitM ✓ | CP MPP ✓ |
| §exp5 variant list | malicious vehicle ✗ | compromised RSU ✗ | **TP via controller** ✗ | Sybil via RSU ✗ | Sybil via impersonation ✗ | MitM ✓ | CP MPP ✓ |

`fig:exp5` has a1/a2 swapped. The §exp5 list is worse — items 3, 4 and 5 are each
shifted. Any per-variant result table built from that list mislabels five of
seven rows. This should be fixed before any results are populated, not after.

**E-3: "MP-S2" is ambiguous.** The nine *signatures* and the seven *attack
variants* share the TP-S\*/MP-S\* namespace. In code, `sig_mask` bit 6 is the
MP-S2 **signature**, while attack class 4 is the MP-S2 **variant** — and G3's
θ_conf override targets the latter. Adopting P4's naming without disambiguating
makes G3 and F4 unreadable. Recommend the paper state the k = attack−1 convention
once and use distinct notation for signature vs variant.

---

## §F — Internal paper inconsistencies found in passing

Not on sir's list, but each is the kind of thing caught at review.

| quantity | conflicting values in the paper |
|---|---|
| **Urban GAT config** | `tab:set-fullmode-ai`: H=4, hidden 32, dropout 0.6 · `tab:gat-selection`: G3 = H=8, hidden 64, emb 32, dropout 0.3 · `tab:fullmode-selected`: H=4, hidden 32, emb 16, dropout 0.1 · `tab:gat-dropout-sensitivity`: dropout 0.6 — **four different configurations** |
| **Φ_th** | 0.5 (`eq:flag`, `tab:pipeline-settings`) · **0.5108** (`tab:set-fullmode-ai`) · **0.40** selected (`tab:phith-sensitivity`) — code is 0.5 |
| **Model-selection tables** | `tab:gat-selection` and `tab:lstmae-selection` bold one row but the "Selected" column names a *different* candidate (urban bolds T2, selects T1; rural bolds T5, selects T4; highway bolds T8, selects T7) |
| **Drift threshold** | `tab:set-lw`: 5.0 m / 15-beacon window · §param-rationale text: 10.0 m / 10-beacon window · `tab:drift-sensitivity` selects 5.0 |
| **Sybil density factor** | `tab:set-lw`: 4.0 · §param-rationale: 5.0 |
| **φ_max** | `tab:set-fullmode-ai`: π/2 (90°) · `tab:fullmode-selected`: urban 45° — code `PHI_MAX_GRAPH` = π/2 |
| **LSTM-AE latent** | `tab:set-fullmode-ai`: 32 · `tab:fullmode-selected`: urban 16 |
| **Vehicle density** | §param-rationale: *"200 vehicles over a 2 km² map yields 100 vehicles/km²"* — map is ≈4 km² (`tab:set-network`, `tab:set-scenarios`), so 50/km² |
| **Reported operating mode** | §sim-settings prose: *"reported runs exercise the lightweight (A1) path"* · `tab:set-run`: *"Detection mode (reported runs): Full mode"* — same subsection |
| **Simulation duration** | `tab:set-run`: 20 s per run, *"no 300–600 s sustained runs"* — the current D1/D4/D6 runs are **300 s**. Stale. |

---

## §G — Summary

| verdict | items |
|---|---|
| ✅ already correct — no patch | **F3**, **P2**, and the equation/definition halves of F1, F2, F5, G1, G2 |
| ⚠️ present but wrong | **F4**, F1 (ablation renormalisation), F2 (denominator, L), **A1**, **A2**, **C3**, G3 (values + dead cross-ref), F5 (general form + missing values), P3 |
| ❌ disabled in the reported runs | **G4**, S3, C1 |
| 🆕 write from scratch | **F4**, **S1**, S2, A3, V1, C2, C4, P1, AB1, AB2 |
| 🔴 mapping errors | **P4 / §E** — five of seven variant labels wrong in §exp5 |

**Priority order.** (1) §E-2, because it mislabels results rather than prose.
(2) A-1, because F4 is sir's flagged priority and is currently wrong.
(3) §B, because three items would describe a pipeline that was not the one
measured. (4) A-4 and A-5, because the feature set and threshold estimator are
methodology claims a reviewer can check against the artefacts.

---

## §H — Still not verifiable

| item | reason |
|---|---|
| P1 — DSRC delivery 7.22% (1,733 / 24,000 over 20 s) | not reproducible from stored logs; needs a run, out of scope under "no more diagnostic experiments" |
| S1 "fires on zero real vehicles" | previously measured, **not re-verified in this audit** |
| LSTM-AE separation (malicious p50 670 vs honest p50 0.46); ghost recall 0.35 → 0.986 | previously measured, **not re-verified in this audit** |
| Whether `main (10).tex` is the current Overleaf state | `MultiTask_GAT_Fusion_Patch.tex` and `Conditioned_Signature_Weights_Patch.tex` do not exist on this machine; their content does appear applied in this file, which suggests it is current |
