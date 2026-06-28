# Phase 1b correction — per-node statistics x̄'_i and σ'_i

Addresses the review comment: Phase 1b must compute and store **per-vehicle-node**
mean and standard deviation, not one pooled global statistic.

## What was wrong before

The previous `calibrate.py` pooled every node embedding from every timestep
together and stored a single `mu` (one vector) and `sd` (one vector). That is a
dataset-wide baseline, so `S_i(t)` measured deviation from the *average vehicle*,
not from vehicle *i*'s own normal behaviour.

## What it does now (exactly the checklist you gave)

1. **Run frozen GAT forward pass on the clean portion** — encoder loaded in
   `eval()`, weights frozen, no gradient.
2. **For each node collect all x'_i across timesteps** — embeddings are grouped by
   the vehicle's raw id (carried through `dataset.py` as `data.node_ids`), so every
   embedding a given vehicle produced over the whole clean portion is gathered.
3. **Compute x̄'_i and σ'_i per node** — mean and std over that vehicle's own
   embeddings (one `(emb_dim,)` vector each, per vehicle).
4. **Save both to disk and lock them** — stored in `<scenario>_stats.npz` as
   `mu_per_node` and `sd_per_node` (shape `n_nodes × emb_dim`), keyed by `vids`.
   They are never recomputed or updated during evaluation.

At inference, `score.py` looks up each node's own `x̄'_i`, `σ'_i` by vehicle id and
computes `S_i(t) = ||(x'_i(t) − x̄'_i) / σ'_i||²`. A pooled global mean/std is also
stored as a fallback for any vehicle id that appears at test time but was never
seen during clean calibration (pseudonym rotation, different seeds).

## Files changed

- `dataset.py` — each graph now carries `node_ids` (raw vehicle id per node) so
  calibration can group embeddings by vehicle. Does not affect training/batching.
- `calibrate.py` — computes and stores per-node `x̄'_i`, `σ'_i` (+ global fallback,
  + locked `theta_S` from the clean per-node `S_i` distribution).
- `score.py` — scores each node against its own locked statistics.

## Sanity check (built in)

For correctly z-scored embeddings the clean `S_i` mean should equal the embedding
dimension. The calibration run reports exactly this per scenario (urban 32,
suburban 16, highway 8), confirming the per-node normalisation is right. `score.py`
also prints how many nodes used their own stats vs the global fallback.

Unchanged: the three-separate-models structure, Phase 1a training, and the open
z-score-vs-head question remain as before.
