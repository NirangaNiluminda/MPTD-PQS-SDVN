# GAT Spatial Anomaly Detector — implementation guide

This is the **GAT component** of the MPTD-PQS framework (the spatial anomaly
detector, report §3.5.3 / Eqs. 3.26–3.29, 3.38). It is built to the supervised
training design in  modeling update (Phase 1a → 1b), runs on a
**laptop CPU**, and uses **three separate models** (urban / suburban / highway).

The LSTM-AE and the Phase-2 fusion are **separate** and not in this folder; this
component outputs the spatial score `S_i(t)` that feeds the fusion `Φ_i` (Eq. 3.43).

---

## 1. Answers to your two questions

**Do we need attacker-free data to train the GAT?**
Under the supervised design you were given: you need **both**.
- **Attack data** (labels from NS-3) trains the GAT in **Phase 1a**.
- **Clean data** (no attacks) calibrates the anomaly statistics x̄'_i, σ'_i and
  the threshold in **Phase 1b**.

(The LSTM-AE, separately, needs only clean data.)

**Three models or one?**
**Three.** Urban / suburban / highway have qualitatively different "normal" graph
structures. A blended mean makes a normal urban platoon look anomalous against
highway sparsity and vice-versa. Here, "three models" = three config entries +
three training runs; the code is shared.

---

## 2. Install (CPU)

```bash
cd gat_detector
python -m venv .venv && source .venv/bin/activate     # optional but recommended
pip install torch                                      # CPU build from PyPI
pip install torch_geometric scikit-learn pandas numpy matplotlib
```
If `pip install torch` gives a CUDA build and you want strictly CPU, use the
official CPU index instead: `pip install torch --index-url https://download.pytorch.org/whl/cpu`

---

## 3. The data you need

One flat CSV, one row per beacon. Full schema in **DATA_FORMAT.md**. Columns:

```
scenario, seed, t, vehicle_id, x, y, speed, heading, accel, label
```

Per scenario you produce two files:
- `data/<scenario>_attack.csv` — NS-3 run **with** attacks, `label` ∈ {0,1}.
- `data/<scenario>_clean.csv`  — NS-3 run **without** attacks, all `label`=0.

*

Artifacts:
- `checkpoints/<scenario>_encoder.pt` — locked encoder (W_h, a_h) + the head
- `checkpoints/<scenario>_stats.npz`  — locked mu (x̄'_i), sd (σ'_i), theta_S
- `outputs/<scenario>_scores.csv`     — per-node `S_i`, `head_prob`, `label`

---

## 5. IMPORTANT: read before you trust the numbers

The modeling update says: train a supervised classifier, **discard the head**,
and score by the Eq. 3.38 z-score. We implemented exactly that — and on gradual
trajectory-drift attacks it underperforms badly, while the trained head does well:

| scoring path | urban MCC | why |
|---|---|---|
| Eq. 3.38 z-score, locked clean threshold | ≈ −0.16 | misses subtle attacks |
| Eq. 3.38 z-score, best possible threshold | ≈ 0.01 | the z-score itself barely separates the classes |
| supervised head probability | ≈ 0.64 | this is the detector the loss actually optimised |

**Why.** Supervised training makes the two classes *separable*, not necessarily
*outlying*. A z-score measures distance from the clean mean; a gradual-drift
attacker early in its drift sits inside the normal embedding cloud, so the z-score
can't see it even though the linear head can. Discarding the head throws away the
discriminative signal you paid to learn.

`score.py --mode all` (default) prints all three so you can see this yourself.

**What to do.** Raise this with your supervisor. Three coherent options:
1. **Use the head at inference** (best performance). Then `S_i` for the fusion
   becomes a function of `head_prob` (e.g. `S_i = -log(1 - ŷ_i)`), still a valid
   spatial anomaly signal — but this deviates from Eq. 3.38 as written.
2. **Keep Eq. 3.38 but train the encoder *unsupervised*** (reconstruction /
   contrastive on clean data only), so the z-score is meaningful. This matches
   the *original* paper text (Eq. 3.38 needs only clean data) but drops the
   supervised update.
3. **Keep both as written** and report the gap as a limitation. Defensible for a
   progress report, but weaker as a final detector.

The code supports 1 and 3 today; option 2 is a different training script (happy
to add it).

---

## 6. Plugging in real NS-3/SUMO data

1. Export beacons to the schema in DATA_FORMAT.md (project lat/long to metric XY;
   heading in radians). One `attack` CSV and one `clean` CSV per scenario.
2. Use several NS-3 seeds per scenario (the `seed` column) — one seed gives too
   few distinct graph structures (your update stresses this).
3. Set `phi_max_deg` and `r_max` per scenario in `config.py`. Calibrate `phi_max`
   by checking on a clean run that edges include lane-mates and exclude oncoming
   traffic before training.
4. Run the Phase 1a → 1b → score sequence above.

---

## 7. How this fits the rest of the framework

- `S_i(t)` from this component is one of the three inputs to the fusion
  `Φ_i = λ1 ψ_i + λ2 S_i + λ3 (ε_i/θ_ae)` (Eq. 3.43).
- `ψ_i` comes from the rule-based signatures (lightweight mode); `ε_i` from the
  LSTM-AE. Both are separate components.
- **Phase 2** (not here): freeze GAT + LSTM-AE, then learn λ1, λ2, λ3 by
  weighted cross-entropy on a labeled validation set.

---

## 8. File map

```
config.py          scenario configs (the "three models" live here)
DATA_FORMAT.md     CSV schema — the contract for NS-3/SUMO export
synthetic_data.py  dev-time data generator (identical schema)
dataset.py         CSV -> per-timestep PyG graphs; Eq. 3.26 edges, Eq. 3.27 norm
model.py           GAT encoder (Eq. 3.28/3.29) + classification head (gat_cls)
train.py           Phase 1a: class-weighted BCE (gat_loss); saves encoder+head
calibrate.py       Phase 1b: lock mu, sd, theta_S from clean embeddings (Eq. 3.38)
score.py           inference: S_i (Eq. 3.38) + head prob; MCC/F1/FPR
run_all.sh         all three scenarios end-to-end
```


# HOW TO RUN

1. Only needed once.

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install torch
pip install torch_geometric scikit-learn pandas numpy matplotlib

2. Verify
python -c "import torch, torch_geometric, sklearn, pandas; print('deps OK')"

3. Confirm the three separate models
python models_summary.py

Expected:
scenario   class        heads hidden  emb dropout  r_max  phi   params
urban      UrbanGAT         8     64   32    0.20    300   45   136257
suburban   SuburbanGAT      4     32   16    0.10    500   30     9505
highway    HighwayGAT       2     16    8    0.05    800   15      849

4. Get the data

Option A: synthetic data (for development / demo)

python synthetic_data.py --scenario urban    --out data/urban
python synthetic_data.py --scenario suburban --out data/suburban
python synthetic_data.py --scenario highway  --out data/highway

Option B: real NS-3/SUMO data
Export to the exact schema in DATA_FORMAT.md (columns
scenario, seed, t, vehicle_id, x, y, speed, heading, accel, label; heading in
radians; x/y in metres). Drop the files in data/ with the same names. No code
changes needed. Use several NS-3 seeds per scenario.


5. Phase 1a — train the GAT (supervised, class-weighted BCE)
python train.py --scenario urban --attack_csv data/urban_attack.csv
python train.py --scenario suburban --attack_csv data/suburban_attack.csv
python train.py --scenario highway --attack_csv data/highway_attack.csv

Phase 1b — calibrate per-node statistics on clean data
python calibrate.py --scenario urban --clean_csv data/urban_clean.csv
python calibrate.py --scenario suburban --clean_csv data/suburban_clean.csv
python calibrate.py --scenario highway --clean_csv data/highway_clean.csv


Phase 1c / Phase 2

Not in this folder — LSTM-AE (Phase 1c) and fusion λ-learning (Phase 2) are
separate components. This GAT pipeline outputs the spatial score S_i that feeds
the fusion later.

python score.py --scenario urban --attack_csv data/urban_attack.csv
python score.py --scenario suburban --attack_csv data/suburban_attack.csv
python score.py --scenario highway  --attack_csv data/highway_attack.csv




6. If want run from the begining, Clean restart
Remove-Item checkpoints\* -Force -ErrorAction SilentlyContinue
Remove-Item outputs\*     -Force -ErrorAction SilentlyContinue
Remove-Item data\*.csv    -Force -ErrorAction SilentlyContinue

Then repeat from 4.