# Three Separate Models — Urban / Suburban / Highway

This project now trains **three genuinely separate models**, one per environment,
exactly as required. They are distinct in four ways:

1. **Separate classes** — `UrbanGAT`, `SuburbanGAT`, `HighwayGAT` (`model.py`).
2. **Separate architectures** — different heads / widths / dropout, so even the
   weight shapes differ (urban 136,257 params; suburban 9,505; highway 849).
3. **Separate trained checkpoints** — `urban_encoder.pt`, `suburban_encoder.pt`,
   `highway_encoder.pt`.
4. **Separate locked statistics** — `urban_stats.npz`, `suburban_stats.npz`,
   `highway_stats.npz` (each scenario's own normal baseline x̄'_i, σ'_i, θ_S).

This satisfies the design requirement: an urban model never measures normality
against highway sparsity, and vice-versa.

---

## What changed from the previous version

| File | Change |
|---|---|
| `config.py` | The three scenarios now have **different architectures** (heads/width/dropout), not shared defaults. Urban = largest, highway = smallest. |
| `model.py` | Added three explicit model classes (`UrbanGAT`, `SuburbanGAT`, `HighwayGAT`) + a `MODEL_REGISTRY` and `build_model()` / `build_encoder()` factories. |
| `train.py` | Builds the scenario's own class via `build_model()`; prints which model it trained; checkpoint records the model class + architecture. |
| `calibrate.py` | Rebuilds the scenario's own encoder via `build_encoder()`; refuses to load a checkpoint from a different scenario. |
| `score.py` | Same scenario-specific rebuild + guard. |
| `models_summary.py` | **New** — prints the three models side by side for review. |

`dataset.py`, `synthetic_data.py`, `DATA_FORMAT.md`, `README.md` are unchanged.

---

## The three models at a glance

```
scenario   class        heads hidden  emb dropout  r_max  phi   params
--------------------------------------------------------------------------
urban      UrbanGAT         8     64   32    0.20    300   45   136257
suburban   SuburbanGAT      4     32   16    0.10    500   30     9505
highway    HighwayGAT       2     16    8    0.05    800   15      849
```

Run `python models_summary.py` any time to print this.

**Why these sizes:** urban graphs are dense with diverse headings and frequent
topology change, so the model gets the most capacity. Highway graphs are sparse,
near-linear platoons, so a small model fits them without over-fitting. `phi_max`
(heading tolerance for an edge) is tight on the highway (co-directional platoons)
and loose in the city (junction diversity); `r_max` is the comm range.

---

## How to run (Windows / PowerShell)

From `...\MPTD-PQS-SDVN\gat_detector` with the venv active (`(.venv)` in prompt).
PowerShell chains commands with `;`, not `&&`; line-continue with a backtick `` ` ``.

### 0. (Optional) confirm the three models exist

```powershell
python models_summary.py
```

### 1. Get data for all three scenarios

Synthetic:

```powershell
python synthetic_data.py --scenario urban    --out data/urban
python synthetic_data.py --scenario suburban --out data/suburban
python synthetic_data.py --scenario highway  --out data/highway
```

Or real NS-3/SUMO via `adapt_ns3.py` (if you have it set up) — same output files.

### 2. Train each model separately (Phase 1a)

```powershell
python train.py --scenario urban    --attack_csv data/urban_attack.csv
python train.py --scenario suburban --attack_csv data/suburban_attack.csv
python train.py --scenario highway  --attack_csv data/highway_attack.csv
```

Each run prints the model class, e.g. `model: UrbanGAT (heads=8, hidden=64, ...)`,
and writes `checkpoints/<scenario>_encoder.pt`.

### 3. Calibrate each model on its own clean data (Phase 1b)

```powershell
python calibrate.py --scenario urban    --clean_csv data/urban_clean.csv
python calibrate.py --scenario suburban --clean_csv data/suburban_clean.csv
python calibrate.py --scenario highway  --clean_csv data/highway_clean.csv
```

Writes `checkpoints/<scenario>_stats.npz`.

### 4. Score each model (inference / eval)

```powershell
python score.py --scenario urban    --attack_csv data/urban_attack.csv
python score.py --scenario suburban --attack_csv data/suburban_attack.csv
python score.py --scenario highway  --attack_csv data/highway_attack.csv
```

Writes `outputs/<scenario>_scores.csv` and prints metrics.

### All three in one loop

```powershell
foreach ($s in "urban","suburban","highway") {
    python train.py     --scenario $s --attack_csv "data/${s}_attack.csv"
    python calibrate.py --scenario $s --clean_csv  "data/${s}_clean.csv"
    python score.py     --scenario $s --attack_csv "data/${s}_attack.csv"
}
```

---

## Safety guard

`calibrate.py` and `score.py` now refuse to mix scenarios. If you point the urban
script at a highway checkpoint you get a clear error instead of silently wrong
results:

```
ValueError: Checkpoint is for 'highway' but you asked for 'urban'.
Use the matching scenario.
```

---

## Verified

The full `train → calibrate → score` flow was run for all three scenarios.
Checkpoint sizes confirm three different models:
`urban_encoder.pt` ≈ 550 KB, `suburban_encoder.pt` ≈ 43 KB, `highway_encoder.pt` ≈ 8 KB.
(For a real run keep `epochs=60` in `config.py`; expect the supervised-head MCC to
return to ≈ 0.64 per scenario as in your earlier full runs.)

---

## Note for the write-up

The three LSTM-AE models (Phase 1c) and the fusion stage (Phase 2) follow the same
"three separate models" pattern — one LSTM-AE and one θ_ae per scenario, then
scenario-specific fusion weights λ1, λ2, λ3. The GAT side is what these files
implement; the LSTM-AE classes would mirror this exact registry structure.
