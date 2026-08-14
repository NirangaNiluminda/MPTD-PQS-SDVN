<!-- # Beacon CSV format — THE schema everything depends on

Every script in this project reads **one flat CSV** with **one row per beacon**
(one vehicle, one timestep). When your NS-3/SUMO pipeline is ready, make it
export exactly these columns and nothing in the code changes.

## Columns

| column       | type    | unit            | meaning                                                        |
|--------------|---------|-----------------|----------------------------------------------------------------|
| `scenario`   | string  | —               | `urban` / `suburban` / `highway` (must match a config name)    |
| `seed`       | int     | —               | NS-3 random seed. Use several seeds per scenario (≥3).         |
| `t`          | float   | seconds         | beacon timestep. All beacons sharing the same `t` (within a    |
|              |         |                 | scenario+seed) form ONE graph.                                 |
| `vehicle_id` | int/str | —               | pseudonymous vehicle ID (`IDi` in the paper).                  |
| `x`          | float   | metres          | projected position X (NOT raw lat/long degrees — project to    |
|              |         |                 | a local metric plane, e.g. SUMO's native XY).                  |
| `y`          | float   | metres          | projected position Y                                           |
| `speed`      | float   | m/s             | `si(t)`                                                         |
| `heading`    | float   | radians         | `θi(t)`, 0 = +X axis, CCW positive                             |
| `accel`      | float   | m/s²            | `ai(t)`                                                        |
| `label`      | int     | {0,1}           | ground truth: 0 = normal, 1 = malicious. From NS-3 attack cfg. |

## Two kinds of file you must produce per scenario

The supervised design needs BOTH:

1. **Attack file (`*_attack.csv`)** — NS-3 run **with attack injection on**.
   `label` column is meaningful (mix of 0 and 1). Used for:
   - **Phase 1a** supervised GAT training
   - test/evaluation

2. **Clean file (`*_clean.csv`)** — NS-3 run **with NO attack injection**,
   all nodes honest. Every `label` is 0. Used for:
   - **Phase 1b** calibration of the anomaly statistics (x̄'_i, σ'_i) and threshold

> The LSTM-AE (a separate model, not in this folder) uses ONLY the clean file.
> The GAT uses the attack file to train and the clean file to calibrate.

## Notes

- Heading: if your source gives degrees or a compass bearing, convert to radians
  in math convention. The loader turns heading into `sin/cos` so wrap-around at
  ±π is handled for you.
- RSU nodes: the paper's graph is vehicle–RSU. This reference implementation
  classifies **vehicle nodes only** and builds vehicle–vehicle edges (Eq. 3.26).
  If you later add RSU rows, give them a sentinel `vehicle_id`, set `label`
  appropriately, and extend `dataset.build_graph` to add vehicle–RSU edges and
  mask RSU nodes out of the loss. A `# RSU EXTENSION POINT` comment marks where.
- Position as a feature: absolute X/Y is per-graph z-scored (Eq. 3.27) so only
  relative geometry matters; this is fine and keeps the model translation-robust.

## Minimal example

```
scenario,seed,t,vehicle_id,x,y,speed,heading,accel,label
urban,1,0.0,10,120.5,80.2,8.3,1.57,0.1,0
urban,1,0.0,11,135.0,79.9,8.1,1.55,0.0,0
urban,1,0.0,12,118.0,200.0,9.0,1.60,0.2,1
urban,1,0.1,10,121.3,80.2,8.3,1.57,0.0,0
...
``` -->


# Data format

## On disk (real NS-3 export — read directly)

    data/<scenario>/a<N>_p<pct>/beacon_log.csv

beacon_log.csv raw columns (full simulator schema):

    sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, accel,
    is_poisoned, detected, sig_mask, psi_score, attack_number, attack_pct,
    attacker_class, gt_pos_x, gt_pos_y, gt_speed

## Column mapping used by the GAT (dataset.py)

| raw column   | used as      | notes                                   |
|--------------|--------------|-----------------------------------------|
| sim_time     | t            | bucketed to 0.1 s (Tb) to form a graph  |
| vehicle_id   | node id      | per-node calibration key                |
| pos_x, pos_y | x, y         | position (m)                            |
| speed        | speed        | m/s                                     |
| heading      | heading      | radians -> expanded to (sin, cos)       |
| accel        | accel        | m/s^2                                   |
| is_poisoned  | label        | 1 = malicious node, 0 = honest          |
| attack_number, attack_pct | seed | seed = attack_number*100 + attack_pct |
| (others)     | ignored      | rsu_id, gt_*, sig_mask, etc.            |

## Clean vs attack split

| split  | rule            | used by                  |
|--------|-----------------|--------------------------|
| clean  | attack_pct == 0 | calibrate.py (Phase 1b)  |
| attack | attack_pct  > 0 | train.py, score.py       |

## Node feature vector (order)

    [x, y, speed, sin(heading), cos(heading), accel]   # 6 dims

Each feature is rolling z-score normalised across the vehicles present in the
same 100 ms graph (Eq. 3.28, eps = 1e-8).
