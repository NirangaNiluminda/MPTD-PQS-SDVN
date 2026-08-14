# """
# dataset.py  —  Graph construction from NS-3 beacon logs
# ========================================================
# Reads per-timestep vehicle beacons and builds a PyG Data object (a snapshot
# graph) for every simulated second.

# Dataset layout on disk
# -----------------------
# BASE/
#   urban/
#     a{1..7}_p{0,20,40,60,80,100}/
#       beacon_log.csv          <- per-vehicle beacons (one row per vehicle per sec)
#       tp_s1_poison_log.csv    <- ground-truth: which vehicle-ids are attackers
#       metrics.csv             <- (optional aggregate, not used for node labels)
#   highway/
#     same sub-folder layout
#   rural/                      <- used for the 'suburban' scenario (alias)
#     same sub-folder layout

# NOTE: config.py calls the middle scenario "suburban"; its data lives under
#       "rural/".  Call get_scenario_dir() rather than using cfg.name directly.

# beacon_log.csv columns (mandatory)
# -----------------------------------
#   time          simulation second  (int or float, cast to int bucket)
#   vehicle_id    string identifier
#   x             UTM-x or local x (metres)
#   y             UTM-y or local y (metres)
#   speed         m/s
#   heading       degrees, 0=north, clockwise
#   acceleration  m/s²   (column alias: "accel" also accepted)

# tp_s1_poison_log.csv columns (mandatory for labelled graphs)
# ------------------------------------------------------------
#   time          same time bucket
#   vehicle_id    attacker vehicle id at that timestep

# Attack folders
# --------------
#   attack_type : a1 … a7  (7 distinct attack strategies)
#   penetration : p0 p20 p40 p60 p80 p100  (% of vehicles that are attackers)

#   p0 folders contain CLEAN traffic (0 % attackers) and are used as the
#   calibration source. All other folders contain mixed clean + attack traffic.

# Public API
# ----------
#   load_graphs(csv_path_or_folder, cfg)
#       Path may be:
#         (a) a single beacon_log.csv  (legacy / explicit)
#         (b) a folder containing beacon_log.csv + tp_s1_poison_log.csv
#         (c) "auto:<scenario>" — loads ALL attack subfolders for that scenario
#             and returns a flat list of all timestep-graphs
#       Returns: list of PyG Data objects, one per simulated second.

#   load_clean_graphs(cfg, base_dir=BASE_DIR)
#       Loads all p0 (clean) subfolders for the given scenario and returns the
#       combined list of clean graphs (used by calibrate.py).

#   load_attack_graphs(cfg, attack_type, penetration, base_dir=BASE_DIR)
#       Loads graphs from a specific attack subfolder.

#   list_attack_folders(scenario_dir)
#       Returns sorted list of (attack_type, penetration, folder_path) tuples.
# """

# import os
# import math
# from typing import List, Tuple, Optional

# import numpy as np
# import pandas as pd
# import torch
# from torch_geometric.data import Data

# # ── Path helpers ──────────────────────────────────────────────────────────────

# # Default dataset root (override with BASE_DIR env var or the base_dir argument)
# BASE_DIR = os.environ.get(
#     "SDVN_DATASET_DIR",
#     "/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN/analytics/datasets",
# )

# # The 'suburban' scenario is stored under the 'rural' directory
# SCENARIO_DIR_MAP = {
#     "urban":    "urban",
#     "suburban": "rural",    # <-- alias: config says "suburban", disk says "rural"
#     "highway":  "highway",
# }

# ATTACK_TYPES = [f"a{i}" for i in range(1, 8)]          # a1 … a7
# PENETRATIONS = ["p0", "p20", "p40", "p60", "p80", "p100"]


# def get_scenario_dir(cfg_name: str, base_dir: str = BASE_DIR) -> str:
#     """Return the absolute path to the scenario's dataset folder."""
#     dir_name = SCENARIO_DIR_MAP.get(cfg_name)
#     if dir_name is None:
#         raise ValueError(
#             f"Unknown scenario '{cfg_name}'. "
#             f"Choose from {list(SCENARIO_DIR_MAP)}"
#         )
#     return os.path.join(base_dir, dir_name)


# def list_attack_folders(
#     scenario_dir: str,
# ) -> List[Tuple[str, str, str]]:
#     """
#     Enumerate all valid attack sub-folders under scenario_dir.

#     Returns
#     -------
#     list of (attack_type, penetration, folder_path)
#     sorted by (attack_type, penetration_int).
#     """
#     results = []
#     for at in ATTACK_TYPES:
#         for pct in PENETRATIONS:
#             folder = os.path.join(scenario_dir, f"{at}_{pct}")
#             if os.path.isdir(folder):
#                 results.append((at, pct, folder))
#     return results


# def _pct_int(pct_str: str) -> int:
#     """'p60' -> 60"""
#     return int(pct_str.lstrip("p"))


# # ── Feature engineering ───────────────────────────────────────────────────────

# def _heading_sincos(heading_deg: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
#     rad = np.radians(heading_deg)
#     return np.sin(rad), np.cos(rad)


# def _build_node_features(df_t: pd.DataFrame) -> np.ndarray:
#     """
#     Build the 6-dim node feature matrix for one timestep.

#     Feature order (must match config.feature_cols):
#       0: x
#       1: y
#       2: speed
#       3: head_sin
#       4: head_cos
#       5: accel
#     """
#     # --- acceleration column: accept both 'acceleration' and 'accel' ---
#     if "accel" in df_t.columns:
#         accel = df_t["accel"].to_numpy(dtype=np.float32)
#     elif "acceleration" in df_t.columns:
#         accel = df_t["acceleration"].to_numpy(dtype=np.float32)
#     else:
#         accel = np.zeros(len(df_t), dtype=np.float32)

#     head_sin, head_cos = _heading_sincos(df_t["heading"].to_numpy(dtype=np.float32))

#     feats = np.column_stack([
#         df_t["x"].to_numpy(dtype=np.float32),
#         df_t["y"].to_numpy(dtype=np.float32),
#         df_t["speed"].to_numpy(dtype=np.float32),
#         head_sin.astype(np.float32),
#         head_cos.astype(np.float32),
#         accel,
#     ])
#     return feats


# # ── Edge construction (Eq. 3.26) ──────────────────────────────────────────────

# def _build_edges(
#     xy: np.ndarray,
#     heading_deg: np.ndarray,
#     r_max: float,
#     phi_max_rad: float,
# ) -> np.ndarray:
#     """
#     Return edge_index (2, E) for one timestep graph.

#     An undirected edge (i, j) exists iff:
#       dist(i, j) <= r_max                          (V2V range)
#       AND |heading_i - heading_j| mod 360 <= phi_max_deg  (heading divergence)

#     Both directed directions are included so GATConv receives a symmetric graph.
#     """
#     n = len(xy)
#     if n == 0:
#         return np.empty((2, 0), dtype=np.int64)

#     # pairwise distances
#     diff = xy[:, None, :] - xy[None, :, :]          # (N, N, 2)
#     dist = np.sqrt((diff ** 2).sum(axis=-1))         # (N, N)

#     # heading divergence (circular, degrees -> radians)
#     h = np.radians(heading_deg)
#     dh = np.abs(h[:, None] - h[None, :])             # (N, N), radians
#     dh = np.minimum(dh, 2 * np.pi - dh)             # fold into [0, pi]

#     mask = (dist <= r_max) & (dh <= phi_max_rad) & (dist > 0)  # no self-loops

#     src, dst = np.where(mask)
#     return np.stack([src, dst], axis=0).astype(np.int64)


# # ── Single-timestep graph builder ─────────────────────────────────────────────

# def _make_graph(
#     df_t: pd.DataFrame,
#     attacker_ids: set,
#     r_max: float,
#     phi_max_rad: float,
# ) -> Optional[Data]:
#     """
#     Build one PyG Data object for a single simulation second.

#     Returns None if the timestep has fewer than 2 vehicles (no edges possible).
#     """
#     if len(df_t) < 2:
#         return None

#     # Node features
#     x = torch.tensor(_build_node_features(df_t), dtype=torch.float32)

#     # Node labels: 1 = attacker, 0 = normal
#     vids = df_t["vehicle_id"].tolist()
#     y = torch.tensor(
#         [1 if vid in attacker_ids else 0 for vid in vids],
#         dtype=torch.float32,
#     )

#     # Edges (Eq. 3.26)
#     xy = df_t[["x", "y"]].to_numpy(dtype=np.float32)
#     heading = df_t["heading"].to_numpy(dtype=np.float32)
#     edge_index = torch.tensor(
#         _build_edges(xy, heading, r_max, phi_max_rad),
#         dtype=torch.long,
#     )

#     g = Data(x=x, edge_index=edge_index, y=y)
#     g.node_ids = vids          # keep for calibrate.py per-node lookup
#     g.num_nodes = len(vids)
#     return g


# # ── CSV loading helpers ────────────────────────────────────────────────────────

# _BEACON_REQUIRED = {"time", "vehicle_id", "x", "y", "speed", "heading"}
# _POISON_REQUIRED = {"time", "vehicle_id"}


# def _read_beacon(path: str) -> pd.DataFrame:
#     df = pd.read_csv(path)
#     df.columns = df.columns.str.strip().str.lower()
#     missing = _BEACON_REQUIRED - set(df.columns)
#     if missing:
#         raise ValueError(f"beacon_log.csv at '{path}' missing columns: {missing}")
#     df["time"] = df["time"].astype(float).astype(int)
#     df["vehicle_id"] = df["vehicle_id"].astype(str).str.strip()
#     return df


# def _read_poison(path: str) -> pd.DataFrame:
#     """Load tp_s1_poison_log.csv. Returns empty DataFrame if file absent."""
#     if not os.path.exists(path):
#         return pd.DataFrame(columns=["time", "vehicle_id"])
#     df = pd.read_csv(path)
#     df.columns = df.columns.str.strip().str.lower()
#     missing = _POISON_REQUIRED - set(df.columns)
#     if missing:
#         raise ValueError(
#             f"tp_s1_poison_log.csv at '{path}' missing columns: {missing}"
#         )
#     df["time"] = df["time"].astype(float).astype(int)
#     df["vehicle_id"] = df["vehicle_id"].astype(str).str.strip()
#     return df


# # ── Core graph-building pipeline ──────────────────────────────────────────────

# def _folder_to_graphs(folder: str, cfg) -> List[Data]:
#     """
#     Build all timestep-graphs from one attack subfolder.

#     Parameters
#     ----------
#     folder : str
#         Path to e.g. .../urban/a3_p60/
#     cfg    : ScenarioConfig
#         Provides r_max, phi_max_rad (edge geometry).

#     Returns
#     -------
#     List[Data]  — one Data per valid simulation second.
#     """
#     beacon_path = os.path.join(folder, "beacon_log.csv")
#     poison_path = os.path.join(folder, "tp_s1_poison_log.csv")

#     if not os.path.exists(beacon_path):
#         raise FileNotFoundError(f"beacon_log.csv not found in '{folder}'")

#     beacon_df = _read_beacon(beacon_path)
#     poison_df = _read_poison(poison_path)

#     # Build {time -> set of attacker vehicle_ids}
#     attacker_by_time: dict = {}
#     for t, grp in poison_df.groupby("time"):
#         attacker_by_time[int(t)] = set(grp["vehicle_id"].tolist())

#     graphs: List[Data] = []
#     for t, df_t in beacon_df.groupby("time"):
#         t_int = int(t)
#         attackers = attacker_by_time.get(t_int, set())
#         g = _make_graph(
#             df_t.reset_index(drop=True),
#             attackers,
#             cfg.r_max,
#             cfg.phi_max_rad,
#         )
#         if g is not None:
#             graphs.append(g)

#     return graphs


# def _csv_to_graphs(beacon_csv: str, cfg) -> List[Data]:
#     """
#     Legacy path: caller passes a beacon_log.csv directly.
#     Looks for tp_s1_poison_log.csv in the same directory.
#     """
#     folder = os.path.dirname(os.path.abspath(beacon_csv))
#     return _folder_to_graphs(folder, cfg)


# # ── Public API ────────────────────────────────────────────────────────────────

# def load_graphs(path_or_spec: str, cfg) -> List[Data]:
#     """
#     Flexible entry point used by train.py, calibrate.py, and score.py.

#     path_or_spec may be:
#       (a) path to a beacon_log.csv  ->  graphs from that file's folder
#       (b) path to a folder containing beacon_log.csv
#       (c) "auto:<scenario>"  ->  all attack subfolders for that scenario

#     Parameters
#     ----------
#     path_or_spec : str
#     cfg          : ScenarioConfig  (from config.py)

#     Returns
#     -------
#     List[Data]
#     """
#     if path_or_spec.startswith("auto:"):
#         scenario = path_or_spec.split(":", 1)[1]
#         scen_dir = get_scenario_dir(scenario)
#         all_graphs: List[Data] = []
#         for at, pct, folder in list_attack_folders(scen_dir):
#             all_graphs.extend(_folder_to_graphs(folder, cfg))
#         return all_graphs

#     # Resolve to a folder
#     if os.path.isfile(path_or_spec):
#         folder = os.path.dirname(os.path.abspath(path_or_spec))
#     elif os.path.isdir(path_or_spec):
#         folder = path_or_spec
#     else:
#         raise FileNotFoundError(
#             f"load_graphs: '{path_or_spec}' is neither a file nor a directory."
#         )
#     return _folder_to_graphs(folder, cfg)


# def load_clean_graphs(cfg, base_dir: str = BASE_DIR) -> List[Data]:
#     """
#     Load all p0 (clean, 0 % attack) subfolders for the given scenario.

#     Used by calibrate.py to build locked per-node statistics from clean traffic.
#     """
#     scen_dir = get_scenario_dir(cfg.name, base_dir)
#     all_graphs: List[Data] = []
#     for at in ATTACK_TYPES:
#         folder = os.path.join(scen_dir, f"{at}_p0")
#         if not os.path.isdir(folder):
#             continue
#         graphs = _folder_to_graphs(folder, cfg)
#         all_graphs.extend(graphs)

#     if not all_graphs:
#         raise RuntimeError(
#             f"No clean (p0) graphs found for scenario '{cfg.name}' "
#             f"under '{scen_dir}'. Check BASE_DIR / SDVN_DATASET_DIR."
#         )
#     return all_graphs


# def load_attack_graphs(
#     cfg,
#     attack_type: str,
#     penetration: str,
#     base_dir: str = BASE_DIR,
# ) -> List[Data]:
#     """
#     Load graphs from one specific attack subfolder.

#     Parameters
#     ----------
#     cfg          : ScenarioConfig
#     attack_type  : 'a1' … 'a7'
#     penetration  : 'p0' 'p20' 'p40' 'p60' 'p80' 'p100'
#     base_dir     : dataset root (default BASE_DIR)

#     Returns
#     -------
#     List[Data]

#     Example
#     -------
#     >>> from config import get_config
#     >>> from dataset import load_attack_graphs
#     >>> cfg = get_config("urban")
#     >>> graphs = load_attack_graphs(cfg, "a3", "p60")
#     >>> len(graphs)
#     120
#     """
#     if attack_type not in ATTACK_TYPES:
#         raise ValueError(
#             f"Unknown attack type '{attack_type}'. Choose from {ATTACK_TYPES}"
#         )
#     if penetration not in PENETRATIONS:
#         raise ValueError(
#             f"Unknown penetration '{penetration}'. Choose from {PENETRATIONS}"
#         )
#     scen_dir = get_scenario_dir(cfg.name, base_dir)
#     folder = os.path.join(scen_dir, f"{attack_type}_{penetration}")
#     if not os.path.isdir(folder):
#         raise FileNotFoundError(
#             f"Attack folder not found: '{folder}'"
#         )
#     return _folder_to_graphs(folder, cfg)


# # ── Dataset summary utility ───────────────────────────────────────────────────

# def dataset_summary(cfg, base_dir: str = BASE_DIR) -> None:
#     """
#     Print a table of available subfolders and their graph counts.

#     Useful for a quick sanity-check that all 7 × 6 = 42 folders are present
#     and contain parseable data.

#     Usage:
#         from config import get_config
#         from dataset import dataset_summary
#         dataset_summary(get_config("urban"))
#     """
#     scen_dir = get_scenario_dir(cfg.name, base_dir)
#     folders = list_attack_folders(scen_dir)
#     if not folders:
#         print(f"No attack folders found under '{scen_dir}'")
#         return

#     print(f"\nDataset summary — scenario: '{cfg.name}'  "
#           f"(dir: {scen_dir})")
#     print(f"{'folder':18s} {'graphs':>8s} {'nodes_total':>12s} "
#           f"{'attack_nodes':>13s} {'atk%':>5s}")
#     print("-" * 62)

#     for at, pct, folder in folders:
#         try:
#             graphs = _folder_to_graphs(folder, cfg)
#             total_nodes = sum(g.num_nodes for g in graphs)
#             atk_nodes   = sum(int(g.y.sum().item()) for g in graphs)
#             atk_frac    = 100.0 * atk_nodes / max(total_nodes, 1)
#             print(f"{at+'_'+pct:18s} {len(graphs):8d} {total_nodes:12d} "
#                   f"{atk_nodes:13d} {atk_frac:5.1f}%")
#         except Exception as exc:
#             print(f"{at+'_'+pct:18s}   ERROR: {exc}")

#     print()


# # ── CLI quick-check ───────────────────────────────────────────────────────────

# if __name__ == "__main__":
#     import argparse
#     from config import get_config

#     ap = argparse.ArgumentParser(
#         description="Dataset loader sanity check — prints per-folder graph counts."
#     )
#     ap.add_argument("--scenario", default="urban",
#                     choices=["urban", "suburban", "highway"],
#                     help="Scenario to summarise (suburban maps to rural/ on disk).")
#     ap.add_argument("--base_dir", default=BASE_DIR,
#                     help="Override the dataset root directory.")
#     args = ap.parse_args()

#     cfg = get_config(args.scenario)
#     dataset_summary(cfg, base_dir=args.base_dir)



"""
dataset.py
==========
Reads the REAL NS-3 beacon logs directly from the data folder. NO synthetic
data, NO separate conversion step.

On-disk layout (exactly as exported by the simulator):

    data/<scenario>/a<N>_p<pct>/beacon_log.csv

      <scenario> in {urban, rural, highway}      (suburban was renamed -> rural)
      a<N>   = attack type   (a1..a7)
      p<pct> = penetration   (p0, p20, p40, p60, p80, p100)

beacon_log.csv columns (raw simulator schema):

    sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, accel,
    is_poisoned, detected, sig_mask, psi_score, attack_number, attack_pct,
    attacker_class, gt_pos_x, gt_pos_y, gt_speed

Column mapping used by the GAT (the rest are ignored):

    sim_time   -> t            (timestep key)
    vehicle_id -> node id
    pos_x,pos_y-> x, y         (position, metres)
    speed      -> speed        (m/s)
    heading    -> heading      (radians)  -> expanded to (sin, cos)
    accel      -> accel        (m/s^2)
    is_poisoned-> label        (1 = malicious node, 0 = honest)

Clean vs attack split (Phase 1a vs 1b):
    attack_pct == 0   -> CLEAN run  (all honest)         used by calibrate.py
    attack_pct  > 0   -> ATTACK run (label=is_poisoned)  used by train.py / score.py

seed (keeps every run's graphs separate, also the multi-seed key for selection):
    seed = attack_number * 100 + attack_pct

Each (seed, sim_time) becomes one graph:
    * Eq. 3.27  edge (i,j) iff ||p_i-p_j|| <= r_max AND heading divergence <= phi_max
    * Eq. 3.28  per-feature rolling z-score across the vehicles in that graph, eps=1e-8
"""
import os
import glob
import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data

EPS = 1e-8

# raw columns we rely on; if any are missing we raise a clear error
RAW_REQUIRED = ["sim_time", "vehicle_id", "pos_x", "pos_y",
                "speed", "heading", "accel", "is_poisoned",
                "attack_number", "attack_pct"]


# ───────────────────────── raw file reading ─────────────────────────
def _read_beacon(path):
    """Read one beacon_log.csv and map raw columns -> project schema."""
    df = pd.read_csv(path)
    missing = [c for c in RAW_REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(
            f"beacon_log.csv at '{path}' missing columns {missing}.\n"
            f"  Found columns: {list(df.columns)}\n"
            f"  Expected the raw simulator schema (sim_time, pos_x, pos_y, ...)."
        )
    out = pd.DataFrame({
        "seed": df["attack_number"].astype(int) * 100 + df["attack_pct"].astype(int),
        "t": df["sim_time"].round(4),
        "vehicle_id": df["vehicle_id"].astype(int),
        "x": df["pos_x"].astype(float),
        "y": df["pos_y"].astype(float),
        "speed": df["speed"].astype(float),
        "heading": df["heading"].astype(float),
        "accel": df["accel"].astype(float),
        "label": df["is_poisoned"].astype(int),
        "attack_pct": df["attack_pct"].astype(int),
    })
    return out


def _scenario_frame(data_root, scenario, split):
    """Concatenate every beacon_log under data/<scenario>/a*/ for the given split."""
    folder = os.path.join(data_root, scenario)
    if not os.path.isdir(folder):
        raise FileNotFoundError(
            f"Scenario folder not found: '{folder}'.\n"
            f"  Expected layout: {data_root}/{scenario}/a<N>_p<pct>/beacon_log.csv"
        )
    files = sorted(glob.glob(os.path.join(folder, "a*", "beacon_log.csv")))
    if not files:
        raise FileNotFoundError(
            f"No beacon_log.csv files under '{folder}/a*/'. "
            f"Check the data path."
        )
    frames = [_read_beacon(f) for f in files]
    df = pd.concat(frames, ignore_index=True)

    if split == "clean":
        df = df[df["attack_pct"] == 0]
        if len(df) == 0:
            raise ValueError(
                f"No CLEAN data for scenario '{scenario}': no a*_p0 run exists under "
                f"'{folder}'. Calibration (Phase 1b) needs an attack_pct==0 run.\n"
                f"  -> Export a p0 (attack-free) run for '{scenario}'."
            )
    elif split == "attack":
        df = df[df["attack_pct"] > 0]
        if len(df) == 0:
            raise ValueError(f"No ATTACK data (attack_pct>0) for scenario '{scenario}'.")
    else:
        raise ValueError(f"split must be 'attack' or 'clean', got '{split}'")
    return df.sort_values(["seed", "t", "vehicle_id"]).reset_index(drop=True)


# ───────────────────────── graph construction ─────────────────────────
def _build_edges(pos, vel, r_max, phi_max_rad):
    """Eq. 3.27: range AND heading-divergence gate -> [2,E] edge_index.
    Vehicle-vehicle graph with self-loops.
    # RSU EXTENSION POINT: Eq. 3.27 is written for v_i and r_j (vehicle-RSU).
    # To add RSU nodes, append RSU rows here and connect in-range vehicles to
    # them. Blocked until rsu_id coordinates are exported in the beacon log.
    """
    n = pos.shape[0]
    if n == 0:
        return torch.empty((2, 0), dtype=torch.long)
    diff = pos[:, None, :] - pos[None, :, :]
    dist = np.sqrt((diff ** 2).sum(-1) + EPS)
    speed = np.linalg.norm(vel, axis=1, keepdims=True) + EPS
    unit = vel / speed
    cos = np.clip(unit @ unit.T, -1.0, 1.0)
    ang = np.arccos(cos)
    mask = (dist <= r_max) & (ang <= phi_max_rad)
    np.fill_diagonal(mask, True)
    src, dst = np.where(mask)
    return torch.tensor(np.vstack([src, dst]), dtype=torch.long)


def _zscore(feat):
    """Eq. 3.28: per-feature rolling z-score across vehicles in this graph."""
    mu = feat.mean(axis=0, keepdims=True)
    sd = feat.std(axis=0, keepdims=True)
    return (feat - mu) / (sd + EPS)


def _graph_from_group(df_t, cfg):
    pos = df_t[["x", "y"]].to_numpy(dtype=np.float64)
    spd = df_t["speed"].to_numpy(dtype=np.float64)
    hd = df_t["heading"].to_numpy(dtype=np.float64)
    acc = df_t["accel"].to_numpy(dtype=np.float64)
    vel = np.stack([spd * np.cos(hd), spd * np.sin(hd)], axis=1)

    # feature order matches cfg.feature_cols: x,y,speed,head_sin,head_cos,accel
    raw = np.stack([pos[:, 0], pos[:, 1], spd, np.sin(hd), np.cos(hd), acc], axis=1)
    x = torch.tensor(_zscore(raw), dtype=torch.float)
    edge_index = _build_edges(pos, vel, cfg.r_max, cfg.phi_max_rad)
    y = torch.tensor(df_t["label"].to_numpy(dtype=np.int64), dtype=torch.float)
    data = Data(x=x, edge_index=edge_index, y=y)
    data.node_ids = torch.tensor(df_t["vehicle_id"].to_numpy(dtype=np.int64), dtype=torch.long)
    return data


def _frame_to_graphs(df, cfg):
    # bucket continuous sim_time into beacon-interval windows (Tb) so that
    # vehicles present in the same ~100ms window form ONE spatial graph.
    tb = cfg.beacon_interval
    df = df.copy()
    df["tbin"] = (df["t"] / tb).round() * tb
    graphs = []
    for _key, df_t in df.groupby(["seed", "tbin"], sort=True):
        if len(df_t) == 0:
            continue
        graphs.append(_graph_from_group(df_t, cfg))
    if not graphs:
        raise ValueError(f"No graphs built for scenario '{cfg.name}'.")
    return graphs


# ───────────────────────── public API ─────────────────────────
def load_attack_graphs(data_root, cfg):
    """Phase 1a / scoring: all attack_pct>0 runs for this scenario -> list[Data]."""
    df = _scenario_frame(data_root, cfg.name, "attack")
    return _frame_to_graphs(df, cfg)


def load_clean_graphs(data_root, cfg):
    """Phase 1b: the attack_pct==0 run for this scenario -> list[Data]."""
    df = _scenario_frame(data_root, cfg.name, "clean")
    return _frame_to_graphs(df, cfg)


def in_dim(cfg):
    return len(cfg.feature_cols)


def temporal_split(graphs, val_frac=0.3):
    """Early segment -> train, strictly later segment -> val (no leakage).
    Graphs come out of groupby sorted by (seed, t), so a tail slice is 'later'.
    """
    n = len(graphs)
    cut = int(round(n * (1.0 - val_frac)))
    cut = max(1, min(cut, n - 1)) if n > 1 else 1
    return graphs[:cut], graphs[cut:]


def temporal_split3(graphs, train_frac=0.6, val_frac=0.2):
    """3-way TEMPORAL split -> (train, val, test), strictly time-ordered and
    DISJOINT (mirrors the LSTM-AE's 60/20/20 temporal_split).

      train : earliest train_frac           -> fit GAT weights (Phase 1a)
      val   : next val_frac                  -> best-checkpoint / model selection
      test  : latest (1-train-val) segment   -> FINAL scoring only (never trained on)

    Because load_attack_graphs() returns graphs deterministically ordered by
    (seed, tbin), train.py and score.py applying this same function with the
    same fractions get the SAME disjoint slices -> no train/test leakage.
    """
    n = len(graphs)
    if n < 3:
        # too few graphs to hold out a test slice; degrade gracefully
        tr, va = temporal_split(graphs, val_frac=val_frac)
        return tr, va, va
    c1 = int(round(n * train_frac))
    c2 = int(round(n * (train_frac + val_frac)))
    c1 = max(1, min(c1, n - 2))
    c2 = max(c1 + 1, min(c2, n - 1))
    return graphs[:c1], graphs[c1:c2], graphs[c2:]
