import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from .config import WINDOW_SIZE, FEATURE_DIM

def load_beacon_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Automatically map GAT schema column names to LSTM expected names
    rename_map = {}
    if "t" in df.columns and "sim_time" not in df.columns:
        rename_map["t"] = "sim_time"
    if "x" in df.columns and "pos_x" not in df.columns:
        rename_map["x"] = "pos_x"
    if "y" in df.columns and "pos_y" not in df.columns:
        rename_map["y"] = "pos_y"
    if "label" in df.columns and "is_poisoned" not in df.columns:
        rename_map["label"] = "is_poisoned"
    if rename_map:
        df = df.rename(columns=rename_map)

    if "run_id" not in df.columns:
        BOUNDARY_DROP = 2.0
        prev = df["sim_time"].shift(1)
        new_run = (prev.notna() & ((prev - df["sim_time"]) > BOUNDARY_DROP))
        df["run_id"] = new_run.cumsum().astype(int)
    return df

def filter_clean_only(df: pd.DataFrame) -> pd.DataFrame:
    if "is_poisoned" in df.columns:
        df = df[df["is_poisoned"] == 0].copy()
    return df

def temporal_split(df: pd.DataFrame, train_frac: float = 0.60, val_frac: float = 0.20):
    train_parts, val_parts, held_parts = [], [], []
    for run_id, rdf in df.groupby("run_id"):
        t_min = rdf["sim_time"].min()
        t_max = rdf["sim_time"].max()
        t_range = t_max - t_min
        if t_range <= 0:
            continue
        t_train_end = t_min + train_frac * t_range
        t_val_end   = t_min + (train_frac + val_frac) * t_range
        train_parts.append(rdf[rdf["sim_time"] < t_train_end])
        val_parts.append(rdf[(rdf["sim_time"] >= t_train_end) & (rdf["sim_time"] < t_val_end)])
        held_parts.append(rdf[rdf["sim_time"] >= t_val_end])

    train_df = pd.concat(train_parts, ignore_index=True) if train_parts else pd.DataFrame()
    val_df   = pd.concat(val_parts, ignore_index=True) if val_parts else pd.DataFrame()
    held_df  = pd.concat(held_parts, ignore_index=True) if held_parts else pd.DataFrame()
    return train_df, val_df, held_df

def build_windows(beacon_df, vehicle_id: int, window: int = WINDOW_SIZE) -> np.ndarray:
    cols = ["pos_x", "pos_y", "speed", "heading", "accel"]
    vdf  = beacon_df[beacon_df["vehicle_id"] == vehicle_id].sort_values("sim_time")
    feats_5 = vdf[cols].values.astype(np.float32)
    
    # Try to find trust score column, otherwise default to 1.0 (fully trusted)
    if "tau_i" in vdf.columns:
        tau = vdf["tau_i"].values.astype(np.float32).reshape(-1, 1)
    elif "trust" in vdf.columns:
        tau = vdf["trust"].values.astype(np.float32).reshape(-1, 1)
    elif "trust_score" in vdf.columns:
        tau = vdf["trust_score"].values.astype(np.float32).reshape(-1, 1)
    else:
        tau = np.ones((len(feats_5), 1), dtype=np.float32)
        
    feats_6 = np.hstack([feats_5, tau])
    
    if len(feats_6) < window:
        return np.empty((0, window, FEATURE_DIM), dtype=np.float32)
    windows = np.stack([feats_6[i:i+window] for i in range(len(feats_6) - window + 1)])
    return windows

def build_all_windows(df: pd.DataFrame, window: int = WINDOW_SIZE) -> np.ndarray:
    group_keys = ["run_id", "vehicle_id"] if "run_id" in df.columns else ["vehicle_id"]
    all_windows = []
    for _key, vdf in df.groupby(group_keys):
        vdf = vdf.sort_values("sim_time").reset_index(drop=True)
        wins = build_windows(vdf, vehicle_id=vdf["vehicle_id"].iloc[0], window=window)
        if len(wins) > 0:
            all_windows.append(wins)
    if not all_windows:
        return np.empty((0, window, FEATURE_DIM), dtype=np.float32)
    return np.concatenate(all_windows, axis=0).astype(np.float32)