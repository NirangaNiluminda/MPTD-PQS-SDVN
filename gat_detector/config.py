"""
config.py
=========
THREE SEPARATE MODELS — one per environment (urban / suburban / highway).

This is not one model reused three times. Each scenario has:
  * its own edge geometry      (r_max, phi_max)          -> different graphs
  * its own GAT architecture   (heads, widths, dropout)  -> different weight shapes
  * its own trained checkpoint (<scenario>_encoder.pt)   -> different parameters
  * its own locked statistics  (<scenario>_stats.npz)    -> different normal baseline

The three architectures are deliberately different, matching the environment:

  urban     dense traffic, short spacing, diverse headings at junctions,
            frequent topology change  -> largest model (more heads / width)
  suburban  intermediate density and heading diversity
            -> medium model
  highway   sparse, long spacing, near co-directional platoons, simple linear
            topology -> smallest model (fewer heads / width)

Edge knobs (Eq. 3.26 in the report):
  r_max     V2V/V2I communication range (metres)
  phi_max   max heading divergence for an edge to exist (degrees)
            highway ~15 (co-directional platoon), urban ~45 (junction diversity),
            suburban ~30 (in between)
"""
from dataclasses import dataclass, field
from typing import List
import math


@dataclass
class ScenarioConfig:
    name: str
    # --- Eq. 3.26 edge definition (environment geometry) ---
    r_max: float          # max comm range in metres
    phi_max_deg: float    # max heading divergence in degrees
    # --- node features fed to the GAT ---
    feature_cols: List[str] = field(
        default_factory=lambda: ["x", "y", "speed", "head_sin", "head_cos", "accel"]
    )
    # --- GAT architecture (DIFFERENT per scenario -> genuinely separate models) ---
    hidden_dim: int = 32      # per-head width of layer 1
    emb_dim: int = 16         # embedding width x'_i (layer 2, head-averaged)
    heads: int = 4            # H attention heads
    dropout: float = 0.1
    # --- training (Phase 1a) ---
    lr: float = 1e-3
    weight_decay: float = 5e-4
    epochs: int = 60
    batch_graphs: int = 16    # how many timestep-graphs per minibatch
    # --- calibration / scoring (Phase 1b, Eq. 3.38) ---
    score_percentile: float = 99.0   # clean S_i percentile -> default threshold

    @property
    def phi_max_rad(self) -> float:
        return math.radians(self.phi_max_deg)


# ── MODEL 1 — URBAN ──────────────────────────────────────────────────────────
# Dense, complex topology: give it the most capacity.
URBAN = ScenarioConfig(
    name="urban",
    r_max=300.0, phi_max_deg=45.0,
    hidden_dim=64, emb_dim=32, heads=8, dropout=0.20,
    lr=1e-3, weight_decay=5e-4, epochs=60, batch_graphs=16,
)

# ── MODEL 2 — SUBURBAN ───────────────────────────────────────────────────────
# Intermediate density: medium capacity.
SUBURBAN = ScenarioConfig(
    name="suburban",
    r_max=500.0, phi_max_deg=30.0,
    hidden_dim=32, emb_dim=16, heads=4, dropout=0.10,
    lr=1e-3, weight_decay=5e-4, epochs=60, batch_graphs=16,
)

# ── MODEL 3 — HIGHWAY ────────────────────────────────────────────────────────
# Sparse, linear topology: smallest model avoids over-fitting simple graphs.
HIGHWAY = ScenarioConfig(
    name="highway",
    r_max=800.0, phi_max_deg=15.0,
    hidden_dim=16, emb_dim=8, heads=2, dropout=0.05,
    lr=1e-3, weight_decay=5e-4, epochs=60, batch_graphs=16,
)

SCENARIOS = {"urban": URBAN, "suburban": SUBURBAN, "highway": HIGHWAY}


def get_config(name: str) -> ScenarioConfig:
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario '{name}'. Choose from {list(SCENARIOS)}")
    return SCENARIOS[name]
