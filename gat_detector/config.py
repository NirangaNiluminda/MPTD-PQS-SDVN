# """
# config.py
# =========
# THREE SEPARATE MODELS — one per environment (urban / suburban / highway).

# This is not one model reused three times. Each scenario has:
#   * its own edge geometry      (r_max, phi_max)          -> different graphs
#   * its own GAT architecture   (heads, widths, dropout)  -> different weight shapes
#   * its own trained checkpoint (<scenario>_encoder.pt)   -> different parameters
#   * its own locked statistics  (<scenario>_stats.npz)    -> different normal baseline

# The three architectures are deliberately different, matching the environment:

#   urban     dense traffic, short spacing, diverse headings at junctions,
#             frequent topology change  -> largest model (more heads / width)
#   suburban  intermediate density and heading diversity
#             -> medium model
#   highway   sparse, long spacing, near co-directional platoons, simple linear
#             topology -> smallest model (fewer heads / width)

# Edge knobs (Eq. 3.26 in the report):
#   r_max     V2V/V2I communication range (metres)
#   phi_max   max heading divergence for an edge to exist (degrees)
#             highway ~15 (co-directional platoon), urban ~45 (junction diversity),
#             suburban ~30 (in between)
# """
# from dataclasses import dataclass, field
# from typing import List
# import math


# @dataclass
# class ScenarioConfig:
#     name: str
#     # --- Eq. 3.26 edge definition (environment geometry) ---
#     r_max: float          # max comm range in metres
#     phi_max_deg: float    # max heading divergence in degrees
#     # --- node features fed to the GAT ---
#     feature_cols: List[str] = field(
#         default_factory=lambda: ["x", "y", "speed", "head_sin", "head_cos", "accel"]
#     )
#     # --- GAT architecture (DIFFERENT per scenario -> genuinely separate models) ---
#     hidden_dim: int = 32      # per-head width of layer 1
#     emb_dim: int = 16         # embedding width x'_i (layer 2, head-averaged)
#     heads: int = 4            # H attention heads
#     dropout: float = 0.1
#     # --- training (Phase 1a) ---
#     lr: float = 1e-3
#     weight_decay: float = 5e-4
#     epochs: int = 60
#     batch_graphs: int = 16    # how many timestep-graphs per minibatch
#     # --- calibration / scoring (Phase 1b, Eq. 3.38) ---
#     score_percentile: float = 99.0   # clean S_i percentile -> default threshold

#     @property
#     def phi_max_rad(self) -> float:
#         return math.radians(self.phi_max_deg)


# # ── MODEL 1 — URBAN ──────────────────────────────────────────────────────────
# # Dense, complex topology: give it the most capacity.
# URBAN = ScenarioConfig(
#     name="urban",
#     r_max=300.0, phi_max_deg=45.0,
#     hidden_dim=64, emb_dim=32, heads=8, dropout=0.20,
#     lr=1e-3, weight_decay=5e-4, epochs=60, batch_graphs=16,
# )

# # ── MODEL 2 — SUBURBAN ───────────────────────────────────────────────────────
# # Intermediate density: medium capacity.
# SUBURBAN = ScenarioConfig(
#     name="suburban",
#     r_max=500.0, phi_max_deg=30.0,
#     hidden_dim=32, emb_dim=16, heads=4, dropout=0.10,
#     lr=1e-3, weight_decay=5e-4, epochs=60, batch_graphs=16,
# )

# # ── MODEL 3 — HIGHWAY ────────────────────────────────────────────────────────
# # Sparse, linear topology: smallest model avoids over-fitting simple graphs.
# HIGHWAY = ScenarioConfig(
#     name="highway",
#     r_max=800.0, phi_max_deg=15.0,
#     hidden_dim=16, emb_dim=8, heads=2, dropout=0.05,
#     lr=1e-3, weight_decay=5e-4, epochs=60, batch_graphs=16,
# )

# SCENARIOS = {"urban": URBAN, "suburban": SUBURBAN, "highway": HIGHWAY}


# def get_config(name: str) -> ScenarioConfig:
#     if name not in SCENARIOS:
#         raise ValueError(f"Unknown scenario '{name}'. Choose from {list(SCENARIOS)}")
#     return SCENARIOS[name]

"""
config.py
=========
THREE SEPARATE GAT MODELS — one per environment (urban / rural / highway).

This is not one model reused three times. Each scenario has:
  * its own edge geometry      (r_max, phi_max)          -> different graphs
  * its own GAT architecture   (heads, widths, dropout)  -> different weight shapes
  * its own trained checkpoint (<scenario>_encoder.pt)   -> different parameters
  * its own locked statistics  (<scenario>_stats.npz)    -> different normal baseline

SELECTED architectures (report Table 4.18, "Selected per-scenario full-mode
configuration"):

  urban   8 heads, hidden 64, emb 32, dropout 0.20   (largest  - dense graph)
  rural   4 heads, hidden 32, emb 16, dropout 0.10   (medium)
  highway 2 heads, hidden 16, emb  8, dropout 0.05   (smallest - sparse platoons)

These selected values are the BEST candidates chosen by the model-selection
sweep in select_models.py (report Table 4.16). The full candidate grid that the
sweep searches over is in CANDIDATES below (G1..G9).

Edge knobs (report Eq. 3.27):
  r_max     V2V/V2I communication range (metres). Paper uses 270 m for all
            scenarios (Sec. 4.1.3), so all three share r_max = 270.
  phi_max   max heading divergence for an edge to exist (degrees):
            highway 15 (co-directional platoon), urban 45 (junction diversity),
            rural 30 (in between).
"""
from dataclasses import dataclass, field
from typing import List
import math


@dataclass
class ScenarioConfig:
    name: str
    # --- Eq. 3.27 edge definition (environment geometry) ---
    r_max: float = 270.0          # paper: 270 m for all scenarios
    phi_max_deg: float = 45.0     # max heading divergence in degrees
    # --- node features fed to the GAT (Eq. 3.28 normalises these) ---
    feature_cols: List[str] = field(
        default_factory=lambda: ["x", "y", "speed", "head_sin", "head_cos", "accel"]
    )
    # --- GAT architecture (DIFFERENT per scenario -> genuinely separate models) ---
    hidden_dim: int = 32      # per-head width of layer 1
    emb_dim: int = 16         # embedding width x'_i (layer 2, head-averaged)
    heads: int = 4            # H attention heads
    dropout: float = 0.1
    # --- training (Phase 1a) ---
    lr: float = 5e-3          # report Table 4.13: Adam / 0.005
    weight_decay: float = 5e-4
    epochs: int = 60
    batch_graphs: int = 16    # how many timestep-graphs per minibatch
    # --- calibration / scoring (Phase 1b, Eq. 3.41) ---
    score_percentile: float = 99.0   # clean S_i percentile -> locked threshold theta_S
    beacon_interval: float = 0.1     # Tb=100ms: bucket sim_time into 0.1s graphs

    @property
    def phi_max_rad(self) -> float:
        return math.radians(self.phi_max_deg)


# ── THE THREE SELECTED MODELS (report Table 4.18) ────────────────────────────
URBAN = ScenarioConfig(
    name="urban",
    r_max=270.0, phi_max_deg=45.0,
    hidden_dim=64, emb_dim=32, heads=8, dropout=0.20,
)

RURAL = ScenarioConfig(
    name="rural",
    r_max=270.0, phi_max_deg=30.0,
    hidden_dim=32, emb_dim=16, heads=4, dropout=0.10,
)

HIGHWAY = ScenarioConfig(
    name="highway",
    r_max=270.0, phi_max_deg=15.0,
    hidden_dim=16, emb_dim=8, heads=2, dropout=0.05,
)

SCENARIOS = {"urban": URBAN, "rural": RURAL, "highway": HIGHWAY}


def get_config(name: str) -> ScenarioConfig:
    if name not in SCENARIOS:
        raise ValueError(f"Unknown scenario '{name}'. Choose from {list(SCENARIOS)}")
    return SCENARIOS[name]


# ── CANDIDATE GRID for model selection (report Table 4.16) ───────────────────
# Each candidate is (cand_id, heads, hidden, emb, dropout). select_models.py
# trains every candidate over >=3 seeds, scores validation MCC/FPR, and the
# best (bold/checkmark in Table 4.16) becomes the SELECTED config above.
CANDIDATES = {
    "urban": [
        ("G1", 4, 32, 16, 0.10),
        ("G2", 8, 64, 32, 0.20),   
        ("G3", 8, 64, 32, 0.30),
    ],
    "rural": [
        ("G4", 2, 16,  8, 0.10),
        ("G5", 4, 32, 16, 0.10),   
        ("G6", 8, 32, 16, 0.20),
    ],
    "highway": [
        ("G7", 2, 16,  8, 0.05),  
        ("G8", 4, 16,  8, 0.10),
        ("G9", 4, 32, 16, 0.10),
    ],
}


def candidate_config(scenario: str, cand_id: str) -> ScenarioConfig:
    """Build a ScenarioConfig for one candidate architecture from CANDIDATES."""
    base = get_config(scenario)
    for cid, heads, hidden, emb, drop in CANDIDATES[scenario]:
        if cid == cand_id:
            return ScenarioConfig(
                name=scenario,
                r_max=base.r_max, phi_max_deg=base.phi_max_deg,
                hidden_dim=hidden, emb_dim=emb, heads=heads, dropout=drop,
                lr=base.lr, weight_decay=base.weight_decay,
                epochs=base.epochs, batch_graphs=base.batch_graphs,
                score_percentile=base.score_percentile,
            )
    raise ValueError(f"Unknown candidate '{cand_id}' for scenario '{scenario}'")
