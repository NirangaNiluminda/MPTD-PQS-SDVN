# """
# model.py
# ========
# THREE SEPARATE GAT MODELS — one class per environment.

#   UrbanGAT      (config.URBAN)      largest:  8 heads, hidden 64, emb 32
#   SuburbanGAT   (config.SUBURBAN)   medium:   4 heads, hidden 32, emb 16
#   HighwayGAT    (config.HIGHWAY)    smallest: 2 heads, hidden 16, emb 8

# They share the same 2-layer graph-attention machinery (GATEncoder) but are
# DISTINCT classes with DIFFERENT architectures, so each produces its own weight
# shapes and its own trained checkpoint. Pick one with build_model() / build_encoder()
# via the MODEL_REGISTRY, keyed by scenario name.

# Encoder (report Eqs. 3.28-3.29):
#   layer 1: GATConv, H heads, concatenated -> ELU -> dropout
#   layer 2: GATConv, H heads, AVERAGED     -> x'_i  (the node embedding)

# Classification head (modeling update, Eq. gat_cls), used only during Phase 1a:
#   ŷ_i = sigmoid( w_cls^T x'_i + b_cls )

# After training the head is discarded; inference uses the Eq. 3.38 z-score on x'_i
# (and, for comparison, the head). See score.py.
# """
# import torch
# import torch.nn as nn
# import torch.nn.functional as F
# from torch_geometric.nn import GATConv


# # Shared encoder machinery (architecture supplied per scenario)
# class GATEncoder(nn.Module):
#     def __init__(self, in_dim, hidden_dim, emb_dim, heads, dropout):
#         super().__init__()
#         self.dropout = dropout
#         self.gat1 = GATConv(in_dim, hidden_dim, heads=heads, concat=True,
#                             dropout=dropout)
#         self.gat2 = GATConv(hidden_dim * heads, emb_dim, heads=heads,
#                             concat=False, dropout=dropout)

#     def forward(self, x, edge_index):
#         h = self.gat1(x, edge_index)
#         h = F.elu(h)
#         h = F.dropout(h, p=self.dropout, training=self.training)
#         x_prime = self.gat2(h, edge_index)      # x'_i, Eq. 3.29
#         return x_prime

# # Base scenario model: encoder + linear sigmoid head
# class _SceneGAT(nn.Module):
#     """Base class for a single-scenario model. Subclasses set `scenario`."""
#     scenario: str = "base"

#     def __init__(self, cfg, in_dim):
#         super().__init__()
#         assert cfg.name == self.scenario, (
#             f"{type(self).__name__} expects scenario '{self.scenario}', "
#             f"got config for '{cfg.name}'")
#         self.cfg_name = cfg.name
#         self.encoder = GATEncoder(in_dim, cfg.hidden_dim, cfg.emb_dim,
#                                   cfg.heads, cfg.dropout)
#         self.head = nn.Linear(cfg.emb_dim, 1)   # w_cls, b_cls (Phase 1a only)

#     def forward(self, x, edge_index):
#         x_prime = self.encoder(x, edge_index)
#         logit = self.head(x_prime).squeeze(-1)  # pre-sigmoid
#         return logit, x_prime

#     def embed(self, x, edge_index):
#         return self.encoder(x, edge_index)
# # THE THREE SEPARATE MODELS

# class UrbanGAT(_SceneGAT):
#     """Model 1 — dense urban traffic (largest architecture)."""
#     scenario = "urban"

# class SuburbanGAT(_SceneGAT):
#     """Model 2 — intermediate suburban traffic (medium architecture)."""
#     scenario = "suburban"

# class HighwayGAT(_SceneGAT):
#     """Model 3 — sparse highway platoons (smallest architecture)."""
#     scenario = "highway"


# # registry: scenario name -> model class
# MODEL_REGISTRY = {
#     "urban": UrbanGAT,
#     "suburban": SuburbanGAT,
#     "highway": HighwayGAT,
# }
# def build_model(cfg, in_dim):
#     """Return the correct scenario model (encoder + head) for Phase 1a training."""
#     if cfg.name not in MODEL_REGISTRY:
#         raise ValueError(f"No model for scenario '{cfg.name}'. "
#                          f"Choose from {list(MODEL_REGISTRY)}")
#     return MODEL_REGISTRY[cfg.name](cfg, in_dim)


# def build_encoder(cfg, in_dim):
#     """Return a standalone encoder with this scenario's architecture.

#     Its state_dict layout matches the `encoder` submodule of the scenario model,
#     so checkpoints saved in Phase 1a load straight into it for Phase 1b / scoring.
#     """
#     return GATEncoder(in_dim, cfg.hidden_dim, cfg.emb_dim, cfg.heads, cfg.dropout)

"""
model.py
========
GAT spatial detector (paper Eqs. 3.29-3.32, 3.41). ONE encoder definition that
is instantiated with DIFFERENT architecture per scenario from config.py, giving
three genuinely separate models (urban / rural / highway), and also driving the
candidate sweep in select_models.py.

Layer 1 : GATConv(in -> hidden, heads=H, concat=True)  -> ELU -> dropout
Layer 2 : GATConv(hidden*H -> emb, heads=H, concat=False) -> head-averaged x'_i
Head    : linear(emb -> 1) + sigmoid  (Eq. 3.31), used ONLY for supervised
          training (Eq. 3.32); discarded at deployment. Deployment score is the
          deviation S_i (Eq. 3.41), computed in score.py.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv


class GATEncoder(nn.Module):
    """Produces the node embedding x'_i (Eq. 3.30)."""
    def __init__(self, in_dim, hidden_dim, emb_dim, heads, dropout):
        super().__init__()
        self.dropout = dropout
        self.gat1 = GATConv(in_dim, hidden_dim, heads=heads, concat=True, dropout=dropout)
        # final layer averages heads (concat=False) -> fixed-size emb (Eq. 3.30)
        self.gat2 = GATConv(hidden_dim * heads, emb_dim, heads=heads, concat=False, dropout=dropout)

    def forward(self, x, edge_index):
        x = self.gat1(x, edge_index)
        x = F.elu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.gat2(x, edge_index)        # x'_i
        return x


class SceneGAT(nn.Module):
    """Encoder + classification head. Architecture comes entirely from cfg, so a
    single class covers all three scenarios and every candidate."""
    def __init__(self, cfg, in_dim):
        super().__init__()
        self.scenario = cfg.name
        self.encoder = GATEncoder(in_dim, cfg.hidden_dim, cfg.emb_dim,
                                  cfg.heads, cfg.dropout)
        self.head = nn.Linear(cfg.emb_dim, 1)   # Eq. 3.31 (training only)

    def forward(self, x, edge_index):
        emb = self.encoder(x, edge_index)
        logit = self.head(emb).squeeze(-1)      # pre-sigmoid
        return logit, emb


def build_model(cfg, in_dim):
    """Full model (encoder+head) for Phase 1a training."""
    return SceneGAT(cfg, in_dim)


def build_encoder(cfg, in_dim):
    """Encoder only, for calibrate.py / score.py (head already discarded)."""
    return GATEncoder(in_dim, cfg.hidden_dim, cfg.emb_dim, cfg.heads, cfg.dropout)

