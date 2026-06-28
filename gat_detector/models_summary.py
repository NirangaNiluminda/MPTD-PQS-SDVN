"""
models_summary.py
=================
Prints the three separate models side by side so a reviewer can see at a glance
that urban / suburban / highway are distinct models, not one reused config.

    python models_summary.py
"""
from config import SCENARIOS
from model import build_model

IN_DIM = 6  # x, y, speed, head_sin, head_cos, accel

def main():
    print(f"{'scenario':10s} {'class':12s} {'heads':>5s} {'hidden':>6s} "
          f"{'emb':>4s} {'dropout':>7s} {'r_max':>6s} {'phi':>4s} {'params':>8s}")
    print("-" * 74)
    for name, cfg in SCENARIOS.items():
        m = build_model(cfg, IN_DIM)
        n = sum(p.numel() for p in m.parameters())
        print(f"{name:10s} {type(m).__name__:12s} {cfg.heads:5d} {cfg.hidden_dim:6d} "
              f"{cfg.emb_dim:4d} {cfg.dropout:7.2f} {cfg.r_max:6.0f} "
              f"{cfg.phi_max_deg:4.0f} {n:8d}")
    print("\nEach scenario -> its own class, architecture, checkpoint, and stats.")

if __name__ == "__main__":
    main()
