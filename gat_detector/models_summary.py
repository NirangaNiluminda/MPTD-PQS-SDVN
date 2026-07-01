# """
# models_summary.py
# =================
# Prints the three separate models side by side so a reviewer can see at a glance
# that urban / suburban / highway are distinct models, not one reused config.

#     python models_summary.py
# """
# from config import SCENARIOS
# from model import build_model

# IN_DIM = 6  # x, y, speed, head_sin, head_cos, accel

# def main():
#     print(f"{'scenario':10s} {'class':12s} {'heads':>5s} {'hidden':>6s} "
#           f"{'emb':>4s} {'dropout':>7s} {'r_max':>6s} {'phi':>4s} {'params':>8s}")
#     print("-" * 74)
#     for name, cfg in SCENARIOS.items():
#         m = build_model(cfg, IN_DIM)
#         n = sum(p.numel() for p in m.parameters())
#         print(f"{name:10s} {type(m).__name__:12s} {cfg.heads:5d} {cfg.hidden_dim:6d} "
#               f"{cfg.emb_dim:4d} {cfg.dropout:7.2f} {cfg.r_max:6.0f} "
#               f"{cfg.phi_max_deg:4.0f} {n:8d}")
#     print("\nEach scenario -> its own class, architecture, checkpoint, and stats.")

# if __name__ == "__main__":
#     main()

"""
models_summary.py  --  print the three SELECTED per-scenario GAT models
(report Table 4.18) and whether their checkpoints exist.

Run:
  python models_summary.py
"""
import os
from config import SCENARIOS


def main():
    print("Three separate GAT spatial detectors (selected configs, Table 4.18):\n")
    hdr = f"{'scenario':8} {'heads':>5} {'hidden':>6} {'emb':>4} {'dropout':>7} " \
          f"{'phi_max':>7} {'r_max':>6}  checkpoints"
    print(hdr); print("-" * len(hdr))
    for name, cfg in SCENARIOS.items():
        enc = os.path.join("checkpoints", f"{name}_encoder.pt")
        sts = os.path.join("checkpoints", f"{name}_stats.npz")
        status = []
        status.append("encoder OK" if os.path.exists(enc) else "encoder MISSING")
        status.append("stats OK" if os.path.exists(sts) else "stats MISSING")
        print(f"{name:8} {cfg.heads:>5} {cfg.hidden_dim:>6} {cfg.emb_dim:>4} "
              f"{cfg.dropout:>7} {cfg.phi_max_deg:>6.0f}d {cfg.r_max:>6.0f}  "
              f"{', '.join(status)}")
    print("\nNote: highway calibration/scoring needs an attack-free p0 run "
          "(data/highway/a*_p0/).")


if __name__ == "__main__":
    main()
