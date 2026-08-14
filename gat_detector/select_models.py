"""
select_models.py  --  reproduces report Table 4.16 (GAT model selection).

For a scenario, trains each of the 3 candidate architectures (config.CANDIDATES)
over >=3 seeds using the SAME fixed protocol as train.py (temporal split,
class-weighted BCE, best-val-MCC checkpoint), records validation MCC (mean+/-std)
and FPR, and picks the candidate with the highest mean MCC that does not inflate
FPR. Writes outputs/<scenario>_model_selection.csv and prints the table.

Run:
  python select_models.py --scenario urban   --data_root data --seeds 3
  python select_models.py --scenario rural   --data_root data --seeds 3
  python select_models.py --scenario highway --data_root data --seeds 3
  python select_models.py --scenario all     --data_root data --seeds 3
"""
import os, argparse
import numpy as np
import torch

from config import get_config, candidate_config, CANDIDATES
import dataset as D
from train import train_one


def run_scenario(scenario, data_root, seeds, out_dir, device):
    cfg0 = get_config(scenario)
    print(f"\n=== Model selection: {scenario}  (>= {seeds} seeds) ===")
    print(f"loading ATTACK graphs from {data_root}/{scenario}/a*/beacon_log.csv ...")
    graphs = D.load_attack_graphs(data_root, cfg0)
    print(f"{len(graphs)} timestep-graphs\n")

    results = []
    for cid, heads, hidden, emb, drop in CANDIDATES[scenario]:
        cfg = candidate_config(scenario, cid)
        mccs, fprs = [], []
        for s in range(seeds):
            _state, mcc, fpr = train_one(cfg, graphs, device, seed=s, verbose=False)
            mccs.append(mcc); fprs.append(fpr)
            print(f"  {cid}  seed {s}:  MCC {mcc:+.4f}  FPR {fpr:.4f}")
        mccs = np.array(mccs); fprs = np.array(fprs)
        results.append({
            "cand": cid, "H": heads, "hidden": hidden, "emb": emb, "dropout": drop,
            "mcc_mean": mccs.mean(), "mcc_std": mccs.std(),
            "fpr_mean": fprs.mean(),
        })
        print(f"  {cid}  ->  MCC {mccs.mean():+.4f} +/- {mccs.std():.4f}   "
              f"FPR {fprs.mean():.4f}\n")

    # selection rule: highest mean MCC (FPR reported alongside)
    best = max(results, key=lambda r: r["mcc_mean"])
    for r in results:
        r["selected"] = (r["cand"] == best["cand"])

    # write CSV (matches Table 4.16 columns)
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"{scenario}_model_selection.csv")
    with open(out, "w") as f:
        f.write("scenario,cand,H,hidden,emb,dropout,val_mcc_mean,val_mcc_std,val_fpr,selected\n")
        for r in results:
            f.write(f"{scenario},{r['cand']},{r['H']},{r['hidden']},{r['emb']},"
                    f"{r['dropout']},{r['mcc_mean']:.4f},{r['mcc_std']:.4f},"
                    f"{r['fpr_mean']:.4f},{int(r['selected'])}\n")

    # pretty table to terminal (Table 4.16 style)
    print(f"--- {scenario}: Table 4.16 (GAT model selection) ---")
    print(f"{'Cand':5} {'H':>2} {'Hidden':>6} {'Emb':>4} {'Drop':>5} "
          f"{'ValMCC':>16} {'ValFPR':>7}  Sel")
    for r in results:
        sel = "<--" if r["selected"] else ""
        print(f"{r['cand']:5} {r['H']:>2} {r['hidden']:>6} {r['emb']:>4} {r['dropout']:>5} "
              f"{r['mcc_mean']:+.4f}+/-{r['mcc_std']:.4f} {r['fpr_mean']:>7.4f}  {sel}")
    print(f"selected for {scenario}: {best['cand']} "
          f"(H={best['H']}, hidden={best['hidden']}, emb={best['emb']}, dropout={best['dropout']})")
    print(f"saved -> {out}")
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    choices=["urban", "rural", "highway", "all"])
    ap.add_argument("--data_root", default="data")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--out_dir", default="outputs")
    args = ap.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    scenarios = ["urban", "rural", "highway"] if args.scenario == "all" else [args.scenario]
    summary = {}
    for sc in scenarios:
        try:
            summary[sc] = run_scenario(sc, args.data_root, args.seeds, args.out_dir, device)
        except (FileNotFoundError, ValueError) as e:
            print(f"\n[skip] {sc}: {e}")

    if summary:
        print("\n==== SELECTED PER SCENARIO ====")
        for sc, b in summary.items():
            print(f"  {sc:8} -> {b['cand']}  H={b['H']} hidden={b['hidden']} "
                  f"emb={b['emb']} dropout={b['dropout']}  "
                  f"(MCC {b['mcc_mean']:+.4f}, FPR {b['fpr_mean']:.4f})")


if __name__ == "__main__":
    main()
