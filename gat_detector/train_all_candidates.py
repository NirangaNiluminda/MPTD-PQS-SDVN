"""
train_all_candidates.py  --  train and SAVE all 9 candidate models (G1..G9).

select_models.py trains these same candidates but only to READ their MCC/FPR and
then discards the weights. This script keeps the weights and writes one encoder
checkpoint per candidate to:

    checkpoints/candidates/<scenario>_<cand>_encoder.pt

9 files total (urban G1-G3, rural G4-G6, highway G7-G9).

Run:
  python train_all_candidates.py --scenario all     --data_root data
  python train_all_candidates.py --scenario urban   --data_root data
  python train_all_candidates.py --scenario all     --data_root data --seed 0
"""
import os, argparse
import torch

from config import get_config, candidate_config, CANDIDATES
import dataset as D
from train import train_one


def run_scenario(scenario, data_root, ckpt_dir, device, seed):
    cfg0 = get_config(scenario)
    print(f"\n=== {scenario}: training {len(CANDIDATES[scenario])} candidates ===")
    print(f"loading ATTACK graphs from {data_root}/{scenario}/a*/beacon_log.csv ...")
    graphs = D.load_attack_graphs(data_root, cfg0)
    print(f"{len(graphs)} timestep-graphs\n")

    out_dir = os.path.join(ckpt_dir, "candidates")
    os.makedirs(out_dir, exist_ok=True)

    for cand_id, heads, hidden, emb, drop in CANDIDATES[scenario]:
        cfg = candidate_config(scenario, cand_id)
        state, mcc, fpr = train_one(cfg, graphs, device, seed=seed, verbose=False)

        # keep encoder weights only (head discarded, same as train.py)
        enc_state = {k[len("encoder."):]: v for k, v in state.items()
                     if k.startswith("encoder.")}
        out = os.path.join(out_dir, f"{scenario}_{cand_id}_encoder.pt")
        torch.save({
            "encoder": enc_state,
            "scenario": scenario,
            "cand": cand_id,
            "arch": {"heads": cfg.heads, "hidden_dim": cfg.hidden_dim,
                     "emb_dim": cfg.emb_dim, "dropout": cfg.dropout},
            "val_mcc": mcc, "val_fpr": fpr, "seed": seed,
        }, out)
        print(f"  {scenario:8} {cand_id}: MCC {mcc:+.4f}  FPR {fpr:.4f}  -> {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    choices=["urban", "rural", "highway", "all"])
    ap.add_argument("--data_root", default="data")
    ap.add_argument("--ckpt_dir", default="checkpoints")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    scenarios = (["urban", "rural", "highway"]
                 if args.scenario == "all" else [args.scenario])
    for sc in scenarios:
        try:
            run_scenario(sc, args.data_root, args.ckpt_dir, device, args.seed)
        except (FileNotFoundError, ValueError) as e:
            print(f"\n[skip] {sc}: {e}")

    print("\nDone. All candidate checkpoints in checkpoints/candidates/")


if __name__ == "__main__":
    main()