"""
search_architecture.py  --  GAT model selection that TRAINS and SAVES all
candidate models (report Table 4.16). This is the GAT counterpart of the
LSTM-AE's search_architecture.py.

For each scenario it:
  1. trains every candidate architecture (config.CANDIDATES: G1..G9) for
     N_SEEDS seeds, using the same protocol as train.py (temporal 60/20/20
     split -> the last 20% test tail is held out and never trained on),
  2. SAVES every candidate x seed encoder under
        checkpoints/candidates/<scenario>/<cand>_seed<k>.pt
  3. records mean +/- std validation MCC and FPR to
        results/arch_search_<scenario>.csv   (Table 4.16 evidence)
        results/arch_search_<scenario>.md    (paste-ready table)
  4. selects the winner = highest mean val MCC, and copies its best-seed
     encoder into the DEPLOYED slot
        checkpoints/<scenario>_encoder.pt
     so calibrate.py / score.py use the model that was actually selected
     (no more "selected says G1 but trained G2" mismatch).

Run (from inside gat_detector/):
  python search_architecture.py --scenario urban   --data_root data --seeds 3
  python search_architecture.py --scenario rural   --data_root data --seeds 3
  python search_architecture.py --scenario highway --data_root data --seeds 3
  python search_architecture.py --scenario all     --data_root data --seeds 3
"""
import os, json, argparse
import numpy as np
import torch

from config import get_config, candidate_config, CANDIDATES
import dataset as D
from train import train_one


def _save_encoder(state, cfg, mcc, fpr, seed, path):
    enc_state = {k[len("encoder."):]: v for k, v in state.items()
                 if k.startswith("encoder.")}
    torch.save({
        "encoder": enc_state,
        "scenario": cfg.name,
        "arch": {"heads": cfg.heads, "hidden_dim": cfg.hidden_dim,
                 "emb_dim": cfg.emb_dim, "dropout": cfg.dropout},
        "val_mcc": mcc, "val_fpr": fpr, "seed": seed,
    }, path)


def search_scenario(scenario, data_root, seeds, ckpt_dir, results_dir, device):
    cfg0 = get_config(scenario)
    print(f"\n=== GAT architecture search: {scenario.upper()}  (>= {seeds} seeds) ===")
    print(f"loading ATTACK graphs from {data_root}/{scenario}/a*/beacon_log.csv ...")
    graphs = D.load_attack_graphs(data_root, cfg0)
    print(f"{len(graphs)} timestep-graphs\n")

    cand_dir = os.path.join(ckpt_dir, "candidates", scenario)
    os.makedirs(cand_dir, exist_ok=True)

    rows = []
    # best_state_by_cand[cand] = (best_seed_mcc, state, fpr, seed, cfg)
    best_state_by_cand = {}

    for cand_id, heads, hidden, emb, drop in CANDIDATES[scenario]:
        cfg = candidate_config(scenario, cand_id)
        mccs, fprs = [], []
        best_seed = (-2.0, None, None, None)   # (mcc, state, fpr, seed)
        for s in range(seeds):
            state, mcc, fpr = train_one(cfg, graphs, device, seed=s, verbose=False)
            mccs.append(mcc); fprs.append(fpr)
            # SAVE every candidate x seed model (the "all models" requirement)
            p = os.path.join(cand_dir, f"{cand_id}_seed{s}.pt")
            _save_encoder(state, cfg, mcc, fpr, s, p)
            if mcc > best_seed[0]:
                best_seed = (mcc, state, fpr, s)
            print(f"  {cand_id} seed {s}: MCC {mcc:+.4f}  FPR {fpr:.4f}  -> {p}")
        mccs = np.array(mccs); fprs = np.array(fprs)
        best_state_by_cand[cand_id] = (best_seed[0], best_seed[1], best_seed[2],
                                       best_seed[3], cfg)
        rows.append({
            "cand": cand_id, "H": heads, "hidden": hidden, "emb": emb, "dropout": drop,
            "mcc_mean": float(mccs.mean()), "mcc_std": float(mccs.std()),
            "fpr_mean": float(fprs.mean()),
        })
        print(f"  {cand_id} -> MCC {mccs.mean():+.4f} +/- {mccs.std():.4f}   "
              f"FPR {fprs.mean():.4f}\n")

    # winner = highest mean val MCC (FPR reported alongside, report protocol)
    best = max(rows, key=lambda r: r["mcc_mean"])
    for r in rows:
        r["selected"] = (r["cand"] == best["cand"])

    # --- results table (Table 4.16 evidence) ---
    os.makedirs(results_dir, exist_ok=True)
    csv_path = os.path.join(results_dir, f"arch_search_{scenario}.csv")
    with open(csv_path, "w") as f:
        f.write("scenario,cand,H,hidden,emb,dropout,val_mcc_mean,val_mcc_std,val_fpr,selected\n")
        for r in rows:
            f.write(f"{scenario},{r['cand']},{r['H']},{r['hidden']},{r['emb']},{r['dropout']},"
                    f"{r['mcc_mean']:.4f},{r['mcc_std']:.4f},{r['fpr_mean']:.4f},"
                    f"{int(r['selected'])}\n")
    md_path = os.path.join(results_dir, f"arch_search_{scenario}.md")
    with open(md_path, "w") as f:
        f.write("| Cand. | H | Hidden | Emb | Dropout | Val MCC | Val FPR | Selected |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            mark = "checkmark" if r["selected"] else ""
            f.write(f"| {r['cand']} | {r['H']} | {r['hidden']} | {r['emb']} | {r['dropout']} | "
                    f"{r['mcc_mean']:+.4f} +/- {r['mcc_std']:.4f} | {r['fpr_mean']:.4f} | {mark} |\n")

    # --- copy winner's best-seed encoder into the DEPLOYED slot ---
    win_mcc, win_state, win_fpr, win_seed, win_cfg = best_state_by_cand[best["cand"]]
    os.makedirs(ckpt_dir, exist_ok=True)
    deployed = os.path.join(ckpt_dir, f"{scenario}_encoder.pt")
    _save_encoder(win_state, win_cfg, win_mcc, win_fpr, win_seed, deployed)
    # also record which candidate won, for calibrate/score to read if needed
    with open(os.path.join(ckpt_dir, f"arch_{scenario}.json"), "w") as f:
        json.dump({"scenario": scenario, "selected_candidate": best["cand"],
                   "heads": win_cfg.heads, "hidden_dim": win_cfg.hidden_dim,
                   "emb_dim": win_cfg.emb_dim, "dropout": win_cfg.dropout,
                   "val_mcc_mean": best["mcc_mean"], "val_fpr_mean": best["fpr_mean"],
                   "best_seed": win_seed}, f, indent=2)

    # --- pretty table (Table 4.16 style) ---
    print(f"--- {scenario}: Table 4.16 (GAT model selection) ---")
    print(f"{'Cand':5} {'H':>2} {'Hidden':>6} {'Emb':>4} {'Drop':>5} "
          f"{'ValMCC':>16} {'ValFPR':>7}  Sel")
    for r in rows:
        sel = "<--" if r["selected"] else ""
        print(f"{r['cand']:5} {r['H']:>2} {r['hidden']:>6} {r['emb']:>4} {r['dropout']:>5} "
              f"{r['mcc_mean']:+.4f}+/-{r['mcc_std']:.4f} {r['fpr_mean']:>7.4f}  {sel}")
    print(f"\nSELECTED for {scenario}: {best['cand']} "
          f"(H={best['H']}, hidden={best['hidden']}, emb={best['emb']}, dropout={best['dropout']}) "
          f"best seed={win_seed}")
    print(f"  all candidate models saved under {cand_dir}/")
    print(f"  winner copied to deployed slot -> {deployed}")
    print(f"  evidence -> {csv_path} , {md_path}")
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    choices=["urban", "rural", "highway", "all"])
    ap.add_argument("--data_root", default="data")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--ckpt_dir", default="checkpoints")
    ap.add_argument("--results_dir", default="results")
    args = ap.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    scenarios = (["urban", "rural", "highway"]
                 if args.scenario == "all" else [args.scenario])
    summary = {}
    for sc in scenarios:
        try:
            summary[sc] = search_scenario(sc, args.data_root, args.seeds,
                                          args.ckpt_dir, args.results_dir, device)
        except (FileNotFoundError, ValueError) as e:
            print(f"\n[skip] {sc}: {e}")

    if summary:
        print("\n==== SELECTED (deployed) PER SCENARIO ====")
        for sc, b in summary.items():
            print(f"  {sc:8} -> {b['cand']}  H={b['H']} hidden={b['hidden']} "
                  f"emb={b['emb']} dropout={b['dropout']}  "
                  f"(MCC {b['mcc_mean']:+.4f}, FPR {b['fpr_mean']:.4f})")
        print("\nNext: calibrate + score the deployed winners:")
        for sc in summary:
            print(f"  python calibrate.py --scenario {sc} --data_root data")
        for sc in summary:
            print(f"  python score.py     --scenario {sc} --data_root data")


if __name__ == "__main__":
    main()
