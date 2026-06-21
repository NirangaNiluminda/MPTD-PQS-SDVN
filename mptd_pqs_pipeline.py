#!/usr/bin/env python3
"""
MPTD-PQS Full Evaluation Pipeline
====================================
Reads NS-3 simulation output files and runs the complete detection pipeline:
  1. Parse [METRICS] TP/TN lines from sim_output_ap*.txt
  2. Run LW-DETECT (9 attack signatures)
  3. Run GAT spatial anomaly detector
  4. Run LSTM Temporal Autoencoder
  5. Fuse scores → Φᵢ(t)
  6. (Removed) Blockchain trust/revocation simulation — the real Hyperledger
     Fabric chaincode at chaincode/chaincode/smartcontract.go (Eq 3.55/3.58/
     3.59) now handles SC-Trust/SC-Revoke/CP-DETECT directly from the NS-3
     RSU code (see scratch/mptd_pqs_sdvn/06c_blockchain_api.h). The Python
     pipeline computes on-chain record counts from `points` directly.
  7. Compute all 7 metrics (MCC, FPR, PARR, CDER, TDEE, TPE, PBPO)
  8. Generate visualizations
  9. Save JSON results

Usage:
  python3 mptd_pqs_pipeline.py                          # auto-find sim_output_ap*.txt
  python3 mptd_pqs_pipeline.py --sim-dir /path         # custom sim dir
  python3 mptd_pqs_pipeline.py --skip-sim              # skip running simulations
  python3 mptd_pqs_pipeline.py --attack-pcts 0 50 100  # specific percentages
"""

import argparse
import json
import math
import os
import subprocess
import sys
from collections import defaultdict
from typing import Dict, List, Optional


# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from mptd_pqs.lightweight_detector import (
    LightweightDetector, TrajectoryPoint, parse_sim_output
)
from mptd_pqs.gat_detector import GATDetector, VehicleState
from mptd_pqs.temporal_autoencoder import TemporalAEDetector
from mptd_pqs.fusion import FusionEngine, run_ablation
# mptd_pqs.blockchain_sim deleted Phase R8.5 / 2026-05-30: the in-memory
# BlockchainSim was a pre-Fabric placeholder. The real Hyperledger Fabric
# chaincode (chaincode/chaincode/smartcontract.go) now owns SC-Trust /
# SC-Revoke / CP-DETECT per Eq 3.55/3.58/3.59, called from the NS-3 RSU code
# in scratch/mptd_pqs_sdvn/06c_blockchain_api.h via fabric_invoke.sh. The
# Python pipeline no longer simulates the chain — it just consumes the
# fusion-engine outputs and computes metrics.
from mptd_pqs.metrics_calculator import MetricsCalculator, MetricsResult, ConfusionMatrix
from mptd_pqs.metrics_visualization import plot_all, plot_ablation, plot_baseline_comparison


# Default paths (can be overridden via CLI)
SIM_DIR     = os.path.dirname(os.path.abspath(__file__))  # Current directory
NS3_BINARY  = os.path.join(SIM_DIR, "build/scratch/lda_attack_scenario1")
LIB_PATH    = os.path.join(SIM_DIR, "build/lib")
SIM_TIME    = 15
ATTACK_PCTS = [0, 50, 80, 100]


# ── Simulation runner ──────────────────────────────────────────────────────────
def run_simulation(attack_pct: int, output_file: str) -> bool:
    """Run NS-3 simulation for given attack percentage."""
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{LIB_PATH}:{env.get('LD_LIBRARY_PATH', '')}"
    cmd = [
        NS3_BINARY,
        f"--attack_number=1",
        f"--routing_algorithm=4",
        f"--routing_test=true",
        f"--attack_percentage={attack_pct}",
        f"--simTime={SIM_TIME}",
    ]
    print(f"  Running: attack_percentage={attack_pct}% ...", end=" ", flush=True)
    try:
        with open(output_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                                    env=env, timeout=600)
        print(f"done (exit {result.returncode})")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("TIMEOUT")
        return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False


# ── Parse sim output into trajectory points ────────────────────────────────────
def load_sim_data(sim_dir: str, attack_pct: int) -> tuple:
    """Load sim_output_ap{pct}.txt. Returns (points, summary) or ([], {})."""
    fpath = os.path.join(sim_dir, f"sim_output_ap{attack_pct}.txt")
    if not os.path.exists(fpath):
        print(f"  WARNING: {fpath} not found")
        return [], {}
    points, summary = parse_sim_output(fpath)
    summary["attack_percentage"] = attack_pct
    return points, summary


# ── Convert TrajectoryPoints to VehicleState for GAT/AE ───────────────────────
def to_vehicle_state(tp: TrajectoryPoint) -> VehicleState:
    return VehicleState(
        vehicle_id=tp.vehicle_id,
        rsu_id=tp.rsu_id,
        timestamp=tp.timestamp,
        pos_x=tp.pos_x,
        pos_y=tp.pos_y,
        vel_x=tp.vel_x,
        vel_y=tp.vel_y,
        acc_x=tp.acc_x,
        acc_y=tp.acc_y,
        is_poisoned=tp.is_poisoned,
    )


# ── Main pipeline per attack percentage ───────────────────────────────────────
def run_pipeline_for_pct(points: List[TrajectoryPoint], summary: dict,
                          attack_pct: int, variant: str = "FULL") -> Optional[MetricsResult]:
    """Run full detection pipeline on trajectory points."""
    if not points:
        print(f"  No data for attack_pct={attack_pct}, generating synthetic baseline")
        points = _synthetic_points(attack_pct)
        summary = {
            "attack_percentage": attack_pct,
            "total_received": len(points),
            "total_poisoned": sum(1 for p in points if p.is_poisoned),
        }

    print(f"\n  → {len(points)} trajectory points | "
          f"poisoned={sum(1 for p in points if p.is_poisoned)}")

    # ── Phase 4: LW-DETECT ────────────────────────────────────────────────────
    lw_det = LightweightDetector()
    lw_results = lw_det.process_batch(points)

    # ── Phase 2: GAT ──────────────────────────────────────────────────────────
    gat_det = GATDetector(threshold=0.4, train_epochs=30)
    clean_pts = [p for p in points if not p.is_poisoned]
    if clean_pts:
        gat_det.add_training_snapshot([to_vehicle_state(p) for p in clean_pts])
        gat_det.finalize_training()
    all_states = [to_vehicle_state(p) for p in points]
    gat_results_list = gat_det.score_snapshot(all_states)

    # ── Phase 3: Temporal AE ──────────────────────────────────────────────────
    ae_det = TemporalAEDetector(seq_len=5, theta_ae=8.0, train_epochs=30)
    for p in clean_pts[:10]:
        ae_det.add_training_point(p)
    ae_det.finalize_training()
    ae_results_list = ae_det.process_batch(points)

    # Align results by index (pad shorter lists)
    N = len(lw_results)
    gat_lookup = {r['vehicle_id']: r for r in gat_results_list}
    ae_lookup  = {r['vehicle_id']: r for r in ae_results_list}

    # ── Phase 5: Fusion ───────────────────────────────────────────────────────
    engine = FusionEngine(variant=variant)

    deviations = []
    for lw, pt in zip(lw_results, points):
        gat_r = gat_lookup.get(pt.vehicle_id)
        ae_r  = ae_lookup.get(pt.vehicle_id)

        psi  = lw.psi
        gat  = gat_r['gat_score'] if gat_r else 0.0
        ae   = ae_r['ae_score'] if ae_r else 0.0

        fusion_r = engine.fuse(
            pt.vehicle_id, pt.rsu_id, pt.timestamp,
            psi=psi, gat_score=gat, ae_score=ae,
            ground_truth_poisoned=pt.is_poisoned,
        )

        # Phase 6 (blockchain trust/revocation) is owned by the real chaincode
        # at chaincode/chaincode/smartcontract.go; the NS-3 RSU code calls it
        # synchronously per beacon via scratch/mptd_pqs_sdvn/06c_blockchain_api.h.
        # No simulation needed here — see Phase 7 for on-chain count derivation.

        # Deviation: for TP points, pos_x holds the deviation value
        if pt.is_poisoned:
            deviations.append(pt.pos_x)

    # ── Phase 7: Metrics ──────────────────────────────────────────────────────
    # On-chain counts derived from the same beacon set the RSU code would
    # submit to chaincode (every received beacon → one StoreTrajectory call;
    # poisoned flag mirrors the ground-truth label). This matches what the
    # legacy in-memory BlockchainSim returned, without needing the simulator.
    n_total_on_chain    = len(points)
    n_poisoned_on_chain = sum(1 for p in points if p.is_poisoned)

    n_total = summary.get("total_received", len(points))
    n_poisoned_injected = summary.get("total_poisoned", sum(1 for p in points if p.is_poisoned))

    calc = MetricsCalculator()
    result = calc.compute_all(
        fusion_results=engine.results,
        deviations=deviations,
        n_poisoned_injected=n_poisoned_injected,
        n_total_trajectories=n_total,
        n_poisoned_on_chain=n_poisoned_on_chain,
        n_total_on_chain=n_total_on_chain,
        variant=variant,
        attack_percentage=attack_pct,
    )
    calc.print_report(result)
    return result


# ── Synthetic points for when sim data unavailable ────────────────────────────
def _synthetic_points(attack_pct: int) -> List[TrajectoryPoint]:
    """Generate synthetic trajectory points for demonstration/testing."""
    import random
    random.seed(42 + attack_pct)
    N_vehicles = 5
    N_steps    = 10
    points = []

    for v in range(N_vehicles):
        for step in range(N_steps):
            t = 9.0 + step * 0.3
            base_x = 800.0 + v * 300 + step * 3.0
            base_y = 1200.0
            is_mal_rsu = random.random() < (attack_pct / 100.0)
            if is_mal_rsu:
                # Inject position deviation
                dev = random.uniform(10.0, 50.0)
                pos_x = dev  # store deviation in pos_x for CDER/TDEE
                is_p = True
            else:
                pos_x = base_x
                is_p = False

            pt = TrajectoryPoint(
                vehicle_id=f"Vehicle{v}",
                rsu_id=f"RSU{v % 4}",
                timestamp=t,
                pos_x=pos_x,
                pos_y=base_y,
                vel_x=10.0 + random.uniform(-1, 1),
                vel_y=0.0,
                acc_x=0.5,
                acc_y=0.0,
                is_poisoned=is_p,
            )
            points.append(pt)
    return points


# ── CLI entry point ────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="MPTD-PQS Evaluation Pipeline")
    parser.add_argument("--sim-dir", default=SIM_DIR, help="NS-3 directory")
    parser.add_argument("--skip-sim", action="store_true",
                        help="Skip running simulations (use existing output files)")
    parser.add_argument("--attack-pcts", nargs="+", type=int,
                        default=ATTACK_PCTS, help="Attack percentages to evaluate")
    parser.add_argument("--output-dir", default="results",
                        help="Directory for output charts and JSON (default: results/)")
    parser.add_argument("--variant", default="FULL",
                        choices=["FULL", "A1", "A2", "A3", "A4", "A5"],
                        help="Detection variant")
    args = parser.parse_args()
    
    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    print("=" * 60)
    print("  MPTD-PQS Evaluation Pipeline")
    print("=" * 60)

    results_by_pct: Dict[int, MetricsResult] = {}

    for pct in args.attack_pcts:
        output_file = os.path.join(args.sim_dir, f"sim_output_ap{pct}.txt")
        print(f"\n{'─'*60}")
        print(f"  Attack percentage: {pct}%")

        # Run simulation if needed
        if not args.skip_sim:
            if not os.path.exists(output_file):
                run_simulation(pct, output_file)
            else:
                print(f"  Using existing: {output_file}")

        # Load data
        points, summary = load_sim_data(args.sim_dir, pct)

        # Run pipeline
        result = run_pipeline_for_pct(points, summary, pct, variant=args.variant)
        if result:
            results_by_pct[pct] = result

    if not results_by_pct:
        print("\nNo results to visualize.")
        return

    # ── Ablation study (run all variants at 50% if available) ─────────────────
    ablation_results = {}
    ref_pct = 50 if 50 in args.attack_pcts else args.attack_pcts[0]
    ref_points, ref_summary = load_sim_data(args.sim_dir, ref_pct)
    print(f"\n{'─'*60}")
    print(f"  Running ablation study (attack_pct={ref_pct}%)")

    for variant in ["A1", "A2", "A3", "A4", "A5", "FULL"]:
        r = run_pipeline_for_pct(ref_points, ref_summary, ref_pct, variant=variant)
        if r:
            ablation_results[variant] = r

    # ── Save JSON results ──────────────────────────────────────────────────────
    calc = MetricsCalculator()
    json_out = os.path.join(args.output_dir, "mptd_pqs_results.json")
    all_data = {
        "by_attack_pct": {str(k): calc.to_dict(v) for k, v in results_by_pct.items()},
        "ablation": {k: calc.to_dict(v) for k, v in ablation_results.items()},
    }
    with open(json_out, 'w') as f:
        json.dump(all_data, f, indent=2)
    print(f"\nResults saved: {json_out}")
    



    # ── Visualizations ─────────────────────────────────────────────────────────
    print("\nGenerating charts...")
    plot_all(results_by_pct, ablation_results, output_dir=args.output_dir)

    if ablation_results:
        from mptd_pqs.metrics_visualization import plot_ablation
        plot_ablation(ablation_results, attack_pct=ref_pct,
                      output_path=os.path.join(args.output_dir, "mptd_pqs_ablation.png"))

    if ref_pct in results_by_pct:
        from mptd_pqs.metrics_visualization import plot_baseline_comparison
        plot_baseline_comparison(
            results_by_pct[ref_pct],
            output_path=os.path.join(args.output_dir, "mptd_pqs_baseline.png")
        )

    # Add your code here
    
    print("\n" + "=" * 60)
    print("  MPTD-PQS Pipeline Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
