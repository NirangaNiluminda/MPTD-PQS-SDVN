#!/usr/bin/env python3
"""
train_fusion_rural_only.py — refit fusion weights (lambda_psi/gat/ae) for RURAL
ONLY, calling train_fusion.process_scenario() directly instead of main().

Why not just run train_fusion.py: its main() loops over urban+rural+highway
and, at the end, copies urban's freshly-recomputed weights to the generic
models/fusion_weights.json default -- that would touch urban even though only
rural's LSTM-AE/GAT were retrained. This script reuses the same scoring/SLSQP
logic but scopes it to rural's own archived beacon logs, so nothing urban is
read, recomputed, or overwritten.

Usage: python3 train_fusion_rural_only.py
"""
import os, sys, glob
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import train_fusion as tf

ML = os.path.dirname(os.path.abspath(__file__))

runs = []
for p in sorted(glob.glob(f"{ML}/data/rural_training_runs/beacon_log_*.csv")):
    d = pd.read_csv(p)
    d["run_id"] = os.path.basename(p)
    runs.append(d)
print(f"[fusion-rural] loaded {len(runs)} rural runs, {sum(len(r) for r in runs)} total rows")

weights = tf.process_scenario("rural", runs)
print(f"[fusion-rural] final weights: {weights}")
