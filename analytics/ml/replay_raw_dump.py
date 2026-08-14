#!/usr/bin/env python3
import re
import numpy as np
import onnxruntime as ort

with open("/tmp/rawdump_x.txt") as f:
    line_x = f.read()
with open("/tmp/rawdump_ei.txt") as f:
    line_ei = f.read()

x_match = re.search(r"N=(\d+) FEATDIM=(\d+) x=\[([^\]]+)\]", line_x)
N = int(x_match.group(1)); FEATDIM = int(x_match.group(2))
x_vals = np.array([float(v) for v in x_match.group(3).split(",")], dtype=np.float32)
x_np = x_vals.reshape(N, FEATDIM)

ei_match = re.search(r"E=(\d+) edge_index=\[([^\]]+)\]", line_ei)
E = int(ei_match.group(1))
ei_vals = np.array([int(v) for v in ei_match.group(2).split(",")], dtype=np.int64)
ei_np = ei_vals.reshape(2, E)

print(f"[replay] N={N} FEATDIM={FEATDIM} E={E}")
print(f"[replay] x row0: {x_np[0]}")
print(f"[replay] x row1: {x_np[1]}")
print(f"[replay] x min/max overall: {x_np.min():.6f} / {x_np.max():.6f}")
print(f"[replay] any NaN: {np.isnan(x_np).any()}  any Inf: {np.isinf(x_np).any()}")

STAGE = "/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN/analytics/ml/models/urban_a3_retrain_test_v3"
sess = ort.InferenceSession(f"{STAGE}/gat_model.onnx")
out = sess.run(None, {"x": x_np, "edge_index": ei_np})
names = [o.name for o in sess.get_outputs()]
d = dict(zip(names, out))
print("\n[replay] === replayed EXACT live input through Python onnxruntime ===")
print("scores (S):", d["scores"].ravel())
print("attack_probs max per node:", d["attack_probs"].max(axis=1))
