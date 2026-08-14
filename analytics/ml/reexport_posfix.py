#!/usr/bin/env python3
"""Re-export the Fix A model with a single-node guard.

BUG THIS FIXES: the previous export computed sig = e.std(0) with torch's default
unbiased=True. For a graph with N=1 that is the std of one sample -> NaN, so
S = ||(e-mu)/sig|| came out NaN. Ghosts are force-flushed individually unless
--ghost_batch is on, so MOST ghost graphs are N=1. Deployed, this drove S=-nan
into the fusion and collapsed the GAT arms: MCC 0.87 -> 0.20 while D1 (no GAT)
was untouched at 0.8585.

With unbiased=False, N=1 gives sig=0 -> (e-mu)=0 -> S=0, which is also the
semantically right answer: a single node has no neighbours, so it carries no
relational anomaly evidence.

Weights are unchanged — this re-exports the same trained .pt.
"""
import os, sys, torch, torch.nn as nn
ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
from gat_detector import GATDetector

STAGE = os.path.join(ML, "models", "urban_ghostk2_posfix")
m = GATDetector()
m.load_state_dict(torch.load(os.path.join(STAGE, "gat_model.pt"), map_location="cpu"))
m.eval()
print(f"score_scale={float(m.score_scale):+.5f} (polarity {'OK' if float(m.score_scale)>0 else 'INVERTED'})")

class GATRawS(nn.Module):
    def __init__(self, b):
        super().__init__()
        self.conv1, self.conv2, self.act, self.cls_heads = b.conv1, b.conv2, b.act, b.cls_heads
    def forward(self, x, edge_index):
        e = self.act(self.conv1(x, edge_index)); e = self.act(self.conv2(e, edge_index))
        mu  = e.mean(0, keepdim=True)
        sig = e.std(0, unbiased=False, keepdim=True) + 1e-6   # <-- the guard
        s_i = ((e - mu) / sig).norm(dim=1, keepdim=True)
        return s_i, torch.sigmoid(self.cls_heads(e))

raw = GATRawS(m).eval()
out = os.path.join(STAGE, "gat_model_nanfix.onnx")
n = 16
torch.onnx.export(raw, (torch.randn(n, 16), torch.tensor([list(range(n)), list(range(n))], dtype=torch.long)),
                  out, input_names=["x", "edge_index"], output_names=["scores", "attack_probs"],
                  dynamic_axes={"x": {0: "N"}, "edge_index": {1: "E"}, "scores": {0: "N"},
                                "attack_probs": {0: "N"}}, opset_version=16, dynamo=False)

# verify the N=1 case that broke it
import onnxruntime as ort, numpy as np
ort.set_default_logger_severity(3)
for tag, path in [("OLD export", os.path.join(STAGE, "gat_model.onnx")),
                  ("NEW export", out)]:
    s = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
    names = [i.name for i in s.get_inputs()]
    for N in (1, 2, 5):
        x = np.random.randn(N, 16).astype(np.float32)
        ei = np.array([[0]*N, [0]*N], dtype=np.int64)
        S = np.asarray(s.run(None, {names[0]: x, names[1]: ei})[0]).ravel()
        print(f"  {tag}  N={N}: S={S[:3]}  has_nan={bool(np.isnan(S).any())}")
