#!/usr/bin/env python3
"""Step 0b: offline RSU-window builder that mirrors the LIVE ghost flush.

Why this exists
---------------
train_ab3_gat_v3/v4 chunk each RSU's beacons into tumbling windows of
IPFS_WINDOW_L=10. That is correct for ordinary traffic, but it is NOT what the
simulator does when a Sybil ring is injected. In 08_detection_engine.h:3977 the
ring is pushed with force_flush on the LAST ghost only (--ghost_batch), so the
window closes early and contains:

    the beacons accumulated so far  +  the 4 ring members

Measured live (30 s smoke): 97.1% of ghost windows hold 5 beacons, 2.9% hold 4,
while every non-ghost window holds 10. Training on N=10 windows and deploying on
N=5 reintroduces the train/deploy mismatch that v3 was written to remove -- and
it matters specifically because S_i = ||(e_i - mu)/sigma|| is normalised
per-graph, so graph size changes the statistic directly.

This builder replays arrival order per (run_id, rsu_id) and flushes on the same
condition the C++ does.

Ring identity is decoded exactly, not guessed:
    ghost_vid = GHOST_VID_BASE + rsu_idx*100 + vid*10 + gi   (08:3901)
  => ring = (vid - 10000) // 10 ,  gi = (vid - 10000) % 10
"""
import numpy as np
import pandas as pd

GHOST_VID_BASE = 10000
IPFS_WINDOW_L = 10
N_GHOST_DEFAULT = 4


def build_windows(df, window_l=IPFS_WINDOW_L, n_ghost=N_GHOST_DEFAULT,
                  mirror_ghost_flush=True):
    """Yield DataFrames, one per RSU window, in the order the sim would flush them.

    mirror_ghost_flush=False reproduces the old v3/v4 tumbling-10 behaviour, so
    the two can be compared on identical data.
    """
    keys = ["run_id", "rsu_id"] if "run_id" in df.columns else ["rsu_id"]
    windows = []
    for _k, grp in df.groupby(keys, sort=False):
        grp = grp.sort_values("sim_time", kind="mergesort")
        if not mirror_ghost_flush:
            n = len(grp)
            for s in range(0, n - n % window_l, window_l):
                windows.append(grp.iloc[s:s + window_l])
            continue

        vid = grp["vehicle_id"].values
        is_ghost = vid >= GHOST_VID_BASE
        ring = np.where(is_ghost, (vid - GHOST_VID_BASE) // 10, -1)

        buf = []          # row positions accumulated in this RSU's window
        ring_count = {}   # ring -> members seen in the CURRENT buffer
        for i in range(len(grp)):
            buf.append(i)
            if is_ghost[i]:
                r = ring[i]
                ring_count[r] = ring_count.get(r, 0) + 1
                # last member of the ring => force_flush (C++ ghost_last)
                if ring_count[r] >= n_ghost:
                    windows.append(grp.iloc[buf])
                    buf = []; ring_count = {}
                    continue
            if len(buf) >= window_l:
                windows.append(grp.iloc[buf])
                buf = []; ring_count = {}
        # trailing partial buffer is dropped: the sim never scores an unflushed
        # window either.
    return windows


def describe(windows, tag=""):
    """Print the size/composition distribution so it can be compared to the live log."""
    sizes, gsizes, nsizes = [], [], []
    for w in windows:
        n = len(w)
        ng = int((w["vehicle_id"] >= GHOST_VID_BASE).sum())
        sizes.append(n)
        (gsizes if ng else nsizes).append(n)
    sizes = np.array(sizes)
    print(f"[{tag}] windows={len(sizes)}  ghost-bearing={len(gsizes)}  other={len(nsizes)}")
    for name, arr in (("ghost-bearing", gsizes), ("other", nsizes)):
        if not arr:
            continue
        a = np.array(arr)
        vc = pd.Series(a).value_counts().sort_index()
        top = ", ".join(f"N={k}: {v} ({100*v/len(a):.1f}%)" for k, v in vc.items() if v / len(a) > 0.005)
        print(f"   {name:14s} {top}")
    return sizes


if __name__ == "__main__":
    import os, sys
    ML = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        ML, "data", "beacon_train_corpus_v3_ghostk2.csv")
    df = pd.read_csv(path)
    print(f"corpus: {path}  rows={len(df)}\n")
    old = build_windows(df, mirror_ghost_flush=False)
    describe(old, "v3/v4 tumbling-10 (OLD)")
    print()
    new = build_windows(df, mirror_ghost_flush=True)
    describe(new, "ghost-flush mirror (NEW)")

    g = df[df.vehicle_id >= GHOST_VID_BASE]
    covered = sum(int((w["vehicle_id"] >= GHOST_VID_BASE).sum()) for w in new)
    print(f"\nghost rows in corpus={len(g)}  ghost rows landing in a window={covered} "
          f"({100*covered/max(len(g),1):.1f}%)")
