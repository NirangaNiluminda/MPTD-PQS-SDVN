#!/usr/bin/env python3
"""
analyze_results.py — MPTD-PQS Paper Results Analysis
======================================================
Reads all metrics_a*_p*_s*_m*.csv files from analytics/results/sweep/
and produces:

  1. Table 4.1 — MCC and FPR per attack, per ablation mode (medium speed)
  2. Table 4.2 — RQ1 speed regime: MCC vs speed regime per attack (A1 mode)
  3. Table 4.3 — RQ5 PARR: A1 vs A4 (TRS contribution)
  4. Table 4.4 — RQ6 CDER: A1 vs A5 (blockchain contribution)
  5. Table 4.5 — PBPO overhead: LW vs Full pipeline
  6. Plots (PNG):
       fig_mcc_per_attack.png      — bar chart MCC by attack number (A1 vs B1)
       fig_mcc_vs_speed.png        — line chart MCC vs speed regime
       fig_mcc_vs_pct.png          — line chart MCC vs penetration rate
       fig_parr_comparison.png     — PARR A1 vs A4

Usage:
  python3 analyze_results.py                  # prints all tables + saves PNGs
  python3 analyze_results.py --no-plots       # text tables only (no matplotlib)
  python3 analyze_results.py --csv            # save tables as CSV for LaTeX import

Output:
  analytics/results/table_*.csv
  analytics/results/fig_*.png
"""

import os, sys, glob, csv, argparse
from collections import defaultdict

# ── Argument parsing ──────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--no-plots',  action='store_true', help='Skip matplotlib plots')
parser.add_argument('--csv',       action='store_true', help='Save tables as CSV')
parser.add_argument('--sweep-dir', default=None,        help='Path to sweep CSV dir')
args = parser.parse_args()

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
NS3_ROOT    = '/home/niranga/ns-allinone-3.35/ns-3.35'
SWEEP_DIR   = args.sweep_dir or os.path.join(NS3_ROOT, 'analytics', 'results', 'sweep')
OUT_DIR     = os.path.join(NS3_ROOT, 'analytics', 'results')
os.makedirs(OUT_DIR, exist_ok=True)

# ── Attack labels ──────────────────────────────────────────────────────────────
ATK_LABEL = {
    1: 'TP1\n(RSU drift)',
    2: 'TP2\n(Veh hdg)',
    3: 'MP1\n(Sybil RSU)',
    4: 'MP2\n(Imperson.)',
    5: 'TP3\n(Ctrl plane)',
    6: 'MP3\n(MitM KL)',
    7: 'MP4\n(Ctrl model)',
}
ATK_SHORT = {1:'TP1', 2:'TP2', 3:'MP1', 4:'MP2', 5:'TP3', 6:'MP3', 7:'MP4'}
MODE_LABEL = {1:'A1 (LW)', 4:'A4 (no TRS)', 5:'A5 (no BC)', 6:'B1 (Ghaleb)'}
SPEED_LABEL = {20:'Low ≤30 km/h', 50:'Med 30–80 km/h', 100:'High >80 km/h'}

# ── Load all CSVs ─────────────────────────────────────────────────────────────
print(f"[ANALYZE] Reading CSVs from: {SWEEP_DIR}")
files = glob.glob(os.path.join(SWEEP_DIR, 'metrics_a*_p*_s*_m*.csv'))
print(f"[ANALYZE] Found {len(files)} CSV files")

if len(files) == 0:
    print("[ANALYZE] ERROR: No CSV files found. Run run_sweep.sh first.")
    sys.exit(1)

# data[atk][pct][speed][mode] = dict of metric values
data = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(dict))))

for fpath in files:
    fname = os.path.basename(fpath)
    try:
        with open(fpath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                atk   = int(row['attack_number'])
                pct   = int(row['attack_pct'])
                spd   = int(row['maxspeed_kmh'])
                mode  = int(row['ablation_mode'])

                def safe_float(key, default=-1.0):
                    try: return float(row[key])
                    except: return default

                data[atk][pct][spd][mode] = {
                    'MCC':   safe_float('MCC'),
                    'FPR':   safe_float('FPR'),
                    'PARR':  safe_float('PARR'),
                    'CDER':  safe_float('CDER'),
                    'PBPO_LW':   safe_float('PBPO_LW_ms'),
                    'PBPO_Full': safe_float('PBPO_Full_ms'),
                    'cm_TP': safe_float('cm_TP'),
                    'cm_FP': safe_float('cm_FP'),
                    'cm_TN': safe_float('cm_TN'),
                    'cm_FN': safe_float('cm_FN'),
                    'total_received':  safe_float('total_received'),
                    'total_poisoned':  safe_float('total_poisoned'),
                }
    except Exception as e:
        print(f"[ANALYZE] WARNING: Could not parse {fname}: {e}")

# ── Helper ────────────────────────────────────────────────────────────────────
def get(atk, pct, spd, mode, metric, default='N/A'):
    try:
        v = data[atk][pct][spd][mode][metric]
        if v == -1.0: return 'N/A'
        return round(v, 4)
    except:
        return default

def fmt(v, decimals=3):
    if v == 'N/A' or v is None: return '  N/A '
    try: return f'{float(v):.{decimals}f}'
    except: return str(v)

# ── TABLE 1: MCC and FPR per attack at medium speed (50), pct=20 ──────────────
print()
print("=" * 80)
print("TABLE 1 — Detection Quality: MCC and FPR per Attack Type")
print("         (penetration=20%, speed=50 km/h)")
print("=" * 80)
SPD, PCT = 50, 20
header = f"{'Attack':<12} | {'A1 MCC':>8} {'A1 FPR':>8} | {'B1 MCC':>8} {'B1 FPR':>8} | {'A1-B1 ΔMCC':>10}"
print(header)
print("-" * 80)
table1_rows = []
atk7_note = {}
for atk in sorted(ATK_SHORT.keys()):
    mcc_a1 = get(atk, PCT, SPD, 1, 'MCC')
    fpr_a1 = get(atk, PCT, SPD, 1, 'FPR')
    mcc_b1 = get(atk, PCT, SPD, 6, 'MCC')
    fpr_b1 = get(atk, PCT, SPD, 6, 'FPR')
    # Attack 7 (MP4): controller poisons ALL beacons → TN=0, MCC=0/0=undefined.
    # Replace 0.0 MCC with 'N/A†' to signal degenerate case; DR=100% still holds.
    try:
        tn_a1 = get(atk, PCT, SPD, 1, 'cm_TN')
        if atk == 7 and tn_a1 != 'N/A' and float(tn_a1) == 0.0:
            mcc_a1 = 'N/A†'
            atk7_note[1] = True
    except: pass
    try:
        delta = f'+{float(mcc_a1)-float(mcc_b1):.3f}' if mcc_a1 not in ('N/A','N/A†') and mcc_b1 not in ('N/A','N/A†') else 'N/A'
    except: delta = 'N/A'
    row = f"{ATK_SHORT[atk]:<12} | {fmt(mcc_a1):>8} {fmt(fpr_a1):>8} | {fmt(mcc_b1):>8} {fmt(fpr_b1):>8} | {str(delta):>10}"
    print(row)
    table1_rows.append({'attack': ATK_SHORT[atk], 'MCC_A1': mcc_a1, 'FPR_A1': fpr_a1,
                        'MCC_B1': mcc_b1, 'FPR_B1': fpr_b1, 'delta_MCC': delta})
if atk7_note:
    print("  † MP4 (attack 7): global controller poisoning → TN=0 → MCC undefined (DR=100%)")

# ── TABLE 2: RQ1 — MCC vs Speed Regime (A1, pct=20) ──────────────────────────
print()
print("=" * 80)
print("TABLE 2 — RQ1: Mobility Amplification Effect on Detection (MCC vs Speed)")
print("         (A1 lightweight mode, penetration=20%)")
print("=" * 80)
header2 = f"{'Attack':<12} | {'Low (20km/h)':>14} | {'Med (50km/h)':>14} | {'High (100km/h)':>14}"
print(header2)
print("-" * 80)
table2_rows = []
for atk in sorted(ATK_SHORT.keys()):
    mcc_low  = get(atk, 20, 20,  1, 'MCC')
    mcc_med  = get(atk, 20, 50,  1, 'MCC')
    mcc_high = get(atk, 20, 100, 1, 'MCC')
    row = f"{ATK_SHORT[atk]:<12} | {fmt(mcc_low):>14} | {fmt(mcc_med):>14} | {fmt(mcc_high):>14}"
    print(row)
    table2_rows.append({'attack': ATK_SHORT[atk], 'MCC_low': mcc_low,
                        'MCC_med': mcc_med, 'MCC_high': mcc_high})

# ── TABLE 3: RQ1 — MCC vs Penetration Rate (A1, medium speed) ────────────────
print()
print("=" * 80)
print("TABLE 3 — MCC vs Penetration Rate (A1 mode, speed=50 km/h)")
print("=" * 80)
header3 = f"{'Attack':<12} | {'5%':>8} | {'10%':>8} | {'20%':>8} | {'30%':>8}"
print(header3)
print("-" * 80)
for atk in sorted(ATK_SHORT.keys()):
    vals = [fmt(get(atk, p, 50, 1, 'MCC')) for p in [5, 10, 20, 30]]
    print(f"{ATK_SHORT[atk]:<12} | {vals[0]:>8} | {vals[1]:>8} | {vals[2]:>8} | {vals[3]:>8}")
print()
print("  [*] RSU attacks (TP1, MP1): round(4×ρ_a)=0 for ρ_a≤12.5% → no RSU compromised → MCC=0")
print("  [*] Vehicle attacks: P(≥1 attacker | N=20, ρ_a=5%)=64% → low-density stochastic effect")

# ── TABLE 4: RQ5 — PARR comparison A1 vs A4 ──────────────────────────────────
print()
print("=" * 80)
print("TABLE 4 — RQ5: TRS Contribution — PARR (Poisoned Aggregate Rejection Rate)")
print("         A1 (with TRS) vs A4 (without TRS/FHE), speed=50 km/h, pct=20%")
print("=" * 80)
header4b = f"{'Attack':<12} | {'PARR A1':>10} | {'PARR A4':>10} | {'ΔPARR':>10} | {'Full A1(ms)':>12} | {'Full A4(ms)':>12} | {'ΔPBPO(ms)':>10}"
print(header4b)
print("-" * 80)
for atk in sorted(ATK_SHORT.keys()):
    p1 = get(atk, 20, 50, 1, 'PARR')
    p4 = get(atk, 20, 50, 4, 'PARR')
    pb1 = get(atk, 20, 50, 1, 'PBPO_Full')
    pb4 = get(atk, 20, 50, 4, 'PBPO_Full')
    try:
        delta = f'+{float(p1)-float(p4):.3f}' if p1 != 'N/A' and p4 != 'N/A' else 'N/A'
    except: delta = 'N/A'
    try:
        d = float(pb1) - float(pb4)
        dpbpo = (f'+{d:.4f}' if d >= 0 else f'{d:.4f}') if pb1 != 'N/A' and pb4 != 'N/A' else 'N/A'
    except: dpbpo = 'N/A'
    print(f"{ATK_SHORT[atk]:<12} | {fmt(p1):>10} | {fmt(p4):>10} | {str(delta):>10} | {fmt(pb1,4):>12} | {fmt(pb4,4):>12} | {str(dpbpo):>10}")
print()
print("  Note: ΔPARR≈0 because TRS validation is on cryptographic authenticity, not trajectory")
print("        anomalies. TRS contribution is in ΔPBPO_Full (overhead for signature verification).")

# ── TABLE 5: RQ6 — CDER comparison A1 vs A5 ──────────────────────────────────
print()
print("=" * 80)
print("TABLE 5 — RQ6: Blockchain Contribution — CDER (Control Decision Error Rate)")
print("         A1 (with blockchain) vs A5 (no blockchain), speed=50 km/h, pct=20%")
print("=" * 80)
header5 = f"{'Attack':<12} | {'CDER A1':>10} | {'CDER A5':>10} | {'ΔCDER':>10}"
print(header5)
print("-" * 80)
for atk in sorted(ATK_SHORT.keys()):
    c1 = get(atk, 20, 50, 1, 'CDER')
    c5 = get(atk, 20, 50, 5, 'CDER')
    try:
        # Positive ΔCDER means A5 (no BC) is worse → blockchain helps
        d = float(c5) - float(c1)
        delta = (f'+{d:.3f}' if d >= 0 else f'{d:.3f}') if c1 != 'N/A' and c5 != 'N/A' else 'N/A'
    except: delta = 'N/A'
    print(f"{ATK_SHORT[atk]:<12} | {fmt(c1):>10} | {fmt(c5):>10} | {str(delta):>10}")

# ── TABLE 6: PBPO overhead ────────────────────────────────────────────────────
print()
print("=" * 80)
print("TABLE 6 — PBPO: Per-Beacon Processing Overhead (ms)")
print("         A1 lightweight (RSU) vs A4 full pipeline (controller)")
print("=" * 80)
print(f"{'Attack':<12} | {'LW (ms)':>10} | {'Full (ms)':>10}")
print("-" * 50)
for atk in sorted(ATK_SHORT.keys()):
    lw   = get(atk, 20, 50, 1, 'PBPO_LW')
    full = get(atk, 20, 50, 1, 'PBPO_Full')
    print(f"{ATK_SHORT[atk]:<12} | {fmt(lw, 4):>10} | {fmt(full, 4):>10}")

# ── Save tables as CSV ────────────────────────────────────────────────────────
if args.csv:
    import csv as csvlib
    # Table 1
    with open(os.path.join(OUT_DIR, 'table_detection_quality.csv'), 'w', newline='') as f:
        w = csvlib.DictWriter(f, fieldnames=['attack','MCC_A1','FPR_A1','MCC_B1','FPR_B1','delta_MCC'])
        w.writeheader(); w.writerows(table1_rows)
    # Table 2
    with open(os.path.join(OUT_DIR, 'table_speed_regime.csv'), 'w', newline='') as f:
        w = csvlib.DictWriter(f, fieldnames=['attack','MCC_low','MCC_med','MCC_high'])
        w.writeheader(); w.writerows(table2_rows)
    print(f"\n[ANALYZE] Tables saved to {OUT_DIR}/table_*.csv")

# ── Plots ──────────────────────────────────────────────────────────────────────
if not args.no_plots:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np

        attacks = sorted(ATK_SHORT.keys())
        atk_names = [ATK_SHORT[a] for a in attacks]
        SPD, PCT = 50, 20

        # ── Plot 1: MCC per attack — A1 vs B1 ─────────────────────────────────
        fig, ax = plt.subplots(figsize=(10, 5))
        x = np.arange(len(attacks))
        w = 0.35
        mcc_a1 = [get(a, PCT, SPD, 1, 'MCC', 0) for a in attacks]
        mcc_b1 = [get(a, PCT, SPD, 6, 'MCC', 0) for a in attacks]
        mcc_a1 = [float(v) if v not in ('N/A', 0) else 0.0 for v in mcc_a1]
        mcc_b1 = [float(v) if v not in ('N/A', 0) else 0.0 for v in mcc_b1]
        bars1 = ax.bar(x - w/2, mcc_a1, w, label='A1 (MPTD-PQS Lightweight)', color='steelblue')
        bars2 = ax.bar(x + w/2, mcc_b1, w, label='B1 (Ghaleb 2014 Baseline)', color='salmon')
        ax.set_xlabel('Attack Scenario', fontsize=12)
        ax.set_ylabel('MCC', fontsize=12)
        ax.set_title(f'Detection Quality (MCC) per Attack — ρ_a={PCT}%, v=50 km/h', fontsize=13)
        ax.set_xticks(x); ax.set_xticklabels(atk_names)
        ax.set_ylim(0, 1.15)
        ax.legend(fontsize=11)
        ax.grid(axis='y', alpha=0.3)
        for bar in bars1: ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.02,
                                   f'{bar.get_height():.2f}', ha='center', va='bottom', fontsize=8)
        for bar in bars2: ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.02,
                                   f'{bar.get_height():.2f}', ha='center', va='bottom', fontsize=8)
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_mcc_per_attack.png'), dpi=150)
        plt.close()
        print(f"[ANALYZE] Saved fig_mcc_per_attack.png")

        # ── Plot 2: MCC vs Speed regime (A1, pct=20) ──────────────────────────
        fig, ax = plt.subplots(figsize=(10, 5))
        speeds = [20, 50, 100]
        spd_labels = ['Low\n(20 km/h)', 'Medium\n(50 km/h)', 'High\n(100 km/h)']
        colors = plt.cm.tab10.colors
        for idx, atk in enumerate(attacks):
            mccs = []
            for s in speeds:
                v = get(atk, 20, s, 1, 'MCC', None)
                mccs.append(float(v) if v not in ('N/A', None) else None)
            valid = [(s, m) for s, m in zip(spd_labels, mccs) if m is not None]
            if valid:
                sx, sy = zip(*valid)
                ax.plot(sx, sy, marker='o', label=ATK_SHORT[atk], color=colors[idx % 10])
        ax.set_xlabel('Speed Regime', fontsize=12)
        ax.set_ylabel('MCC', fontsize=12)
        ax.set_title('RQ1: Mobility Amplification — MCC vs Speed Regime (A1, ρ_a=20%)', fontsize=13)
        ax.set_ylim(0, 1.1)
        ax.legend(fontsize=10, bbox_to_anchor=(1.01, 1), loc='upper left')
        ax.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_mcc_vs_speed.png'), dpi=150)
        plt.close()
        print(f"[ANALYZE] Saved fig_mcc_vs_speed.png")

        # ── Plot 3: MCC vs Penetration rate (A1, medium speed) ────────────────
        fig, ax = plt.subplots(figsize=(10, 5))
        pcts = [5, 10, 20, 30]
        for idx, atk in enumerate(attacks):
            mccs = []
            for p in pcts:
                v = get(atk, p, 50, 1, 'MCC', None)
                mccs.append(float(v) if v not in ('N/A', None) else None)
            valid_p = [(p, m) for p, m in zip(pcts, mccs) if m is not None]
            if valid_p:
                px, py = zip(*valid_p)
                ax.plot(px, py, marker='s', label=ATK_SHORT[atk], color=colors[idx % 10])
        ax.set_xlabel('Penetration Rate ρ_a (%)', fontsize=12)
        ax.set_ylabel('MCC', fontsize=12)
        ax.set_title('MCC vs Penetration Rate (A1, 50 km/h)', fontsize=13)
        ax.set_ylim(0, 1.1)
        ax.set_xticks(pcts); ax.set_xticklabels([f'{p}%' for p in pcts])
        ax.legend(fontsize=10, bbox_to_anchor=(1.01, 1), loc='upper left')
        ax.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_mcc_vs_pct.png'), dpi=150)
        plt.close()
        print(f"[ANALYZE] Saved fig_mcc_vs_pct.png")

        # ── Plot 4: PARR — A1 vs A4 ───────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(10, 5))
        parr_a1 = [get(a, 20, 50, 1, 'PARR', 0) for a in attacks]
        parr_a4 = [get(a, 20, 50, 4, 'PARR', 0) for a in attacks]
        parr_a1 = [float(v) if v not in ('N/A', 0) else 0.0 for v in parr_a1]
        parr_a4 = [float(v) if v not in ('N/A', 0) else 0.0 for v in parr_a4]
        bars1 = ax.bar(x - w/2, parr_a1, w, label='A1 (TRS active)',     color='forestgreen')
        bars2 = ax.bar(x + w/2, parr_a4, w, label='A4 (no TRS/FHE)',     color='lightcoral')
        ax.set_xlabel('Attack Scenario', fontsize=12)
        ax.set_ylabel('PARR', fontsize=12)
        ax.set_title(f'RQ5: TRS Contribution — PARR per Attack (ρ_a=20%, 50 km/h)', fontsize=13)
        ax.set_xticks(x); ax.set_xticklabels(atk_names)
        ax.set_ylim(0, 1.15)
        ax.legend(fontsize=11)
        ax.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_parr_comparison.png'), dpi=150)
        plt.close()
        print(f"[ANALYZE] Saved fig_parr_comparison.png")

        # ── Plot 5: FPR per attack — A1 vs B1 ─────────────────────────────────
        fig, ax = plt.subplots(figsize=(10, 5))
        fpr_a1 = [get(a, PCT, SPD, 1, 'FPR', 0) for a in attacks]
        fpr_b1 = [get(a, PCT, SPD, 6, 'FPR', 0) for a in attacks]
        fpr_a1 = [float(v) if v not in ('N/A', 0) else 0.0 for v in fpr_a1]
        fpr_b1 = [float(v) if v not in ('N/A', 0) else 0.0 for v in fpr_b1]
        ax.bar(x - w/2, fpr_a1, w, label='A1 (MPTD-PQS)', color='steelblue')
        ax.bar(x + w/2, fpr_b1, w, label='B1 (Ghaleb)',   color='salmon')
        ax.set_xlabel('Attack Scenario', fontsize=12)
        ax.set_ylabel('FPR (lower is better)', fontsize=12)
        ax.set_title(f'False Positive Rate per Attack — ρ_a={PCT}%, v=50 km/h', fontsize=13)
        ax.set_xticks(x); ax.set_xticklabels(atk_names)
        ax.set_ylim(0, 1.1)
        ax.legend(fontsize=11)
        ax.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_fpr_per_attack.png'), dpi=150)
        plt.close()
        print(f"[ANALYZE] Saved fig_fpr_per_attack.png")

    except ImportError:
        print("[ANALYZE] matplotlib not available — skipping plots")
        print("[ANALYZE] Install with: pip3 install matplotlib numpy")

# ── KEY FINDINGS SUMMARY ─────────────────────────────────────────────────────
print()
print("=" * 80)
print("KEY FINDINGS SUMMARY (for paper Results section)")
print("=" * 80)

# Best MCC across attacks for A1 vs B1
SPD, PCT = 50, 20
mccs_a1 = [(a, get(a, PCT, SPD, 1, 'MCC', None)) for a in sorted(ATK_SHORT.keys())]
mccs_b1 = [(a, get(a, PCT, SPD, 6, 'MCC', None)) for a in sorted(ATK_SHORT.keys())]
valid_a1 = [(a, float(v)) for a,v in mccs_a1 if v not in ('N/A', None)]
valid_b1 = [(a, float(v)) for a,v in mccs_b1 if v not in ('N/A', None)]
if valid_a1:
    avg_a1 = sum(v for _,v in valid_a1) / len(valid_a1)
    best_a1 = max(valid_a1, key=lambda x: x[1])
    worst_a1 = min(valid_a1, key=lambda x: x[1])
    print(f"\nDetection Quality (Table 1):")
    print(f"  A1 MCC:  avg={avg_a1:.3f}  best={ATK_SHORT[best_a1[0]]}={best_a1[1]:.3f}  worst={ATK_SHORT[worst_a1[0]]}={worst_a1[1]:.3f}")
if valid_b1:
    avg_b1 = sum(v for _,v in valid_b1) / len(valid_b1)
    print(f"  B1 MCC:  avg={avg_b1:.3f}")
    if valid_a1: print(f"  ΔMCC (A1-B1): +{avg_a1-avg_b1:.3f} average improvement")

# PBPO summary
pbpo_lw  = [get(a, PCT, SPD, 1, 'PBPO_LW',   None) for a in sorted(ATK_SHORT.keys())]
pbpo_ful = [get(a, PCT, SPD, 1, 'PBPO_Full',  None) for a in sorted(ATK_SHORT.keys())]
pbpo_lw  = [float(v) for v in pbpo_lw  if v not in ('N/A', None)]
pbpo_ful = [float(v) for v in pbpo_ful if v not in ('N/A', None)]
if pbpo_lw and pbpo_ful:
    print(f"\nPBPO Overhead (Table 6):")
    print(f"  Lightweight pipeline: {min(pbpo_lw):.4f}–{max(pbpo_lw):.4f} ms  (avg {sum(pbpo_lw)/len(pbpo_lw):.4f} ms)")
    print(f"  Full pipeline:        {min(pbpo_ful):.4f}–{max(pbpo_ful):.4f} ms  (avg {sum(pbpo_ful)/len(pbpo_ful):.4f} ms)")

# CDER summary
cder_a1 = [(a, get(a, PCT, SPD, 1, 'CDER', None)) for a in sorted(ATK_SHORT.keys())]
cder_a5 = [(a, get(a, PCT, SPD, 5, 'CDER', None)) for a in sorted(ATK_SHORT.keys())]
valid_c1 = [(a, float(v)) for a,v in cder_a1 if v not in ('N/A', None)]
valid_c5 = [(a, float(v)) for a,v in cder_a5 if v not in ('N/A', None)]
if valid_c1 and valid_c5:
    avg_c1 = sum(v for _,v in valid_c1) / len(valid_c1)
    avg_c5 = sum(v for _,v in valid_c5) / len(valid_c5)
    print(f"\nBlockchain Contribution (Table 5):")
    print(f"  CDER A1 (with BC): avg={avg_c1:.3f}")
    print(f"  CDER A5 (no BC):   avg={avg_c5:.3f}  Δ={avg_c5-avg_c1:+.3f}")
elif valid_c1:
    print(f"\nBlockchain Contribution (Table 5): A5 data pending (run cder sweep)")

print(f"\nData completeness: {len(files)} CSV files read from {SWEEP_DIR}")
print()
print("=" * 80)
print("[ANALYZE] COMPLETE")
print(f"[ANALYZE] Output in: {OUT_DIR}")
print("=" * 80)
