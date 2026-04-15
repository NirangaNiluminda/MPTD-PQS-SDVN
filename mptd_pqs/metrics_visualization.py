"""
Metrics Visualization — 8-panel chart + ablation comparison
============================================================
Implements the evaluation figures from Section 4 of the paper.

Chart 1 (8-panel): Per-metric comparison across attack percentages
  Panels: MCC, FPR, PARR, CDER, TDEE, TPE, PBPO, F1

Chart 2: Ablation study — A1 through A5 vs FULL
  Bar chart comparing MCC, FPR, PARR across all variants

Chart 3: Baseline comparison — B1, B2, B3 vs MPTD-PQS
  Grouped bar chart

Chart 4: Extended attack_comparison — 4-column grid (0%, 50%, 80%, 100%)
"""

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from typing import Dict, List, Optional
from mptd_pqs.metrics_calculator import MetricsResult, BASELINES


# ── Color palette ─────────────────────────────────────────────────────────────
COLORS = {
    "FULL": "#1f77b4",
    "A1":   "#ff7f0e",
    "A2":   "#2ca02c",
    "A3":   "#d62728",
    "A4":   "#9467bd",
    "A5":   "#8c564b",
    "B1":   "#e377c2",
    "B2":   "#7f7f7f",
    "B3":   "#bcbd22",
}

VARIANT_LABELS = {
    "FULL": "MPTD-PQS (Full)",
    "A1":   "A1: LW-DETECT only",
    "A2":   "A2: GAT only",
    "A3":   "A3: AE only",
    "A4":   "A4: AI, no PQ",
    "A5":   "A5: no Blockchain",
}


def plot_metric_vs_attack_pct(results: List[MetricsResult],
                               output_path: str = "mptd_pqs_metrics.png"):
    """
    8-panel figure: each panel shows one metric across attack percentages.
    results: list of MetricsResult for different attack_percentage values.
    """
    if not MATPLOTLIB_AVAILABLE:
        print("matplotlib not available — skipping chart 1")
        _text_report(results)
        return

    attack_pcts = [r.attack_percentage for r in results]

    metrics = [
        ("mcc",  "MCC",   "Matthews Correlation Coefficient",  True,  [-1, 1]),
        ("fpr",  "FPR",   "False Positive Rate",               False, [0, 1]),
        ("parr", "PARR",  "Poisoned Attack Record Rate",        True,  [0, 1]),
        ("cder", "CDER",  "Cumul. Deviation Error Rate (m)",    False, None),
        ("tdee", "TDEE",  "Traj. Deviation Error Energy (m²)",  False, None),
        ("tpe",  "TPE",   "Traj. Poisoning Effectiveness",      False, [0, 1]),
        ("pbpo", "PBPO",  "Poisoned Blockchain Proportion",     False, [0, 1]),
        ("f1",   "F1",    "F1 Score",                           True,  [0, 1]),
    ]

    fig, axes = plt.subplots(2, 4, figsize=(16, 8))
    fig.suptitle("MPTD-PQS Framework — Detection Metrics vs Attack Percentage",
                 fontsize=14, fontweight='bold', y=1.01)

    for ax, (attr, label, title, higher_better, ylim) in zip(axes.flat, metrics):
        vals = [getattr(r, attr) for r in results]
        ax.plot(attack_pcts, vals, 'o-', color=COLORS["FULL"],
                linewidth=2, markersize=6, label="MPTD-PQS")
        ax.set_xlabel("Attack Percentage (%)", fontsize=9)
        ax.set_ylabel(label, fontsize=9)
        ax.set_title(title, fontsize=9, pad=4)
        ax.set_xticks(attack_pcts)
        if ylim:
            ax.set_ylim(ylim)
        ax.grid(True, alpha=0.3)

        # Annotate trend direction
        arrow = "↑ better" if higher_better else "↓ better"
        ax.text(0.98, 0.05, arrow, transform=ax.transAxes,
                ha='right', va='bottom', fontsize=7, color='gray')

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")


def plot_ablation(ablation_results: Dict[str, 'MetricsResult'],
                  attack_pct: int = 50,
                  output_path: str = "mptd_pqs_ablation.png"):
    """
    Grouped bar chart comparing variants A1-A5 vs FULL on key metrics.
    ablation_results: dict mapping variant name → MetricsResult
    """
    if not MATPLOTLIB_AVAILABLE:
        print("matplotlib not available — skipping ablation chart")
        _text_ablation(ablation_results)
        return

    variants = ["A1", "A2", "A3", "A4", "A5", "FULL"]
    metrics  = [("mcc", "MCC"), ("fpr", "FPR (lower=better)"),
                ("parr", "PARR"), ("f1", "F1")]

    n_metrics = len(metrics)
    x = range(len(variants))
    bar_width = 0.2

    fig, axes = plt.subplots(1, n_metrics, figsize=(16, 5))
    fig.suptitle(f"Ablation Study — Attack Percentage = {attack_pct}%",
                 fontsize=13, fontweight='bold')

    for ax, (attr, label) in zip(axes, metrics):
        vals = []
        colors = []
        for v in variants:
            r = ablation_results.get(v)
            vals.append(getattr(r, attr, 0.0) if r else 0.0)
            colors.append(COLORS.get(v, "#999"))

        bars = ax.bar(x, vals, color=colors, width=0.6, alpha=0.85)
        ax.set_xticks(list(x))
        ax.set_xticklabels([VARIANT_LABELS.get(v, v) for v in variants],
                            rotation=15, ha='right', fontsize=8)
        ax.set_title(label, fontsize=10)
        ax.grid(True, axis='y', alpha=0.3)

        # Value labels
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.3f}", ha='center', va='bottom', fontsize=7)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")


def plot_baseline_comparison(mptd_result: 'MetricsResult',
                              output_path: str = "mptd_pqs_baseline.png"):
    """
    Compare MPTD-PQS against B1, B2, B3 baselines.
    """
    if not MATPLOTLIB_AVAILABLE:
        print("matplotlib not available — skipping baseline chart")
        return

    systems = ["B1\nGhaleb 2014", "B2\nVishwanath 2026", "B3\nSomma 2025",
               "MPTD-PQS\n(ours)"]
    metrics = ["mcc", "fpr", "parr"]
    labels  = ["MCC ↑", "FPR ↓", "PARR ↑"]

    data = {
        "mcc":  [BASELINES["B1_Ghaleb2014"]["mcc"],
                 BASELINES["B2_Vishwanath2026"]["mcc"],
                 BASELINES["B3_Somma2025"]["mcc"],
                 mptd_result.mcc],
        "fpr":  [BASELINES["B1_Ghaleb2014"]["fpr"],
                 BASELINES["B2_Vishwanath2026"]["fpr"],
                 BASELINES["B3_Somma2025"]["fpr"],
                 mptd_result.fpr],
        "parr": [BASELINES["B1_Ghaleb2014"]["parr"],
                 BASELINES["B2_Vishwanath2026"]["parr"],
                 BASELINES["B3_Somma2025"]["parr"],
                 mptd_result.parr],
    }

    x = range(len(systems))
    bar_w = 0.25
    offsets = [-bar_w, 0, bar_w]
    palette = ["#1f77b4", "#ff7f0e", "#2ca02c"]

    fig, ax = plt.subplots(figsize=(10, 5))
    for offset, metric, label, color in zip(offsets, metrics, labels, palette):
        vals = data[metric]
        pos = [xi + offset for xi in x]
        bars = ax.bar(pos, vals, width=bar_w, label=label, color=color, alpha=0.85)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.2f}", ha='center', va='bottom', fontsize=7)

    ax.set_xticks(list(x))
    ax.set_xticklabels(systems, fontsize=10)
    ax.set_ylabel("Metric Value", fontsize=11)
    ax.set_title("MPTD-PQS vs Baselines (B1/B2/B3)", fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.set_ylim(0, 1.15)
    ax.grid(True, axis='y', alpha=0.3)

    # Highlight MPTD-PQS column
    ax.axvspan(len(systems) - 1 - 0.5, len(systems) - 0.5, alpha=0.08, color='green')

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")


def plot_all(results_by_pct: Dict[int, 'MetricsResult'],
             ablation_by_variant: Optional[Dict[str, 'MetricsResult']] = None,
             output_dir: str = "."):
    """
    Generate all visualization charts.
    results_by_pct: {attack_percentage: MetricsResult}
    """
    import os
    os.makedirs(output_dir, exist_ok=True)

    sorted_results = [results_by_pct[k] for k in sorted(results_by_pct.keys())]

    # Chart 1: metrics vs attack %
    plot_metric_vs_attack_pct(
        sorted_results,
        output_path=os.path.join(output_dir, "mptd_pqs_metrics.png")
    )

    # Chart 2: ablation
    if ablation_by_variant:
        plot_ablation(
            ablation_by_variant,
            attack_pct=50,
            output_path=os.path.join(output_dir, "mptd_pqs_ablation.png")
        )

    # Chart 3: baseline comparison (use 50% attack result as representative)
    if 50 in results_by_pct:
        plot_baseline_comparison(
            results_by_pct[50],
            output_path=os.path.join(output_dir, "mptd_pqs_baseline.png")
        )


# ── Text fallbacks when matplotlib not available ──────────────────────────────
def _text_report(results: List['MetricsResult']):
    print("\nMetrics Summary (text mode — matplotlib not available):")
    print(f"{'PCT':>5} {'MCC':>8} {'FPR':>8} {'PARR':>8} {'F1':>8} {'TDEE':>12}")
    print("-" * 55)
    for r in results:
        print(f"{r.attack_percentage:>5}% {r.mcc:>+8.4f} {r.fpr:>8.4f} "
              f"{r.parr:>8.4f} {r.f1:>8.4f} {r.tdee:>12.4f}")


def _text_ablation(ablation: Dict):
    print("\nAblation Study (text mode):")
    print(f"{'Variant':>8} {'MCC':>8} {'FPR':>8} {'PARR':>8} {'F1':>8}")
    print("-" * 40)
    for v, r in ablation.items():
        if r:
            print(f"{v:>8} {r.mcc:>+8.4f} {r.fpr:>8.4f} {r.parr:>8.4f} {r.f1:>8.4f}")


if __name__ == "__main__":
    # Synthetic test data
    from mptd_pqs.metrics_calculator import MetricsCalculator, ConfusionMatrix, MetricsResult

    calc = MetricsCalculator()
    results = {}
    for pct in [0, 50, 80, 100]:
        tp = int(pct * 0.9)
        fn = int(pct * 0.1)
        tn = 100 - pct
        fp = max(0, int(tn * 0.05))
        cm = ConfusionMatrix(TP=tp, FP=fp, TN=tn, FN=fn)
        r = MetricsResult(variant="FULL", attack_percentage=pct, cm=cm)
        r.mcc  = calc.compute_mcc(cm)
        r.fpr  = calc.compute_fpr(cm)
        r.parr = calc.compute_parr(tp, tp + fn)
        r.cder = pct * 0.3
        r.tdee = pct * 50.0
        r.tpe  = pct / 100.0
        r.pbpo = max(0, pct / 100.0 - 0.1)
        r.precision = cm.precision
        r.recall = cm.recall
        r.f1 = cm.f1
        r.accuracy = cm.accuracy
        results[pct] = r

    plot_all(results, output_dir="/home/niranga/ns-allinone-3.35/ns-3.35")
    print("All charts generated.")
