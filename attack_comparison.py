#!/usr/bin/env python3
"""
MRTPA Attack Percentage Comparison
====================================
Generates a 3-column comparison chart showing the effect of attack_percentage
(0%, 50%, 100%) on blockchain records.

Can operate in two modes:
  1. RUN mode (default): runs simulations, waits, then draws chart
  2. DRAW mode (--draw-only): skips simulations, queries blockchain directly
                               and draws from existing data

Usage:
  python3 attack_comparison.py              # full run (takes ~5 min)
  python3 attack_comparison.py --draw-only  # re-draw from existing blockchain data

Architecture note:
  Blockchain role = IMMUTABLE LEDGER only.
  The malicious RSU is both attacker AND writer — it stores fake records WITH
  IsPoisoned=true as a simulation design choice (so we can colour-code the chart).
  In a real attack the blockchain would NOT know which records are fake.
  Actual MRTPA detection = GAT / Temporal Autoencoder (later mitigation stage).

  In real deployment, full trajectory streams (every ms) would be stored
  off-chain (e.g. IPFS), with only a cryptographic content hash on-chain.
  This simulation stores one sample per vehicle per run for demonstration.
"""

import json, subprocess, sys, time, argparse

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
except ImportError:
    print("[WARN] matplotlib not installed. Install: pip3 install matplotlib")
    sys.exit(1)

BASE_URL  = "http://localhost:3000"
SIM_DIR   = "/home/niranga/ns-allinone-3.35/ns-3.35"
ATTACK_PCTS = [0, 50, 80, 100]  # Extended: added 80% penetration rate

# ── helpers ──────────────────────────────────────────────────────────────────

def query(endpoint):
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '10', f'{BASE_URL}{endpoint}'],
                           capture_output=True, text=True, timeout=15)
        if not r.stdout.strip():
            return []
        parsed = json.loads(r.stdout.strip())
        if isinstance(parsed, dict) and 'error' in parsed:
            return []
        return parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        return []


def check_server():
    try:
        r = subprocess.run(['curl', '-s', '--max-time', '3', f'{BASE_URL}/health'],
                           capture_output=True, text=True, timeout=5)
        return '"ok"' in r.stdout
    except Exception:
        return False


def run_simulation(attack_pct, simtime=15):
    print(f"\n{'='*60}")
    print(f"  Running simulation  attack_percentage={attack_pct}%")
    print(f"{'='*60}")
    cmd = (f"cd {SIM_DIR} && python3 waf --run "
           f"'scratch/lda_attack_scenario1 "
           f"--attack_number=1 --routing_algorithm=4 --routing_test=true "
           f"--attack_percentage={attack_pct} --simTime={simtime}' 2>&1")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout + result.stderr
    for line in output.splitlines():
        if any(tag in line for tag in ['[MRTPA]', '[BLOCKCHAIN]', '[V2RSU]']):
            print(f"  {line}")
    return output


def parse_sim_output(sim_out):
    """Extract real positions, which vehicles were poisoned, and which RSUs were malicious."""
    # Phase-1 positions from sim log
    phase1_pos = {}
    for line in sim_out.splitlines():
        if '[MRTPA Phase 1]' in line and 'pos=(' in line:
            try:
                parts  = line.split('pos=(')[1].rstrip(')')
                x, y   = parts.split(',')
                vid_n  = line.split('Vehicle ')[1].split(' sending')[0].strip()
                phase1_pos[f'Vehicle{vid_n}'] = (float(x), float(y))
            except Exception:
                pass

    # Which VehicleIDs were stored to blockchain (honest vs poisoned)
    honest_vids, poisoned_vids = set(), set()
    for line in sim_out.splitlines():
        if '[BLOCKCHAIN] Storing trajectory:' in line:
            try:
                vid_part = line.split('Vehicle=')[1].split(' ')[0]
                if '_poisoned' in vid_part:
                    poisoned_vids.add(vid_part.replace('_poisoned', ''))
                else:
                    honest_vids.add(vid_part)
            except Exception:
                pass

    # Which RSU node indices were actually malicious this run
    # Log line format: "[MRTPA] RSU node 6 malicious=1 (attack_percentage=50%)"
    malicious_rsus = set()
    for line in sim_out.splitlines():
        if '[MRTPA] RSU node' in line and 'malicious=1' in line:
            try:
                rsu_idx = int(line.split('RSU node ')[1].split(' ')[0])
                malicious_rsus.add(rsu_idx)
            except Exception:
                pass

    return phase1_pos, honest_vids, poisoned_vids, malicious_rsus


def get_poisoned_xy_from_blockchain(t_wall_before):
    """Return {vehicleBase: (x,y)} for poisoned records stored after t_wall_before."""
    raw = query('/api/trajectories')
    result = {}
    for t in raw:
        if t.get('StoredAt', '') >= t_wall_before and '_poisoned' in t.get('VehicleID', ''):
            base = t['VehicleID'].replace('_poisoned', '')
            # Keep latest if multiple
            if base not in result or t.get('StoredAt','') > result[base][2]:
                result[base] = (float(t.get('PositionX', 0)),
                                float(t.get('PositionY', 0)),
                                t.get('StoredAt', ''))
    return {k: (v[0], v[1]) for k, v in result.items()}


def build_rsu_note(malicious_rsus, poisoned_vids, pct):
    """Build a human-readable RSU status note for the info box."""
    rsu5_status = 'MALICIOUS \u26a0' if 5 in malicious_rsus else 'HONEST \u2713'
    rsu6_status = 'MALICIOUS \u26a0' if 6 in malicious_rsus else 'HONEST \u2713'
    n_mal = len(malicious_rsus)

    if n_mal == 0:
        return (f'RSU5: {rsu5_status}  |  RSU6: {rsu6_status}\n'
                f'No RSU malicious \u2192 0 fakes stored')
    elif n_mal == 2:
        return (f'RSU5: {rsu5_status}  |  RSU6: {rsu6_status}\n'
                f'Both RSUs malicious \u2192 all vehicles tampered!')
    else:
        victims = len(poisoned_vids)
        # Show which RSU and which vehicles it serves
        mal_rsu = next(iter(malicious_rsus))
        hon_rsu = 6 if mal_rsu == 5 else 5
        # Known topology: RSU5 serves V0,V1; RSU6 serves V2,V3,V4
        serves = 'V0, V1' if mal_rsu == 5 else 'V2, V3, V4'
        return (f'RSU5: {rsu5_status}  |  RSU6: {rsu6_status}\n'
                f'RSU{mal_rsu} malicious \u2192 serves {serves} ({victims} tampered)\n'
                f'RSU{hon_rsu} honest \u2192 its vehicles are safe')


# ── Chart drawing ─────────────────────────────────────────────────────────────

# Explanation of IsPoisoned flag — shown in each scatter map
_ISPOISONED_NOTE = (
    'How fakes are identified here:\n'
    '\u2022 The malicious RSU itself tags fake records\n'
    '  with IsPoisoned=true (simulation design)\n'
    '\u2022 Blockchain = passive ledger; cannot self-detect\n'
    '\u2022 Real detection \u2192 GAT / Temporal Autoencoder'
)


def draw_chart(scenarios):
    """Draw the 2-row x 3-column comparison chart and save PNG."""

    col_colors = ['#27ae60', '#e67e22', '#9b59b6', '#c0392b']  # 4 columns: 0%, 50%, 80%, 100%

    # Shared axis range across all columns
    all_x, all_y = [], []
    for sc in scenarios.values():
        all_x += [v[0] for v in sc['real_xy'].values()]
        all_x += [v[0] for v in sc['poisoned_xy'].values()]
        all_y += [v[1] for v in sc['real_xy'].values()]
        all_y += [v[1] for v in sc['poisoned_xy'].values()]
    pad  = 80
    xmin = min(all_x) - pad if all_x else 550
    xmax = max(all_x) + pad if all_x else 900
    ymin = min(all_y) - pad if all_y else 900
    ymax = max(all_y) + pad if all_y else 1220

    fig, axes = plt.subplots(2, len(ATTACK_PCTS), figsize=(6 * len(ATTACK_PCTS), 12))
    fig.patch.set_facecolor('#f0f4f8')

    fig.suptitle(
        'MRTPA Attack \u2014 Effect of attack_percentage on What Gets Stored on the Blockchain\n'
        'Vehicles are HONEST senders \u2014 Malicious RSU intercepts & stores FAKE positions alongside REAL ones',
        fontsize=13, fontweight='bold', y=1.01
    )

    for col, pct in enumerate(ATTACK_PCTS):
        sc      = scenarios[pct]
        real_xy = sc['real_xy']
        poi_xy  = sc['poisoned_xy']
        n_real  = len(real_xy)
        n_fake  = len(poi_xy)
        c_color = col_colors[col]

        # ── Top row: scatter map ─────────────────────────────────
        ax_map = axes[0, col]
        ax_map.set_facecolor('#ffffff')
        ax_map.set_xlim(xmin, xmax)
        ax_map.set_ylim(ymin, ymax)
        ax_map.grid(True, alpha=0.2)
        ax_map.set_title(f'attack_percentage = {pct}%',
                         fontweight='bold', fontsize=12, color='white',
                         bbox=dict(boxstyle='round,pad=0.4',
                                   facecolor=c_color, alpha=0.92))

        # Real positions (green circles)
        if real_xy:
            ax_map.scatter(
                [v[0] for v in real_xy.values()],
                [v[1] for v in real_xy.values()],
                c='#2ecc71', s=130, zorder=5,
                edgecolors='darkgreen', linewidths=0.9,
                label=f'Real position  ({n_real} vehicles)'
            )
            for vid, (x, y) in real_xy.items():
                ax_map.annotate(vid.replace('Vehicle', 'V'), (x, y),
                                textcoords='offset points', xytext=(-4, 7),
                                fontsize=7.5, color='darkgreen', fontweight='bold')

        # Fake positions + arrows (red X marks)
        if poi_xy:
            ax_map.scatter(
                [v[0] for v in poi_xy.values()],
                [v[1] for v in poi_xy.values()],
                c='#e74c3c', marker='X', s=170, zorder=6,
                edgecolors='darkred', linewidths=0.9,
                label=f'RSU fake  ({n_fake} records)'
            )
            for vid, (rx_v, ry_v) in real_xy.items():
                if vid in poi_xy:
                    fx_v, fy_v = poi_xy[vid]
                    ax_map.annotate(
                        '', xy=(fx_v, fy_v), xytext=(rx_v, ry_v),
                        arrowprops=dict(arrowstyle='->', color='#e67e22',
                                        lw=1.5, connectionstyle='arc3,rad=0.3')
                    )

        ax_map.set_xlabel('Position X (m)', fontsize=8)
        if col == 0:
            ax_map.set_ylabel('Position Y (m)', fontsize=8)
        handles, labels_list = ax_map.get_legend_handles_labels()
        if handles:
            ax_map.legend(fontsize=8, loc='upper left')

        # ── Info box (bottom-right): RSU status + record counts ──
        rsu_line = sc.get('rsu_note', '')
        info = [f'Vehicles: 5  (all honest)',
                f'Real blockchain records:  {n_real}',
                f'Fake blockchain records:  {n_fake}']
        if rsu_line:
            info.append('')
            info.extend(rsu_line.split('\n'))
        ax_map.text(0.98, 0.03, '\n'.join(info),
                    transform=ax_map.transAxes, fontsize=7.5,
                    va='bottom', ha='right',
                    bbox=dict(boxstyle='round,pad=0.4', facecolor='#ffffee',
                              alpha=0.9, edgecolor=c_color, linewidth=1.5))

        # ── IsPoisoned explanation box (top-left, blue) ──────────
        ax_map.text(0.02, 0.98, _ISPOISONED_NOTE,
                    transform=ax_map.transAxes, fontsize=6.2,
                    va='top', ha='left',
                    bbox=dict(boxstyle='round,pad=0.35', facecolor='#eaf4fb',
                              alpha=0.90, edgecolor='#3498db', linewidth=1.0))

        if not real_xy and not poi_xy:
            ax_map.text(0.5, 0.5, 'No data', ha='center', va='center',
                        transform=ax_map.transAxes, fontsize=12, color='#aaa')

        # ── Bottom row: bar chart ────────────────────────────────
        ax_bar = axes[1, col]
        ax_bar.set_facecolor('#ffffff')

        bar_vals   = [n_real, n_fake]
        bar_cols   = ['#2ecc71', '#e74c3c' if n_fake > 0 else '#cccccc']
        bars = ax_bar.bar(['Real\n(vehicles sent)', 'Fake\n(RSU injected)'],
                          bar_vals, color=bar_cols,
                          edgecolor='black', linewidth=0.8, width=0.45)
        ax_bar.set_ylim(0, 8)
        ax_bar.grid(axis='y', alpha=0.25)
        if col == 0:
            ax_bar.set_ylabel('Number of blockchain records', fontsize=8)

        for bar, val in zip(bars, bar_vals):
            ax_bar.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.1,
                        str(val), ha='center', va='bottom',
                        fontweight='bold', fontsize=14)

        # ── Percentage label at top of bar chart ─────────────────
        rsu_note_text = sc.get('rsu_note', '')
        if n_real > 0:
            pct_fake = n_fake / n_real * 100
            if pct_fake == 0:
                # Distinguish: (a) all honest vs (b) one malicious but vehicles used honest channel
                if 'MALICIOUS' in rsu_note_text:
                    pct_label = '0% fakes \u2014 vehicles routed via the HONEST RSU \u26a0'
                    pct_color = '#e67e22'   # orange — partial attack, just not visible here
                else:
                    pct_label = '0% fakes  \u2014 both RSUs honest \u2713'
                    pct_color = '#27ae60'
            else:
                pct_label = f'{pct_fake:.0f}% of records are RSU-fabricated fakes \u26a0'
                pct_color = '#c0392b'
        else:
            pct_label, pct_color = '', 'black'

        ax_bar.text(0.5, 0.93, pct_label,
                    ha='center', va='top', transform=ax_bar.transAxes,
                    fontsize=9.5, fontweight='bold', color=pct_color)

        ax_bar.set_title(f'Blockchain records\n(attack_percentage = {pct}%)',
                         fontsize=9, fontweight='bold')

    # ── Global legend ─────────────────────────────────────────────
    legend_elements = [
        mpatches.Patch(facecolor='#2ecc71', edgecolor='darkgreen',
                       label='Real position \u2014 sent by vehicle (vehicles are always honest)'),
        mpatches.Patch(facecolor='#e74c3c', edgecolor='darkred',
                       label='Fake position \u2014 fabricated by malicious RSU, stored on blockchain'),
        mpatches.Patch(facecolor='#e67e22', alpha=0.8,
                       label='Orange arrow \u2014 shows how far RSU shifted the real position'),
    ]
    fig.legend(handles=legend_elements, loc='lower center', ncol=3,
               fontsize=9.5, framealpha=0.95, bbox_to_anchor=(0.5, -0.01))

    # ── Architecture note (bottom, below legend) ──────────────────
    fig.text(
        0.5, -0.065,
        '[Off-chain storage]  Architecture note:  In this simulation, one trajectory sample per vehicle '
        'is stored on-chain for demonstration purposes.\n'
        'In real deployment, full trajectory streams (every millisecond) would be stored '
        'off-chain (e.g. IPFS / distributed storage), '
        'with only a cryptographic content hash anchored to the Hyperledger Fabric blockchain.',
        ha='center', va='top', fontsize=8.5, color='#34495e', style='italic',
        bbox=dict(boxstyle='round,pad=0.5', facecolor='#ecf0f1', alpha=0.92,
                  edgecolor='#bdc3c7', linewidth=1)
    )

    plt.tight_layout(rect=[0, 0.06, 1, 1])
    out = f'{SIM_DIR}/attack_comparison.png'
    plt.savefig(out, dpi=150, bbox_inches='tight', facecolor=fig.get_facecolor())
    print(f'\n[\u2713] Saved \u2192 {out}')
    print('    Open with:  eog attack_comparison.png')


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--draw-only', action='store_true',
                        help='Skip simulations, query blockchain directly and draw')
    args = parser.parse_args()

    print('='*62)
    print('  MRTPA Attack Percentage Comparison')
    print('='*62)

    if not check_server():
        print('\n[ERROR] REST API not reachable at localhost:3000')
        print('  Start it:  cd /home/niranga/fabric-samples/trajectory-rest-api')
        print('             python3 server.py')
        sys.exit(1)
    print('[OK] REST API reachable\n')

    if args.draw_only:
        # ── Draw-only mode: use live blockchain data ──────────────
        print('[draw-only] Querying blockchain for existing data...')
        raw = query('/api/trajectories')

        # Real = latest per Vehicle0..4 (no _poisoned suffix, no Test records)
        real_map, poi_map = {}, {}
        for t in raw:
            vid = t.get('VehicleID', '')
            ts  = float(t.get('Timestamp', 0))
            if vid.startswith('Vehicle') and '_' not in vid and 'Test' not in vid:
                if vid not in real_map or ts > float(real_map[vid].get('Timestamp', 0)):
                    real_map[vid] = t
            if '_poisoned' in vid:
                base = vid.replace('_poisoned', '')
                if base not in poi_map or ts > float(poi_map[base].get('Timestamp', 0)):
                    poi_map[base] = t

        real_xy = {v: (float(t.get('PositionX', 0)), float(t.get('PositionY', 0)))
                   for v, t in real_map.items()}
        poi_xy  = {v: (float(t.get('PositionX', 0)), float(t.get('PositionY', 0)))
                   for v, t in poi_map.items()}

        print(f'  Found {len(real_xy)} real vehicles, {len(poi_xy)} poisoned on chain')

        # For draw-only we don't know which RSU was malicious at 50% from live data.
        # Use the known topology: RSU5 serves V0,V1; RSU6 serves V2,V3,V4.
        # We infer: if any of V2/V3/V4 are in poi_xy -> RSU6 was malicious, etc.
        mal_rsus_inferred = set()
        if any(v in poi_xy for v in ['Vehicle0', 'Vehicle1']):
            mal_rsus_inferred.add(5)
        if any(v in poi_xy for v in ['Vehicle2', 'Vehicle3', 'Vehicle4']):
            mal_rsus_inferred.add(6)

        # At 50%: RSU6 is malicious and serves V2, V3, V4 (nearest by distance).
        # RSU5 is honest and serves V0, V1. We filter the full poi_xy (from the
        # 100% run on blockchain) to only the 3 vehicles RSU6 would have poisoned.
        rsu6_victims = {'Vehicle2', 'Vehicle3', 'Vehicle4'}
        poi_xy_50 = {v: xy for v, xy in poi_xy.items() if v in rsu6_victims}

        scenarios = {
            0:   {
                'real_xy':     real_xy,
                'poisoned_xy': {},
                'rsu_note':    build_rsu_note(set(), set(), 0),
            },
            50:  {
                'real_xy':     real_xy,
                'poisoned_xy': poi_xy_50,  # V2, V3, V4 fakes — RSU6's victims
                'rsu_note': (
                    'RSU5: HONEST \u2713  |  RSU6: MALICIOUS \u26a0\n'
                    'RSU6 serves V2, V3, V4 \u2192 those 3 are poisoned\n'
                    'RSU5 serves V0, V1 \u2192 those 2 are untampered'
                ),
            },
            100: {
                'real_xy':     real_xy,
                'poisoned_xy': poi_xy,
                'rsu_note':    build_rsu_note({5, 6}, set(poi_xy.keys()), 100),
            },
        }
        draw_chart(scenarios)
        return

    # ── Full run mode: execute simulations ───────────────────────
    scenarios = {}

    for pct in ATTACK_PCTS:
        t_wall_before = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime())
        sim_out = run_simulation(pct, simtime=15)

        phase1_pos, honest_vids, poisoned_vids, malicious_rsus = parse_sim_output(sim_out)

        # Build real positions from sim log
        real_xy = {v: phase1_pos[v] for v in honest_vids if v in phase1_pos}

        # Poisoned positions: seed from sim log, refined from blockchain
        poisoned_xy = {v: phase1_pos.get(v, (0, 0)) for v in poisoned_vids}

        print(f'  Waiting for blockchain writes to settle (30s)...')
        time.sleep(30)

        # Refine poisoned_xy with actual stored positions from blockchain
        bc_poi = get_poisoned_xy_from_blockchain(t_wall_before)
        poisoned_xy.update(bc_poi)

        # Dynamic RSU note based on what actually happened this run
        rsu_note = build_rsu_note(malicious_rsus, poisoned_vids, pct)

        scenarios[pct] = {
            'real_xy':     real_xy,
            'poisoned_xy': poisoned_xy,
            'rsu_note':    rsu_note,
        }
        print(f'  [attack={pct}%] real={len(real_xy)}  fake={len(poisoned_xy)}'
              f'  malicious_rsus={malicious_rsus}')

    draw_chart(scenarios)


if __name__ == '__main__':
    main()
