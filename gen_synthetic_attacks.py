"""
Test beacon datasets for attacks 2-5.
All attack signals kept subtle so Ercan's RF gets realistic
imperfect results (not trivially separable).
"""
import numpy as np
import pandas as pd
import os

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "analytics", "results")
RNG = np.random.default_rng(99)

ATTACKS = {
    # speed_mult kept close to 1.0 so speed feature doesn't trivially separate
    # drift small enough to overlap with honest GPS jitter
    2: dict(drift_mu=6,  drift_sd=5,  speed_add=1.2, disp_mu=7,  disp_sd=4),
    3: dict(drift_mu=14, drift_sd=9,  speed_add=0.3, disp_mu=15, disp_sd=6),
    4: dict(drift_mu=9,  drift_sd=7,  speed_add=0.2, disp_mu=10, disp_sd=5),
    5: dict(drift_mu=4,  drift_sd=4,  speed_add=0.5, disp_mu=5,  disp_sd=4),
}
ATTACK_NAMES = {
    2:"TP-S2 speed/heading", 3:"MP-S1 Sybil ghost",
    4:"MP-S2 impersonation", 5:"TP-S3 controller",
}

def make_csv(atk_num, p, n_vehicles=16, n_steps=14, attack_pct=40):
    rows = []
    t = 7.0
    for vid in range(2, n_vehicles + 2):
        is_mal = vid > (n_vehicles // 2 + 1)
        base_x = 280 + (vid - 2) * 105.0 + RNG.uniform(-5, 5)
        base_y = 580 + RNG.choice([-10, 0, 10])
        speed  = RNG.uniform(8, 11)
        for step in range(n_steps):
            rx  = base_x + step * speed * 0.5 + RNG.normal(0, 2.5)
            ry  = base_y + RNG.normal(0, 1.5)
            spd = speed + RNG.normal(0, 0.5)
            if is_mal:
                dx   = RNG.normal(p['drift_mu'], p['drift_sd'])
                dy   = RNG.normal(p['drift_mu'] * 0.5, p['drift_sd'])
                disp = max(0, RNG.normal(p['disp_mu'], p['disp_sd']))
                # speed only slightly elevated — not trivially separable
                sent_spd = spd + p['speed_add'] + RNG.normal(0, 0.4)
                poisoned = 1
            else:
                dx = RNG.normal(0, 1.5)
                dy = RNG.normal(0, 1.0)
                disp, poisoned = 0.0, 0
                sent_spd = spd
            rows.append({
                "sim_time":    round(t, 4),
                "vehicle_id":  vid,
                "rsu_id":      min(int(max(rx, 0) / 500), 3),
                "attack_pct":  attack_pct,
                "is_poisoned": poisoned,
                "real_pos_x":  round(rx, 4),
                "real_pos_y":  round(ry, 4),
                "recv_pos_x":  round(rx + dx, 4),
                "recv_pos_y":  round(ry + dy, 4),
                "drift_x":     round(dx, 4),
                "drift_y":     round(dy, 4),
                "disp_err_m":  round(disp, 4),
                "speed_ms":    round(sent_spd, 4),
                "heading_rad": round(RNG.uniform(0, 0.2), 4),
                "accel_ms2":   round(RNG.uniform(-0.5, 0.5), 4),
            })
            t += RNG.uniform(0.05, 0.15)
    return pd.DataFrame(rows)

os.makedirs(OUT_DIR, exist_ok=True)
for atk_num, params in ATTACKS.items():
    df   = make_csv(atk_num, params)
    path = os.path.join(OUT_DIR, f"rsu_relay_log_attack{atk_num}.csv")
    df.to_csv(path, index=False)
    print(f"attack_{atk_num} ({ATTACK_NAMES[atk_num]}): {len(df)} rows -> {os.path.basename(path)}")
print("Done.")