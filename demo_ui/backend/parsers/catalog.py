"""Discover replayable scenarios in the pre-recorded corpus.

Corpus layout (confirmed 2026-08-14):
  ~/Desktop/dataset_G50-mobility/{urban,rural,highway}/a<N>_p<PCT>/
    beacon_log.csv   — always present
    metrics.csv      — always present
    <attack-specific detail log, e.g. tp_s1_poison_log.csv>

  N = attack_number (1-7, see ATTACK_NAMES). No a0 (combined) folders exist
  in this corpus — combined-mode replay, if wanted, must come from a fresh
  run (see DEMO_UI_PLAN's Phase-6/open-items note on regenerating a small set).

Folder counts differ per road type (urban/rural: 42 = 7 attacks x 6 pct
levels; highway: 29, some combos missing) — do not assume full coverage,
scan and report what actually exists.
"""

import re
from dataclasses import dataclass
from pathlib import Path

# scratch/mptd_pqs_sdvn/02_config_globals.h:170-179 attack_scenario_name[]
ATTACK_NAMES = {
    0: "COMBINED:All7AttackTypes",
    1: "TP-S1:MaliciousRSU-TrajectoryPoisoning",
    2: "TP-S2:MaliciousVehicle-TrajectoryPoisoning",
    3: "MP-S1:Sybil-CompromisedRSU",
    4: "MP-S2:Sybil-VehicleImpersonation",
    5: "TP-S3:ControlPlane-TrajectoryPoisoning",
    6: "MP-S3:MitM-DataPlane-MobilityPattern",
    7: "MP-S4:ControlPlane-MobilityPatternPoisoning",
}

# Actor + plain description, verified against 06a_attack_models.h's own
# comments (declare_attack_states(), attack_number == 1..7 branches).
ATTACK_INFO = {
    1: {
        "actor": "compromised_rsu",
        "plain": "A hijacked roadside unit rewrites vehicles' trajectories as it relays them.",
    },
    2: {
        "actor": "malicious_vehicle",
        "plain": "A lying vehicle reports a fake but physically plausible trajectory.",
    },
    3: {
        "actor": "compromised_rsu",
        "plain": "A hijacked roadside unit injects ghost identities (Sybil). In enhanced mode "
        "the ghosts pre-register with valid pool IDs, so detection must be behavioural.",
    },
    4: {
        "actor": "malicious_vehicle",
        "plain": "A vehicle steals another vehicle's identity and beacons under it.",
    },
    5: {
        "actor": "malicious_controller",
        "plain": "A hijacked network controller poisons trajectories at the control plane; "
        "vehicles and roadside units stay honest throughout.",
    },
    6: {
        "actor": "mitm_relay",
        "plain": "A vehicle acts as an intercepting relay, amplifying reported speed to "
        "breach the neighbourhood similarity threshold.",
    },
    7: {
        "actor": "malicious_controller",
        "plain": "A hijacked controller corrupts the global mobility model despite receiving "
        "correct data from every honest vehicle and roadside unit.",
    },
}

_FOLDER_RE = re.compile(r"^a(?P<attack>\d+)_p(?P<pct>\d+)$")


@dataclass(frozen=True)
class Scenario:
    id: str  # "<road>/a<N>_p<PCT>", stable key for API routes
    road: str  # "urban" | "rural" | "highway"
    attack_number: int
    attack_name: str
    attack_pct: int
    dir: Path
    has_beacon_log: bool
    has_metrics: bool


def scan_corpus(corpus_root: str | Path) -> list[Scenario]:
    root = Path(corpus_root)
    scenarios: list[Scenario] = []
    if not root.is_dir():
        return scenarios
    for road_dir in sorted(root.iterdir()):
        if not road_dir.is_dir():
            continue
        road = road_dir.name
        for scen_dir in sorted(road_dir.iterdir()):
            m = _FOLDER_RE.match(scen_dir.name)
            if not m or not scen_dir.is_dir():
                continue
            attack_n = int(m.group("attack"))
            scenarios.append(
                Scenario(
                    id=f"{road}/{scen_dir.name}",
                    road=road,
                    attack_number=attack_n,
                    attack_name=ATTACK_NAMES.get(attack_n, f"unknown-{attack_n}"),
                    attack_pct=int(m.group("pct")),
                    dir=scen_dir,
                    has_beacon_log=(scen_dir / "beacon_log.csv").is_file(),
                    has_metrics=(scen_dir / "metrics.csv").is_file(),
                )
            )
    return scenarios


def find_scenario(corpus_root: str | Path, scenario_id: str) -> Scenario | None:
    for s in scan_corpus(corpus_root):
        if s.id == scenario_id:
            return s
    return None
