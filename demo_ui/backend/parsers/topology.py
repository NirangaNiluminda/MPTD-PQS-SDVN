"""Control-plane topology: controllers, their RSU clusters, and who is hostile.

Controller assignment is the simulator's own deterministic partition
(11_blockchain_setup.h:271):

    rsu_controller_ID[r] = (r * N_Controllers) / N_RSUs

With the reported 64-RSU / 4-controller setup that is 16 contiguous RSUs per
controller. Contiguous RSU indices are placed adjacently, so this doubles as
the geo-proximity partition described in that file's comment.

IMPORTANT — controllers have NO physical coordinates. They are logical SDN
control-plane nodes; nothing in mobility/ or the CSVs gives them an (x, y).
The position returned here is the CENTROID of the controller's assigned RSU
cluster, computed for display only. It is labelled `position_is_derived: true`
so the UI can say so rather than implying the simulator placed them there.

Attacker identification uses the `attacker_class` column, which is the
simulator's own per-beacon attribution (AttackerClass enum,
02_config_globals.h:204-208) — NOT a heuristic. An earlier attempt here
inferred "compromised RSU" from the fraction of poisoned beacons an RSU
relayed; that silently mislabels the controller-plane attacks (a5/a7), where
RSUs are honest and relay poisoned data they never created.
"""

from dataclasses import dataclass, field

from .beacon import (
    ATTACKER_COMPROMISED_RSU,
    ATTACKER_MALICIOUS_CONTROLLER,
    ATTACKER_MALICIOUS_VEHICLE,
    ATTACKER_MITM,
    Beacon,
)
from .geometry import RsuPosition

DEFAULT_N_CONTROLLERS = 4


def controller_for_rsu(rsu_id: int, n_rsus: int, n_controllers: int) -> int:
    if n_controllers <= 0:
        return 0
    return (rsu_id * n_controllers) // n_rsus


@dataclass
class Controller:
    controller_id: int
    rsu_ids: list[int]
    x: float
    y: float
    position_is_derived: bool = True
    hostile: bool = False


@dataclass
class ThreatRoster:
    """Who is hostile in this scenario, per the simulator's own attribution."""

    compromised_rsus: set[int] = field(default_factory=set)
    malicious_vehicles: set[int] = field(default_factory=set)
    mitm_relays: set[int] = field(default_factory=set)
    controller_plane_rsus: set[int] = field(default_factory=set)
    hostile_controllers: set[int] = field(default_factory=set)


def build_controllers(
    rsus: list[RsuPosition], n_controllers: int = DEFAULT_N_CONTROLLERS
) -> list[Controller]:
    n_rsus = len(rsus)
    if n_rsus == 0:
        return []
    groups: dict[int, list[RsuPosition]] = {}
    for r in rsus:
        cid = controller_for_rsu(r.rsu_id, n_rsus, n_controllers)
        groups.setdefault(cid, []).append(r)

    out: list[Controller] = []
    for cid in sorted(groups):
        members = groups[cid]
        out.append(
            Controller(
                controller_id=cid,
                rsu_ids=sorted(m.rsu_id for m in members),
                x=sum(m.x for m in members) / len(members),
                y=sum(m.y for m in members) / len(members),
            )
        )
    return out


def build_threat_roster(
    beacons: list[Beacon], n_rsus: int, n_controllers: int = DEFAULT_N_CONTROLLERS
) -> ThreatRoster:
    roster = ThreatRoster()
    for b in beacons:
        ac = b.attacker_class
        if ac == ATTACKER_COMPROMISED_RSU:
            roster.compromised_rsus.add(b.rsu_id)
        elif ac == ATTACKER_MALICIOUS_VEHICLE:
            roster.malicious_vehicles.add(b.vehicle_id)
        elif ac == ATTACKER_MITM:
            roster.mitm_relays.add(b.vehicle_id)
        elif ac == ATTACKER_MALICIOUS_CONTROLLER:
            # The controller poisons data that honest RSUs then relay, so the
            # hostile entity is the CONTROLLER assigned to this RSU, not the RSU.
            roster.controller_plane_rsus.add(b.rsu_id)
            roster.hostile_controllers.add(
                controller_for_rsu(b.rsu_id, n_rsus, n_controllers)
            )
    return roster
