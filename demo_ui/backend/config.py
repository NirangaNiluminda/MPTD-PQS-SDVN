"""Paths the backend reads from. Override via environment variables so the
server is portable to another checkout/user without editing source.
"""

import os
from pathlib import Path

REPO_ROOT = Path(os.environ.get("MPTD_REPO_ROOT", Path(__file__).resolve().parents[2]))

# Pre-recorded replay corpus: 113 scenarios, {urban,rural,highway} x a<N>_p<PCT>.
# See parsers/catalog.py for the confirmed layout.
CORPUS_ROOT = Path(
    os.environ.get(
        "MPTD_CORPUS_ROOT",
        "/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility",
    )
)

MOBILITY_DIR = REPO_ROOT / "mobility"

# rsu_positions_<road>.csv / mobility_<road>_<speed>.tcl naming, per road type.
ROAD_TRACE_FILES = {
    "urban": {"rsu": "rsu_positions_urban.csv", "trace": "mobility_urban_60.tcl"},
    "rural": {"rsu": "rsu_positions_rural.csv", "trace": "mobility_rural_60.tcl"},
    "highway": {"rsu": "rsu_positions_autobahn.csv", "trace": "mobility_autobahn_150.tcl"},
}
