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

SUMO_DIR = REPO_ROOT / "sumo"

# Written by scripts/snapshot_ledger.py. Deliberately a point-in-time capture,
# not a live query on every request — see that script's docstring.
CAPTURES_DIR = Path(__file__).resolve().parents[1] / "captures"
LEDGER_SNAPSHOT = CAPTURES_DIR / "ledger_snapshot.json"
FUSION_CAPTURE_LOG = CAPTURES_DIR / "combined_bc_90s.log"

# results_e5_final/e5_final_table.json: SENTINEL vs B1/B2/B3 baselines, per
# attack variant. Validated 2026-08-14 against the repo's own results dir.
E5_RESULTS_FILE = REPO_ROOT / "results_e5_final" / "e5_final_table.json"

# ns-3 root and the compiled binary. Paths from CLAUDE.md's own $NS3/$BIN.
NS3_ROOT = Path(os.environ.get("MPTD_NS3_ROOT", "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35"))
SIM_BINARY = NS3_ROOT / "build" / "scratch" / "mptd_pqs_sdvn" / "mptd_pqs_sdvn"

# Deployed-model sanity check (CLAUDE.md "Deployed model must stay reverted").
# The Fix-A model swap once collapsed MCC to 0.036 — this is checked before
# every UI-launched run, not just documented as a manual step.
GAT_MODEL_DIR = NS3_ROOT / "analytics" / "ml" / "models" / "urban_combined"
EXPECTED_GAT_LINK_TARGET = "../urban/gat_model.onnx"
EXPECTED_THETA_S = 19.74
EXPECTED_THETA_AE = 33.693885

# Offline LSTM-AE reconstruction (ml_scripts/lstm_reconstruct.py) runs the
# exact deployed ONNX artifact via onnxruntime, which isn't installed in
# this backend's own venv — gat_detector/.venv has torch+onnx+onnxruntime
# already, so the script is invoked as a short-lived subprocess in THAT
# interpreter rather than adding a heavy ML dependency to the always-running
# API server.
ML_SCRIPTS_DIR = REPO_ROOT / "demo_ui" / "backend" / "ml_scripts"
ML_VENV_PYTHON = REPO_ROOT / "gat_detector" / ".venv" / "bin" / "python3"
ML_MODEL_ROOT = NS3_ROOT / "analytics" / "ml" / "models"

RUN_LOGS_DIR = CAPTURES_DIR / "runs"
RUN_MANIFEST = RUN_LOGS_DIR / "manifest.json"

# E1 (penetration/intensity sweep) and E2 (speed regime sweep): the raw CSVs
# have no header row and no generating script survives in the repo, so their
# ~13 numeric columns can't be safely re-derived — a wrong guess there would
# silently plot the wrong metric. The PNGs were already correctly built by
# someone who had that context; serve them as static images rather than
# reinterpret the columns.
RESULTS_DIRS = {
    "e1": REPO_ROOT / "results_e1_final",
    "e2": REPO_ROOT / "results_e2_final",
    "e5": REPO_ROOT / "results_e5_final",
}

# SUMO .net.xml per road type — the real street geometry the traces were
# generated on. Same coordinate frame as the traces (verified via
# convBoundary vs trace extent), so no transform is needed.
ROAD_NET_FILES = {
    "urban": "urban/urban.net.xml",
    "rural": "rural/rural.net.xml",
    "highway": "autobahn/autobahn.net.xml",
}
