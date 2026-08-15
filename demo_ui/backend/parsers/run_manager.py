"""Launch, track, and stream real simulation runs from the UI.

This is the one part of the demo that runs LIVE ns-3 code rather than
replaying a recording — so it inherits every trap RUN_CONFIG.md documents.
Every flag this module emits is hardcoded to the safe value; nothing here
lets a caller accidentally reproduce those traps through the API.

Timing constants below are MEASURED, not estimated (see
project-sim-wallclock-40x / project-demo-ui-capture-run in the assistant's
memory, and this session's own capture run):
  - simulation wall-clock: ~40x slowdown (600s wall -> 14.8s sim, timed
    2026-08-14 on this exact box)
  - blockchain registration: ~12 min for 264 identities (64 RSU + 200
    vehicle + 4 controller) = ~2.7s/identity, timed 2026-08-15
Both drift with box load — they are ETA estimates, not guarantees, and are
labelled as such in every API response that uses them.
"""

import json
import os
import re
import signal
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import config

SIM_SLOWDOWN_FACTOR = 40.5  # wall-seconds per sim-second, measured
SEC_PER_REGISTRATION = 2.7  # wall-seconds per SC-Register call, measured
DEFAULT_N_CONTROLLERS = 4


@dataclass
class RunConfig:
    attack_number: int = 0  # 0 = combined, 1-7 = single variant
    attack_pct: int = 40
    sim_time: float = 30.0  # kept short by default — this box runs live demos, not sweeps
    mobility_scenario: int = 0  # 0=urban, 1=rural, 2=highway
    n_vehicles: int = 200
    n_rsus: int = 64
    enable_gat: bool = True
    enable_lstm_ae: bool = True
    enable_blockchain: bool = False
    seed: int = 1


@dataclass
class RunRecord:
    run_id: str
    pid: int
    cmd: list[str]
    log_path: str
    config: dict
    started_at: float
    model_check: dict


def verify_deployed_model() -> dict:
    """CLAUDE.md: 'Deployed model must stay reverted' — the Fix-A swap once
    collapsed MCC to 0.036. Checked before every UI-launched run."""
    link = config.GAT_MODEL_DIR / "gat_model.onnx"
    theta_s_file = config.GAT_MODEL_DIR / "theta_s.txt"
    theta_ae_file = config.GAT_MODEL_DIR / "theta_ae.txt"

    link_target = os.readlink(link) if link.is_symlink() else None
    theta_s = theta_s_file.read_text().strip() if theta_s_file.is_file() else None
    theta_ae = theta_ae_file.read_text().strip() if theta_ae_file.is_file() else None

    link_ok = link_target == config.EXPECTED_GAT_LINK_TARGET
    theta_s_ok = theta_s == str(config.EXPECTED_THETA_S)
    theta_ae_ok = theta_ae == str(config.EXPECTED_THETA_AE)

    return {
        "ok": link_ok and theta_s_ok and theta_ae_ok,
        "gat_model_link": {"actual": link_target, "expected": config.EXPECTED_GAT_LINK_TARGET, "ok": link_ok},
        "theta_s": {"actual": theta_s, "expected": str(config.EXPECTED_THETA_S), "ok": theta_s_ok},
        "theta_ae": {"actual": theta_ae, "expected": str(config.EXPECTED_THETA_AE), "ok": theta_ae_ok},
    }


def resolve_args(rc: RunConfig, run_id: str) -> list[str]:
    """Every flag here is fixed at its documented-safe value — see
    RUN_CONFIG.md's traps table. The caller cannot override routing_test,
    ablation_mode, gat_det_flag_heads, or the routing_algorithm/
    skip_blockchain pairing through this function; those are exactly the
    flags that have silently invalidated runs before.
    """
    args = [
        str(config.SIM_BINARY),
        "--mobility_source=1",
        f"--mobility_scenario={rc.mobility_scenario}",
        "--maxspeed=60",
        f"--N_Vehicles={rc.n_vehicles}",
        f"--N_RSUs={rc.n_rsus}",
        f"--attack_number={rc.attack_number}",
        f"--attack_percentage={rc.attack_pct}",
        f"--simTime={rc.sim_time}",
        "--ablation_mode=0",
        "--routing_test=false",
        f"--enable_gat={1 if rc.enable_gat else 0}",
        f"--enable_lstm_ae={1 if rc.enable_lstm_ae else 0}",
        f"--seed={rc.seed}",
        "--per_pid_results=1",
        "--per_rsu_vehicle_state=1",
        "--ring_detect=1",
        "--gat_det_flag_heads=0",
        "--psi_cond_floor=1",
    ]
    # routing_algorithm=4 and skip_blockchain=false must always travel
    # together — the first is a no-op-producing trap without the second
    # (RUN_CONFIG.md, found 2026-08-15: skip_blockchain=false alone silently
    # does nothing because the check is nested inside routing_algorithm==4).
    if rc.enable_blockchain:
        args += ["--skip_blockchain=false", "--routing_algorithm=4"]
    else:
        args += ["--skip_blockchain=true"]
    return args


def launch_run(rc: RunConfig, force: bool = False) -> RunRecord:
    model_check = verify_deployed_model()
    if not model_check["ok"] and not force:
        raise ValueError(f"deployed model verification failed: {model_check}")

    run_id = f"{int(time.time())}_{uuid.uuid4().hex[:6]}"
    config.RUN_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = config.RUN_LOGS_DIR / f"{run_id}.log"

    args = resolve_args(rc, run_id)
    # stdbuf -oL forces line-buffered stdout. Without it, progress parsing
    # reads a stale prefix for minutes at a time — confirmed directly in
    # this session (the ledger showed 62 RSUs registered while a block-
    # buffered log still showed 58, ~80 lines of buffering lag).
    full_cmd = ["stdbuf", "-oL", "-eL"] + args

    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(config.NS3_ROOT / "build" / "lib")

    log_fh = open(log_path, "wb")
    proc = subprocess.Popen(
        full_cmd,
        cwd=str(config.NS3_ROOT),
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # own process group, so stop_run can't hit anything else
    )
    log_fh.close()  # the child holds its own fd to the file; safe to close ours

    record = RunRecord(
        run_id=run_id,
        pid=proc.pid,
        cmd=full_cmd,
        log_path=str(log_path),
        config=asdict(rc),
        started_at=time.time(),
        model_check=model_check,
    )
    _save_record(record)
    return record


def _manifest() -> dict:
    if config.RUN_MANIFEST.is_file():
        try:
            return json.loads(config.RUN_MANIFEST.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_record(record: RunRecord):
    m = _manifest()
    m[record.run_id] = asdict(record)
    config.RUN_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    config.RUN_MANIFEST.write_text(json.dumps(m, indent=2))


def _reap_children(*_args):
    """SIGCHLD handler — reap every finished child immediately.

    Without this, a stopped/finished run's process becomes a zombie: it has
    genuinely exited, but nothing ever calls wait() on it (this module
    tracks PIDs across HTTP requests via the JSON manifest, not a live
    Popen handle), so it lingers in the process table. Confirmed directly:
    after stop_run() sent SIGTERM, `ps` showed the target PID as
    "[mptd_pqs_sdvn] <defunct>" — genuinely dead — while os.kill(pid, 0)
    kept succeeding because that call only checks process-table presence,
    which a zombie still has. Every run would have shown "alive: true"
    forever, for as long as this backend process stayed up.
    """
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
        except ChildProcessError:
            break


signal.signal(signal.SIGCHLD, _reap_children)


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def list_runs() -> list[dict]:
    m = _manifest()
    out = []
    for run_id, rec in sorted(m.items(), key=lambda kv: kv[1]["started_at"], reverse=True):
        out.append({**rec, "alive": _is_alive(rec["pid"])})
    return out


def get_run(run_id: str) -> dict | None:
    m = _manifest()
    rec = m.get(run_id)
    if rec is None:
        return None
    return {**rec, "alive": _is_alive(rec["pid"])}


def stop_run(run_id: str) -> bool:
    """SIGTERM the tracked PID (never a pattern match — RUN_CONFIG.md notes
    pkill -f matches your own shell; this only ever signals a PID this
    module itself recorded at launch)."""
    rec = get_run(run_id)
    if rec is None or not rec["alive"]:
        return False
    try:
        os.killpg(os.getpgid(rec["pid"]), signal.SIGTERM)
    except ProcessLookupError:
        return False
    return True


# ── Progress parsing ─────────────────────────────────────────────────────

_SC_REGISTER_RE = re.compile(r"\[SC-REGISTER\]")
_REGISTER_DONE_RE = re.compile(r"\[SC-REGISTER\] boot-time registration complete")
# The source (07_socket_layer.h:446) streams a raw double with no fixed
# format: cout << "[SIM] t=" << Simulator::Now().GetSeconds() << "s". C++
# stream precision/fixed flags are sticky and get changed elsewhere in the
# same run, so the SAME line prints as bare "t=7s" early on and "t=18.0s"
# later in one observed log. Confirmed directly (grep -n on a real run) —
# an integer-only regex silently stopped matching partway through and the
# UI's progress bar froze. Match both.
_SIM_T_RE = re.compile(r"\[SIM\] t=(\d+(?:\.\d+)?)s")
_SUMMARY_RE = re.compile(r"ATTACK SUMMARY")
_MCC_FULL_RE = re.compile(r"MCC_full\s*=\s*([\d.]+)")


# Sticky last-known progress per run. NECESSARY, not defensive fluff: a
# 200-vehicle run was measured producing a [SIM] t=Ns heartbeat only every
# ~400KB (thousands of per-beacon debug lines between each one). Any fixed
# tail-read window can be outrun by log volume in a denser config (combined
# mode, more vehicles) — when that happens the regex simply finds nothing
# in the window and progress must not visibly snap back to "starting" for
# a run that has already reached, say, 60%. Confirmed this regression
# directly: a real run went pct=30 -> phase="starting" pct=0 mid-poll.
_last_progress: dict[str, dict] = {}


def parse_progress(log_tail: str, rc: dict, run_id: str | None = None) -> dict:
    sim_time = float(rc["sim_time"])
    blockchain = bool(rc["enable_blockchain"])
    prior = _last_progress.get(run_id) if run_id else None

    def remember(result: dict) -> dict:
        if run_id:
            _last_progress[run_id] = result
        return result

    if _SUMMARY_RE.search(log_tail):
        mcc_m = _MCC_FULL_RE.search(log_tail)
        return remember({
            "phase": "finished",
            "pct": 100,
            "eta_seconds": 0,
            "mcc_full": float(mcc_m.group(1)) if mcc_m else None,
        })

    sim_matches = _SIM_T_RE.findall(log_tail)
    if sim_matches:
        t_reached = float(sim_matches[-1])  # int() would raise on "18.0" — see the regex comment above
        # Monotonic: a later poll's tail window could in principle only
        # contain an OLDER heartbeat than one already seen (never a real
        # regression, just window placement), so never report backwards.
        if prior and prior.get("sim_time_reached") is not None:
            t_reached = max(t_reached, prior["sim_time_reached"])
        pct = min(99, int(100 * t_reached / sim_time)) if sim_time > 0 else 0
        remaining_sim_s = max(sim_time - t_reached, 0)
        eta = remaining_sim_s * SIM_SLOWDOWN_FACTOR
        return remember({"phase": "simulating", "pct": pct, "sim_time_reached": t_reached, "eta_seconds": round(eta)})

    if blockchain:
        n_registered = len(_SC_REGISTER_RE.findall(log_tail))
        if prior and prior.get("registered") is not None:
            n_registered = max(n_registered, prior["registered"])
        expected = int(rc["n_vehicles"]) + int(rc["n_rsus"]) + DEFAULT_N_CONTROLLERS
        if _REGISTER_DONE_RE.search(log_tail):
            # Registration just finished, simulation hasn't printed [SIM] yet.
            return remember({"phase": "simulating", "pct": 1, "eta_seconds": round(sim_time * SIM_SLOWDOWN_FACTOR)})
        pct = min(99, int(100 * n_registered / expected)) if expected else 0
        remaining = max(expected - n_registered, 0)
        eta = remaining * SEC_PER_REGISTRATION + sim_time * SIM_SLOWDOWN_FACTOR
        return remember({
            "phase": "registering",
            "pct": pct,
            "registered": n_registered,
            "expected": expected,
            "eta_seconds": round(eta),
        })

    # No fresh signal in this window. If we've already seen real progress
    # for this run, that is what must be shown — see the block comment
    # above _last_progress for why a fixed tail window can miss a
    # heartbeat entirely in a dense log, and why falling back to
    # "starting" here would be a visible, false regression.
    if prior and prior["phase"] != "starting":
        return remember({**prior, "stale": True})

    return remember({"phase": "starting", "pct": 0, "eta_seconds": round(sim_time * SIM_SLOWDOWN_FACTOR)})
