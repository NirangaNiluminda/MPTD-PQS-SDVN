"""Parse the end-of-run ATTACK SUMMARY block a completed sim prints to stdout.

Source: scratch/mptd_pqs_sdvn/10_metrics_csv.h's print_mptd_metrics() (the
same function that writes metrics.csv, printed to the console as well). This
module reads the printed text rather than metrics.csv because three of the
fields the demo wants (COO, BWO, TCL cost breakdowns; IPFS window/hash
counts) are not columns in metrics.csv — they only appear in this text.

IMPORTANT — the IPFS numbers here are NOT proof of real decentralized
storage. 04_state_globals.h:391 documents this explicitly: "Simulation
stub: no real IPFS daemon; we log [IPFS-STORE-RSUx] ... lines and increment
counters. The hash is a deterministic FNV-1a digest ... Swap to OpenSSL
EVP_sha3_256 for published runs." Confirmed in the capture log itself:

    [IPFS] add failed (curl=7 http=0 ep=http://127.0.0.1:5002) —
    falling back to FNV-1a for h(b_i(t)). Start daemon with `ipfs daemon`
    and re-run to use real CIDs.

So every `hash=ipfs_XXXXXXXX` in this run is the deterministic fallback, not
a content-addressed CID. Any UI built on this data must say so — the ground
rule (CLAUDE.md, DEMO_UI_PLAN) is never imply more than what was measured.
"""

import re
from dataclasses import dataclass


@dataclass
class CryptoOffchainSummary:
    ipfs_windows: int | None
    ipfs_hashes: int | None
    ipfs_is_real: bool  # False here: this run fell back to the FNV-1a stub
    coo_epoch_ms: float | None
    coo_trs_ms: float | None
    coo_fhe_ms: float | None
    coo_epochs_sampled: int | None
    coo_dkg_ms: float | None
    bwo_ratio: float | None
    bwo_hmac_bytes: int | None
    bwo_fhe_bytes: int | None
    bwo_trs_bytes: int | None
    bwo_rekey_bytes: int | None
    bwo_base_bytes: int | None
    tcl_confirm_ms: float | None
    tcl_confirm_invokes: int | None
    tcl_reassign_ms: float | None
    tcl_reassign_rollovers: int | None
    trs_verify_ok: int | None
    trs_verify_fail: int | None
    ttd_s: float | None
    cp_detect_alerts: int | None
    cp_detect_epochs_audited: int | None


_PATTERNS = {
    "ipfs": re.compile(
        r"^\s*IPFS\s*=\s*(?P<windows>\d+) windows off-chain, (?P<hashes>\d+) hashes on-chain"
    ),
    "coo": re.compile(
        r"^\s*COO\s*=\s*epoch (?P<epoch>[\d.]+) ms \(TRS (?P<trs>[\d.]+) \+ FHE (?P<fhe>[\d.]+) "
        r"over (?P<epochs>\d+) epochs\), DKG (?P<dkg>[\d.]+) ms"
    ),
    "bwo": re.compile(
        r"^\s*BWO\s*=\s*ratio (?P<ratio>[\d.]+) \(hmac=(?P<hmac>\d+)B fhe=(?P<fhe>\d+)B "
        r"trs=(?P<trs>\d+)B rekey=(?P<rekey>\d+)B / base=(?P<base>\d+)B\)"
    ),
    "tcl": re.compile(
        r"^\s*TCL\s*=\s*confirm (?P<confirm>[\d.]+) ms \((?P<invokes>\d+) invokes\), "
        r"reassign (?P<reassign>[\d.]+) ms \((?P<rollovers>\d+) rollovers\)"
    ),
    "trs_verify": re.compile(
        r"^\s*TRS-verify:\s*(?P<ok>\d+) ok / (?P<fail>\d+) fail"
    ),
    "ttd": re.compile(r"^\s*TTD\s*=\s*(?P<ttd>[\d.]+) s"),
    "cp_detect": re.compile(
        r"^\s*CP-DETECT\s*=\s*(?P<alerts>\d+) CTRL_COMPROMISED alerts .* "
        r"over (?P<epochs>\d+) audited epochs"
    ),
}


def parse_run_summary(log_text: str) -> CryptoOffchainSummary:
    """Scans the WHOLE log text for the last occurrence of each summary line
    (a log may contain output from more than one run appended together;
    the final ATTACK SUMMARY block is the one that reflects the full run)."""
    found: dict[str, re.Match] = {}
    for line in log_text.splitlines():
        for key, pat in _PATTERNS.items():
            m = pat.match(line)
            if m:
                found[key] = m  # overwrite -> keep the LAST match

    def g(key: str, group: str, cast=float):
        m = found.get(key)
        return cast(m.group(group)) if m else None

    return CryptoOffchainSummary(
        ipfs_windows=g("ipfs", "windows", int),
        ipfs_hashes=g("ipfs", "hashes", int),
        ipfs_is_real=False,
        coo_epoch_ms=g("coo", "epoch"),
        coo_trs_ms=g("coo", "trs"),
        coo_fhe_ms=g("coo", "fhe"),
        coo_epochs_sampled=g("coo", "epochs", int),
        coo_dkg_ms=g("coo", "dkg"),
        bwo_ratio=g("bwo", "ratio"),
        bwo_hmac_bytes=g("bwo", "hmac", int),
        bwo_fhe_bytes=g("bwo", "fhe", int),
        bwo_trs_bytes=g("bwo", "trs", int),
        bwo_rekey_bytes=g("bwo", "rekey", int),
        bwo_base_bytes=g("bwo", "base", int),
        tcl_confirm_ms=g("tcl", "confirm"),
        tcl_confirm_invokes=g("tcl", "invokes", int),
        tcl_reassign_ms=g("tcl", "reassign"),
        tcl_reassign_rollovers=g("tcl", "rollovers", int),
        trs_verify_ok=g("trs_verify", "ok", int),
        trs_verify_fail=g("trs_verify", "fail", int),
        ttd_s=g("ttd", "ttd"),
        cp_detect_alerts=g("cp_detect", "alerts", int),
        cp_detect_epochs_audited=g("cp_detect", "epochs", int),
    )
