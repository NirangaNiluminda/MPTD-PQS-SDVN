#!/bin/bash
# Post-sim IPFS MFS mirror — browse beacon evidence in the IPFS WebUI Files tab.
#
# Reads every recursive pin (the alert-path beacon hashes written by
# mptd_ipfs_add at 06c_blockchain_api.h), parses the pipe-delimited blob
# (vehicleID|posX,posY,posZ|velX,velY,velZ|accX,accY,accZ|timestamp), and
# attaches an MFS reference under /beacons/v<vid>/t<ts>_<short-cid>.txt.
#
# Runs AFTER the NS-3 sim exits. Zero impact on PBPO_LW / PBPO_Full or any
# of the 7 metrics — the sim process is untouched.
#
# Usage:
#   ./scratch/mptd_pqs_sdvn/tools/ipfs_mfs_mirror.sh
#
# Env overrides:
#   IPFS_BIN  : path to ipfs CLI                    (default: ipfs)
#   MFS_ROOT  : MFS directory under /               (default: /beacons)

IPFS_BIN="${IPFS_BIN:-ipfs}"
MFS_ROOT="${MFS_ROOT:-/beacons}"

if ! command -v "$IPFS_BIN" >/dev/null 2>&1; then
    echo "[ipfs-mirror] ERROR: $IPFS_BIN not on PATH" >&2
    exit 1
fi

if ! "$IPFS_BIN" id >/dev/null 2>&1; then
    echo "[ipfs-mirror] ERROR: IPFS daemon not reachable (start with: ipfs daemon)" >&2
    exit 1
fi

"$IPFS_BIN" files mkdir -p "$MFS_ROOT" 2>/dev/null || true

count_new=0
count_skip=0
count_nonbeacon=0
count_fail=0

while read -r cid _; do
    [ -z "$cid" ] && continue

    blob=$(timeout 3 "$IPFS_BIN" cat "$cid" 2>/dev/null)
    if [ -z "$blob" ]; then
        count_fail=$((count_fail+1))
        continue
    fi

    # parse: vehicleID|posX,posY,posZ|velX,velY,velZ|accX,accY,accZ|timestamp
    IFS='|' read -r vid _pos _vel _acc ts <<< "$blob"

    if [[ -z "$vid" || -z "$ts" || ! "$vid" =~ ^[0-9]+$ ]]; then
        count_nonbeacon=$((count_nonbeacon+1))
        continue
    fi

    veh_dir="$MFS_ROOT/v${vid}"
    "$IPFS_BIN" files mkdir -p "$veh_dir" 2>/dev/null || true

    short_cid="${cid:0:12}"
    fname="$veh_dir/t${ts}_${short_cid}.txt"

    if "$IPFS_BIN" files stat "$fname" >/dev/null 2>&1; then
        count_skip=$((count_skip+1))
        continue
    fi

    if "$IPFS_BIN" files cp "/ipfs/$cid" "$fname" 2>/dev/null; then
        count_new=$((count_new+1))
    else
        count_fail=$((count_fail+1))
    fi
done < <("$IPFS_BIN" pin ls --type=recursive --quiet 2>/dev/null)

echo "[ipfs-mirror] new: $count_new   already-mirrored: $count_skip   non-beacon: $count_nonbeacon   failed: $count_fail"
echo "[ipfs-mirror] browse: http://127.0.0.1:5002/webui/  →  Files tab  →  $MFS_ROOT/"
