#!/usr/bin/env bash
# promote_models.sh — publish trained artifacts into the canonical layout the
# ns-3 C++ AiInferenceEngine (12_main.h) loads at startup:
#
#   models/shared/gat_model.onnx
#   models/<scenario>/lstm_ae_model.onnx
#   models/<scenario>/scaler.json
#   models/<scenario>/theta_ae.txt
#   models/<scenario>/fusion_weights.json
#
# Selection stays in Python (best-beta AE, SLSQP fusion); this only copies the
# chosen winners into place. Non-destructive: originals are left untouched.
#
# For each per-scenario artifact it prefers a scenario-specific file (from
# train_lstm_ae.py, e.g. lstm_ae_urban.onnx) and falls back to the shared flat
# file (from train.py, e.g. lstm_ae_model.onnx). So it works for both the
# single-master plumbing test and the per-scenario paper run.
set -euo pipefail

ML_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELS="${ML_DIR}/models"
SCENARIOS=(urban rural highway)

pick() {  # pick <dst> <candidate1> [candidate2 ...]; copies first existing candidate
    local dst="$1"; shift
    local src
    for src in "$@"; do
        if [[ -f "$src" ]]; then
            if [[ "$src" == "$dst" ]]; then
                echo "  ok   $(basename "$dst")  (already in place)"
                return 0
            fi
            mkdir -p "$(dirname "$dst")"
            cp -f "$src" "$dst"
            echo "  ok   $(basename "$dst")  <-  ${src#"$MODELS"/}"
            return 0
        fi
    done
    echo "  MISS $(basename "$dst")  (none of: ${*#"$MODELS"/})"
    return 1
}

echo "== GAT (shared) =="
pick "${MODELS}/shared/gat_model.onnx" \
     "${MODELS}/shared/gat_model.onnx" "${MODELS}/gat_model.onnx" || true

for scn in "${SCENARIOS[@]}"; do
    echo "== ${scn} =="
    pick "${MODELS}/${scn}/lstm_ae_model.onnx" \
         "${MODELS}/${scn}/lstm_ae_model.onnx" "${MODELS}/lstm_ae_${scn}.onnx" "${MODELS}/lstm_ae_model.onnx" || true
    pick "${MODELS}/${scn}/scaler.json" \
         "${MODELS}/${scn}/scaler.json" "${MODELS}/scaler_${scn}.json" "${MODELS}/scaler.json" || true
    pick "${MODELS}/${scn}/theta_ae.txt" \
         "${MODELS}/${scn}/theta_ae.txt" "${MODELS}/theta_ae_${scn}.txt" "${MODELS}/theta_ae.txt" || true
    pick "${MODELS}/${scn}/fusion_weights.json" \
         "${MODELS}/${scn}/fusion_weights.json" "${MODELS}/fusion_weights_${scn}.json" "${MODELS}/fusion_weights.json" || true
done

echo "== promoted layout =="
find "${MODELS}/shared" "${MODELS}"/{urban,rural,highway} -maxdepth 1 -type f 2>/dev/null | sort
