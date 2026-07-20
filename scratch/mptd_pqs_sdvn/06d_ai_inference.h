// ============================================================
// 06d_ai_inference.h — ONNX Runtime C++ wrapper for GAT + LSTM-AE
// MPTD-PQS SDVN, R7d
// ============================================================
// Paper §3.5.3 (Eq 3.38–3.45) Full-mode AI pipeline.
//
// What this module does
//   Loads the two .onnx artifacts produced by analytics/ml/train.py:
//     • gat_model.onnx     — Graph Attention Net, 6-dim per-vehicle features,
//                             returns per-vehicle anomaly logit (N, 1)
//     • lstm_ae_model.onnx — Temporal autoencoder over a 10-beacon sliding
//                             window of 6-dim features [5 kinematic + tau_i],
//                             returns reconstruction (B, 10, 6); anomaly = ||x − x_hat||²
//   …plus the StandardScaler params (analytics/ml/models/scaler.json) and the
//   LSTM-AE detection threshold θ_ae (analytics/ml/models/theta_ae.txt).
//
// Why a single class, not a free function
//   Ort::Env and Ort::Session are heavyweight and must outlive every call.
//   AiInferenceEngine owns them; init() runs once during simulation setup,
//   destruction happens at process exit. Subsequent score_*() calls are
//   thread-safe lock-free reads of the immutable session.
//
// Where this gets called from
//   08_detection_engine.h's controller-window rollover hook (around line 1295).
//   At each W = L·T_b window close, the detector hands the accumulated kinematic
//   snapshot to score_gat() to obtain per-vehicle spatial anomaly logits, and
//   (in R7e+) consults the per-vehicle LSTM-AE ring buffer for temporal scores.
//   Fusion + decision (Eq 3.46) is R7e — for R7d we only log the raw scores.
//
// Build deps
//   • -I$HOME/.local/include  (onnxruntime_cxx_api.h)
//   • -L$HOME/.local/lib -lonnxruntime
//   • -Wl,-rpath,$HOME/.local/lib  (so the binary finds libonnxruntime.so.1)
//   The wscript in this scratch dir already wires all three.
//
// Ablation hooks (R7f)
//   • Variant A2 (GAT only, no LSTM-AE): leave lstm_ae_session_=nullptr;
//     score_lstm_ae() returns 0.0 and never trips the fusion gate.
//   • Variant A3 (LSTM-AE only, no GAT): leave gat_session_=nullptr;
//     score_gat() returns zeros and the controller falls back to LSTM-AE only.
//   • Variant A1 (Lightweight only): don't construct AiInferenceEngine at all.
//   These selectors live on g_enable_gat / g_enable_lstm_ae globals introduced
//   in R7f; for now both default to true (Full-mode baseline).
//
// Paper invariants preserved
//   • Inv #3 (LW skip-on-pass): inference fires only at window close, not per
//     beacon — RSU lightweight path never depends on this module.
//   • Inv #4 (Full adds, never replaces): scores produced here flow into the
//     fusion layer (R7e); RSU LW-DETECT keeps running unchanged.
// ============================================================

#ifndef MPTD_PQS_06D_AI_INFERENCE_H
#define MPTD_PQS_06D_AI_INFERENCE_H

#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

struct FusionParams {
    static constexpr int K_ATTACK = 7;   // attack classes (Experiment 5 threat model)

    float lambda_psi   = 0.3f;   // λ₁  (always active — LW-DETECT is the base)
    float lambda_gat   = 0.4f;   // λ₂
    float lambda_ae    = 0.3f;   // λ₃
    float phi_threshold = 0.5f;  // Φ_th
    bool  use_gat      = true;
    bool  use_ae       = true;

    // Attack-conditioned fusion weights (revised eq:fusion). Index k∈[0,K-1] is
    // the predicted attack type k̂_i (GAT argmax). When the weights JSON carries
    // per-attack "lambda_sets", per_attack=true and fuse_scores() selects the
    // set matching k̂_i; otherwise every set mirrors the global λ so behaviour is
    // identical to the pre-patch single-weight fusion.
    float lam_psi_k[K_ATTACK] = {0.3f,0.3f,0.3f,0.3f,0.3f,0.3f,0.3f};
    float lam_gat_k[K_ATTACK] = {0.4f,0.4f,0.4f,0.4f,0.4f,0.4f,0.4f};
    float lam_ae_k [K_ATTACK] = {0.3f,0.3f,0.3f,0.3f,0.3f,0.3f,0.3f};
    bool  per_attack = false;

    // sir Change 1: attack-conditioned signature reliability weights w_s^(k) over
    // the 9 LW signatures. In FULL mode ψ_i = Σ_s w_s^(k̂)·bit_s(sig_mask); k̂_i is
    // the GAT argmax. sig_w_global is the aggregate (lightweight / low-confidence
    // fallback). Default = current global SIG_WEIGHTS so behaviour is unchanged
    // until the JSON supplies "sig_weight_sets".
    static constexpr int N_SIG = 9;
    float sig_w_k[K_ATTACK][N_SIG] = {
        {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f},
        {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f},
        {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f},
        {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f},
        {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f},
        {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f},
        {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f}};
    float sig_w_global[N_SIG] = {0.15f,0.10f,0.10f,0.15f,0.15f,0.15f,0.05f,0.10f,0.05f};
    bool  has_sig_weights = false;
    // Change 2: GAT confidence gate. Commit to k̂'s weight sets only when
    // max_k ŷ^(k) ≥ theta_conf; else fall back to global w + average λ (k̂=-1).
    float theta_conf = 0.5f;
};

inline FusionParams g_fusion = FusionParams{};

// Minimal JSON parser for {"lambda_psi": 0.05, "lambda_gat": 0.7168, "lambda_ae": 0.2332, "phi_threshold": 0.5}
static inline bool load_fusion_weights_json(const std::string &path, FusionParams &out) {
    std::ifstream f(path);
    if (!f) return false;
    std::stringstream ss; ss << f.rdbuf();
    const std::string blob = ss.str();

    auto extract_float = [&](const std::string &key, float &dst) -> bool {
        const std::string needle = "\"" + key + "\"";
        size_t k = blob.find(needle);
        if (k == std::string::npos) return false;
        size_t colon = blob.find(':', k);
        if (colon == std::string::npos) return false;
        size_t start = blob.find_first_not_of(" \t\r\n", colon + 1);
        if (start == std::string::npos) return false;
        size_t end = blob.find_first_of(",}\r\n", start);
        if (end == std::string::npos) end = blob.size();
        std::string val_str = blob.substr(start, end - start);
        try {
            dst = std::stof(val_str);
            return true;
        } catch (...) {
            return false;
        }
    };

    float lp = 0.0f, lg = 0.0f, la = 0.0f, pt = 0.0f;
    if (!extract_float("lambda_psi", lp)) return false;
    if (!extract_float("lambda_gat", lg)) return false;
    if (!extract_float("lambda_ae", la)) return false;
    if (!extract_float("phi_threshold", pt)) return false;

    out.lambda_psi = lp;
    out.lambda_gat = lg;
    out.lambda_ae = la;
    out.phi_threshold = pt;

    // Default: every attack-conditioned set mirrors the global λ (pre-patch
    // behaviour). Overwritten below if the JSON supplies "lambda_sets".
    for (int k = 0; k < FusionParams::K_ATTACK; ++k) {
        out.lam_psi_k[k] = lp;
        out.lam_gat_k[k] = lg;
        out.lam_ae_k[k]  = la;
    }
    out.per_attack = false;

    // Optional per-attack weights (revised eq:fusion):
    //   "lambda_sets": [ {"psi":..,"gat":..,"ae":..}, ... K entries .. ]
    // ordered by attack class 1..K (index 0..K-1). Parsed sequentially so the
    // dumb key-search finds each object's psi/gat/ae in emission order.
    auto extract_float_after = [&](const std::string &key, size_t &cursor,
                                   size_t stop, float &dst) -> bool {
        const std::string needle = "\"" + key + "\"";
        size_t k = blob.find(needle, cursor);
        if (k == std::string::npos || k >= stop) return false;
        size_t colon = blob.find(':', k);
        if (colon == std::string::npos || colon >= stop) return false;
        size_t start = blob.find_first_not_of(" \t\r\n", colon + 1);
        if (start == std::string::npos) return false;
        size_t end = blob.find_first_of(",}]\r\n", start);
        if (end == std::string::npos) end = blob.size();
        try { dst = std::stof(blob.substr(start, end - start)); }
        catch (...) { return false; }
        cursor = end;
        return true;
    };
    size_t sets_key = blob.find("\"lambda_sets\"");
    if (sets_key != std::string::npos) {
        size_t arr_beg = blob.find('[', sets_key);
        size_t arr_end = (arr_beg != std::string::npos) ? blob.find(']', arr_beg)
                                                        : std::string::npos;
        if (arr_beg != std::string::npos && arr_end != std::string::npos) {
            size_t cur = arr_beg;
            int parsed = 0;
            for (int k = 0; k < FusionParams::K_ATTACK; ++k) {
                float p, g, a;
                if (!extract_float_after("psi", cur, arr_end, p)) break;
                if (!extract_float_after("gat", cur, arr_end, g)) break;
                if (!extract_float_after("ae",  cur, arr_end, a)) break;
                out.lam_psi_k[k] = p;
                out.lam_gat_k[k] = g;
                out.lam_ae_k[k]  = a;
                ++parsed;
            }
            out.per_attack = (parsed == FusionParams::K_ATTACK);
        }
    }

    // sir Change 2: confidence gate θ_conf (optional; default keeps 0.5).
    { float tc; if (extract_float("theta_conf", tc)) out.theta_conf = tc; }

    // sir Change 1: signature weight sets. "sig_weight_global": [w0..w8] and
    // "sig_weight_sets": [ {"attack":k, "w":[w0..w8]}, ...K ]. Parsed by walking
    // the numeric array elements after each key (dumb but robust to spacing).
    auto parse_num_array = [&](size_t &cur, size_t stop, float *dst, int n) -> int {
        size_t br = blob.find('[', cur);
        if (br == std::string::npos || br >= stop) return 0;
        size_t end = blob.find(']', br);
        if (end == std::string::npos) end = stop;
        size_t p = br + 1; int got = 0;
        while (got < n && p < end) {
            size_t s = blob.find_first_not_of(" \t\r\n,", p);
            if (s == std::string::npos || s >= end) break;
            size_t e = blob.find_first_of(",]\r\n \t", s);
            if (e == std::string::npos || e > end) e = end;
            try { dst[got++] = std::stof(blob.substr(s, e - s)); } catch (...) { break; }
            p = e;
        }
        cur = end;
        return got;
    };
    { size_t g = blob.find("\"sig_weight_global\"");
      if (g != std::string::npos) { size_t c = g; parse_num_array(c, blob.size(), out.sig_w_global, FusionParams::N_SIG); } }
    size_t sw_key = blob.find("\"sig_weight_sets\"");
    if (sw_key != std::string::npos) {
        size_t arr_beg = blob.find('[', sw_key);
        // outer array end = matching ']' of the LAST inner set; use the key's
        // section up to the next top-level key or end.
        size_t sec_end = blob.find("\"sig_weight_global\"", sw_key);
        if (sec_end == std::string::npos) sec_end = blob.size();
        int nset = 0; size_t cur = (arr_beg != std::string::npos) ? arr_beg + 1 : sw_key;
        for (int k = 0; k < FusionParams::K_ATTACK; ++k) {
            size_t wk = blob.find("\"w\"", cur);
            if (wk == std::string::npos || wk >= sec_end) break;
            size_t c = wk;
            if (parse_num_array(c, sec_end, out.sig_w_k[k], FusionParams::N_SIG) == FusionParams::N_SIG) {
                cur = c; ++nset;
            } else break;
        }
        out.has_sig_weights = (nset == FusionParams::K_ATTACK);
    }
    return true;
}

#if __has_include(<onnxruntime_cxx_api.h>)
#include <onnxruntime_cxx_api.h>

// ────────────────────────────────────────────────────────────────────────────
// Constants — must match analytics/ml/gat_detector.py + lstm_ae.py
// ────────────────────────────────────────────────────────────────────────────
namespace mptd_ai {

constexpr int    KINEMATIC_DIM   = 5;          // raw kinematic features: pos_x, pos_y, speed, heading, accel
constexpr int    GAT_SIG_BITS    = 9;          // sig_mask width (must match gat_detector.py SIG_BITS)
// Richer GAT node features (must match gat_detector.py FEATURE_DIM):
//   [5 kinematic (scaled), tau (raw), psi (raw), sig_mask bits 0..8 (raw 0/1)] = 16
constexpr int    GAT_FEATURE_DIM = 7 + GAT_SIG_BITS;   // = 16
constexpr int    LSTM_FEATURE_DIM = 6;         // 5 kinematic + tau_i — all 6 z-scaled (paper Table set-fullmode-ai, d=6)
constexpr int    LSTM_WINDOW_SIZE = 10;        // beacons per temporal window (trained arch_{urban,rural,highway}.json all window=10)
constexpr double R_MAX_GRAPH   = 300.0;        // metres — gat_detector.py R_MAX
constexpr double PHI_MAX_GRAPH = 1.5707963267948966; // π/2 rad — gat_detector.py PHI_MAX
constexpr float  TAU_DEFAULT   = 1.0f;         // SC-Trust default when not queried
constexpr float  GAT_HEAD_DETECT_THRESH = 0.5f; // per-head sigmoid threshold for flag_i^GAT (revised eq:gat_det_flag)

} // namespace mptd_ai

// ────────────────────────────────────────────────────────────────────────────
// Per-feature StandardScaler params loaded from analytics/ml/models/scaler.json.
// Trivially-copyable struct so threads can share it lock-free.
// ────────────────────────────────────────────────────────────────────────────
struct AiScaler {
    float mean [mptd_ai::LSTM_FEATURE_DIM] = {0,0,0,0,0,0};
    float scale[mptd_ai::LSTM_FEATURE_DIM] = {1,1,1,1,1,1};
    bool  loaded = false;

    // Apply per-feature z-score normalization in place. Caller passes a buffer
    // of length n_rows * LSTM_FEATURE_DIM in row-major order [row0:f0..f5, row1:...].
    // The 6th column is tau_i; the trained scaler has tau mean=1.0 scale=1.0, so
    // a trusted vehicle (tau=1.0) maps to 0.0 — exactly what the AE saw in training.
    void apply(float *buf, int n_rows) const {
        if (!loaded) return;
        for (int r = 0; r < n_rows; ++r) {
            for (int f = 0; f < mptd_ai::LSTM_FEATURE_DIM; ++f) {
                buf[r * mptd_ai::LSTM_FEATURE_DIM + f] =
                    (buf[r * mptd_ai::LSTM_FEATURE_DIM + f] - mean[f])
                    / (scale[f] == 0.0f ? 1.0f : scale[f]);
            }
        }
    }
};

// Minimal JSON parser for {"mean":[a,b,c,d,e],"scale":[a,b,c,d,e],...}.
// Files we read are produced by train.py::export_scaler_json so the layout is
// fixed; avoiding a third-party JSON dep keeps the build simple.
static inline bool load_scaler_json(const std::string &path, AiScaler &out) {
    std::ifstream f(path);
    if (!f) return false;
    std::stringstream ss; ss << f.rdbuf();
    const std::string blob = ss.str();

    auto extract_array = [&](const std::string &key, float *dst, int n) -> bool {
        const std::string needle = "\"" + key + "\"";
        size_t k = blob.find(needle);
        if (k == std::string::npos) return false;
        size_t lb = blob.find('[', k);
        size_t rb = blob.find(']', lb);
        if (lb == std::string::npos || rb == std::string::npos) return false;
        std::string nums = blob.substr(lb + 1, rb - lb - 1);
        std::stringstream ns(nums);
        for (int i = 0; i < n; ++i) {
            std::string tok;
            if (!std::getline(ns, tok, ',') && i < n - 1) return false;
            try { dst[i] = std::stof(tok); } catch (...) { return false; }
        }
        return true;
    };

    if (!extract_array("mean",  out.mean,  mptd_ai::LSTM_FEATURE_DIM)) return false;
    if (!extract_array("scale", out.scale, mptd_ai::LSTM_FEATURE_DIM)) return false;
    out.loaded = true;
    return true;
}


// ────────────────────────────────────────────────────────────────────────────
// AiInferenceEngine — owns Ort::Env + Ort::Sessions for GAT and LSTM-AE.
// Lifetime: constructed once via global g_ai_engine.init(...) in 12_main.h,
// destroyed at simulation end.
// ────────────────────────────────────────────────────────────────────────────
class AiInferenceEngine {
public:
    AiInferenceEngine() : env_(ORT_LOGGING_LEVEL_WARNING, "mptd_pqs") {}

    // Returns true if at least one of the two sessions is live. Caller can then
    // check has_gat() / has_lstm_ae() to dispatch ablation variants.
    bool init(const std::string &gat_path,
              const std::string &lstm_ae_path,
              const std::string &scaler_path,
              const std::string &theta_path,
              const std::string &weights_path = "") {
        Ort::SessionOptions opts;
        opts.SetIntraOpNumThreads(1);              // determinism for PBPO timing
        opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_BASIC);

        // GAT session — may be absent if R7f --enable_gat=false.
        if (!gat_path.empty()) {
            try {
                gat_session_ = std::make_unique<Ort::Session>(env_, gat_path.c_str(), opts);
                std::cout << "[AI-INIT] GAT session loaded: " << gat_path << std::endl;
            } catch (const Ort::Exception &e) {
                std::cerr << "[AI-INIT] GAT load failed: " << e.what() << std::endl;
                gat_session_.reset();
            }
        }

        // LSTM-AE session — may be absent if R7f --enable_lstm_ae=false.
        if (!lstm_ae_path.empty()) {
            try {
                lstm_session_ = std::make_unique<Ort::Session>(env_, lstm_ae_path.c_str(), opts);
                // Set the runtime AE window from the model's own input shape
                // [1, window, 6] so C++ feeds exactly what the model expects
                // (urban=50 after sir Step 4, rural/highway=10). Falls back to the
                // default (10) if the dim is dynamic/unknown.
                try {
                    auto shp = lstm_session_->GetInputTypeInfo(0)
                                   .GetTensorTypeAndShapeInfo().GetShape();
                    if (shp.size() >= 2 && shp[1] > 0 && shp[1] <= LSTM_RING_SIZE)
                        g_lstm_window = (int)shp[1];
                } catch (...) {}
                std::cout << "[AI-INIT] LSTM-AE session loaded: " << lstm_ae_path
                          << "  (window=" << g_lstm_window << ")" << std::endl;
            } catch (const Ort::Exception &e) {
                std::cerr << "[AI-INIT] LSTM-AE load failed: " << e.what() << std::endl;
                lstm_session_.reset();
            }
        }

        // Scaler — required for LSTM-AE input normalization.
        if (!load_scaler_json(scaler_path, scaler_)) {
            std::cerr << "[AI-INIT] scaler.json load failed: " << scaler_path
                      << " (LSTM-AE scores will be raw, not z-normalized)" << std::endl;
        } else {
            std::cout << "[AI-INIT] scaler loaded: " << scaler_path << std::endl;
        }

        // θ_ae — adaptive LSTM-AE threshold. Falls back to a conservative
        // value if file is missing (won't trip alarms but won't block init).
        std::ifstream tf(theta_path);
        if (tf) {
            tf >> theta_ae_;
            std::cout << "[AI-INIT] θ_ae loaded: " << theta_ae_ << std::endl;
        } else {
            std::cerr << "[AI-INIT] θ_ae file missing, using fallback "
                      << theta_ae_ << std::endl;
        }

        // Option A (Eq 3.46): θ_S — GAT spatial calibration threshold, sits next
        // to the GAT model (models/shared/theta_s.txt). Falls back to the compiled
        // default g_theta_s if missing.
        if (!gat_path.empty()) {
            std::string ts_path =
                gat_path.substr(0, gat_path.find_last_of('/') + 1) + "theta_s.txt";
            std::ifstream tsf(ts_path);
            if (tsf) { tsf >> g_theta_s;
                std::cout << "[AI-INIT] θ_S loaded: " << g_theta_s << std::endl; }
            else std::cerr << "[AI-INIT] θ_S file missing, using fallback "
                           << g_theta_s << std::endl;
        }

        // Fusion weights
        if (!weights_path.empty()) {
            if (!load_fusion_weights_json(weights_path, g_fusion)) {
                std::cerr << "[AI-INIT] fusion weights load failed: " << weights_path << std::endl;
            } else {
                std::cout << "[AI-INIT] fusion weights loaded: " << weights_path
                          << " (lambda_psi=" << g_fusion.lambda_psi
                          << " lambda_gat=" << g_fusion.lambda_gat
                          << " lambda_ae=" << g_fusion.lambda_ae
                          << " threshold=" << g_fusion.phi_threshold
                          << " per_attack=" << (g_fusion.per_attack ? "YES" : "no") << ")"
                          << std::endl;
                if (g_fusion.per_attack) {
                    std::cout << "[AI-INIT] attack-conditioned lambda_sets (psi,gat,ae):";
                    for (int k = 0; k < FusionParams::K_ATTACK; ++k)
                        std::cout << " k" << (k+1) << "=(" << g_fusion.lam_psi_k[k]
                                  << "," << g_fusion.lam_gat_k[k]
                                  << "," << g_fusion.lam_ae_k[k] << ")";
                    std::cout << std::endl;
                }
                // sir Change 1+2 confirmation
                std::cout << "[AI-INIT] sig_weights=" << (g_fusion.has_sig_weights ? "YES" : "NO")
                          << " θ_conf=" << g_fusion.theta_conf;
                if (g_fusion.has_sig_weights) {
                    std::cout << "  w^(k1)=[";
                    for (int b = 0; b < FusionParams::N_SIG; ++b)
                        std::cout << g_fusion.sig_w_k[0][b] << (b<8?",":"");
                    std::cout << "]";
                }
                std::cout << std::endl;
            }
        }

        ready_ = (gat_session_ != nullptr) || (lstm_session_ != nullptr);
        return ready_;
    }

    bool ready()        const { return ready_; }
    bool has_gat()      const { return gat_session_ != nullptr; }
    bool has_lstm_ae()  const { return lstm_session_ != nullptr; }
    float theta_ae()    const { return theta_ae_; }
    const AiScaler &scaler() const { return scaler_; }

    // ─────────────────────────────────────────────────────────────────────
    // GAT inference: per-vehicle spatial anomaly logits.
    //
    // Input:
    //   per_vehicle: row-major (N × KINEMATIC_DIM=5) [pos_x, pos_y, speed,
    //                heading, accel] in RAW (unscaled) units. Normalized internally.
    //   N: number of vehicle rows.
    //   tau (optional): per-vehicle SC-Trust score, length N. Pass nullptr to
    //                   use TAU_DEFAULT (1.0) for all.
    // Output:
    //   scores: length N, logit per vehicle (higher = more anomalous).
    //   Returns false if has_gat()=false or session call throws.
    // ─────────────────────────────────────────────────────────────────────
    bool score_gat(const float *per_vehicle_raw, int N,
                   const float *tau,
                   std::vector<float> &scores,
                   std::vector<int> *attack_types = nullptr,
                   const float *psi = nullptr,
                   const uint32_t *sig_mask = nullptr) {
        scores.clear();
        if (attack_types) attack_types->clear();
        if (!has_gat() || N <= 0) return false;

        // 1. Build (N × 6) z-scaled feature matrix.
        //    per_vehicle_raw stride is KINEMATIC_DIM (5); we scale the 5
        //    kinematic columns and write into a wider GAT_FEATURE_DIM (6) row.
        //    Column 5 (tau_i) is appended UNSCALED here — matches train.py which
        //    sets the GAT tau_col=1.0 *after* StandardScaler. (Note the LSTM path
        //    scales tau instead; see AiScaler::apply.)
        std::vector<float> feats(static_cast<size_t>(N) * mptd_ai::GAT_FEATURE_DIM);
        for (int i = 0; i < N; ++i) {
            float *row = &feats[i * mptd_ai::GAT_FEATURE_DIM];
            // cols 0..4 — z-scaled kinematics
            for (int f = 0; f < mptd_ai::KINEMATIC_DIM; ++f) {
                const float raw = per_vehicle_raw[i * mptd_ai::KINEMATIC_DIM + f];
                row[f] = scaler_.loaded
                       ? (raw - scaler_.mean[f]) /
                         (scaler_.scale[f] == 0.0f ? 1.0f : scaler_.scale[f])
                       : raw;
            }
            // col 5 — tau (raw), matches train.py tau_col appended after scaling
            row[mptd_ai::KINEMATIC_DIM] = tau ? tau[i] : mptd_ai::TAU_DEFAULT;
            // col 6 — composite ψ (raw); col 7..15 — 9 sig_mask bits (raw 0/1).
            // These are the ψ sub-scores that let the multi-task heads ID the
            // attack TYPE. Zero when unavailable (keeps clean/degenerate rows inert).
            row[mptd_ai::KINEMATIC_DIM + 1] = psi ? psi[i] : 0.0f;
            const uint32_t sm = sig_mask ? sig_mask[i] : 0u;
            for (int b = 0; b < mptd_ai::GAT_SIG_BITS; ++b)
                row[mptd_ai::KINEMATIC_DIM + 2 + b] = (float)((sm >> b) & 1u);
        }

        // 2. Build edge_index (COO) — same predicate as gat_detector.py
        //    build_edge_index: distance ≤ R_MAX_GRAPH AND heading aligned ≤ π/2.
        //    Edge direction in the trained model is bidirectional via two rows.
        std::vector<int64_t> src, dst;
        src.reserve(static_cast<size_t>(N) * (N - 1));
        dst.reserve(static_cast<size_t>(N) * (N - 1));
        for (int i = 0; i < N; ++i) {
            const float px_i = per_vehicle_raw[i * mptd_ai::KINEMATIC_DIM + 0];
            const float py_i = per_vehicle_raw[i * mptd_ai::KINEMATIC_DIM + 1];
            const float sp_i = per_vehicle_raw[i * mptd_ai::KINEMATIC_DIM + 2];
            const float hd_i = per_vehicle_raw[i * mptd_ai::KINEMATIC_DIM + 3];
            const float vx_i = sp_i * std::cos(hd_i);
            const float vy_i = sp_i * std::sin(hd_i);
            for (int j = 0; j < N; ++j) {
                if (i == j) continue;
                const float px_j = per_vehicle_raw[j * mptd_ai::KINEMATIC_DIM + 0];
                const float py_j = per_vehicle_raw[j * mptd_ai::KINEMATIC_DIM + 1];
                const float sp_j = per_vehicle_raw[j * mptd_ai::KINEMATIC_DIM + 2];
                const float hd_j = per_vehicle_raw[j * mptd_ai::KINEMATIC_DIM + 3];
                const float dx = px_i - px_j, dy = py_i - py_j;
                if (std::sqrt(dx*dx + dy*dy) > mptd_ai::R_MAX_GRAPH) continue;
                const float vx_j = sp_j * std::cos(hd_j);
                const float vy_j = sp_j * std::sin(hd_j);
                const float n_i = std::sqrt(vx_i*vx_i + vy_i*vy_i);
                const float n_j = std::sqrt(vx_j*vx_j + vy_j*vy_j);
                if (n_i < 1e-6f || n_j < 1e-6f) {
                    src.push_back(i); dst.push_back(j); continue;
                }
                const float cos_a = (vx_i*vx_j + vy_i*vy_j) / (n_i * n_j);
                if (std::acos(std::max(-1.0f, std::min(1.0f, cos_a)))
                    > (float)g_phi_max_graph) continue;   // #9 sensitivity: runtime phi_max
                src.push_back(i);
                dst.push_back(j);
            }
        }
        if (src.empty()) {
            // Fully isolated snapshot — emit self-loops so the graph isn't
            // empty (gat_detector.py does the same fallback).
            for (int i = 0; i < N; ++i) { src.push_back(i); dst.push_back(i); }
        }
        const int64_t E = (int64_t)src.size();
        std::vector<int64_t> edge_index;
        edge_index.reserve(2 * E);
        edge_index.insert(edge_index.end(), src.begin(), src.end());
        edge_index.insert(edge_index.end(), dst.begin(), dst.end());

        // 3. Run inference.
        try {
            Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(
                OrtArenaAllocator, OrtMemTypeDefault);

            std::array<int64_t, 2> x_shape  = {N, mptd_ai::GAT_FEATURE_DIM};
            std::array<int64_t, 2> ei_shape = {2, E};

            std::array<Ort::Value, 2> inputs = {
                Ort::Value::CreateTensor<float>(mem, feats.data(),
                    feats.size(), x_shape.data(), x_shape.size()),
                Ort::Value::CreateTensor<int64_t>(mem, edge_index.data(),
                    edge_index.size(), ei_shape.data(), ei_shape.size())
            };

            const char *input_names[]  = {"x", "edge_index"};
            // Multi-task GAT emits 2 outputs: scores (N,1) + attack_probs (N,K).
            // Request the second only if the caller wants k̂ AND the loaded model
            // actually has it (shared fallback model may still be single-output).
            const char *output_names[] = {"scores", "attack_probs"};
            const bool want_atk = (attack_types != nullptr) &&
                                  (gat_session_->GetOutputCount() >= 2);
            auto out = gat_session_->Run(
                Ort::RunOptions{nullptr},
                input_names, inputs.data(), inputs.size(),
                output_names, want_atk ? 2 : 1);

            const float *raw = out[0].GetTensorData<float>();
            scores.assign(raw, raw + N);

            if (want_atk) {
                // attack_probs shape (N, K) — argmax over K gives k̂_i (0-based).
                auto info = out[1].GetTensorTypeAndShapeInfo();
                auto shp  = info.GetShape();
                const int Kc = (shp.size() >= 2 && shp[1] > 0) ? (int)shp[1] : 1;
                const float *ap = out[1].GetTensorData<float>();
                attack_types->resize(N);
                for (int i = 0; i < N; ++i) {
                    int   best = 0;
                    float bv   = ap[(size_t)i * Kc];
                    for (int k = 1; k < Kc; ++k) {
                        const float v = ap[(size_t)i * Kc + k];
                        if (v > bv) { bv = v; best = k; }
                    }
                    // flag_i^GAT (revised eq:gat_det_flag): the GAT detects an
                    // attack iff ANY head fires (max_k ŷ^(k) > 0.5). We encode the
                    // verdict in k̂: >0.5 → predicted class best (routes λ^(k̂) and
                    // OR-flag=1); ≤0.5 → -1 (no GAT detection, OR-flag=0, fusion
                    // falls back to global λ). Strictly ≥ any single head's
                    // sensitivity, exactly as the equation states.
                    // Change 2 gate: require max-head confidence ≥ θ_conf (loaded
                    // from fusion_weights.json) to commit to k̂'s weight sets; else
                    // -1 → global w + average λ. Falls back to the legacy 0.5 head
                    // threshold when θ_conf is unset.
                    (*attack_types)[i] =
                        (bv >= std::max(mptd_ai::GAT_HEAD_DETECT_THRESH, g_fusion.theta_conf))
                        ? best : -1;
                }
            }
            return true;
        } catch (const Ort::Exception &e) {
            std::cerr << "[AI-GAT] inference exception: " << e.what() << std::endl;
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // LSTM-AE inference: temporal anomaly score = mean-squared reconstruction
    // error of the L-beacon window.
    //
    // Input:
    //   window_raw: row-major (LSTM_WINDOW_SIZE × LSTM_FEATURE_DIM = 10 × 6) RAW
    //               features [pos_x, pos_y, speed, heading, accel, tau_i]. All 6
    //               columns are z-scaled internally (tau via the scaler's 6th row).
    // Output:
    //   recon_mse: scalar — averaged squared error over all 60 (=10·6) cells.
    //   Returns false if has_lstm_ae()=false.
    // ─────────────────────────────────────────────────────────────────────
    bool score_lstm_ae(const float *window_raw, float &recon_mse) {
        recon_mse = 0.0f;
        if (!has_lstm_ae()) return false;

        const int win = g_lstm_window;   // runtime AE window (urban=50, else 10)
        const size_t n_cells = (size_t)win * mptd_ai::LSTM_FEATURE_DIM;
        std::vector<float> normed(window_raw, window_raw + n_cells);
        scaler_.apply(normed.data(), win);

        try {
            Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(
                OrtArenaAllocator, OrtMemTypeDefault);
            std::array<int64_t, 3> x_shape = {
                1, win, mptd_ai::LSTM_FEATURE_DIM};

            Ort::Value in = Ort::Value::CreateTensor<float>(
                mem, normed.data(), normed.size(),
                x_shape.data(), x_shape.size());

            const char *input_names[]  = {"x"};
            const char *output_names[] = {"recon"};

            auto out = lstm_session_->Run(
                Ort::RunOptions{nullptr},
                input_names, &in, 1,
                output_names, 1);

            const float *recon = out[0].GetTensorData<float>();
            double sse = 0.0;
            for (size_t k = 0; k < n_cells; ++k) {
                const double d = (double)normed[k] - (double)recon[k];
                sse += d * d;
            }
            recon_mse = (float)(sse / (double)n_cells);
            return true;
        } catch (const Ort::Exception &e) {
            std::cerr << "[AI-LSTM] inference exception: " << e.what() << std::endl;
            return false;
        }
    }

private:
    Ort::Env                       env_;
    std::unique_ptr<Ort::Session>  gat_session_;
    std::unique_ptr<Ort::Session>  lstm_session_;
    AiScaler                       scaler_;
    float                          theta_ae_ = 0.05f;   // fallback if file missing
    bool                           ready_    = false;
};

// Global engine — initialized once at startup by 12_main.h.
// Inline storage keeps this header self-contained (no .cc file needed).
inline AiInferenceEngine g_ai_engine;

// ────────────────────────────────────────────────────────────────────────────
// Fusion (paper §3.5.3 Eq 3.46 / score_fusion.py Eq 3.46 in README)
//   Φ_i(t) = λ₁·ψ_i(t) + λ₂·S_i(t) + λ₃·min(ε_i(t)/θ_ae, 1.0)
//   default λ₁=0.3, λ₂=0.4, λ₃=0.3, decision Φ > 0.5 → anomalous.
//
// Inputs:
//   psi       — lightweight composite score ∈ [0,1] from LW-DETECT (paper Eq 3.20)
//   gat_score — GAT spatial logit, expected to be already in [0,1] post-sigmoid
//   ae_err    — LSTM-AE raw MSE reconstruction error (≥ 0)
//   theta_ae  — adaptive threshold from training (analytics/ml/models/theta_ae.txt)
//
// The clamp on ae_norm prevents a single outlier reconstruction from dominating
// Φ when θ_ae is small — matches score_fusion.py:55 `min(..., 1.0)`.
// ────────────────────────────────────────────────────────────────────────────
// FusionParams and g_fusion are defined globally at the top of the file

struct FusionScore {
    float psi;
    float gat;
    float ae_norm;
    float phi;
    bool  anomalous;
};

inline FusionScore fuse_scores(float psi, float gat_score, float ae_err,
                               float theta_ae,
                               int attack_type = -1,
                               const FusionParams &p = g_fusion) {
    const float denom = (theta_ae > 1e-9f ? theta_ae : 1e-9f);
    float ae_norm = ae_err / denom;
    if (ae_norm > 1.0f) ae_norm = 1.0f;
    if (ae_norm < 0.0f) ae_norm = 0.0f;

    // Attack-conditioned weights (revised eq:fusion): if per-attack sets were
    // loaded and the GAT predicted a valid attack class k̂_i, use λ^(k̂);
    // otherwise fall back to the global λ (unchanged pre-patch behaviour).
    float base_psi = p.lambda_psi, base_gat = p.lambda_gat, base_ae = p.lambda_ae;
    if (p.per_attack && attack_type >= 0 && attack_type < FusionParams::K_ATTACK) {
        base_psi = p.lam_psi_k[attack_type];
        base_gat = p.lam_gat_k[attack_type];
        base_ae  = p.lam_ae_k[attack_type];
    }

    // Build the active-weight vector and renormalise.
    float lp = base_psi;
    float lg = p.use_gat ? base_gat : 0.0f;
    float la = p.use_ae  ? base_ae  : 0.0f;
    const float sum_w = lp + lg + la;
    if (sum_w > 1e-9f) {
        lp /= sum_w;
        lg /= sum_w;
        la /= sum_w;
    }

    // H8 Tier-1: normalize ψ to its LW decision scale (ψ_th) so a lightweight
    // detection (ψ>ψ_th) reaches [0,1] like the other components and can carry
    // the fused Φ>Φ_th decision. Raw ψ maxes ~0.35 for poisoned and could never
    // reach Φ_th=0.5, so the fusion silently discarded the LW signal → full<LW.
    const float psi_denom = (psi_th > 1e-9 ? (float)psi_th : 1e-9f);
    float psi_n = psi / psi_denom;
    if (psi_n > 1.0f) psi_n = 1.0f;
    if (psi_n < 0.0f) psi_n = 0.0f;

    // Option A (Eq 3.46): the GAT model now emits the RAW spatial anomaly score
    // S_i = ||(x'−x̄'_clean)/σ'_clean||₂; normalise by θ_S and clip to [0,1] so it
    // is a comparable weighted-average term (was raw sigmoid before).
    float used_gat = 0.0f;
    if (p.use_gat) {
        used_gat = gat_score / (g_theta_s > 1e-9f ? g_theta_s : 1e-9f);
        if (used_gat > 1.0f) used_gat = 1.0f;
        if (used_gat < 0.0f) used_gat = 0.0f;
    }
    const float used_ae  = p.use_ae  ? ae_norm   : 0.0f;
    const float phi = lp * psi_n + lg * used_gat + la * used_ae;
    return FusionScore{psi_n, used_gat, used_ae, phi, phi > p.phi_threshold};
}

#else

// Mock implementation of AiInferenceEngine when onnxruntime_cxx_api.h is missing
namespace mptd_ai {
constexpr int    KINEMATIC_DIM   = 5;
constexpr int    GAT_FEATURE_DIM = 6;
constexpr int    LSTM_FEATURE_DIM = 6;
constexpr int    LSTM_WINDOW_SIZE = 10;
constexpr double R_MAX_GRAPH   = 300.0;
constexpr double PHI_MAX_GRAPH = 1.5707963267948966;
constexpr float  TAU_DEFAULT = 1.0f;

struct AiScaler {
    bool loaded = false;
    std::vector<float> mean;
    std::vector<float> scale;
};
} // namespace mptd_ai

// FusionParams and g_fusion are defined globally at the top of the file

class AiInferenceEngine {
public:
    AiInferenceEngine() {}

    bool init(const std::string &gat_path,
              const std::string &lstm_ae_path,
              const std::string &scaler_path,
              const std::string &theta_path,
              const std::string &weights_path = "") {
        theta_ae_ = 0.05f;
        ready_ = false;
        if (!weights_path.empty()) {
            if (!load_fusion_weights_json(weights_path, g_fusion)) {
                std::cerr << "[AI-INIT] (Mock) fusion weights load failed: " << weights_path << std::endl;
            } else {
                std::cout << "[AI-INIT] (Mock) fusion weights loaded: " << weights_path
                          << " (lambda_psi=" << g_fusion.lambda_psi
                          << " lambda_gat=" << g_fusion.lambda_gat
                          << " lambda_ae=" << g_fusion.lambda_ae
                          << " threshold=" << g_fusion.phi_threshold << ")" << std::endl;
            }
        }
        std::cerr << "[WARNING] ONNX Runtime header <onnxruntime_cxx_api.h> not found. Mock AI Engine initialized." << std::endl;
        return false;
    }

    bool ready()        const { return ready_; }
    bool has_gat()      const { return false; }
    bool has_lstm_ae()  const { return false; }
    float theta_ae()    const { return theta_ae_; }
    const mptd_ai::AiScaler &scaler() const { return scaler_; }

    bool score_gat(const float *per_vehicle_raw, int N,
                   const float *tau,
                   std::vector<float> &scores,
                   std::vector<int> *attack_types = nullptr,
                   const float *psi = nullptr,
                   const uint32_t *sig_mask = nullptr) {
        (void)per_vehicle_raw;
        (void)tau; (void)psi; (void)sig_mask;
        scores.assign(N, 0.0f);
        if (attack_types) attack_types->assign(N, 0);
        return false;
    }

    bool score_lstm_ae(const float *window_raw, float &recon_mse) {
        (void)window_raw;
        recon_mse = 0.0f;
        return false;
    }

private:
    bool ready_ = false;
    float theta_ae_ = 0.05f;
    mptd_ai::AiScaler scaler_;
};

inline AiInferenceEngine g_ai_engine;

struct FusionScore {
    float psi;
    float gat;
    float ae_norm;
    float phi;
    bool  anomalous;
};

inline FusionScore fuse_scores(float psi, float gat_score, float ae_err,
                               float theta_ae,
                               int attack_type = -1,
                               const FusionParams &p = g_fusion) {
    const float denom = (theta_ae > 1e-9f ? theta_ae : 1e-9f);
    float ae_norm = ae_err / denom;
    if (ae_norm > 1.0f) ae_norm = 1.0f;
    if (ae_norm < 0.0f) ae_norm = 0.0f;

    float base_psi = p.lambda_psi, base_gat = p.lambda_gat, base_ae = p.lambda_ae;
    if (p.per_attack && attack_type >= 0 && attack_type < FusionParams::K_ATTACK) {
        base_psi = p.lam_psi_k[attack_type];
        base_gat = p.lam_gat_k[attack_type];
        base_ae  = p.lam_ae_k[attack_type];
    }
    float lp = base_psi;
    float lg = p.use_gat ? base_gat : 0.0f;
    float la = p.use_ae  ? base_ae  : 0.0f;
    const float sum_w = lp + lg + la;
    if (sum_w > 1e-9f) {
        lp /= sum_w;
        lg /= sum_w;
        la /= sum_w;
    }

    // H8 Tier-1: normalize ψ to its LW decision scale (ψ_th) so a lightweight
    // detection (ψ>ψ_th) reaches [0,1] like the other components and can carry
    // the fused Φ>Φ_th decision. Raw ψ maxes ~0.35 for poisoned and could never
    // reach Φ_th=0.5, so the fusion silently discarded the LW signal → full<LW.
    const float psi_denom = (psi_th > 1e-9 ? (float)psi_th : 1e-9f);
    float psi_n = psi / psi_denom;
    if (psi_n > 1.0f) psi_n = 1.0f;
    if (psi_n < 0.0f) psi_n = 0.0f;

    // Option A (Eq 3.46): the GAT model now emits the RAW spatial anomaly score
    // S_i = ||(x'−x̄'_clean)/σ'_clean||₂; normalise by θ_S and clip to [0,1] so it
    // is a comparable weighted-average term (was raw sigmoid before).
    float used_gat = 0.0f;
    if (p.use_gat) {
        used_gat = gat_score / (g_theta_s > 1e-9f ? g_theta_s : 1e-9f);
        if (used_gat > 1.0f) used_gat = 1.0f;
        if (used_gat < 0.0f) used_gat = 0.0f;
    }
    const float used_ae  = p.use_ae  ? ae_norm   : 0.0f;
    const float phi = lp * psi_n + lg * used_gat + la * used_ae;
    return FusionScore{psi_n, used_gat, used_ae, phi, phi > p.phi_threshold};
}

#endif

#endif // MPTD_PQS_06D_AI_INFERENCE_H
