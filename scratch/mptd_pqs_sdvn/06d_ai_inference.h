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
//     • lstm_ae_model.onnx — Temporal autoencoder over a 20-beacon sliding
//                             window of 5-dim features, returns reconstruction
//                             (B, 20, 5); anomaly = ||x − x_hat||²
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

#if __has_include(<onnxruntime_cxx_api.h>)
#include <onnxruntime_cxx_api.h>

#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// ────────────────────────────────────────────────────────────────────────────
// Constants — must match analytics/ml/gat_detector.py + lstm_ae.py
// ────────────────────────────────────────────────────────────────────────────
namespace mptd_ai {

constexpr int    GAT_FEATURE_DIM = 6;          // pos_x, pos_y, speed, heading, accel, tau_i
constexpr int    LSTM_FEATURE_DIM = 5;         // pos_x, pos_y, speed, heading, accel (no tau)
constexpr int    LSTM_WINDOW_SIZE = 20;        // beacons per temporal window
constexpr double R_MAX_GRAPH   = 300.0;        // metres — gat_detector.py R_MAX
constexpr double PHI_MAX_GRAPH = 1.5707963267948966; // π/2 rad — gat_detector.py PHI_MAX
constexpr float  TAU_DEFAULT   = 1.0f;         // SC-Trust default when not queried

} // namespace mptd_ai

// ────────────────────────────────────────────────────────────────────────────
// Per-feature StandardScaler params loaded from analytics/ml/models/scaler.json.
// Trivially-copyable struct so threads can share it lock-free.
// ────────────────────────────────────────────────────────────────────────────
struct AiScaler {
    float mean [mptd_ai::LSTM_FEATURE_DIM] = {0,0,0,0,0};
    float scale[mptd_ai::LSTM_FEATURE_DIM] = {1,1,1,1,1};
    bool  loaded = false;

    // Apply per-feature z-score normalization in place. Caller passes a buffer
    // of length n_rows * LSTM_FEATURE_DIM in row-major order [row0:f0..f4, row1:...].
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
              const std::string &theta_path) {
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
                std::cout << "[AI-INIT] LSTM-AE session loaded: " << lstm_ae_path << std::endl;
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
    //   per_vehicle: row-major (N × 5) [pos_x, pos_y, speed, heading, accel]
    //                in RAW (unscaled) units. Function normalizes internally.
    //   N: number of vehicle rows.
    //   tau (optional): per-vehicle SC-Trust score, length N. Pass nullptr to
    //                   use TAU_DEFAULT (1.0) for all.
    // Output:
    //   scores: length N, logit per vehicle (higher = more anomalous).
    //   Returns false if has_gat()=false or session call throws.
    // ─────────────────────────────────────────────────────────────────────
    bool score_gat(const float *per_vehicle_raw, int N,
                   const float *tau,
                   std::vector<float> &scores) {
        scores.clear();
        if (!has_gat() || N <= 0) return false;

        // 1. Build (N × 6) z-scaled feature matrix.
        //    Stride here is GAT_FEATURE_DIM (6); AiScaler::apply assumes
        //    LSTM_FEATURE_DIM stride, so we inline the z-norm to match the
        //    wider row layout. Column 5 (tau_i) is appended unscaled — matches
        //    train.py which sets tau_col=1.0 *after* StandardScaler.
        std::vector<float> feats(static_cast<size_t>(N) * mptd_ai::GAT_FEATURE_DIM);
        for (int i = 0; i < N; ++i) {
            for (int f = 0; f < mptd_ai::LSTM_FEATURE_DIM; ++f) {
                const float raw = per_vehicle_raw[i * mptd_ai::LSTM_FEATURE_DIM + f];
                const float sc  = scaler_.loaded
                                ? (raw - scaler_.mean[f]) /
                                  (scaler_.scale[f] == 0.0f ? 1.0f : scaler_.scale[f])
                                : raw;
                feats[i * mptd_ai::GAT_FEATURE_DIM + f] = sc;
            }
            feats[i * mptd_ai::GAT_FEATURE_DIM + mptd_ai::LSTM_FEATURE_DIM] =
                tau ? tau[i] : mptd_ai::TAU_DEFAULT;
        }

        // 2. Build edge_index (COO) — same predicate as gat_detector.py
        //    build_edge_index: distance ≤ R_MAX_GRAPH AND heading aligned ≤ π/2.
        //    Edge direction in the trained model is bidirectional via two rows.
        std::vector<int64_t> src, dst;
        src.reserve(static_cast<size_t>(N) * (N - 1));
        dst.reserve(static_cast<size_t>(N) * (N - 1));
        for (int i = 0; i < N; ++i) {
            const float px_i = per_vehicle_raw[i * mptd_ai::LSTM_FEATURE_DIM + 0];
            const float py_i = per_vehicle_raw[i * mptd_ai::LSTM_FEATURE_DIM + 1];
            const float sp_i = per_vehicle_raw[i * mptd_ai::LSTM_FEATURE_DIM + 2];
            const float hd_i = per_vehicle_raw[i * mptd_ai::LSTM_FEATURE_DIM + 3];
            const float vx_i = sp_i * std::cos(hd_i);
            const float vy_i = sp_i * std::sin(hd_i);
            for (int j = 0; j < N; ++j) {
                if (i == j) continue;
                const float px_j = per_vehicle_raw[j * mptd_ai::LSTM_FEATURE_DIM + 0];
                const float py_j = per_vehicle_raw[j * mptd_ai::LSTM_FEATURE_DIM + 1];
                const float sp_j = per_vehicle_raw[j * mptd_ai::LSTM_FEATURE_DIM + 2];
                const float hd_j = per_vehicle_raw[j * mptd_ai::LSTM_FEATURE_DIM + 3];
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
                    > (float)mptd_ai::PHI_MAX_GRAPH) continue;
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
            const char *output_names[] = {"scores"};

            auto out = gat_session_->Run(
                Ort::RunOptions{nullptr},
                input_names, inputs.data(), inputs.size(),
                output_names, 1);

            const float *raw = out[0].GetTensorData<float>();
            scores.assign(raw, raw + N);
            return true;
        } catch (const Ort::Exception &e) {
            std::cerr << "[AI-GAT] inference exception: " << e.what() << std::endl;
            return false;
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // LSTM-AE inference: temporal anomaly score = mean-squared reconstruction
    // error of the 20-beacon window.
    //
    // Input:
    //   window_raw: row-major (LSTM_WINDOW_SIZE × 5) RAW kinematics.
    // Output:
    //   recon_mse: scalar — averaged squared error over all 100 (=20·5) cells.
    //   Returns false if has_lstm_ae()=false.
    // ─────────────────────────────────────────────────────────────────────
    bool score_lstm_ae(const float *window_raw, float &recon_mse) {
        recon_mse = 0.0f;
        if (!has_lstm_ae()) return false;

        const size_t n_cells = mptd_ai::LSTM_WINDOW_SIZE * mptd_ai::LSTM_FEATURE_DIM;
        std::vector<float> normed(window_raw, window_raw + n_cells);
        scaler_.apply(normed.data(), mptd_ai::LSTM_WINDOW_SIZE);

        try {
            Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(
                OrtArenaAllocator, OrtMemTypeDefault);
            std::array<int64_t, 3> x_shape = {
                1, mptd_ai::LSTM_WINDOW_SIZE, mptd_ai::LSTM_FEATURE_DIM};

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
struct FusionParams {
    float lambda_psi   = 0.3f;   // λ₁  (always active — LW-DETECT is the base)
    float lambda_gat   = 0.4f;   // λ₂
    float lambda_ae    = 0.3f;   // λ₃
    float phi_threshold = 0.5f;  // Φ_th
    // R7f: ablation flags. When false, the corresponding term is dropped and
    // the surviving λs are RENORMALISED so they still sum to 1 — preserving
    // the paper's Φ_th = 0.5 semantics across A2/A3/Full configurations.
    bool  use_gat      = true;
    bool  use_ae       = true;
};

inline FusionParams g_fusion = FusionParams{};

struct FusionScore {
    float psi;
    float gat;
    float ae_norm;
    float phi;
    bool  anomalous;
};

inline FusionScore fuse_scores(float psi, float gat_score, float ae_err,
                               float theta_ae,
                               const FusionParams &p = g_fusion) {
    const float denom = (theta_ae > 1e-9f ? theta_ae : 1e-9f);
    float ae_norm = ae_err / denom;
    if (ae_norm > 1.0f) ae_norm = 1.0f;
    if (ae_norm < 0.0f) ae_norm = 0.0f;

    // Build the active-weight vector and renormalise.
    float lp = p.lambda_psi;
    float lg = p.use_gat ? p.lambda_gat : 0.0f;
    float la = p.use_ae  ? p.lambda_ae  : 0.0f;
    const float sum_w = lp + lg + la;
    if (sum_w > 1e-9f) {
        lp /= sum_w;
        lg /= sum_w;
        la /= sum_w;
    }

    const float used_gat = p.use_gat ? gat_score : 0.0f;
    const float used_ae  = p.use_ae  ? ae_norm   : 0.0f;
    const float phi = lp * psi + lg * used_gat + la * used_ae;
    return FusionScore{psi, used_gat, used_ae, phi, phi > p.phi_threshold};
}

#else

// Mock implementation of AiInferenceEngine when onnxruntime_cxx_api.h is missing
namespace mptd_ai {
constexpr int    GAT_FEATURE_DIM = 6;
constexpr int    LSTM_FEATURE_DIM = 5;
constexpr int    LSTM_WINDOW_SIZE = 20;
constexpr double R_MAX_GRAPH   = 300.0;
constexpr double PHI_MAX_GRAPH = 1.5707963267948966;
constexpr float  TAU_DEFAULT = 1.0f;

struct AiScaler {
    bool loaded = false;
    std::vector<float> mean;
    std::vector<float> scale;
};
} // namespace mptd_ai

struct FusionParams {
    bool  use_gat       = true;
    bool  use_ae        = true;
    float lambda_psi    = 0.4f;
    float lambda_gat    = 0.3f;
    float lambda_ae     = 0.3f;
    float phi_threshold = 0.5f;
};

inline FusionParams g_fusion;

class AiInferenceEngine {
public:
    AiInferenceEngine() {}

    bool init(const std::string &gat_path,
              const std::string &lstm_ae_path,
              const std::string &scaler_path,
              const std::string &theta_path) {
        theta_ae_ = 0.05f;
        ready_ = false;
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
                   std::vector<float> &scores) {
        (void)per_vehicle_raw;
        (void)tau;
        scores.assign(N, 0.0f);
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
                               const FusionParams &p = g_fusion) {
    const float denom = (theta_ae > 1e-9f ? theta_ae : 1e-9f);
    float ae_norm = ae_err / denom;
    if (ae_norm > 1.0f) ae_norm = 1.0f;
    if (ae_norm < 0.0f) ae_norm = 0.0f;

    float lp = p.lambda_psi;
    float lg = p.use_gat ? p.lambda_gat : 0.0f;
    float la = p.use_ae  ? p.lambda_ae  : 0.0f;
    const float sum_w = lp + lg + la;
    if (sum_w > 1e-9f) {
        lp /= sum_w;
        lg /= sum_w;
        la /= sum_w;
    }

    const float used_gat = p.use_gat ? gat_score : 0.0f;
    const float used_ae  = p.use_ae  ? ae_norm   : 0.0f;
    const float phi = lp * psi + lg * used_gat + la * used_ae;
    return FusionScore{psi, used_gat, used_ae, phi, phi > p.phi_threshold};
}

#endif

#endif // MPTD_PQS_06D_AI_INFERENCE_H
