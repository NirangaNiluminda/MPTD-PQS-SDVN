import { Node, Edge, MarkerType } from "@xyflow/react";
import { ArchNodeData } from "./ArchitectureNodes";

// ─────────────────────────────────────────────────────────────────────────
// Every Algorithm/Eq number below was verified against report/main.tex (the
// compiled thesis is the authoritative numbering — the .h/.go source files'
// own inline comments carry stale numbers from earlier drafts and disagree
// with both the paper and each other; see the corrections list this
// component's own commit message/PR description carries). Two numbers here
// contradict what an earlier pass in this same demo assumed from those
// stale code comments (CP-DETECT is Algorithm 9, not 7; fusion Φ is Eq
// 3.48, not 3.46) — the paper wins in both cases.
// ─────────────────────────────────────────────────────────────────────────

export type ViewName = "ABSTRACT" | "LIGHTWEIGHT_MODE" | "FULL_MODE" | "BLOCKCHAIN_LAYER" | "KEY_MANAGEMENT" | "ALGO_DETAIL";
export type SubFlow =
  | "TP_DETECT"
  | "SYB_DETECT"
  | "MITM_DETECT"
  | "CP_DETECT"
  | "PQ_FHE_TRS"
  | "SC_REVOKE"
  | "SC_REGISTER"
  | "DKG_KEYGEN"
  | "LKH_REKEY"
  | null;
export type ScenarioName = "NORMAL" | "TRAJECTORY_POISONING" | "SYBIL_ATTACK" | "MITM_ATTACK" | "CONTROLLER_COMPROMISE";

type ArchNode = Node<ArchNodeData>;

function n(
  id: string,
  x: number,
  y: number,
  data: ArchNodeData,
  type: "archNode" | "decision" = "archNode"
): ArchNode {
  return { id, type, position: { x, y }, data };
}

function e(id: string, source: string, target: string, opts: Partial<Edge> = {}): Edge {
  return {
    id,
    source,
    target,
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: "#64748b" },
    style: { stroke: "#475569", strokeWidth: 1.5 },
    ...opts,
  };
}

// ── LEVEL 1 — ABSTRACT SYSTEM VIEW ──────────────────────────────────────
// RSU Cluster is the real hub (degree 4: Vehicles, Controller, Cloud,
// Blockchain) — verified directly against report/main.tex:3195-3232 and
// 3390-3400 (prose: "the signed aggregate... is sent to the Cloud" by the
// RING, "the Cloud returns Enc(X̄_global) to the originating RSU cluster")
// AND the actual sockets in scratch/mptd_pqs_sdvn/07_socket_layer.h:178-201
// (only RSU0 opens a send/reply-receive socket to the Cloud; the Controller
// node's socket setup has no Cloud connection at all) plus
// 08_detection_engine.h (send_aggregate_to_cloud/handle_cloud_reply_at_rsu
// are both RSU-side). An earlier version of this diagram drew Controller→
// Cloud→Blockchain instead — both edges were wrong: FHE/TRS never touches
// the controller, and the Cloud has no on-chain identity at all (confirmed
// by grep: zero cloud references in 06c_blockchain_api.h's CallSC* wrappers
// and none in register_all_nodes(), 11_blockchain_setup.h:993-1080 — RSUs,
// vehicles and controllers register on-chain; the Cloud never does).
// Laid out as a star around RSU Cluster (Controller up-right, Cloud
// down-right) with Blockchain further right at the vertical midpoint, so
// rsu→chain runs straight through the open corridor between the
// Controller/Cloud rows without crossing either box.
export const abstractGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("veh", 20, 220, { label: "Vehicles", subtitle: "IEEE 802.11p beacons, 10 Hz (T_b = 100 ms)", category: "vehicle" }),
    n("rsu", 400, 220, {
      label: "RSU Cluster",
      subtitle: "Lightweight Mode detection + FHE/TRS ring coordinator",
      category: "rsu",
      drillable: true,
    }),
    n("ctrl", 780, 40, {
      label: "SDVN Controller",
      subtitle: "Full Mode — spatio-temporal deep learning",
      category: "ai",
      drillable: true,
    }),
    n("cloud", 780, 420, {
      label: "Cloud / ITS Server",
      subtitle: "Homomorphic blind aggregation — RSU cluster completes threshold decryption using the Cloud's partial share",
      category: "cloud",
      drillable: true,
    }),
    n("chain", 1160, 220, {
      label: "Blockchain & IPFS Layer",
      subtitle: "Smart contracts, distributed trust, off-chain storage",
      category: "blockchain",
      drillable: true,
    }),
  ],
  edges: [
    e("ab-veh-rsu", "veh", "rsu", { label: "beacon b_i(t)" }),
    e("ab-rsu-ctrl", "rsu", "ctrl", { label: "flagged windows" }),
    e("ab-rsu-cloud", "rsu", "cloud", {
      label: "ring-signed aggregate ↔ partial-decrypt reply",
      style: { stroke: "#0284c7", strokeWidth: 1.5 },
      markerStart: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: "#0284c7" },
    }),
    e("ab-rsu-chain", "rsu", "chain", { label: "evidence E_j(t)", style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
    e("ab-ctrl-chain", "ctrl", "chain", { label: "Φ_i(t) evidence", style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
  ],
};

// ── LEVEL 2A — LIGHTWEIGHT MODE (RSU CLUSTER) ───────────────────────────
export const lightweightGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("lw-ingest", 20, 220, { label: "Beacon ingestion", subtitle: "b_i(t) received at RSU", category: "rsu" }),
    n("lw-hmac", 260, 220, { label: "HMAC & Nonce Verifier", algoRef: "Eq 3.42", category: "rsu" }),
    n("lw-tp", 540, 40, {
      label: "TP-DETECT",
      subtitle: "TP-S1..TP-S5 — kinematic feasibility, heading, accel, drift",
      algoRef: "Algorithm 2",
      category: "rsu",
      drillable: true,
    }),
    n("lw-syb", 540, 220, {
      label: "SYB-DETECT",
      subtitle: "MP-S1, MP-S2, MP-S4 — Sybil / impersonation",
      algoRef: "Algorithm 3",
      category: "rsu",
      drillable: true,
    }),
    n("lw-mitm", 540, 400, {
      label: "MITM-DETECT",
      subtitle: "HMAC gate, MP-S3 (KL-divergence), residuals",
      algoRef: "Algorithm 4",
      category: "rsu",
      drillable: true,
    }),
    n("lw-scorer", 840, 220, {
      label: "Composite Anomaly Scorer",
      subtitle: "ψ_i(t) = weighted signature violations",
      algoRef: "Eq 3.21",
      category: "rsu",
    }),
    n("lw-gate", 1090, 220, { label: "ψ_i(t) > ψ_th ?", category: "rsu" }, "decision"),
    n("lw-pass", 1310, 100, { label: "PASS", subtitle: "Forward to LKH / normal path", category: "generic", status: "idle" }),
    n("lw-alert", 1310, 340, {
      label: "ALERT",
      subtitle: "Submit evidence E_j(t) to blockchain",
      category: "alert",
    }),
  ],
  edges: [
    e("lw-e1", "lw-ingest", "lw-hmac"),
    e("lw-e2a", "lw-hmac", "lw-tp"),
    e("lw-e2b", "lw-hmac", "lw-syb"),
    e("lw-e2c", "lw-hmac", "lw-mitm"),
    e("lw-e3a", "lw-tp", "lw-scorer"),
    e("lw-e3b", "lw-syb", "lw-scorer"),
    e("lw-e3c", "lw-mitm", "lw-scorer"),
    e("lw-e4", "lw-scorer", "lw-gate"),
    e("lw-e5a", "lw-gate", "lw-pass", { label: "no", style: { stroke: "#22c55e", strokeWidth: 1.5 } }),
    e("lw-e5b", "lw-gate", "lw-alert", { label: "yes", style: { stroke: "#f43f5e", strokeWidth: 1.5 } }),
  ],
};

// ── LEVEL 2B — FULL MODE (SDVN CONTROLLER) ──────────────────────────────
export const fullModeGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    // AI pipeline
    n("fm-ipfs", 20, 60, { label: "IPFS Loader", subtitle: "Retrieves window X_i(t) via content hash", category: "ai" }),
    n("fm-gat", 300, 60, {
      label: "GAT Spatial Detector",
      subtitle: "Dynamic graph G(t), multi-head attention, K=7 attack heads",
      algoRef: "Eq 3.31–3.32",
      category: "ai",
    }),
    n("fm-lstm", 580, 60, {
      label: "LSTM-AE Temporal Detector",
      subtitle: "Reconstruction error ε_i(t) on latent history h_i",
      category: "ai",
    }),
    n("fm-fusion", 860, 60, {
      label: "Fusion Engine",
      subtitle: "Attack-conditioned weighted score Φ_i(t)",
      algoRef: "Eq 3.48",
      category: "ai",
    }),
    n("fm-evidence", 1140, 60, { label: "Untrusted Peer Evidence", subtitle: "Submitted for CP-DETECT audit", category: "alert" }),

    // Crypto pipeline
    n("fm-fhe", 20, 320, {
      label: "Pre-Coordination FHE",
      subtitle: "c_j = Enc(pk_FHE, A_j(t))",
      algoRef: "Eq 3.51",
      category: "crypto",
    }),
    n("fm-hadd", 300, 320, { label: "Homomorphic Addition", subtitle: "Combines ciphertexts without decrypting", category: "crypto" }),
    n("fm-trs", 580, 320, {
      label: "PQ Threshold Ring Signature",
      subtitle: "ML-DSA-87 / Dilithium5, signing subset t_sign = f+1",
      algoRef: "Algorithm 6",
      category: "crypto",
      drillable: true,
    }),
    n("fm-decrypt", 860, 320, {
      label: "Cloud Blind Aggregation + THRESH-DEC",
      subtitle: "Threshold decryption, t_decrypt = f+2",
      algoRef: "Algorithm 7",
      category: "crypto",
    }),
  ],
  edges: [
    e("fm-e1", "fm-ipfs", "fm-gat"),
    e("fm-e2", "fm-gat", "fm-lstm"),
    e("fm-e3", "fm-lstm", "fm-fusion"),
    e("fm-e4", "fm-fusion", "fm-evidence", { style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
    e("fm-e5", "fm-fhe", "fm-hadd", { style: { stroke: "#10b981", strokeWidth: 1.5 } }),
    e("fm-e6", "fm-hadd", "fm-trs", { style: { stroke: "#10b981", strokeWidth: 1.5 } }),
    e("fm-e7", "fm-trs", "fm-decrypt", { style: { stroke: "#10b981", strokeWidth: 1.5 } }),
  ],
};

// ── LEVEL 2C — BLOCKCHAIN & TRUST LAYER ─────────────────────────────────
export const blockchainGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("bc-register", 20, 200, {
      label: "SC-Register",
      subtitle: "2f+1 RSU endorsement validation",
      algoRef: "Algorithm 8",
      category: "blockchain",
      drillable: true,
    }),
    n("bc-trust", 320, 200, {
      label: "SC-Trust",
      subtitle: "EMA trust updates — vehicles τ_i, RSUs τ_rj, controllers τ_ck",
      algoRef: "Eq 3.63–3.66",
      category: "blockchain",
    }),
    n("bc-revoke", 620, 60, {
      label: "SC-Revoke",
      subtitle: "RSU BFT quorum accumulator — 2f+1 distinct witnesses over T_w → CRL broadcast",
      algoRef: "Eq 3.69",
      category: "blockchain",
      drillable: true,
    }),
    n("bc-cpdetect", 620, 340, {
      label: "CP-DETECT",
      subtitle: "conflict_j = (1 − flag^ctrl)·flag^rsu → exclude + update C_trusted(t)",
      algoRef: "Algorithm 9",
      category: "blockchain",
      drillable: true,
    }),
  ],
  edges: [
    e("bc-e1", "bc-register", "bc-trust"),
    e("bc-e2a", "bc-trust", "bc-revoke"),
    e("bc-e2b", "bc-trust", "bc-cpdetect"),
  ],
};

// ── LEVEL 2D — KEY MANAGEMENT, CRYPTOGRAPHIC SETUP & DYNAMIC REASSIGNMENT ──
// Verified against report/main.tex + the real source (research pass, see
// this component's own commit message): the FHE keypair is generated by a
// genuine Joint-Feldman VSS DKG among the RSU ring (+ Cloud) — no dealer,
// no single party ever holds sk_FHE (Eq 3.25-3.26; real EC math in
// 06b1_trs_backend.h, confirmed not a stub). The LKH tree and its session-
// key KDF are equally real (Eq 3.22-3.24; 00_lkh_keys.h). One honest gap:
// the paper's own claim that RSUs publish DKG commitments to the
// blockchain as a public bulletin board (§3.5.2.4) has NO chaincode
// implementation today — DKG_RING_KEYS.md lists it as an open TODO. That
// edge is drawn dashed/muted and labeled as planned, not verified, rather
// than silently presented as working.
export const keyManagementGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("km-veh", 20, 40, {
      label: "Vehicle",
      subtitle: "Holds a per-session key K_i, re-derived at every RSU handoff",
      category: "vehicle",
    }),
    n("km-rsu", 440, 40, {
      label: "RSU Node",
      subtitle: "Embeds the LKH tree — leaf-key & session-key derivation",
      algoRef: "Eq 3.22–3.24",
      category: "rsu",
      drillable: true,
    }),
    n("km-ring", 860, 40, {
      label: "RSU Ring",
      subtitle: "Joint-Feldman VSS peers — no dealer, no single point of trust",
      algoRef: "Eq 3.25–3.26",
      category: "crypto",
      drillable: true,
    }),
    n("km-cloud", 1280, 40, {
      label: "Cloud",
      subtitle: "FHE-DKG participant — holds one decryption share, sk_cloud^share",
      category: "cloud",
    }),
    n("km-chain", 660, 460, {
      label: "Blockchain",
      subtitle: "SC-Register · SC-Revoke · trust registry — defines C_trusted(t)",
      algoRef: "Eq 3.1 · Algorithm 8",
      category: "blockchain",
      drillable: true,
    }),
    n("km-ctrl-a", 1040, 460, {
      label: "Controller A",
      subtitle: "Active — Full Mode fusion authority for its RSU set",
      category: "ai",
    }),
    n("km-ctrl-b", 1400, 460, {
      label: "Controller B",
      subtitle: "Standby — trusted successor, τ_c > τ_min",
      category: "ai",
    }),
  ],
  edges: [
    // Labels kept short (equation numbers live on the node badge itself, or
    // in the drilled-down flowchart/pseudocode) — a full formula on an edge
    // label between closely-spaced nodes was confirmed to overlap neighboring
    // node text (verified via a live screenshot before this fix).
    e("km-e1", "km-veh", "km-rsu", { label: "K_i via LKH" }),
    e("km-e2", "km-rsu", "km-ring", { label: "DKG peer set", style: { stroke: "#10b981", strokeWidth: 1.5 } }),
    e("km-e3", "km-ring", "km-cloud", { label: "FHE-DKG + Cloud", style: { stroke: "#10b981", strokeWidth: 1.5 } }),
    e("km-e4", "km-ring", "km-chain", {
      label: "commitments (planned)",
      style: { stroke: "#64748b", strokeWidth: 1.5, strokeDasharray: "4 3" },
    }),
    e("km-e5", "km-rsu", "km-chain", { label: "SC-Register", style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
    e("km-e6", "km-ctrl-a", "km-rsu", { label: "active control" }),
    e("km-e7", "km-ctrl-b", "km-rsu", { label: "standby", style: { stroke: "#475569", strokeWidth: 1.5, strokeDasharray: "4 3" } }),
    e("km-e8", "km-ctrl-a", "km-chain", { label: "SC-Revoke", style: { stroke: "#f43f5e", strokeWidth: 1.5 } }),
    e("km-e9", "km-chain", "km-rsu", { label: "C_trusted(t)", style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
  ],
};

export const LEVEL2_GRAPHS: Record<string, { nodes: ArchNode[]; edges: Edge[] }> = {
  LIGHTWEIGHT_MODE: lightweightGraph,
  FULL_MODE: fullModeGraph,
  BLOCKCHAIN_LAYER: blockchainGraph,
  KEY_MANAGEMENT: keyManagementGraph,
};

// ── LEVEL 3 — ALGORITHM DETAIL FLOWCHARTS ───────────────────────────────

const tpDetectGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("tp-in", 20, 260, { label: "Windowed beacon b_i(t)", category: "rsu" }),
    n("tp-s1", 280, 40, { label: "TP-S1: kinematic feasibility", category: "rsu" }, "decision"),
    n("tp-s2", 280, 190, { label: "TP-S2: heading-rate bound", category: "rsu" }, "decision"),
    n("tp-s3", 280, 340, { label: "TP-S3: acceleration bound", category: "rsu" }, "decision"),
    n("tp-s4", 560, 115, { label: "TP-S4: cumulative drift residual", category: "rsu" }, "decision"),
    n("tp-s5", 560, 340, { label: "TP-S5: drift vs threshold δ_th", category: "rsu" }, "decision"),
    n("tp-pass", 840, 40, { label: "PASS — no signature tripped", category: "generic" }),
    n("tp-alert", 840, 340, { label: "ALERT — TP signature violated", category: "alert" }),
    n("tp-evidence", 1080, 340, { label: "Submit E_j(t) to blockchain", category: "blockchain" }),
  ],
  edges: [
    e("tp-e1", "tp-in", "tp-s1"),
    e("tp-e2", "tp-in", "tp-s2"),
    e("tp-e3", "tp-in", "tp-s3"),
    e("tp-e4a", "tp-s1", "tp-alert", { label: "violated", style: { stroke: "#f43f5e" } }),
    e("tp-e4b", "tp-s1", "tp-s4", { label: "ok", style: { stroke: "#22c55e" } }),
    e("tp-e5a", "tp-s2", "tp-alert", { label: "violated", style: { stroke: "#f43f5e" } }),
    e("tp-e5b", "tp-s2", "tp-s4", { label: "ok", style: { stroke: "#22c55e" } }),
    e("tp-e6a", "tp-s3", "tp-alert", { label: "violated", style: { stroke: "#f43f5e" } }),
    e("tp-e6b", "tp-s3", "tp-s5", { label: "ok", style: { stroke: "#22c55e" } }),
    e("tp-e7", "tp-s4", "tp-pass"),
    e("tp-e8a", "tp-s5", "tp-alert", { label: "> δ_th", style: { stroke: "#f43f5e" } }),
    e("tp-e8b", "tp-s5", "tp-pass", { label: "≤ δ_th", style: { stroke: "#22c55e" } }),
    e("tp-e9", "tp-alert", "tp-evidence", { style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
  ],
};

const sybDetectGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("syb-in", 20, 220, { label: "Vehicle registration density", category: "rsu" }),
    n("syb-s1", 280, 40, { label: "MP-S1: compromised-RSU Sybil bound K_sybil", category: "rsu" }, "decision"),
    n("syb-s2", 280, 220, { label: "MP-S2: vehicle-side impersonation pattern", category: "rsu" }, "decision"),
    n("syb-s4", 280, 400, { label: "MP-S4: control-plane Sybil-like injection", category: "rsu" }, "decision"),
    n("syb-pass", 620, 40, { label: "PASS", category: "generic" }),
    n("syb-alert", 620, 300, { label: "ALERT — Sybil signature violated", category: "alert" }),
    n("syb-evidence", 900, 300, { label: "Submit E_j(t) to blockchain", category: "blockchain" }),
  ],
  edges: [
    e("syb-e1", "syb-in", "syb-s1"),
    e("syb-e2", "syb-in", "syb-s2"),
    e("syb-e3", "syb-in", "syb-s4"),
    e("syb-e4a", "syb-s1", "syb-alert", { label: "violated", style: { stroke: "#f43f5e" } }),
    e("syb-e4b", "syb-s1", "syb-pass", { label: "ok", style: { stroke: "#22c55e" } }),
    e("syb-e5a", "syb-s2", "syb-alert", { label: "violated", style: { stroke: "#f43f5e" } }),
    e("syb-e5b", "syb-s2", "syb-pass", { label: "ok", style: { stroke: "#22c55e" } }),
    e("syb-e6a", "syb-s4", "syb-alert", { label: "violated", style: { stroke: "#f43f5e" } }),
    e("syb-e6b", "syb-s4", "syb-pass", { label: "ok", style: { stroke: "#22c55e" } }),
    e("syb-e7", "syb-alert", "syb-evidence", { style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
  ],
};

const mitmDetectGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("mitm-in", 20, 180, { label: "Beacon + claimed HMAC", category: "rsu" }),
    n("mitm-gate", 280, 180, { label: "HMAC gate: MAC valid?", algoRef: "Eq 3.42", category: "rsu" }, "decision"),
    n("mitm-s3", 560, 60, { label: "MP-S3: speed-distribution KL-divergence", category: "rsu" }, "decision"),
    n("mitm-resid", 560, 300, { label: "Residual check vs recent window", category: "rsu" }, "decision"),
    n("mitm-pass", 840, 60, { label: "PASS", category: "generic" }),
    n("mitm-alert", 840, 300, { label: "ALERT — MitM relay suspected", category: "alert" }),
    n("mitm-evidence", 1080, 300, { label: "Submit E_j(t) to blockchain", category: "blockchain" }),
  ],
  edges: [
    e("mitm-e1", "mitm-in", "mitm-gate"),
    e("mitm-e2a", "mitm-gate", "mitm-alert", { label: "fails immediately", style: { stroke: "#f43f5e" } }),
    e("mitm-e2b", "mitm-gate", "mitm-s3", { label: "valid", style: { stroke: "#22c55e" } }),
    e("mitm-e3", "mitm-gate", "mitm-resid", { label: "valid", style: { stroke: "#22c55e" } }),
    e("mitm-e4a", "mitm-s3", "mitm-alert", { label: "D_KL > κ_th", style: { stroke: "#f43f5e" } }),
    e("mitm-e4b", "mitm-s3", "mitm-pass", { label: "ok", style: { stroke: "#22c55e" } }),
    e("mitm-e5a", "mitm-resid", "mitm-alert", { label: "anomalous", style: { stroke: "#f43f5e" } }),
    e("mitm-e5b", "mitm-resid", "mitm-pass", { label: "ok", style: { stroke: "#22c55e" } }),
    e("mitm-e6", "mitm-alert", "mitm-evidence", { style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
  ],
};

const cpDetectGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("cp-ctrl", 20, 80, { label: "Controller's own decision", subtitle: "flag^ctrl = 1[Φ_i(t) > Φ_th]", algoRef: "Eq 3.70", category: "ai" }),
    n("cp-rsu", 20, 320, { label: "RSU's independent view", subtitle: "flag^rsu — this RSU's own ψ/Φ read", category: "rsu" }),
    n("cp-conflict", 300, 200, {
      label: "Directional conflict",
      subtitle: "conflict_j = (1 − flag^ctrl)·flag^rsu",
      algoRef: "Eq 3.72",
      category: "blockchain",
    }, "decision"),
    n("cp-quorum", 580, 200, {
      label: "Σ conflict ≥ f+1 witnesses?",
      subtitle: "Aggregate flag over observing RSU set",
      algoRef: "Eq 3.73",
      category: "blockchain",
    }, "decision"),
    n("cp-clean", 860, 60, { label: "No flag — controller stays trusted", category: "generic" }),
    n("cp-exclude", 860, 340, {
      label: "Exclude controller",
      subtitle: "Successor = lowest-numbered ACTIVE controller; refuses if it would empty C_trusted",
      category: "alert",
    }),
    n("cp-reassign", 1120, 340, { label: "Update C_trusted(t), reassign RSUs", category: "blockchain" }),
  ],
  edges: [
    e("cp-e1", "cp-ctrl", "cp-conflict"),
    e("cp-e2", "cp-rsu", "cp-conflict"),
    e("cp-e3", "cp-conflict", "cp-quorum"),
    e("cp-e4a", "cp-quorum", "cp-clean", { label: "no", style: { stroke: "#22c55e" } }),
    e("cp-e4b", "cp-quorum", "cp-exclude", { label: "yes", style: { stroke: "#f43f5e" } }),
    e("cp-e5", "cp-exclude", "cp-reassign", { style: { stroke: "#a855f7", strokeWidth: 1.5 } }),
  ],
};

const pqFheTrsGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("pq-enc", 20, 180, { label: "Each RSU encrypts local aggregate", subtitle: "c_j = Enc(pk_FHE, A_j(t))", algoRef: "Eq 3.51", category: "crypto" }),
    n("pq-add", 300, 180, { label: "Homomorphic addition", subtitle: "Combine ciphertexts, no decryption", category: "crypto" }),
    n("pq-sign", 580, 180, {
      label: "Threshold ring signing",
      subtitle: "ML-DSA-87 (Dilithium5), signing subset t_sign = f+1",
      category: "crypto",
    }),
    n("pq-cloud", 860, 180, { label: "Cloud collects signed aggregate", category: "cloud" }),
    n("pq-decrypt", 1120, 180, {
      label: "Threshold decryption",
      subtitle: "t_decrypt = f+2 shares required",
      algoRef: "Algorithm 7 (THRESH-DEC)",
      category: "crypto",
    }),
  ],
  edges: [
    e("pq-e1", "pq-enc", "pq-add", { style: { stroke: "#10b981", strokeWidth: 1.5 } }),
    e("pq-e2", "pq-add", "pq-sign", { style: { stroke: "#10b981", strokeWidth: 1.5 } }),
    e("pq-e3", "pq-sign", "pq-cloud", { style: { stroke: "#10b981", strokeWidth: 1.5 } }),
    e("pq-e4", "pq-cloud", "pq-decrypt", { style: { stroke: "#10b981", strokeWidth: 1.5 } }),
  ],
};

// SC-Revoke has no dedicated "Algorithm N" environment in the paper (grep
// confirmed: no \label{alg:sc_revoke} exists) — it's specified entirely in
// prose + a sequence of equations (Eq 3.59/3.60 evidence tuples, Eq 3.69 the
// BFT quorum condition). This flowchart is a faithful synthesis of that real
// process (witness vote -> distinct-RSU count -> quorum compare -> CRL
// broadcast), not an invented one — see the pseudocode panel for the actual
// source prose/equations this reconstructs.
const scRevokeGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("sr-vote", 20, 60, {
      label: "RSU casts evidence vote",
      subtitle: "E_j(t) = (ID_i, ψ_j^(i)(t), t, h(b_i(t)), σ_j^sub) — submitted directly on-chain, bypasses controller",
      category: "rsu",
    }),
    n("sr-ctrl-vote", 20, 260, {
      label: "Controller's supplementary vote (optional)",
      subtitle: "E_c(t) — one additional peer vote, never a prerequisite for revocation",
      category: "ai",
    }),
    n("sr-count", 320, 160, {
      label: "Count distinct trusted RSU witnesses",
      subtitle: "Each RSU counted at most once within window T_w, regardless of repeat submissions",
      category: "blockchain",
    }),
    n("sr-quorum", 600, 160, {
      label: "Count ≥ 2f+1 ?",
      subtitle: "Eq 3.69 BFT revocation condition",
      category: "blockchain",
    }, "decision"),
    n("sr-wait", 860, 40, { label: "Keep accumulating", subtitle: "Window T_w still open — wait for more witnesses", category: "generic" }),
    n("sr-revoke", 860, 300, {
      label: "Emit Revoke(ID_i)",
      subtitle: "Signed CRL-Update broadcast directly to all RSUs — no controller relay",
      category: "alert",
    }),
  ],
  edges: [
    e("sr-e1", "sr-vote", "sr-count"),
    e("sr-e2", "sr-ctrl-vote", "sr-count", { style: { strokeDasharray: "4 3" } }),
    e("sr-e3", "sr-count", "sr-quorum"),
    e("sr-e4a", "sr-quorum", "sr-wait", { label: "no", style: { stroke: "#22c55e" } }),
    e("sr-e4b", "sr-quorum", "sr-revoke", { label: "yes", style: { stroke: "#f43f5e" } }),
  ],
};

// Algorithm 8 (SC-Register), pseudocode-faithful.
const scRegisterGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("sreg-in", 20, 160, { label: "Registration request", subtitle: "ID_i, pk_i, h(K_ui), {σ_j^endorse}", category: "blockchain" }),
    n("sreg-dup", 300, 160, { label: "ID_i already on-chain?", category: "blockchain" }, "decision"),
    n("sreg-reject-dup", 560, 40, { label: "Reject — duplicate identity", category: "alert" }),
    n("sreg-count", 560, 260, {
      label: "Count verified RSU endorsements",
      subtitle: "n_endorse = Σ 1[Verify(pk_j, ID_i‖pk_i‖h(K_ui), σ_j^endorse)]",
      category: "blockchain",
    }),
    n("sreg-quorum", 840, 260, { label: "n_endorse ≥ 2f+1 ?", category: "blockchain" }, "decision"),
    n("sreg-reject-quorum", 1100, 140, { label: "Reject — insufficient endorsements", category: "alert" }),
    n("sreg-commit", 1100, 380, {
      label: "Commit to ledger",
      subtitle: "(ID_i, pk_i, h(K_ui), t_reg); τ_i ← τ_init, status ← ACTIVE",
      category: "blockchain",
    }),
    n("sreg-emit", 1360, 380, { label: "Emit Registered(ID_i, t_reg)", category: "blockchain" }),
  ],
  edges: [
    e("sreg-e1", "sreg-in", "sreg-dup"),
    e("sreg-e2a", "sreg-dup", "sreg-reject-dup", { label: "yes", style: { stroke: "#f43f5e" } }),
    e("sreg-e2b", "sreg-dup", "sreg-count", { label: "no", style: { stroke: "#22c55e" } }),
    e("sreg-e3", "sreg-count", "sreg-quorum"),
    e("sreg-e4a", "sreg-quorum", "sreg-reject-quorum", { label: "no", style: { stroke: "#f43f5e" } }),
    e("sreg-e4b", "sreg-quorum", "sreg-commit", { label: "yes", style: { stroke: "#22c55e" } }),
    e("sreg-e5", "sreg-commit", "sreg-emit"),
  ],
};

// RSU Ring / FHE distributed key generation — Joint-Feldman VSS, no dealer.
// Real EC math confirmed in 06b1_trs_backend.h:211-360 (BN_rand_range per-
// party polynomials, Feldman commitments, share verification). No dedicated
// "Algorithm N" environment exists for this in the paper (it's specified in
// prose, §3.5.2.4) — only the two generation equations, 3.25 and 3.26. The
// "publish commitments to chain" step is drawn but explicitly marked
// unimplemented — DKG_RING_KEYS.md's own TODO list confirms it, and this
// component would misrepresent the system if that gap weren't shown.
const dkgKeygenGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("dkg-init", 20, 180, { label: "RSU Ring init", subtitle: "Each RSU samples its own polynomial f_j(x) — no shared seed, no dealer", category: "crypto" }),
    n("dkg-commit", 300, 40, { label: "Broadcast Feldman commitments", subtitle: "C_{j,k} = a_{j,k}·G, k=0..t_sign−1", category: "crypto" }),
    n("dkg-share", 300, 320, { label: "Exchange encrypted shares", subtitle: "s_{j→i} = f_j(i), sent peer-to-peer", category: "crypto" }),
    n("dkg-verify", 600, 180, { label: "Share matches its commitment?", category: "crypto" }, "decision"),
    n("dkg-fail", 900, 20, { label: "Complaint — sender excluded, round retries", category: "alert" }),
    n("dkg-agg", 900, 320, {
      label: "Aggregate shares",
      subtitle: "master_pk = Σ C_{j,0}; each RSU retains sk_j^share locally",
      algoRef: "Eq 3.25",
      category: "crypto",
    }),
    n("dkg-fhe", 1180, 320, {
      label: "FHE-DKG extension",
      subtitle: "Repeat with Cloud as an (n+1)-th party → pk_FHE, sk_j^share, sk_cloud^share, evk",
      algoRef: "Eq 3.26",
      category: "crypto",
    }),
    n("dkg-done", 1460, 320, { label: "sk_FHE never assembled anywhere", subtitle: "Only pk_FHE and {pk_j} are made public", category: "generic" }),
    n("dkg-chain", 1460, 60, {
      label: "Publish commitments to blockchain",
      subtitle: "Paper-specified public bulletin board (§3.5.2.4) — NOT wired in this codebase (DKG_RING_KEYS.md: open TODO)",
      category: "blockchain",
    }),
  ],
  edges: [
    e("dkg-e1", "dkg-init", "dkg-commit"),
    e("dkg-e2", "dkg-init", "dkg-share"),
    e("dkg-e3a", "dkg-commit", "dkg-verify"),
    e("dkg-e3b", "dkg-share", "dkg-verify"),
    e("dkg-e4a", "dkg-verify", "dkg-fail", { label: "invalid", style: { stroke: "#f43f5e" } }),
    e("dkg-e4b", "dkg-verify", "dkg-agg", { label: "valid", style: { stroke: "#22c55e" } }),
    e("dkg-e5", "dkg-agg", "dkg-fhe"),
    e("dkg-e6", "dkg-fhe", "dkg-done"),
    e("dkg-e7", "dkg-commit", "dkg-chain", { label: "planned, not implemented", style: { stroke: "#64748b", strokeDasharray: "4 3" } }),
  ],
};

// Logical Key Hierarchy — real tree + real KDF, confirmed in 00_lkh_keys.h.
// AB11 is a dedicated ablation that swaps LKH for flat unicast rekeying
// specifically to isolate this O(log n) claim, not just assert it.
const lkhRekeyGraph: { nodes: ArchNode[]; edges: Edge[] } = {
  nodes: [
    n("lkh-tree", 20, 200, { label: "LKH binary tree", subtitle: "Leaves = vehicles/RSUs; K_root = shared group key", category: "rsu" }),
    n("lkh-event", 300, 200, { label: "Vehicle joins or leaves?", category: "rsu" }, "decision"),
    n("lkh-leaf", 600, 40, { label: "Assign leaf key K_leaf", subtitle: "New leaf inserted into the tree", category: "rsu" }),
    n("lkh-path", 860, 40, { label: "Key-set along path to root", subtitle: "K_ei = {K_u : u ∈ path(u_i→root)}", algoRef: "Eq 3.22", category: "rsu" }),
    n("lkh-session", 1120, 40, { label: "Derive session key", subtitle: "K_i = KDF(K_leaf, η_i, ID_i) — HKDF-SHA256", algoRef: "Eq 3.23", category: "crypto" }),
    n("lkh-leave", 600, 360, { label: "Remove leaf, rekey ancestors", category: "rsu" }),
    n("lkh-cost", 860, 360, {
      label: "Only O(log2|V|) keys change",
      subtitle: "N_rekey = log2|V_j| vs O(n) for flat unicast rekeying",
      algoRef: "Eq 3.24",
      category: "rsu",
    }),
    n("lkh-ablation", 1120, 360, { label: "AB11 isolates this claim", subtitle: "Swaps LKH for unicast rekeying to measure the real cost difference", category: "generic" }),
  ],
  edges: [
    e("lkh-e1", "lkh-tree", "lkh-event"),
    e("lkh-e2a", "lkh-event", "lkh-leaf", { label: "joins", style: { stroke: "#22c55e" } }),
    e("lkh-e2b", "lkh-event", "lkh-leave", { label: "leaves", style: { stroke: "#f43f5e" } }),
    e("lkh-e3", "lkh-leaf", "lkh-path"),
    e("lkh-e4", "lkh-path", "lkh-session"),
    e("lkh-e5", "lkh-leave", "lkh-cost"),
    e("lkh-e6", "lkh-cost", "lkh-ablation"),
  ],
};

export const ALGO_DETAIL_GRAPHS: Record<Exclude<SubFlow, null>, { nodes: ArchNode[]; edges: Edge[]; title: string; algoRef: string }> = {
  TP_DETECT: { ...tpDetectGraph, title: "TP-DETECT — Trajectory Poisoning Detection", algoRef: "Algorithm 2" },
  SYB_DETECT: { ...sybDetectGraph, title: "SYB-DETECT — Sybil Mobility Pattern Detection", algoRef: "Algorithm 3" },
  MITM_DETECT: { ...mitmDetectGraph, title: "MITM-DETECT — MitM Mobility Pattern Detection", algoRef: "Algorithm 4" },
  CP_DETECT: { ...cpDetectGraph, title: "CP-DETECT — Control-Plane Poisoning Detection", algoRef: "Algorithm 9" },
  PQ_FHE_TRS: { ...pqFheTrsGraph, title: "Pre-Coordination FHE + PQ-TRS Signing", algoRef: "Algorithm 6" },
  SC_REVOKE: { ...scRevokeGraph, title: "SC-Revoke — BFT Revocation Quorum", algoRef: "Eq 3.69" },
  SC_REGISTER: { ...scRegisterGraph, title: "SC-Register — Registration Smart Contract", algoRef: "Algorithm 8" },
  DKG_KEYGEN: { ...dkgKeygenGraph, title: "RSU Ring / FHE Key Generation — Distributed Key Generation", algoRef: "Eq 3.25–3.26" },
  LKH_REKEY: { ...lkhRekeyGraph, title: "Logical Key Hierarchy — Session Keys & Rekeying", algoRef: "Eq 3.22–3.24" },
};

// ── REAL ALGORITHM PSEUDOCODE ────────────────────────────────────────────
// Transcribed from report/main.tex's actual algorithm environments (cross-
// checked against the compiled PDF), not paraphrased from the flowchart
// nodes above — variable names, thresholds and step order match the thesis
// exactly. SC-Revoke has no \label{alg:sc_revoke} of its own (confirmed by
// grep); its "steps" here are the real prose/equation sequence from
// §3.5.5.3, synthesized into step form, not an invented Algorithm block.
export interface PseudocodeBlock {
  title: string;
  inputs?: string;
  output?: string;
  steps: string[];
}

export const ALGO_PSEUDOCODE: Record<Exclude<SubFlow, null>, PseudocodeBlock[]> = {
  TP_DETECT: [
    {
      title: "Algorithm 2 — TP-DETECT",
      inputs: "b_i(t), b_i(t−T_b), δ_th, k",
      output: "[viol₁, viol₂, viol₃, viol₄] — flag vector fed into ψ_i(t) in LW-DETECT",
      steps: [
        "TP-S1: viol₁ ← 1[ ‖p_i(t) − p_i(t−T_b)‖ > s_max · T_b ]",
        "TP-S2: viol₂ ← 1[ |θ_i(t) − θ_i(t−T_b)| > ω_max · T_b ]",
        "TP-S3: viol₃ ← 1[ |a_i(t)| > a_max ∨ s_i(t) > s_max ]",
        "Compute dead-reckoned position p̂_i(t) (Eq 3.14)",
        "Compute residual r_i(t) ← ‖p_i(t) − p̂_i(t)‖ (Eq 3.15, TP-S4)",
        "Update drift window D_i(k) ← (1/k) Σ_{j=1}^{k} r_i(t − (k−j)T_b) (Eq 3.16)",
        "TP-S5: viol₄ ← 1[ D_i(k) > δ_th ]",
        "return [viol₁, viol₂, viol₃, viol₄]",
      ],
    },
  ],
  SYB_DETECT: [
    {
      title: "Algorithm 3 — SYB-DETECT",
      inputs: "B_j(t), A_j, K_sybil, τ_sync, ρ_sync",
      output: "[viol₁, viol₂, viol₃] — flag vector fed into ψ_i(t) in LW-DETECT",
      steps: [
        "Extract identity set ID_j ← { ID_i : p_i(t) ∈ A_j }",
        "MP-S1: viol₁ ← 1[ |ID_j| > K_sybil + ρ_v · A_j ] (Eq 3.17)",
        "for each pair (ID_a, ID_b) ∈ ID_j² do",
        "  compute synchronization score (Eq 3.18)",
        "  if score > ρ_sync then viol₂ ← 1; flag pair as co-sourced",
        "MP-S4: ghost transit test via Eq 3.20 across neighbouring RSUs",
        "viol₃ ← 1[ ∃ ID_i failing ghost test ]",
        "return [viol₁, viol₂, viol₃]",
      ],
    },
  ],
  MITM_DETECT: [
    {
      title: "Algorithm 4 — MITM-DETECT",
      inputs: "b_i(t), K_i, κ_th, P_hist",
      output: "immediate ALERT_MITM(ID_i, MAC_FAIL) on HMAC failure, else [viol₁, viol₂]",
      steps: [
        "Verify HMAC: valid ← HMAC_{K_i}(b_i(t) ‖ t ‖ ID_i) (Eq 3.42)",
        "if ¬valid then return ALERT_MITM(ID_i, MAC_FAIL)",
        "Compute current regional speed distribution P_t from {s_i(t)} over the RSU's vehicles",
        "MP-S3: viol₁ ← 1[ D_KL(P_t ‖ P_hist) > κ_th ] (Eq 3.19)",
        "Run TP-S4 residual check on modified fields (Eq 3.15)",
        "viol₂ ← 1[ r_i(t) > δ_th ]",
        "return [viol₁, viol₂]",
      ],
    },
  ],
  PQ_FHE_TRS: [
    {
      title: "Algorithm 6 — Pre-Coordination FHE Encryption and PQ-TRS Signing",
      inputs: "V_j(t), R, {sk_j}, sk_j^share, pk_FHE, evk, t",
      output: "σ_TRS, Enc(A_ring)",
      steps: [
        "Compute local plaintext aggregate A_j(t) (Eq 3.50)",
        "Pre-encryption range check against SUMO-derived bounds — abort and log to SC-Trust on anomaly",
        "Encrypt local aggregate: c_j ← Enc(pk_FHE, A_j(t)) (Eq 3.51)",
        "Broadcast c_j to all ring peers r_k ∈ S, k ≠ j; receive {c_k} in return",
        "Combine: Enc(A_ring) ← ⊕_{j∈S} c_j (Eq 3.52)",
        "Form TRS message m ← (Enc(A_ring), t, ν_S, ID_S, h(S)) (Eq 3.53)",
        "for each r_j ∈ S: σ_j ← Sign(sk_j, m) (Eq 3.54)",
        "σ_TRS ← Aggregate({σ_j}) (Eq 3.55)",
        "Transmit (Enc(A_ring), σ_TRS) to cloud; return σ_TRS, Enc(A_ring)",
      ],
    },
    {
      title: "Algorithm 7 — THRESH-DEC (Threshold FHE Decryption at RSU Cluster)",
      inputs: "Enc(X̄_global), {sk_e^share}_{e∈D}, t_decrypt   (D ⊆ R ∪ {Cloud}; Cloud not mandatory)",
      output: "X̄_global — the accepted or last-valid-reused global aggregate",
      steps: [
        "if |D| < t_decrypt then abort — insufficient shares for decryption",
        "for each e ∈ D: pd_e ← PDec(sk_e^share, Enc(X̄_global)) (Eq 3.61); broadcast pd_e to peers",
        "X̄_global ← ThDec({pd_e}) (Eq 3.62)",
        "if X̄_global ∈ [L^SUMO, U^SUMO] then accept as X̄_global^valid",
        "else log aggregate anomaly to SC-Trust (best-effort) and reuse last valid window instead",
        "return X̄_global",
      ],
    },
  ],
  SC_REGISTER: [
    {
      title: "Algorithm 8 — SC-Register",
      inputs: "ID_i, pk_i, h(K_ui), {σ_j^endorse}_{j∈S}",
      output: "ledger commit + Registered(ID_i, t_reg) event, or a rejection",
      steps: [
        "if ID_i already exists on-chain then reject — duplicate identity",
        "n_endorse ← Σ_{r_j∈R} 1[ Verify(pk_j, ID_i‖pk_i‖h(K_ui), σ_j^endorse) ]",
        "if n_endorse < 2f+1 then reject — insufficient RSU endorsements",
        "Commit (ID_i, pk_i, h(K_ui), t_reg) to ledger",
        "Set τ_i ← τ_init, status_i ← ACTIVE",
        "emit Registered(ID_i, t_reg)",
      ],
    },
  ],
  SC_REVOKE: [
    {
      title: "SC-Revoke — Revocation Smart Contract (§3.5.5.3; no dedicated Algorithm block in the paper)",
      inputs: "Per-RSU evidence tuples E_j(t) submitted directly on-chain",
      output: "Revoke(ID_i) + signed CRL-Update broadcast to all RSUs, once quorum is reached",
      steps: [
        "Each RSU r_j that observes ψ_j^(i)(t') > ψ_th for vehicle v_i within [t−T_w, t] casts a signed evidence vote E_j(t) = (ID_i, ψ_j^(i)(t), t, h(b_i(t)), σ_j^sub) directly on-chain — bypasses the controller entirely",
        "Controller may optionally submit a supplementary vote E_c(t) = (ID_i, Φ_i(t), t, h(X_i(t)), σ_c^sub) — counted as one additional peer vote, never a prerequisite",
        "Count DISTINCT trusted RSUs that flagged ID_i anywhere within T_w — each RSU counted at most once, regardless of repeat submissions (prevents one malicious RSU inflating the count)",
        "Revocation condition (Eq 3.69): |{ r_j ∈ R_trusted(t) : ∃t'∈[t−T_w,t], ψ_j^(i)(t') > ψ_th }| ≥ 2f+1 ⟹ emit Revoke(ID_i)",
        "On revoke: broadcast a signed CRL-Update directly to all RSUs — no controller relay",
        "Parallel controller-compromise path (shares this infrastructure): flag_c = 1[ Σ_{r_j} conflict_j(t) ≥ f+1 ] (Eq 3.73) — if set, exclude the controller's evidence and reassign RSUs to C_trusted(t)",
      ],
    },
  ],
  CP_DETECT: [
    {
      title: "Algorithm 9 — CP-DETECT",
      inputs: "A_j(t), σ_TRS, {pk_j}, {E_j(t)}_{r_j∈R}",
      output: "early return on TRS failure, or return ALERT_CP(ID_c, CTRL_COMPROMISED), or return PASS",
      steps: [
        "Verify TRS at RSU level: valid ← Verify({pk_j}, m_j, σ_TRS) (Eq 3.56)",
        "if ¬valid then RSUs emit ALERT_CP(ID_{r_j}, TRS_FAIL) directly to blockchain; return",
        "Retrieve controller submission E_c(t) from blockchain",
        "For each r_j ∈ R: conflict_j(t) = (1 − flag_i^ctrl) · flag_i^{rsu,j} (Eq 3.72)",
        "Compute aggregate flag_c (Eq 3.73)",
        "if flag_c = 1 then SC-Revoke excludes E_c(t) from consensus; RSUs reassign to C_trusted(t) (Eq 3.1), no manual failover; return ALERT_CP(ID_c, CTRL_COMPROMISED)",
        "else return PASS",
      ],
    },
  ],
  DKG_KEYGEN: [
    {
      title: "RSU Ring / FHE Key Generation — Distributed Key Generation (§3.5.2.4; no dedicated Algorithm block in the paper)",
      inputs: "Ring R of n RSUs (+ Cloud for the FHE extension), signing threshold t_sign, decryption threshold t_decrypt",
      output: "{sk_j, pk_j}_{j=1}^n (Eq 3.25) and (pk_FHE, {sk_j^share}, sk_cloud^share, evk) (Eq 3.26) — sk_FHE is never assembled at any single party",
      steps: [
        "Each RSU r_j samples its own random polynomial f_j(x) of degree t_sign−1 — no shared seed, no dealer",
        "r_j broadcasts Feldman commitments C_{j,k} = a_{j,k}·G for k = 0..t_sign−1",
        "r_j sends an encrypted share s_{j→i} = f_j(i) to every peer r_i",
        "Each recipient verifies s_{j→i} against r_j's published commitments; a mismatch raises a complaint, excludes r_j, and the round retries",
        "{sk_j, pk_j} ← ({verified shares}, Σ C_{j,0}) once all n parties' shares check out (Eq 3.25)",
        "Repeat the same protocol with Cloud included as an (n+1)-th party to additionally derive (pk_FHE, {sk_j^share}, sk_cloud^share, evk) under threshold t_decrypt (Eq 3.26)",
        "Verified in code: scratch/mptd_pqs_sdvn/06b1_trs_backend.h:211-360 implements this as real Joint-Feldman VSS EC math — not a stub — but the RSU parties currently run in-process within one ns-3 simulation, not over the network",
        "NOT yet implemented: publishing commitments to the blockchain as a public bulletin board — the paper specifies this (§3.5.2.4); scratch/mptd_pqs_sdvn/DKG_RING_KEYS.md lists it as an open TODO",
      ],
    },
  ],
  LKH_REKEY: [
    {
      title: "Group Key Management via Logical Key Hierarchy (§3.5.2; no dedicated Algorithm block in the paper)",
      inputs: "Vehicle/RSU set V_j at an RSU, a join/leave event, nonce η_i",
      output: "K_i — the vehicle's session key (used directly for beacon HMAC tagging, Eq 3.42) and, on a leave event, a rekeyed tree",
      steps: [
        "Maintain a balanced binary key tree per RSU: leaves are vehicles/RSUs, internal nodes are key-encrypting keys, the root key K_root is the shared group key",
        "On join: assign the new member a leaf key K_leaf",
        "Key-set along its path to the root: K_ei = {K_u : u ∈ path(u_i→root)} (Eq 3.22)",
        "Session key: K_i = KDF(K_leaf, η_i, ID_i) (Eq 3.23) — HKDF-SHA256 per the paper; computed for real in scratch/mptd_pqs_sdvn/00_lkh_keys.h's lkh_compute_session_key()",
        "On leave: remove the leaf and rekey only the ancestor keys on its path to the root",
        "Rekey cost: N_rekey = log2|V_j| (Eq 3.24) — versus O(n) for a flat unicast rekey to every remaining member",
        "AB11 ablation (swap LKH for unicast rekeying) isolates and measures this cost claim directly rather than asserting it",
      ],
    },
  ],
};

// ── SIMULATION SCENARIOS ─────────────────────────────────────────────────
export interface SimStep {
  view: Exclude<ViewName, "ABSTRACT" | "ALGO_DETAIL">;
  caption: string;
  evaluating: string[];
  pass: string[];
  flagged: string[];
  activeEdges: string[];
}

export interface Scenario {
  label: string;
  description: string;
  steps: SimStep[];
}

export const SCENARIOS: Record<ScenarioName, Scenario> = {
  NORMAL: {
    label: "Normal traffic",
    description: "An honest vehicle's beacon passes every gate cleanly.",
    steps: [
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "Beacon arrives, HMAC verified.",
        evaluating: ["lw-hmac"],
        pass: ["lw-ingest"],
        flagged: [],
        activeEdges: ["lw-e1"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "All three rule-based detectors evaluate the window in parallel.",
        evaluating: ["lw-tp", "lw-syb", "lw-mitm"],
        pass: ["lw-hmac"],
        flagged: [],
        activeEdges: ["lw-e2a", "lw-e2b", "lw-e2c"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "No signature trips. Composite score ψ_i(t) stays near zero.",
        evaluating: ["lw-scorer"],
        pass: ["lw-tp", "lw-syb", "lw-mitm"],
        flagged: [],
        activeEdges: ["lw-e3a", "lw-e3b", "lw-e3c"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "ψ_i(t) ≤ ψ_th — the beacon passes and is forwarded normally.",
        evaluating: ["lw-gate"],
        pass: ["lw-scorer", "lw-pass"],
        flagged: [],
        activeEdges: ["lw-e4", "lw-e5a"],
      },
      {
        view: "FULL_MODE",
        caption: "In parallel, the controller's Full Mode pipeline analyzes the same window — GAT and LSTM-AE both stay quiet.",
        evaluating: ["fm-gat", "fm-lstm"],
        pass: ["fm-ipfs"],
        flagged: [],
        activeEdges: ["fm-e1", "fm-e2"],
      },
      {
        view: "FULL_MODE",
        caption: "Φ_i(t) stays well under θ_Φ — corroborates the Lightweight pass. No evidence is submitted; nothing reaches the blockchain for this beacon.",
        evaluating: [],
        pass: ["fm-gat", "fm-lstm", "fm-fusion"],
        flagged: [],
        activeEdges: ["fm-e3"],
      },
    ],
  },
  TRAJECTORY_POISONING: {
    label: "Trajectory poisoning",
    description: "A falsified position survives single-beacon checks but violates cumulative drift.",
    steps: [
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "Beacon arrives with a plausible but falsified position.",
        evaluating: ["lw-hmac"],
        pass: ["lw-ingest"],
        flagged: [],
        activeEdges: ["lw-e1"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "TP-DETECT engages — early single-beacon gates (TP-S1..S3) look clean.",
        evaluating: ["lw-tp"],
        pass: ["lw-hmac", "lw-syb", "lw-mitm"],
        flagged: [],
        activeEdges: ["lw-e2a"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "TP-S5's cumulative drift residual crosses δ_th — TP-DETECT flags the vehicle.",
        evaluating: [],
        pass: [],
        flagged: ["lw-tp"],
        activeEdges: ["lw-e3a"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "ψ_i(t) exceeds ψ_th — ALERT, evidence submitted to the blockchain.",
        evaluating: ["lw-scorer", "lw-gate"],
        pass: [],
        flagged: ["lw-alert"],
        activeEdges: ["lw-e4", "lw-e5b"],
      },
      {
        view: "FULL_MODE",
        caption: "The same window also reaches the controller's Full Mode pipeline. GAT's spatial read is clean, but LSTM-AE's reconstruction error is already elevated from the drift.",
        evaluating: ["fm-lstm"],
        pass: ["fm-ipfs", "fm-gat"],
        flagged: [],
        activeEdges: ["fm-e1", "fm-e2"],
      },
      {
        view: "FULL_MODE",
        caption: "Φ_i(t) = λ_ψ·ψ̂ + λ_gat·Ŝ + λ_ae·ε̂ (Eq 3.48) crosses θ_Φ — Full Mode corroborates the Lightweight alert independently and submits its own evidence.",
        evaluating: [],
        pass: ["fm-lstm"],
        flagged: ["fm-fusion", "fm-evidence"],
        activeEdges: ["fm-e3", "fm-e4"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "Evidence lands on-chain. SC-Trust decays this vehicle's τ_i via its EMA update (Eq 3.63).",
        evaluating: ["bc-trust"],
        pass: ["bc-register"],
        flagged: [],
        activeEdges: ["bc-e1"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "The RSU that caught it casts a revoke-vote — the first of 2f+1 distinct-RSU witnesses SC-Revoke's quorum requires within window T_w (Eq 3.69).",
        evaluating: ["bc-revoke"],
        pass: ["bc-trust"],
        flagged: [],
        activeEdges: ["bc-e2a"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "A second, independent RSU witnesses the same vehicle inside T_w — quorum reached. SC-Revoke emits a CRL broadcast; the vehicle is revoked network-wide.",
        evaluating: [],
        pass: [],
        flagged: ["bc-revoke"],
        activeEdges: ["bc-e2a"],
      },
    ],
  },
  SYBIL_ATTACK: {
    label: "Sybil impersonation",
    description: "A compromised RSU sustains ghost identities — caught by the relational signature, not a single beacon.",
    steps: [
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "Beacon arrives from a fabricated identity.",
        evaluating: ["lw-hmac"],
        pass: ["lw-ingest"],
        flagged: [],
        activeEdges: ["lw-e1"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "SYB-DETECT checks the ghost-identity density bound (MP-S1) and impersonation pattern (MP-S2).",
        evaluating: ["lw-syb"],
        pass: ["lw-hmac", "lw-tp", "lw-mitm"],
        flagged: [],
        activeEdges: ["lw-e2b"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "Ghost density exceeds K_sybil — SYB-DETECT flags the constellation.",
        evaluating: [],
        pass: [],
        flagged: ["lw-syb"],
        activeEdges: ["lw-e3b"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "ALERT — evidence submitted; the GAT spatial detector corroborates on the next full-mode pass.",
        evaluating: ["lw-scorer", "lw-gate"],
        pass: [],
        flagged: ["lw-alert"],
        activeEdges: ["lw-e4", "lw-e5b"],
      },
      {
        view: "FULL_MODE",
        caption: "The ghost constellation reaches Full Mode — GAT's attention over the vehicle-RSU graph (K=7 attack heads) sees what no single beacon reveals: implausible density, correlated kinematics.",
        evaluating: ["fm-gat"],
        pass: ["fm-ipfs"],
        flagged: [],
        activeEdges: ["fm-e1"],
      },
      {
        view: "FULL_MODE",
        caption: "GAT's spatial score S_i(t) drives Φ_i(t) over θ_Φ — corroborates SYB-DETECT independently, through a relational signal rules alone structurally cannot see.",
        evaluating: ["fm-lstm"],
        pass: ["fm-gat"],
        flagged: ["fm-fusion", "fm-evidence"],
        activeEdges: ["fm-e2", "fm-e3", "fm-e4"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "Evidence lands on-chain — SC-Trust decays the compromised RSU's τ_rj via its own misbehaviour-signal EMA (Eq 3.65-3.66).",
        evaluating: ["bc-trust"],
        pass: ["bc-register"],
        flagged: [],
        activeEdges: ["bc-e1"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "A first distinct RSU witness casts a revoke-vote against the compromised RSU — 1 of 2f+1 needed within T_w.",
        evaluating: ["bc-revoke"],
        pass: ["bc-trust"],
        flagged: [],
        activeEdges: ["bc-e2a"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "2f+1 distinct witnesses reached within T_w — SC-Revoke emits a CRL broadcast; the RSU is revoked and its ghost identities go with it.",
        evaluating: [],
        pass: [],
        flagged: ["bc-revoke"],
        activeEdges: ["bc-e2a"],
      },
    ],
  },
  MITM_ATTACK: {
    label: "MitM injection",
    description: "A relayed/altered beacon fails HMAC outright — the fastest possible rejection path.",
    steps: [
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "Beacon arrives with a tampered payload.",
        evaluating: ["lw-ingest"],
        pass: [],
        flagged: [],
        activeEdges: [],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "HMAC verification fails immediately — MITM-DETECT's fast-fail gate trips.",
        evaluating: ["lw-hmac", "lw-mitm"],
        pass: [],
        flagged: ["lw-mitm"],
        activeEdges: ["lw-e1", "lw-e2c"],
      },
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "No need to wait for the composite scorer — this fast-fails straight to ALERT. No Full Mode corroboration needed either; the failure is unambiguous at the RSU.",
        evaluating: [],
        pass: [],
        flagged: ["lw-alert"],
        activeEdges: ["lw-e3c", "lw-e5b"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "Evidence lands on-chain immediately — SC-Trust decays this identity's trust score.",
        evaluating: ["bc-trust"],
        pass: ["bc-register"],
        flagged: [],
        activeEdges: ["bc-e1"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "A first distinct RSU witness casts a revoke-vote — 1 of 2f+1 needed within T_w.",
        evaluating: ["bc-revoke"],
        pass: ["bc-trust"],
        flagged: [],
        activeEdges: ["bc-e2a"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "Quorum reached — SC-Revoke emits a CRL broadcast. The identity is revoked network-wide; no further beacons from it are accepted.",
        evaluating: [],
        pass: [],
        flagged: ["bc-revoke"],
        activeEdges: ["bc-e2a"],
      },
    ],
  },
  CONTROLLER_COMPROMISE: {
    label: "Malicious controller",
    description: "The RSU layer stays clean throughout — this attack lives entirely in the control plane, and only CP-DETECT can see it.",
    steps: [
      {
        view: "LIGHTWEIGHT_MODE",
        caption: "Beacon is genuinely honest and passes the RSU layer normally.",
        evaluating: ["lw-scorer"],
        pass: ["lw-hmac", "lw-tp", "lw-syb", "lw-mitm", "lw-pass"],
        flagged: [],
        activeEdges: ["lw-e4", "lw-e5a"],
      },
      {
        view: "FULL_MODE",
        caption: "The controller receives the same clean window — but its own decision Φ_i(t) is suppressed/falsified.",
        evaluating: ["fm-fusion"],
        pass: ["fm-ipfs", "fm-gat", "fm-lstm"],
        flagged: ["fm-evidence"],
        activeEdges: ["fm-e1", "fm-e2", "fm-e3", "fm-e4"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "CP-DETECT compares the controller's benign claim against a trusted RSU's own anomalous read for the same (vehicle, epoch).",
        evaluating: ["bc-cpdetect"],
        pass: ["bc-register", "bc-trust"],
        flagged: [],
        activeEdges: ["bc-e1", "bc-e2b"],
      },
      {
        view: "BLOCKCHAIN_LAYER",
        caption: "Directional conflict confirmed, quorum met — the controller is excluded and RSUs reassign to a trusted successor.",
        evaluating: [],
        pass: [],
        flagged: ["bc-cpdetect"],
        activeEdges: ["bc-e2b"],
      },
    ],
  },
};

// ── KEY MANAGEMENT SCENARIOS — separate from the SCENARIOS above (attack
// detection) since these walk the crypto-setup/registration/reassignment
// lifecycle, not the detection pipeline. Reuses the same Scenario/SimStep
// shape and statusesForStep() logic — everything here happens on the one
// KEY_MANAGEMENT view, so unlike SCENARIOS, no step ever needs to jump the
// canvas to a different view. ──────────────────────────────────────────────
export type KeyMgmtScenarioName = "DKG_SETUP" | "VEHICLE_REGISTRATION" | "CONTROLLER_REASSIGNMENT";

export const KEY_MGMT_SCENARIOS: Record<KeyMgmtScenarioName, Scenario> = {
  DKG_SETUP: {
    label: "Distributed key generation",
    description: "RSUs and the Cloud jointly generate keys — no central authority, no single point of trust.",
    steps: [
      {
        view: "KEY_MANAGEMENT",
        caption: "Each RSU in the ring samples its own polynomial independently — no dealer, no shared seed.",
        evaluating: ["km-ring"],
        pass: [],
        flagged: [],
        activeEdges: ["km-e2"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "Feldman commitments and encrypted shares are exchanged peer-to-peer; every share is checked against its sender's commitment.",
        evaluating: ["km-ring"],
        pass: [],
        flagged: [],
        activeEdges: ["km-e2"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "{sk_j, pk_j} generated per RSU (Eq 3.25) — verified; no single RSU ever holds the full secret.",
        evaluating: [],
        pass: ["km-ring"],
        flagged: [],
        activeEdges: [],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "The same protocol repeats with the Cloud included — deriving pk_FHE and per-party decryption shares sk_j^share / sk_cloud^share (Eq 3.26).",
        evaluating: ["km-cloud"],
        pass: ["km-ring"],
        flagged: [],
        activeEdges: ["km-e3"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "The paper specifies posting these commitments to the blockchain as a public bulletin board — this edge shows that intended path. It is NOT yet wired in code (confirmed: no chaincode function does this today).",
        evaluating: [],
        pass: ["km-cloud"],
        flagged: [],
        activeEdges: ["km-e4"],
      },
    ],
  },
  VEHICLE_REGISTRATION: {
    label: "Vehicle registration & LKH",
    description: "A vehicle derives a unique per-session key, then registers on-chain — later rekeying touches only O(log n) tree nodes.",
    steps: [
      {
        view: "KEY_MANAGEMENT",
        caption: "Vehicle moves into range of the RSU Node.",
        evaluating: ["km-veh"],
        pass: [],
        flagged: [],
        activeEdges: ["km-e1"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "Inside the RSU, the vehicle is assigned a leaf in the LKH tree; its key-set along the path to the root is fixed (Eq 3.22).",
        evaluating: ["km-rsu"],
        pass: ["km-veh"],
        flagged: [],
        activeEdges: [],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "Session key derived: K_i = KDF(K_leaf, η_i, ID_i) (Eq 3.23) — a real HKDF construction, not a placeholder.",
        evaluating: ["km-rsu"],
        pass: ["km-veh"],
        flagged: [],
        activeEdges: ["km-e1"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "K_i is handed to the vehicle and used directly for beacon HMAC tagging (Eq 3.42).",
        evaluating: [],
        pass: ["km-rsu", "km-veh"],
        flagged: [],
        activeEdges: ["km-e1"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "RSU submits SC-Register: identity, public key, and the leaf-key HASH h(K_ui) — needs 2f+1 RSU endorsement (Algorithm 8).",
        evaluating: ["km-chain"],
        pass: ["km-rsu"],
        flagged: [],
        activeEdges: ["km-e5"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "Registered on-chain. If this vehicle later leaves, only the O(log2|V|) path from its leaf to the root needs rekeying (Eq 3.24) — not the whole group.",
        evaluating: [],
        pass: ["km-chain"],
        flagged: [],
        activeEdges: [],
      },
    ],
  },
  CONTROLLER_REASSIGNMENT: {
    label: "Controller reassignment",
    description: "Automated failover when the active controller is compromised — no manual intervention.",
    steps: [
      {
        view: "KEY_MANAGEMENT",
        caption: "Controller A is compromised — CP-DETECT's directional conflict signal crosses threshold.",
        evaluating: [],
        pass: [],
        flagged: ["km-ctrl-a"],
        activeEdges: [],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "The SC-Revoke path triggers: RSU witnesses accumulate toward the 2f+1 BFT quorum over window T_w (Eq 3.69).",
        evaluating: ["km-chain"],
        pass: [],
        flagged: ["km-ctrl-a"],
        activeEdges: ["km-e8"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "The active control link to Controller A is excluded from consensus.",
        evaluating: ["km-rsu"],
        pass: [],
        flagged: ["km-ctrl-a"],
        activeEdges: [],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "RSU queries the ledger for C_trusted(t) — the set of controllers whose trust score still exceeds τ_min (Eq 3.1).",
        evaluating: ["km-chain"],
        pass: [],
        flagged: ["km-ctrl-a"],
        activeEdges: ["km-e9"],
      },
      {
        view: "KEY_MANAGEMENT",
        caption: "A new active link is established with Controller B — the lowest-numbered ACTIVE controller in C_trusted(t). The network resumes with no manual failover.",
        evaluating: [],
        pass: ["km-ctrl-b", "km-chain"],
        flagged: ["km-ctrl-a"],
        activeEdges: ["km-e7"],
      },
    ],
  },
};
