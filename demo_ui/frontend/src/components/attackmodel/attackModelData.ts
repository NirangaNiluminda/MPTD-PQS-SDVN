// Threat-model content for the Attack Model Explorer.
//
// Every attack_number → actor/description mapping below is copied VERBATIM
// from demo_ui/backend/parsers/catalog.py's ATTACK_NAMES/ATTACK_INFO (itself
// verified against scratch/mptd_pqs_sdvn/06a_attack_models.h's own attack
// branches) — the same data /api/attacks serves to Attack Explainer, so this
// screen never drifts from what the rest of the app already says about these
// seven variants. TPE and TDEE are real, defined metrics — report/main.tex
// §"Traffic Density Estimation Error (TDEE)" / "Trajectory Prediction Error
// (TPE)" (search main.tex for \label{eq:tdee} / \label{eq:tpe}) — not
// invented acronyms. TDEE = relative error between the controller's learned
// traffic density and SUMO ground truth; TPE = mean displacement error
// between the controller's predicted vehicle positions and SUMO ground
// truth. The paper explicitly states TDEE is "the primary attack-impact
// metric for mobility pattern poisoning" (all four MP variants converge on
// a distorted density estimate) and TPE is the same for all three TP
// variants (degraded per-vehicle position prediction) — hence this split.
// The "missed collision warnings" / "phantom congestion and misrouting"
// consequence framing is the paper's own abstract (main.tex:207): "...
// inducing safety-critical misrouting, phantom congestion, and suppression
// of collision warnings...".

export type ViewMode = "TAXONOMY_OVERVIEW" | "VARIANT_EXPLORER";
export type VariantCode = "a1" | "a2" | "a5" | "a3" | "a4" | "a6" | "a7";
export type Category = "trajectory" | "mobility_pattern";
export type Plane = "data" | "control";
export type PacketKind = "honest" | "poisoned" | "sybil" | "faulty_control" | "blocked";

export interface ThreatNode {
  id: "ctrl" | "rsu" | "car1" | "attacker" | "car2" | "ghost1" | "ghost2";
  label: string;
  x: number;
  y: number;
  kind: "controller" | "rsu" | "car" | "ghost";
}

// Fixed triangular topology — which of these 7 possible nodes actually
// RENDERS is computed per variant (AttackModelExplorerScreen's usedNodeIds)
// from that variant's own step data, not hardcoded here. Controller top,
// RSU middle, vehicle row at the bottom (the center slot doubles as
// "attacker car" or the MitM relay depending on the variant — omitted
// entirely for RSU/controller-compromised variants, matching the paper's
// own Figures 3.1/3.3/3.4/3.7, which never draw a compromised-vehicle icon
// for those four). ghost1/ghost2 are the fabricated Sybil identities the
// paper's Figures 3.4 and 3.5 draw as extra vehicle icons — verified
// directly against those figures, not invented; they render only for a3/a4.
export const THREAT_NODES: ThreatNode[] = [
  { id: "ctrl", label: "SDVN Controller", x: 420, y: 40, kind: "controller" },
  { id: "rsu", label: "RSU Tower", x: 420, y: 260, kind: "rsu" },
  { id: "car1", label: "Honest Car 1", x: 120, y: 480, kind: "car" },
  { id: "attacker", label: "Attacker Car / MitM Entity", x: 420, y: 480, kind: "car" },
  { id: "car2", label: "Honest Car 2", x: 720, y: 480, kind: "car" },
  { id: "ghost1", label: "Ghost Identity #1", x: 300, y: 660, kind: "ghost" },
  { id: "ghost2", label: "Ghost Identity #2", x: 540, y: 660, kind: "ghost" },
];

export interface ThreatEdgeFrame {
  source: string;
  target: string;
  kind: PacketKind;
  label: string;
}

export interface ThreatStep {
  caption: string;
  /** The paper's OWN figure step numbers this beat corresponds to (e.g.
   * "Step 2" or "Steps 5–6") — shown as its own badge in the sidebar, not
   * just buried in the caption prose, so it's directly checkable against
   * Figures 3.1–3.7 in report/main.pdf. */
  paperSteps: string;
  skullNode: ThreatNode["id"] | null;
  deceivedNode: ThreatNode["id"] | null;
  edges: ThreatEdgeFrame[];
}

export interface Variant {
  code: VariantCode;
  attackNumber: number; // real attack_number (1-7), matches /api/attacks, RUN_CONFIG etc.
  paperCode: string; // "TP-S1" etc — printed exactly as scratch/mptd_pqs_sdvn/02_config_globals.h:170-179 names it
  label: string;
  category: Category;
  plane: Plane;
  actor: string; // same actor keys AttackExplainerScreen's ACTOR_LABEL/ACTOR_GLYPH use
  description: string; // verbatim from catalog.ATTACK_INFO[n].plain
  steps: ThreatStep[];
}

export const CATEGORY_LABEL: Record<Category, string> = {
  trajectory: "Trajectory Poisoning (Micro Level)",
  mobility_pattern: "Mobility Pattern Poisoning (Macro Level)",
};

export const CATEGORY_CARD: Record<
  Category,
  { summary: string; metric: string; metricFull: string; consequence: string }
> = {
  trajectory: {
    summary:
      "Injects false position/speed data to corrupt a single vehicle's own path — the controller's individual per-vehicle prediction model degrades even though every OTHER vehicle stays honest.",
    metric: "TPE",
    metricFull: "Trajectory Prediction Error — mean displacement between the controller's predicted vehicle positions and SUMO ground truth (Eq. tpe)",
    consequence: "Missed collision warnings",
  },
  mobility_pattern: {
    summary:
      "Uses Sybil ghost identities or a MitM relay to corrupt the controller's GLOBAL traffic-density model — every source converges on the same distorted density estimate regardless of injection method.",
    metric: "TDEE",
    metricFull: "Traffic Density Estimation Error — relative error between the controller's learned density and SUMO ground truth density (Eq. tdee)",
    consequence: "Phantom congestion and misrouting",
  },
};

export const VARIANT_ORDER: VariantCode[] = ["a1", "a2", "a5", "a3", "a4", "a6", "a7"];

// ── PACKET-KIND VISUAL LANGUAGE ──────────────────────────────────────────
export const PACKET_COLOR: Record<PacketKind, string> = {
  honest: "#22c55e", // green — honest data / safe BSM
  poisoned: "#ec4899", // pink — poisoned / falsified data
  sybil: "#3b82f6", // blue — impersonated Sybil packets
  faulty_control: "#eab308", // yellow — faulty control packets
  blocked: "#ef4444", // red — suppressed / blocked (paired with an X icon, not a delivered packet)
};

function step(
  paperSteps: string,
  caption: string,
  skullNode: ThreatNode["id"] | null,
  deceivedNode: ThreatNode["id"] | null,
  edges: ThreatEdgeFrame[]
): ThreatStep {
  return { caption, paperSteps, skullNode, deceivedNode, edges };
}

export const VARIANTS: Record<VariantCode, Variant> = {
  a1: {
    code: "a1",
    attackNumber: 1,
    paperCode: "TP-S1",
    label: "Malicious RSU",
    category: "trajectory",
    plane: "data",
    actor: "compromised_rsu",
    description: "A hijacked roadside unit rewrites vehicles' trajectories as it relays them.",
    steps: [
      step("Step 1", "Honest Car 1 sends its correct position and movement path to the RSU — normal data-plane communication.", "rsu", null, [
        { source: "car1", target: "rsu", kind: "honest", label: "safe BSM" },
      ]),
      step("Step 2", "Instead of forwarding it honestly, the compromised RSU injects falsified but realistic trajectory values — smooth enough to evade detection.", "rsu", null, [
        { source: "rsu", target: "ctrl", kind: "poisoned", label: "rewritten trajectory" },
      ]),
      step("Step 5", "Based on this corrupted input, the controller learns an incorrect trajectory model and is deceived into believing the traffic situation is safe.", "rsu", "ctrl", [
        { source: "ctrl", target: "rsu", kind: "faulty_control", label: "poisoned prediction" },
      ]),
      step("Step 7", "The resulting safety-critical warning is suppressed before it ever reaches Honest Car 2 — vehicles behaved honestly throughout.", "rsu", "ctrl", [
        { source: "rsu", target: "car2", kind: "blocked", label: "warning blocked" },
      ]),
    ],
  },
  a2: {
    code: "a2",
    attackNumber: 2,
    paperCode: "TP-S2",
    label: "Malicious Vehicle",
    category: "trajectory",
    plane: "data",
    actor: "malicious_vehicle",
    description: "A lying vehicle reports a fake but physically plausible trajectory.",
    steps: [
      step("Step 1", "The compromised vehicle generates fake but smooth, realistic trajectory data instead of its true movement — the RSU sees nothing abnormal and forwards it unmodified.", "attacker", null, [
        { source: "attacker", target: "rsu", kind: "poisoned", label: "fake trajectory" },
      ]),
      step("Step 2", "Over multiple time steps, the controller keeps receiving this falsified trajectory and gradually learns an incorrect model for this vehicle.", "attacker", "ctrl", [
        { source: "rsu", target: "ctrl", kind: "poisoned", label: "relayed falsehood" },
      ]),
      step("Steps 3–4", "The controller assumes the situation is safe and suppresses the safety-critical warning that should reach nearby vehicles.", "attacker", "ctrl", [
        { source: "ctrl", target: "rsu", kind: "faulty_control", label: "poisoned prediction" },
        { source: "rsu", target: "car1", kind: "blocked", label: "warning blocked" },
        { source: "rsu", target: "car2", kind: "blocked", label: "warning blocked" },
      ]),
    ],
  },
  a5: {
    code: "a5",
    attackNumber: 5,
    paperCode: "TP-S3",
    label: "Malicious Controller",
    category: "trajectory",
    plane: "control",
    actor: "malicious_controller",
    description:
      "A hijacked network controller poisons trajectories at the control plane; vehicles and roadside units stay honest throughout.",
    steps: [
      step("Steps 1–4", "Vehicles honestly generate and transmit correct trajectory data, and the RSU forwards it on — up to this point nothing falsified is injected.", null, null, [
        { source: "car1", target: "rsu", kind: "honest", label: "safe BSM" },
        { source: "rsu", target: "ctrl", kind: "honest", label: "clean relay" },
      ]),
      step("Steps 5–6", "The attack begins entirely inside the controller: although it receives correct data, it deliberately poisons its own learning model into indicating a safe traffic situation.", "ctrl", "ctrl", []),
      step("Steps 7–8", "The self-poisoned controller's incorrect control decision reaches the RSU, and the collision warning to Honest Car 2 is blocked or suppressed in the data plane.", "ctrl", "ctrl", [
        { source: "ctrl", target: "rsu", kind: "faulty_control", label: "poisoned prediction" },
        { source: "rsu", target: "car2", kind: "blocked", label: "warning blocked" },
      ]),
    ],
  },
  a3: {
    code: "a3",
    attackNumber: 3,
    paperCode: "MP-S1",
    label: "Sybil via RSU",
    category: "mobility_pattern",
    plane: "data",
    actor: "compromised_rsu",
    description:
      "A hijacked roadside unit injects ghost identities (Sybil). In enhanced mode the ghosts pre-register with valid pool IDs, so detection must be behavioural.",
    steps: [
      step("Steps 1, 3", "Honest Car 1 transmits correct position, speed, and movement data to the RSU through the data plane — normal network behaviour.", "rsu", null, [
        { source: "car1", target: "rsu", kind: "honest", label: "safe BSM" },
      ]),
      step("Steps 2, 4", "This legitimate packet is forwarded on to the controller — nothing falsified yet.", "rsu", null, [
        { source: "rsu", target: "ctrl", kind: "honest", label: "clean forward" },
      ]),
      step(
        "Steps 5–6",
        "The compromised RSU now impersonates multiple fake vehicle identities that don't actually exist — Figure 3.4's extra vehicle icons, shown here as two ghost identities transmitting straight to the RSU — and forwards these forged, valid-looking reports on to the controller.",
        "rsu",
        null,
        [
          { source: "ghost1", target: "rsu", kind: "sybil", label: "ghost #1" },
          { source: "ghost2", target: "rsu", kind: "sybil", label: "ghost #2" },
          { source: "rsu", target: "ctrl", kind: "sybil", label: "ghost identities" },
        ]
      ),
      step("Steps 7–10", "The controller aggregates the forged reports into its global model — false traffic-density estimation now drives misrouting guidance sent to every car.", "rsu", "ctrl", [
        { source: "ctrl", target: "rsu", kind: "faulty_control", label: "distorted density" },
        { source: "rsu", target: "car1", kind: "faulty_control", label: "misrouting guidance" },
        { source: "rsu", target: "car2", kind: "faulty_control", label: "misrouting guidance" },
      ]),
    ],
  },
  a4: {
    code: "a4",
    attackNumber: 4,
    paperCode: "MP-S2",
    label: "Sybil via Vehicle Impersonation",
    category: "mobility_pattern",
    plane: "data",
    actor: "malicious_vehicle",
    description: "A vehicle steals another vehicle's identity and beacons under it.",
    steps: [
      step(
        "Steps 1, 3–4",
        "The attacker vehicle forges multiple mobility packets under stolen or invented identities — Figure 3.5's extra vehicle icons, shown here as two ghost identities transmitting alongside the attacker's own beacon — even though these vehicles don't actually exist.",
        "attacker",
        null,
        [
          { source: "attacker", target: "rsu", kind: "sybil", label: "impersonated ID" },
          { source: "ghost1", target: "rsu", kind: "sybil", label: "ghost #1" },
          { source: "ghost2", target: "rsu", kind: "sybil", label: "ghost #2" },
        ]
      ),
      step("Steps 2, 5–6", "The RSU forwards the impersonated packets to the controller without detecting anything — the identities look valid.", "attacker", "ctrl", [
        { source: "rsu", target: "ctrl", kind: "sybil", label: "forwarded ghost ID" },
      ]),
      step("Steps 7–8", "The controller's global mobility model is now corrupted with false traffic density — misrouting guidance flows back to every honest car.", "attacker", "ctrl", [
        { source: "ctrl", target: "rsu", kind: "faulty_control", label: "distorted density" },
        { source: "rsu", target: "car1", kind: "faulty_control", label: "misrouting guidance" },
        { source: "rsu", target: "car2", kind: "faulty_control", label: "misrouting guidance" },
      ]),
    ],
  },
  a6: {
    code: "a6",
    attackNumber: 6,
    paperCode: "MP-S3",
    label: "MitM Modification",
    category: "mobility_pattern",
    plane: "data",
    actor: "mitm_relay",
    description:
      "A vehicle acts as an intercepting relay, amplifying reported speed to breach the neighbourhood similarity threshold.",
    // Split into 5 distinct beats (capture, then alter, then forward, then
    // relay, then consequence) rather than compressing "intercept" and
    // "modify-and-forward" into one simultaneous step — the paper's own
    // text (§3.4.2) is explicit that the relay first "observes the
    // legitimate messages" and only THEN "fabricates new mobility reports,"
    // two separate actions the earlier 3-step version blurred together.
    steps: [
      step("Steps 1–2", "Honest Car 1 transmits its genuine position/speed data — the MitM relay, sitting in the data plane between the vehicle and the RSU, intercepts and captures it before it ever arrives.", "attacker", null, [
        { source: "car1", target: "attacker", kind: "honest", label: "intercepted" },
      ]),
      step("Step 2", "Having captured the real reading, the relay now fabricates a new report — realistic values, but with speed amplified beyond the honest reading.", "attacker", null, []),
      step("Step 4", "The altered, amplified-speed report is forwarded to the RSU as if it came directly from the vehicle — the RSU has no way to tell it apart from a genuine beacon.", "attacker", null, [
        { source: "attacker", target: "rsu", kind: "poisoned", label: "amplified speed" },
      ]),
      step("Steps 3, 5", "The RSU, unaware of the interception, forwards the tampered report on to the controller.", "attacker", null, [
        { source: "rsu", target: "ctrl", kind: "poisoned", label: "relayed tamper" },
      ]),
      step("Steps 6–7", "The controller aggregates the poisoned reading into its global model — misrouting guidance now reaches every honest car.", "attacker", "ctrl", [
        { source: "ctrl", target: "rsu", kind: "faulty_control", label: "distorted density" },
        { source: "rsu", target: "car1", kind: "faulty_control", label: "misrouting guidance" },
        { source: "rsu", target: "car2", kind: "faulty_control", label: "misrouting guidance" },
      ]),
    ],
  },
  a7: {
    code: "a7",
    attackNumber: 7,
    paperCode: "MP-S4",
    label: "Controller Mobility Poisoning",
    category: "mobility_pattern",
    plane: "control",
    actor: "malicious_controller",
    description:
      "A hijacked controller corrupts the global mobility model despite receiving correct data from every honest vehicle and roadside unit.",
    steps: [
      step("Steps 1–4", "Vehicles transmit legitimate mobility data and the RSU forwards it on — both vehicles and the RSU operate correctly and inject no false data.", null, null, [
        { source: "car1", target: "rsu", kind: "honest", label: "safe BSM" },
        { source: "rsu", target: "ctrl", kind: "honest", label: "clean relay" },
      ]),
      step("Step 5", "Despite receiving correct mobility inputs, the malicious controller intentionally poisons its internal learning model into a corrupted view of traffic conditions.", "ctrl", "ctrl", []),
      step("Step 6", "Based on the poisoned model, the controller generates incorrect control packets that reach every honest car — safety warnings may be suppressed and collision risks misread as safe.", "ctrl", "ctrl", [
        { source: "ctrl", target: "rsu", kind: "faulty_control", label: "corrupted density model" },
        { source: "rsu", target: "car1", kind: "faulty_control", label: "misrouting guidance" },
        { source: "rsu", target: "car2", kind: "faulty_control", label: "misrouting guidance" },
      ]),
    ],
  },
};
