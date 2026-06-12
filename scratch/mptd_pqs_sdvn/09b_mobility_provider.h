// ============================================================
// 09b_mobility_provider.h — Mobility source abstraction (R7a)
// MPTD-PQS SDVN — Pluggable mobility driver + GT side-channel
// ============================================================
// Purpose
//   The paper (§4.1.3 + Eq 4.5/4.6) names SUMO as the authoritative ground
//   truth for vehicle position & density. To support both:
//     (a) quick smoke tests with the existing 16-vehicle hand-placed scenario
//     (b) paper-conformant evaluation runs driven by SUMO FCD traces
//   …without scattering if/else across 12_main.h, this header defines a
//   single IMobilityProvider interface with multiple backends, selected at
//   run-time via --mobility_source=<src>.
//
// Selected via CLI (see 02_config_globals.h::g_mobility_source):
//   0 = MOBILITY_SRC_HARDCODED   — current 16-vehicle ConstantVelocity scenario
//                                  (default, fast iteration, NOT paper-conformant)
//   1 = MOBILITY_SRC_SUMO_TRACE  — Ns2MobilityHelper consumes a .tcl file
//                                  exported from SUMO via traceExporter.py
//                                  (paper-conformant)
//   2 = MOBILITY_SRC_SUMO_LIVE   — RESERVED for future live TraCI bridge
//                                  (R7a-B, not implemented)
//
// Ground-truth side-channel
//   In ns-3, the MobilityModel attached to a vehicle node ALWAYS holds the
//   true position — attacks (06a_attack_models.h) only poison the values
//   inside beacon payloads, never the underlying mobility model. Therefore
//   get_gt_position(vid) = Vehicle_Nodes.Get(vid)->GetObject<MobilityModel>()
//   ->GetPosition() works for ALL providers. The "SUMO-derived" qualifier
//   in the paper is satisfied when the mobility model is driven by SUMO
//   (provider = MOBILITY_SRC_SUMO_TRACE).
//
// Add a new provider:
//   1. Add enum value in MobilitySource below.
//   2. Subclass IMobilityProvider, implement install(); GT helpers can
//      usually use the default impl that reads the MobilityModel.
//   3. Extend create_mobility_provider() factory.
// ============================================================

#ifndef MPTD_PQS_09B_MOBILITY_PROVIDER_H
#define MPTD_PQS_09B_MOBILITY_PROVIDER_H

#include <memory>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <vector>
#include <utility>
#include <sys/stat.h>

#include "ns3/mobility-module.h"
#include "ns3/ns2-mobility-helper.h"
#include "ns3/constant-velocity-mobility-model.h"

using namespace ns3;

// ── Mobility source enum (set via --mobility_source CLI arg) ──────────────
enum MobilitySource {
    MOBILITY_SRC_HARDCODED  = 0,
    MOBILITY_SRC_SUMO_TRACE = 1,
    MOBILITY_SRC_SUMO_LIVE  = 2,  // reserved (R7a-B, not implemented)
};

// Defined in 02_config_globals.h. Default = MOBILITY_SRC_HARDCODED.
extern int g_mobility_source;

// ── IMobilityProvider — abstract interface ────────────────────────────────
// Backends implement install(); GT helpers have working default impls that
// read the ns-3 MobilityModel directly.
class IMobilityProvider {
public:
    virtual ~IMobilityProvider() = default;

    // Human-readable name for logs.
    virtual const char* provider_name() const = 0;

    // Install mobility model + initial state on each vehicle node in the
    // container. Called once at sim startup from 12_main.h, replacing the
    // legacy in-place mobility install block.
    virtual bool install(NodeContainer& vehicles) = 0;

    // Whether GT readings from this provider are paper-conformant (Eq 4.5/4.6
    // require SUMO-derived ground truth). False for MOBILITY_SRC_HARDCODED.
    virtual bool is_sumo_derived() const { return false; }

    // ── Ground-truth helpers — default impl reads from MobilityModel ──
    // For TDEE (Eq 4.5) and TPE (Eq 4.6) computation in 10_metrics_csv.h.

    // True position of vehicle vid at the current sim time.
    // vid is the LOCAL vehicle index (0 .. N_Vehicles-1), NOT the ns-3 NodeID.
    virtual Vector get_gt_position(uint32_t vid) const
    {
        extern NodeContainer Vehicle_Nodes;
        if (vid >= Vehicle_Nodes.GetN()) return Vector(0, 0, 0);
        Ptr<MobilityModel> mm = Vehicle_Nodes.Get(vid)->GetObject<MobilityModel>();
        return mm ? mm->GetPosition() : Vector(0, 0, 0);
    }

    // True velocity of vehicle vid at the current sim time.
    virtual Vector get_gt_velocity(uint32_t vid) const
    {
        extern NodeContainer Vehicle_Nodes;
        if (vid >= Vehicle_Nodes.GetN()) return Vector(0, 0, 0);
        Ptr<MobilityModel> mm = Vehicle_Nodes.Get(vid)->GetObject<MobilityModel>();
        return mm ? mm->GetVelocity() : Vector(0, 0, 0);
    }

    // Count vehicles whose true position lies within radius of (cx, cy).
    // Used by compute_TDEE() to compute ρ_gt(t) per RSU coverage cell.
    virtual uint32_t get_gt_density_in_cell(double cx, double cy, double radius) const
    {
        extern NodeContainer Vehicle_Nodes;
        uint32_t n = 0;
        const double r2 = radius * radius;
        for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++) {
            Vector p = get_gt_position(i);
            const double dx = p.x - cx;
            const double dy = p.y - cy;
            if (dx*dx + dy*dy <= r2) n++;
        }
        return n;
    }
};

extern std::unique_ptr<IMobilityProvider> g_mobility_provider;

// ── HardcodedMobilityProvider — current 16-vehicle ConstantVelocity ───────
// Reproduces the existing hand-placed scenario from 12_main.h:139-203 verbatim
// so smoke-test runs (--mobility_source=hardcoded, default) remain bit-for-bit
// identical to pre-R7a behaviour.
class HardcodedMobilityProvider : public IMobilityProvider {
public:
    const char* provider_name() const override { return "hardcoded-16veh"; }
    bool is_sumo_derived() const override { return false; }

    bool install(NodeContainer& vehicles) override
    {
        // Position layout: 4 vehicles per RSU cluster, 2 lanes (y=570/590).
        // RSU0=(250,480) RSU1=(750,480) RSU2=(1250,480) RSU3=(1750,480)
        // → V2I gap ≈ 90–110 m (realistic urban handover).
        // V12-V15 move in −x to give bidirectional traffic.
        static const double init_pos[16][3] = {
            {210.0,  570.0, 0.0}, {250.0,  590.0, 0.0},   // V0..V1  near RSU0
            {280.0,  570.0, 0.0}, {290.0,  590.0, 0.0},   // V2..V3  near RSU0
            {710.0,  570.0, 0.0}, {750.0,  590.0, 0.0},   // V4..V5  near RSU1
            {780.0,  570.0, 0.0}, {790.0,  590.0, 0.0},   // V6..V7  near RSU1
            {1210.0, 570.0, 0.0}, {1250.0, 590.0, 0.0},   // V8..V9  near RSU2
            {1280.0, 570.0, 0.0}, {1290.0, 590.0, 0.0},   // V10..V11 near RSU2
            {1710.0, 570.0, 0.0}, {1750.0, 590.0, 0.0},   // V12..V13 near RSU3
            {1780.0, 570.0, 0.0}, {1790.0, 590.0, 0.0},   // V14..V15 near RSU3
        };
        // Per-vehicle target speed (m/s). + = east, − = west.
        // Urban regime: 8–11 m/s ≈ 29–40 km/h.
        static const double init_vx[16] = {
            10.0, 9.0, 11.0, 8.0,   // V0–V3   → east
            10.0, 9.0, 11.0, 8.0,   // V4–V7   → east
            10.0, 9.0, 11.0, 8.0,   // V8–V11  → east
           -10.0,-9.0,-11.0,-8.0,   // V12–V15 ← west (oncoming)
        };

        MobilityHelper helper;
        Ptr<ListPositionAllocator> alloc = CreateObject<ListPositionAllocator>();
        const uint32_t n = vehicles.GetN();
        for (uint32_t i = 0; i < n && i < 16; i++) {
            alloc->Add(Vector(init_pos[i][0], init_pos[i][1], init_pos[i][2]));
        }
        helper.SetPositionAllocator(alloc);
        helper.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
        helper.Install(vehicles);

        for (uint32_t i = 0; i < n && i < 16; i++) {
            Ptr<ConstantVelocityMobilityModel> cvmm =
                DynamicCast<ConstantVelocityMobilityModel>(
                    vehicles.Get(i)->GetObject<MobilityModel>());
            if (cvmm) cvmm->SetVelocity(Vector(init_vx[i], 0.0, 0.0));
        }
        std::cout << "[MOBILITY/HARDCODED] installed " << n
                  << " vehicles (urban 8–11 m/s, 4 per RSU cluster)\n";
        return true;
    }
};

// ── FcdTraceMobilityProvider — Ns2MobilityHelper (SUMO FCD via .tcl) ──────
// Consumes an ns-2 mobility trace file (the format SUMO emits via
// `traceExporter.py --ns2mobility-output`). Existing legacy traces in
// mobility/mobility_{urban,rural,autobahn}_*.tcl follow this format.
//
// Once installed, ns-3's WaypointMobilityModel-style backing of Ns2Mobility
// drives Vehicle_Nodes positions deterministically from the file. Reading
// GetObject<MobilityModel>()->GetPosition() at any later time returns the
// SUMO-derived ground-truth → satisfies paper Eq 4.5/4.6.
class FcdTraceMobilityProvider : public IMobilityProvider {
    std::string trace_path;

public:
    explicit FcdTraceMobilityProvider(const std::string& f) : trace_path(f) {}

    const char* provider_name() const override { return "sumo-trace-ns2"; }
    bool is_sumo_derived() const override { return true; }

    bool install(NodeContainer& vehicles) override
    {
        if (trace_path.empty()) {
            std::cerr << "[MOBILITY/SUMO_TRACE] empty trace_path — install FAILED\n";
            return false;
        }
        struct stat st;
        if (stat(trace_path.c_str(), &st) != 0) {
            std::cerr << "[MOBILITY/SUMO_TRACE] trace file not found: "
                      << trace_path << " — install FAILED\n";
            return false;
        }

        Ns2MobilityHelper ns2(trace_path);
        ns2.Install(vehicles.Begin(), vehicles.End());
        std::cout << "[MOBILITY/SUMO_TRACE] installed " << vehicles.GetN()
                  << " vehicles from " << trace_path << "\n";
        return true;
    }
};

// ── default_sumo_trace_path() — pick .tcl from scenario + speed ──────────
// Maps (mobility_scenario, maxspeed_kmh) → legacy trace file path under
// $NS3_ROOT/mobility/. Mirrors the existing selector at 12_main.h:476-599
// so we can replace that dead-code block in a follow-up.
//   scenario: 0=urban, 1=non-urban, 2=highway (paper §4.1.3 speed regimes)
//   speed_kmh: must match a generated trace file's suffix
// Returns "" if no trace exists for the (scenario, speed) pair.
inline std::string default_sumo_trace_path(int scenario, int speed_kmh)
{
    const char* root = NS3_ROOT "/mobility/";
    const char* tag  = (scenario == 0) ? "urban"
                     : (scenario == 1) ? "rural"
                     : (scenario == 2) ? "autobahn"
                                       : nullptr;
    if (!tag) return "";
    std::ostringstream oss;
    oss << root << "mobility_" << tag << "_" << speed_kmh << ".tcl";

    struct stat st;
    if (stat(oss.str().c_str(), &st) != 0) return "";  // file not present
    return oss.str();
}

// ── default_rsu_positions_path() — pick RSU layout CSV from scenario ──────
// Maps mobility_scenario → $NS3_ROOT/mobility/rsu_positions_{tag}.csv, the
// realistic coverage-aware layout produced offline by sumo/place_rsus.py.
// Returns "" if no CSV exists (caller then keeps the hardcoded grid layout).
inline std::string default_rsu_positions_path(int scenario)
{
    const char* root = NS3_ROOT "/mobility/";
    const char* tag  = (scenario == 0) ? "urban"
                     : (scenario == 1) ? "rural"
                     : (scenario == 2) ? "autobahn"
                                       : nullptr;
    if (!tag) return "";
    std::ostringstream oss;
    oss << root << "rsu_positions_" << tag << ".csv";
    struct stat st;
    if (stat(oss.str().c_str(), &st) != 0) return "";  // not generated yet
    return oss.str();
}

// ── load_rsu_positions() — read "rsu_id,x,y" CSV into (x,y) pairs ─────────
// Consumes the CSV emitted by sumo/place_rsus.py. The header row and any
// malformed lines are skipped. Returns positions in file order (rsu_id 0..N-1).
inline std::vector<std::pair<double, double>>
load_rsu_positions(const std::string& csv_path)
{
    std::vector<std::pair<double, double>> out;
    if (csv_path.empty()) return out;
    std::ifstream fh(csv_path.c_str());
    if (!fh.is_open()) {
        std::cerr << "[RSU/PLACEMENT] cannot open " << csv_path << "\n";
        return out;
    }
    std::string line;
    bool first = true;
    while (std::getline(fh, line)) {
        if (line.empty()) continue;
        if (first) {                       // skip header "rsu_id,x,y"
            first = false;
            if (line.find("rsu_id") != std::string::npos) continue;
        }
        std::istringstream ss(line);
        std::string id_s, x_s, y_s;
        if (!std::getline(ss, id_s, ',')) continue;
        if (!std::getline(ss, x_s, ','))  continue;
        if (!std::getline(ss, y_s, ','))  continue;
        try {
            out.emplace_back(std::stod(x_s), std::stod(y_s));
        } catch (const std::exception&) {
            continue;                      // malformed numeric → skip
        }
    }
    std::cout << "[RSU/PLACEMENT] loaded " << out.size()
              << " RSU positions from " << csv_path << "\n";
    return out;
}

// ── Factory ─────────────────────────────────────────────────────────────
// Called from 12_main.h after cmd.Parse() but before vehicle install.
//   trace_path: only used for MOBILITY_SRC_SUMO_TRACE. Caller usually passes
//   default_sumo_trace_path(mobility_scenario, maxspeed).
inline std::unique_ptr<IMobilityProvider>
create_mobility_provider(int source, const std::string& trace_path)
{
    switch (source) {
        case MOBILITY_SRC_HARDCODED:
            return std::unique_ptr<IMobilityProvider>(new HardcodedMobilityProvider());
        case MOBILITY_SRC_SUMO_TRACE:
            return std::unique_ptr<IMobilityProvider>(new FcdTraceMobilityProvider(trace_path));
        case MOBILITY_SRC_SUMO_LIVE:
            std::cerr << "[MOBILITY] SUMO_LIVE (TraCI) not implemented yet — "
                      << "falling back to HARDCODED\n";
            return std::unique_ptr<IMobilityProvider>(new HardcodedMobilityProvider());
        default:
            std::cerr << "[MOBILITY] unknown source=" << source
                      << " — falling back to HARDCODED\n";
            return std::unique_ptr<IMobilityProvider>(new HardcodedMobilityProvider());
    }
}

// Singleton instance, created in 12_main.h.
std::unique_ptr<IMobilityProvider> g_mobility_provider;

#endif // MPTD_PQS_09B_MOBILITY_PROVIDER_H
