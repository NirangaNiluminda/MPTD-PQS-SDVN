/* ============================================================
 * vanet_netanim_test.cc
 *
 * Standalone VANET test network for NetAnim visualization.
 * Demonstrates the MRTPA (Malicious RSU Trajectory Poisoning Attack)
 * topology used in our FYP simulation.
 *
 * Topology:
 *   5 Vehicles (Green)  <-- 802.11p WiFi -->  4 RSUs (Yellow/Red)
 *   4 RSUs              <-- CSMA wired   -->  Controller (Purple)
 *                                         -->  Management (Red)
 *
 * Usage:
 *   python3 waf --run "scratch/vanet_netanim_test --attack_percentage=0"
 *   python3 waf --run "scratch/vanet_netanim_test --attack_percentage=80"
 *   python3 waf --run "scratch/vanet_netanim_test --attack_percentage=100"
 *
 * Output: vanet_test.xml  (open in NetAnim)
 * ============================================================ */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/ssid.h"
#include "ns3/ipv4-static-routing-helper.h"

#include <cstdlib>
#include <ctime>
#include <cmath>      // std::sqrt, std::pow — for Euclidean distance
#include <iomanip>    // std::fixed, std::setprecision — for formatted distance output
#include <random>     // std::mt19937, std::uniform_int_distribution — Mersenne Twister PRNG
#include <chrono>     // std::chrono::high_resolution_clock — nanosecond seed
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("VanetNetAnimTest");

// ── Global RSU positions — used by CheckHandoff() scheduled callback ──────────
// Must be global so the free function can access them without a pointer argument.
static const uint32_t G_N_RSUS = 4;
static double g_rsuPositions[G_N_RSUS][2] = { {100,200}, {200,200}, {300,200}, {400,200} };

// ── Global current RSU tracker — which RSU each vehicle is currently routed to ─
static uint32_t g_current_rsu[5] = {0, 0, 0, 0, 0};  // updated by CheckHandoff()

// ── Global node/interface containers — used by CheckHandoff() ─────────────────
// NS-3 Simulator::Schedule supports at most 6 args for free functions.
// Storing these globally avoids exceeding that limit.
static NodeContainer            g_vehicleNodes;
static NodeContainer            g_rsuNodes;
static Ipv4InterfaceContainer   g_dsrcInterfaces;

// ── CheckHandoff() — periodic callback that re-evaluates nearest RSU for each vehicle ─
// Called every 'interval' seconds during Simulator::Run().
// When a vehicle moves closer to a different RSU:
//   1. Removes old static host route and adds new one
//   2. Updates NetAnim label to show new target RSU
//   3. Prints a [HANDOFF] log line to stdout
void CheckHandoff (uint32_t nVehicles, uint32_t nRsus,
                   AnimationInterface* anim, Time interval)
{
  Ipv4StaticRoutingHelper staticRouting;

  for (uint32_t i = 0; i < nVehicles; i++)
    {
      // ── Get vehicle's live position via MobilityModel ─────────────────────
      Vector pos = g_vehicleNodes.Get (i)->GetObject<MobilityModel> ()->GetPosition ();

      // ── Find nearest RSU by Euclidean distance ────────────────────────────
      uint32_t nearest  = 0;
      double   min_dist = 1e9;
      for (uint32_t j = 0; j < nRsus; j++)
        {
          double dx   = pos.x - g_rsuPositions[j][0];
          double dy   = pos.y - g_rsuPositions[j][1];
          double dist = std::sqrt (dx*dx + dy*dy);
          if (dist < min_dist) { min_dist = dist; nearest = j; }
        }

      // ── Perform handoff if nearest RSU has changed ────────────────────────
      if (nearest != g_current_rsu[i])
        {
          uint32_t old_rsu = g_current_rsu[i];
          g_current_rsu[i] = nearest;

          std::cout << std::fixed << std::setprecision(1)
                    << "[HANDOFF] Vehicle " << i
                    << " at (" << (int)pos.x << "," << (int)pos.y << ")"
                    << "  RSU " << old_rsu << " -> RSU " << nearest
                    << "  dist=" << min_dist << "m"
                    << "  t=" << Simulator::Now ().GetSeconds () << "s"
                    << std::endl;

          // Update Ipv4StaticRouting: remove old host route, add new one
          Ptr<Ipv4StaticRouting> sr =
            staticRouting.GetStaticRouting (g_vehicleNodes.Get (i)->GetObject<Ipv4> ());
          Ipv4Address old_addr = g_dsrcInterfaces.GetAddress (nVehicles + old_rsu);
          uint32_t nRoutes = sr->GetNRoutes ();
          for (uint32_t r = 0; r < nRoutes; r++)
            {
              if (sr->GetRoute (r).GetDest () == old_addr)
                { sr->RemoveRoute (r); break; }
            }
          sr->AddHostRouteTo (g_dsrcInterfaces.GetAddress (nVehicles + nearest), 1);

          // Update NetAnim label to reflect new RSU
          anim->UpdateNodeDescription (g_vehicleNodes.Get (i),
            "V" + std::to_string (i) + "->" + "RSU" + std::to_string (nearest));
        }
    }

  // Reschedule — this creates a self-repeating periodic timer
  Simulator::Schedule (interval, &CheckHandoff, nVehicles, nRsus, anim, interval);
}

int main (int argc, char *argv[])
{
  // ── Parameters ──────────────────────────────────────────────────────────
  double attack_percentage = 0.0;   // 0=no attack, 80=partial, 100=full attack
  double simTime = 10.0;            // seconds

  CommandLine cmd (__FILE__);
  cmd.AddValue ("attack_percentage", "Percentage of RSUs that are malicious (0-100)", attack_percentage);
  cmd.AddValue ("simTime", "Simulation duration in seconds", simTime);
  cmd.Parse (argc, argv);

  // ── Seed randomness using Mersenne Twister — avoids glibc LCG clustering ──
  // glibc's rand() (Linear Congruential Generator) produces badly distributed
  // first values after seeding — all 4 RSU rolls cluster in the same range.
  // std::mt19937 (Mersenne Twister) guarantees genuine variation each run.
  // Seed = nanosecond timestamp XOR PID: different every run, no same-second problem.
  uint64_t mt_seed = (uint64_t)std::chrono::high_resolution_clock::now ()
                                           .time_since_epoch ().count ()
                   ^ ((uint64_t)getpid () << 16);
  std::mt19937 rng (mt_seed);
  std::uniform_int_distribution<int> dist (0, 99);  // uniform [0,99] — no modulo bias

  // ── Node counts ─────────────────────────────────────────────────────────
  const uint32_t N_VEHICLES   = 5;
  const uint32_t N_RSUS       = 4;

  // ── Create node containers ───────────────────────────────────────────────
  NodeContainer vehicleNodes;
  vehicleNodes.Create (N_VEHICLES);

  NodeContainer rsuNodes;
  rsuNodes.Create (N_RSUS);

  NodeContainer controllerNode;
  controllerNode.Create (1);

  NodeContainer managementNode;
  managementNode.Create (1);

  // ── Copy node containers into globals so CheckHandoff() can access them ───
  g_vehicleNodes = vehicleNodes;
  g_rsuNodes     = rsuNodes;

  // ── Determine which RSUs are malicious ───────────────────────────────────
  // Each RSU rolls independently: malicious if roll < attack_percentage.
  // With mt19937, consecutive runs within the same second give different results.
  bool rsu_malicious[N_RSUS];
  for (uint32_t i = 0; i < N_RSUS; i++)
    {
      int roll = dist (rng);                               // high-quality uniform random
      rsu_malicious[i] = (roll < (int) attack_percentage);
      std::cout << "[MRTPA] RSU " << i
                << " malicious=" << rsu_malicious[i]
                << " (roll=" << roll
                << ", attack_percentage=" << attack_percentage << "%)" << std::endl;
    }

  // ── WiFi setup (802.11p style — ad-hoc DSRC channel) ────────────────────
  // Use RangePropagationLossModel with MaxRange=500m (realistic for DSRC/802.11p)
  // Default LogDistancePropagationLossModel only reaches ~50m — too short for our layout
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel",
                                  "MaxRange", DoubleValue (200.0)); //default having 50m we set it as 500m
  YansWifiPhyHelper     wifiPhy;
  wifiPhy.SetChannel (wifiChannel.Create ());

  WifiHelper wifi;
  wifi.SetRemoteStationManager ("ns3::AarfWifiManager"); // here adjust the data rate auto corresponding to singnal quality

  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");

  // Install WiFi on vehicles and RSUs
  NodeContainer dsrcNodes;
  dsrcNodes.Add (vehicleNodes);
  dsrcNodes.Add (rsuNodes);

  NetDeviceContainer dsrcDevices = wifi.Install (wifiPhy, wifiMac, dsrcNodes);

  // ── CSMA wired backhaul: RSUs + Controller + Management ─────────────────
  NodeContainer csmaNodes;
  csmaNodes.Add (rsuNodes);
  csmaNodes.Add (controllerNode);
  csmaNodes.Add (managementNode);

  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));
  NetDeviceContainer csmaDevices = csma.Install (csmaNodes);

  // ── Internet stack ───────────────────────────────────────────────────────
  InternetStackHelper stack;
  stack.Install (vehicleNodes);
  stack.Install (rsuNodes);
  stack.Install (controllerNode);
  stack.Install (managementNode);

  // Assign IPs: WiFi subnet
  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer dsrcInterfaces = address.Assign (dsrcDevices);
  g_dsrcInterfaces = dsrcInterfaces;  // copy into global for CheckHandoff()

  // Assign IPs: CSMA subnet
  address.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer csmaInterfaces = address.Assign (csmaDevices);

  // ── Mobility: RSU positions (stationary, in a row) ───────────────────────
  // RSU 0 at (100,200), RSU 1 at (200,200), RSU 2 at (300,200), RSU 3 at (400,200)
  MobilityHelper rsuMobility;
  rsuMobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  rsuMobility.Install (rsuNodes);

  // Use global g_rsuPositions (defined above main()) so CheckHandoff() can access them
  double (&rsuPositions)[G_N_RSUS][2] = g_rsuPositions;
  for (uint32_t i = 0; i < N_RSUS; i++)
    {
      Ptr<ConstantPositionMobilityModel> m =
        DynamicCast<ConstantPositionMobilityModel> (rsuNodes.Get (i)->GetObject<MobilityModel> ());
      m->SetPosition (Vector (rsuPositions[i][0], rsuPositions[i][1], 0.0));
    }

  // ── Mobility: Vehicles (moving slowly left to right below RSUs) ───────────
  // Vehicle i starts at (80+i*80, 100) and moves at 5 m/s rightward
  MobilityHelper vehicleMobility;
  vehicleMobility.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
  vehicleMobility.Install (vehicleNodes);

  double vehicleStartX[N_VEHICLES] = {80, 160, 240, 320, 400};
  for (uint32_t i = 0; i < N_VEHICLES; i++)
    {
      Ptr<ConstantVelocityMobilityModel> m =
        DynamicCast<ConstantVelocityMobilityModel> (vehicleNodes.Get (i)->GetObject<MobilityModel> ());
      m->SetPosition (Vector (vehicleStartX[i], 100.0, 0.0));
      m->SetVelocity (Vector (5.0, 0.0, 0.0));   // 5 m/s rightward — visible in NetAnim
    }

  // ── Mobility: Controller + Management (stationary, top-right) ────────────
  AnimationInterface::SetConstantPosition (controllerNode.Get (0), 480, 300);
  AnimationInterface::SetConstantPosition (managementNode.Get (0), 480, 350);

  // ── Applications: UDP echo (vehicles → RSUs) ─────────────────────────────
  // Each vehicle sends UDP packets to its nearest RSU
  uint16_t echoPort = 9;
  UdpEchoServerHelper echoServer (echoPort);

  // Install server on all RSUs
  ApplicationContainer serverApps = echoServer.Install (rsuNodes);
  serverApps.Start (Seconds (1.0));
  serverApps.Stop (Seconds (simTime));

  // Dynamic nearest RSU assignment — computed at runtime using Euclidean distance.
  // Uses the same vehicleStartX[] and rsuPositions[][] arrays already defined above.
  // Automatically stays correct if positions are changed — no manual update needed.
  uint32_t nearest_rsu[N_VEHICLES];
  std::cout << "\n[NEAREST] Computing nearest RSU for each vehicle at t=0:" << std::endl;
  for (uint32_t i = 0; i < N_VEHICLES; i++)
    {
      double vx       = vehicleStartX[i];
      double vy       = 100.0;          // all vehicles start at y=100
      double min_dist = 1e9;            // large sentinel, will be replaced immediately
      nearest_rsu[i]  = 0;             // default (overwritten by the inner loop below)

      for (uint32_t j = 0; j < N_RSUS; j++)
        {
          double rx   = rsuPositions[j][0];
          double ry   = rsuPositions[j][1];
          double dx   = vx - rx;
          double dy   = vy - ry;
          double dist = std::sqrt (dx*dx + dy*dy);
          if (dist < min_dist)
            {
              min_dist       = dist;
              nearest_rsu[i] = j;
            }
        }

      // Print computed assignment — visible in terminal during simulation
      double final_dist = std::sqrt (
          std::pow (vx - rsuPositions[nearest_rsu[i]][0], 2.0) +
          std::pow (vy - rsuPositions[nearest_rsu[i]][1], 2.0));
      std::cout << "[NEAREST]   Vehicle " << i
                << " at (" << (int)vx << ",100)"
                << " -> RSU " << nearest_rsu[i]
                << " at (" << (int)rsuPositions[nearest_rsu[i]][0]
                << "," << (int)rsuPositions[nearest_rsu[i]][1] << ")"
                << "  dist=" << std::fixed << std::setprecision(1)
                << final_dist << "m" << std::endl;
    }
  // Initialise g_current_rsu[] from the computed nearest_rsu[] so CheckHandoff()
  // can track changes relative to the correct starting assignment.
  for (uint32_t i = 0; i < N_VEHICLES; i++) g_current_rsu[i] = nearest_rsu[i];

  std::cout << std::endl;
  for (uint32_t i = 0; i < N_VEHICLES; i++)
    {
      uint32_t rsu_idx = nearest_rsu[i];
      // Use the RSU's WiFi (dsrc) IP address — same subnet as vehicles
      UdpEchoClientHelper echoClient (dsrcInterfaces.GetAddress (N_VEHICLES + rsu_idx), echoPort);
      echoClient.SetAttribute ("MaxPackets", UintegerValue (20));
      echoClient.SetAttribute ("Interval", TimeValue (Seconds (0.4)));
      echoClient.SetAttribute ("PacketSize", UintegerValue (512));
      ApplicationContainer clientApp = echoClient.Install (vehicleNodes.Get (i));
      clientApp.Start (Seconds (2.0));
      clientApp.Stop (Seconds (simTime));
    }
  // ── Static routing: each vehicle → its target RSU (WiFi subnet) ────────────
  // Ipv4GlobalRoutingHelper::PopulateRoutingTables() crashes with ad-hoc WiFi.
  // Instead we install static host routes: each vehicle gets a route to its
  // target RSU's IP address via the WiFi interface (idx 1 on vehicles).
  Ipv4StaticRoutingHelper staticRouting;
  for (uint32_t i = 0; i < N_VEHICLES; i++)
    {
      uint32_t rsu_idx = nearest_rsu[i];
      Ptr<Ipv4StaticRouting> sr =
        staticRouting.GetStaticRouting (vehicleNodes.Get (i)->GetObject<Ipv4> ());
      // Route to target RSU's WiFi IP — interface 1 is the WiFi (dsrc) interface
      sr->AddHostRouteTo (dsrcInterfaces.GetAddress (N_VEHICLES + rsu_idx), 1);
    }

  Simulator::Stop (Seconds (simTime));

  // ── NetAnim setup ─────────────────────────────────────────────────────────
  AnimationInterface anim ("vanet_test.xml");
  anim.EnablePacketMetadata ();   // shows packet labels in animation

  // ── Schedule periodic RSU handoff check every 0.5 seconds ─────────────────
  // First call at t=0.5s — by then vehicles have moved and MobilityModel is live.
  // CheckHandoff() reschedules itself at the end to create a repeating timer.
  Time handoffInterval = MilliSeconds (500);
  Simulator::Schedule (handoffInterval, &CheckHandoff,
      N_VEHICLES, N_RSUS, &anim, handoffInterval);

  // Color and label vehicles (Green) — label shows target RSU so it's clear in NetAnim
  for (uint32_t i = 0; i < N_VEHICLES; i++)
    {
      anim.UpdateNodeColor (vehicleNodes.Get (i), 0, 255, 0);
      // Label format: "V0→RSU0" — makes vehicle-to-RSU assignment visually obvious
      anim.UpdateNodeDescription (vehicleNodes.Get (i),
          "V" + std::to_string (i) + "->" + "RSU" + std::to_string (nearest_rsu[i]));
      anim.UpdateNodeSize (vehicleNodes.Get (i)->GetId (), 10.0, 10.0);
    }

  // Color and label RSUs: Yellow if HONEST, Red if MALICIOUS
  for (uint32_t i = 0; i < N_RSUS; i++)
    {
      if (rsu_malicious[i])
        {
          anim.UpdateNodeColor (rsuNodes.Get (i), 255, 0, 0);       // Red = malicious
          anim.UpdateNodeDescription (rsuNodes.Get (i), "RSU" + std::to_string (i) + "-MALICIOUS");
        }
      else
        {
          anim.UpdateNodeColor (rsuNodes.Get (i), 255, 255, 0);     // Yellow = honest
          anim.UpdateNodeDescription (rsuNodes.Get (i), "RSU" + std::to_string (i) + "-HONEST");
        }
      anim.UpdateNodeSize (rsuNodes.Get (i)->GetId (), 15.0, 15.0);
    }

  // Color and label Controller (Purple)
  anim.UpdateNodeColor (controllerNode.Get (0), 255, 0, 255);
  anim.UpdateNodeDescription (controllerNode.Get (0), "SDN-Controller");
  anim.UpdateNodeSize (controllerNode.Get (0)->GetId (), 15.0, 15.0);

  // Color and label Management (Dark Red)
  anim.UpdateNodeColor (managementNode.Get (0), 180, 0, 0);
  anim.UpdateNodeDescription (managementNode.Get (0), "Management");
  anim.UpdateNodeSize (managementNode.Get (0)->GetId (), 15.0, 15.0);

  // ── Print summary ─────────────────────────────────────────────────────────
  int malicious_count = 0;
  for (uint32_t i = 0; i < N_RSUS; i++) if (rsu_malicious[i]) malicious_count++;

  std::cout << "\n========================================" << std::endl;
  std::cout << "  MRTPA Test Network - NetAnim Output" << std::endl;
  std::cout << "========================================" << std::endl;
  std::cout << "  Vehicles          : " << N_VEHICLES << std::endl;
  std::cout << "  RSUs              : " << N_RSUS << std::endl;
  std::cout << "  Attack percentage : " << attack_percentage << "%" << std::endl;
  std::cout << "  Malicious RSUs    : " << malicious_count << "/" << N_RSUS << std::endl;
  std::cout << "  Sim time          : " << simTime << "s" << std::endl;
  std::cout << "  Animation file    : vanet_test.xml" << std::endl;
  std::cout << "========================================" << std::endl;
  std::cout << "  Open in NetAnim:" << std::endl;
  std::cout << "  /home/niranga/ns-allinone-3.35/netanim-3.108/NetAnim vanet_test.xml" << std::endl;
  std::cout << "========================================\n" << std::endl;

  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}
