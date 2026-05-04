// ============================================================
// SECTION 1: NS-3 Includes and Standard Library Headers
// All #include directives and using namespace statements
// ============================================================
#include "ns3/wave-module.h"
#include "ns3/csma-helper.h"
#include "ns3/lte-helper.h"
#include "ns3/aodv-module.h"
#include "ns3/lte-module.h"
#include "ns3/lte-net-device.h"
#include "ns3/wifi-module.h"
#include "ns3/wifi-net-device.h"
#include "ns3/mobility-module.h"
#include "ns3/core-module.h"
#include "ns3/wave-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/node.h"
#include "ns3/core-module.h"
//#include "ns3/ns3-ai-module.h"
#include "ns3/log.h"
#include "ns3/tag.h"
#include "ns3/vector.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include "ns3/mac48-address.h"
#include "ns3/mac64-address.h"
#include "ns3/constant-acceleration-mobility-model.h"
#include "ns3/mobility-model.h"
#include "ns3/nstime.h"
#include "ns3/event-id.h"
#include "ns3/wifi-mac-queue.h"
//#include "ns3/console-color.h"
#include <iomanip>      // std::setprecision
#include <cmath>
#include "ns3/socket.h"
#include "ns3/application.h"
#include "ns3/udp-socket.h"
#include "ns3/csma-net-device.h"
#include "ns3/ethernet-header.h"
#include "ns3/arp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/udp-header.h"
#include "ns3/ns2-mobility-helper.h"
#include "string.h"
#include "cstdlib"
#include "sstream"
#include "iostream"
#include "fstream"
#include "vector"
#include <cstdlib>
#include <limits.h>
#include <bits/stdc++.h>
#include "ns3/random-variable-stream.h"
#include <random>     // std::mt19937, std::shuffle
#include <algorithm>  // std::shuffle, std::round
#include <vector>     // std::vector (for RSU candidate list)
#include "ns3/core-module.h"
#include <chrono>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>

