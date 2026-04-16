// ============================================================
// SECTION 3: Packet Tags
// MPTD-PQS: Dual-Mode Detection for MP and TP Attacks in SDVN
// ============================================================
// Reduced from ~95,840 lines (746 legacy LDA tag classes) to
// only the tags needed for MPTD-PQS:
//
//  BsmBeaconTag        — Primary BSM beacon (paper §3.4.4 Eq.3.9)
//  CustomDataTag       — V2I broadcast (legacy, migrated in Stage 5)
//  [Stubs]             — 8 tags still referenced by 08/11 headers
//                        Will be removed when those files are rewritten
//                        in Stages 4 and 6.
// ============================================================

#ifndef MPTD_PQS_PACKET_TAGS_H
#define MPTD_PQS_PACKET_TAGS_H

#include "ns3/tag.h"
#include "ns3/vector.h"
#include "ns3/simulator.h"

// ============================================================
// BsmBeaconTag — Paper §3.4.4 Eq. (3.9)
// b_i(t) = (p_i(t), s_i(t), θ_i(t), a_i(t), t, ID_i)
// ============================================================
class BsmBeaconTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId(void);
    virtual ns3::TypeId GetInstanceTypeId(void) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(ns3::TagBuffer i) const;
    virtual void Deserialize(ns3::TagBuffer i);
    virtual void Print(std::ostream &os) const;

    BsmBeaconTag();

    // Setters
    void SetPosition(double x, double y)   { m_pos_x = x; m_pos_y = y; }
    void SetSpeed(double s)                 { m_speed = s; }
    void SetHeading(double h)               { m_heading = h; }
    void SetAcceleration(double a)          { m_accel = a; }
    void SetTimestamp(double t)             { m_timestamp = t; }
    void SetVehicleId(uint32_t id)          { m_vehicle_id = id; }
    void SetIsPoisoned(bool p)              { m_is_poisoned = p; }
    void SetAttackType(uint32_t at)         { m_attack_type = at; }
    void SetSigViolated(uint32_t sv)        { m_sig_violated = sv; }

    // Getters
    double   GetPosX()        const { return m_pos_x; }
    double   GetPosY()        const { return m_pos_y; }
    double   GetSpeed()       const { return m_speed; }
    double   GetHeading()     const { return m_heading; }
    double   GetAcceleration()const { return m_accel; }
    double   GetTimestamp()   const { return m_timestamp; }
    uint32_t GetVehicleId()   const { return m_vehicle_id; }
    bool     GetIsPoisoned()  const { return m_is_poisoned; }
    uint32_t GetAttackType()  const { return m_attack_type; }
    uint32_t GetSigViolated() const { return m_sig_violated; }

private:
    double   m_pos_x       = 0.0;
    double   m_pos_y       = 0.0;
    double   m_speed       = 0.0;   // m/s
    double   m_heading     = 0.0;   // radians
    double   m_accel       = 0.0;   // m/s²
    double   m_timestamp   = 0.0;   // simulation seconds
    uint32_t m_vehicle_id  = 0;
    bool     m_is_poisoned = false;
    uint32_t m_attack_type = 0;     // 1-7 matching attack_number
    uint32_t m_sig_violated = 0;    // bitmask: bit0=TP-S1 .. bit8=MP-S4
};

NS_OBJECT_ENSURE_REGISTERED(BsmBeaconTag);

BsmBeaconTag::BsmBeaconTag() {}

ns3::TypeId BsmBeaconTag::GetTypeId(void) {
    static ns3::TypeId tid = ns3::TypeId("ns3::BsmBeaconTag")
        .SetParent<ns3::Tag>()
        .AddConstructor<BsmBeaconTag>();
    return tid;
}
ns3::TypeId BsmBeaconTag::GetInstanceTypeId(void) const {
    return BsmBeaconTag::GetTypeId();
}
uint32_t BsmBeaconTag::GetSerializedSize(void) const {
    return 5 * sizeof(double) + 3 * sizeof(uint32_t) + sizeof(bool);
}
void BsmBeaconTag::Serialize(ns3::TagBuffer i) const {
    i.WriteDouble(m_pos_x);
    i.WriteDouble(m_pos_y);
    i.WriteDouble(m_speed);
    i.WriteDouble(m_heading);
    i.WriteDouble(m_accel);
    i.WriteDouble(m_timestamp);
    i.WriteU32(m_vehicle_id);
    i.WriteU8(m_is_poisoned ? 1 : 0);
    i.WriteU32(m_attack_type);
    i.WriteU32(m_sig_violated);
}
void BsmBeaconTag::Deserialize(ns3::TagBuffer i) {
    m_pos_x      = i.ReadDouble();
    m_pos_y      = i.ReadDouble();
    m_speed      = i.ReadDouble();
    m_heading    = i.ReadDouble();
    m_accel      = i.ReadDouble();
    m_timestamp  = i.ReadDouble();
    m_vehicle_id = i.ReadU32();
    m_is_poisoned = (i.ReadU8() != 0);
    m_attack_type = i.ReadU32();
    m_sig_violated = i.ReadU32();
}
void BsmBeaconTag::Print(std::ostream &os) const {
    os << "BSM[v=" << m_vehicle_id
       << " pos=(" << m_pos_x << "," << m_pos_y << ")"
       << " spd=" << m_speed
       << " hdg=" << m_heading
       << " acc=" << m_accel
       << " t=" << m_timestamp
       << (m_is_poisoned ? " POISONED" : " CLEAN")
       << "]";
}

// ============================================================
// CustomDataTag — Legacy V2I broadcast tag (migrated in Stage 5)
// Has position/velocity/accel — functionally similar to BsmBeaconTag
// Kept until 08_lldp_handlers.h is replaced in Stage 4.
// ============================================================
class CustomDataTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId(void);
    virtual ns3::TypeId GetInstanceTypeId(void) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(ns3::TagBuffer i) const;
    virtual void Deserialize(ns3::TagBuffer i);
    virtual void Print(std::ostream &os) const;

    CustomDataTag();
    CustomDataTag(uint32_t node_id);
    virtual ~CustomDataTag();

    ns3::Vector GetPosition(void)     { return m_currentPosition; }
    ns3::Vector GetVelocity(void)     { return m_currentVelocity; }
    ns3::Vector GetAcceleration(void) { return m_currentAcceleration; }
    uint32_t    GetNodeId()           { return m_nodeId; }
    uint32_t    GetPortId()           { return m_portId; }
    ns3::Time   GetTimestamp()        { return m_timestamp; }
    uint8_t*    GetHMAC1()            { return m_HMAC1; }

    void SetPosition(ns3::Vector pos)     { m_currentPosition = pos; }
    void SetVelocity(ns3::Vector vel)     { m_currentVelocity = vel; }
    void SetAcceleration(ns3::Vector acc) { m_currentAcceleration = acc; }
    void SetNodeId(uint32_t id)           { m_nodeId = id; }
    void SetPortId(uint32_t id)           { m_portId = id; }
    void SetTimestamp(ns3::Time t)        { m_timestamp = t; }
    void SetHMAC1(uint8_t* hmac)          { memcpy(m_HMAC1, hmac, 65); }

private:
    uint32_t    m_nodeId = 0;
    uint32_t    m_portId = 0;
    ns3::Vector m_currentPosition;
    ns3::Vector m_currentVelocity;
    ns3::Vector m_currentAcceleration;
    ns3::Time   m_timestamp;
    uint8_t     m_HMAC1[65] = {0};
};

NS_OBJECT_ENSURE_REGISTERED(CustomDataTag);

CustomDataTag::CustomDataTag() {
    m_timestamp = ns3::Simulator::Now();
    m_nodeId = 0;
}
CustomDataTag::CustomDataTag(uint32_t node_id) {
    m_timestamp = ns3::Simulator::Now();
    m_nodeId = node_id;
}
CustomDataTag::~CustomDataTag() {}

ns3::TypeId CustomDataTag::GetTypeId(void) {
    static ns3::TypeId tid = ns3::TypeId("ns3::CustomDataTag")
        .SetParent<ns3::Tag>()
        .AddConstructor<CustomDataTag>();
    return tid;
}
ns3::TypeId CustomDataTag::GetInstanceTypeId(void) const {
    return CustomDataTag::GetTypeId();
}
uint32_t CustomDataTag::GetSerializedSize(void) const {
    return 2 * sizeof(uint32_t) + 3 * sizeof(double) * 3 + sizeof(double) + 65;
}
void CustomDataTag::Serialize(ns3::TagBuffer i) const {
    i.WriteU32(m_nodeId);
    i.WriteU32(m_portId);
    i.WriteDouble(m_currentPosition.x);
    i.WriteDouble(m_currentPosition.y);
    i.WriteDouble(m_currentPosition.z);
    i.WriteDouble(m_currentVelocity.x);
    i.WriteDouble(m_currentVelocity.y);
    i.WriteDouble(m_currentVelocity.z);
    i.WriteDouble(m_currentAcceleration.x);
    i.WriteDouble(m_currentAcceleration.y);
    i.WriteDouble(m_currentAcceleration.z);
    i.WriteDouble(m_timestamp.GetSeconds());
    i.Write(m_HMAC1, 65);
}
void CustomDataTag::Deserialize(ns3::TagBuffer i) {
    m_nodeId = i.ReadU32();
    m_portId = i.ReadU32();
    m_currentPosition.x     = i.ReadDouble();
    m_currentPosition.y     = i.ReadDouble();
    m_currentPosition.z     = i.ReadDouble();
    m_currentVelocity.x     = i.ReadDouble();
    m_currentVelocity.y     = i.ReadDouble();
    m_currentVelocity.z     = i.ReadDouble();
    m_currentAcceleration.x = i.ReadDouble();
    m_currentAcceleration.y = i.ReadDouble();
    m_currentAcceleration.z = i.ReadDouble();
    double ts = i.ReadDouble();
    m_timestamp = ns3::Seconds(ts);
    i.Read(m_HMAC1, 65);
}
void CustomDataTag::Print(std::ostream &os) const {
    os << "DataTag[node=" << m_nodeId << " pos=(" << m_currentPosition << ")]";
}

// ============================================================
// STUB TAGS — referenced by 08_lldp_handlers.h and
// 11_routing_blockchain_transmission.h which will be rewritten
// in Stages 4 and 6. Stubs are minimal but compile cleanly.
// ============================================================

// ── Numbered metadata tag stubs for 09_send_lte.h ─────────────────────────
// 08_lldp_handlers.h defined CustomMetaDataUnicastTag0..25; we stub them here.
// Each had SetNodeId, SetTimestamp, Setneighborid; only these 3 are used.
// Remove when 09_send_lte.h is cleaned in Stage 5.
#define DEFINE_META_UNICAST_TAG(N)                                                          \
class CustomMetaDataUnicastTag##N : public ns3::Tag {                                       \
public:                                                                                     \
    static ns3::TypeId GetTypeId() {                                                        \
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomMetaDataUnicastTag" #N)           \
            .SetParent<ns3::Tag>().AddConstructor<CustomMetaDataUnicastTag##N>();           \
        return tid;                                                                         \
    }                                                                                       \
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }                  \
    uint32_t GetSerializedSize() const override { return 4; }                               \
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }                     \
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }                            \
    void Print(std::ostream &os) const override { os << "MetaUnicast" #N; }                \
    void SetNodeId(uint32_t id) { m_nodeId = id; }                                         \
    uint32_t GetNodeId() const { return m_nodeId; }                                         \
    void SetTimestamp(ns3::Time t) { m_ts = t; }                                            \
    ns3::Time GetTimestamp() const { return m_ts; }                                         \
    void Setneighborid(uint32_t*) {}                                                        \
private:                                                                                    \
    uint32_t  m_nodeId = 0;                                                                 \
    ns3::Time m_ts;                                                                         \
};                                                                                          \
NS_OBJECT_ENSURE_REGISTERED(CustomMetaDataUnicastTag##N);

DEFINE_META_UNICAST_TAG(0)  DEFINE_META_UNICAST_TAG(1)  DEFINE_META_UNICAST_TAG(2)
DEFINE_META_UNICAST_TAG(3)  DEFINE_META_UNICAST_TAG(4)  DEFINE_META_UNICAST_TAG(5)
DEFINE_META_UNICAST_TAG(6)  DEFINE_META_UNICAST_TAG(7)  DEFINE_META_UNICAST_TAG(8)
DEFINE_META_UNICAST_TAG(9)  DEFINE_META_UNICAST_TAG(10) DEFINE_META_UNICAST_TAG(11)
DEFINE_META_UNICAST_TAG(12) DEFINE_META_UNICAST_TAG(13) DEFINE_META_UNICAST_TAG(14)
DEFINE_META_UNICAST_TAG(15) DEFINE_META_UNICAST_TAG(16) DEFINE_META_UNICAST_TAG(17)
DEFINE_META_UNICAST_TAG(18) DEFINE_META_UNICAST_TAG(19) DEFINE_META_UNICAST_TAG(20)
DEFINE_META_UNICAST_TAG(21) DEFINE_META_UNICAST_TAG(22) DEFINE_META_UNICAST_TAG(23)
DEFINE_META_UNICAST_TAG(24) DEFINE_META_UNICAST_TAG(25)

#define DEFINE_STUB_TAG(ClassName, TypeName)                             \
class ClassName : public ns3::Tag {                                      \
public:                                                                  \
    static ns3::TypeId GetTypeId(void) {                                 \
        static ns3::TypeId tid = ns3::TypeId(TypeName)                   \
            .SetParent<ns3::Tag>().AddConstructor<ClassName>();          \
        return tid;                                                      \
    }                                                                    \
    virtual ns3::TypeId GetInstanceTypeId(void) const                    \
        { return GetTypeId(); }                                          \
    virtual uint32_t GetSerializedSize(void) const { return 4; }        \
    virtual void Serialize(ns3::TagBuffer i) const { i.WriteU32(0); }   \
    virtual void Deserialize(ns3::TagBuffer i) { i.ReadU32(); }         \
    virtual void Print(std::ostream &os) const { os << TypeName; }      \
    uint32_t GetNodeId() const { return m_nodeId; }                     \
    void SetNodeId(uint32_t id) { m_nodeId = id; }                      \
    uint32_t GetPortId() const { return m_portId; }                     \
    void SetPortId(uint32_t id) { m_portId = id; }                      \
    ns3::Time GetTimestamp() const { return m_ts; }                     \
    void SetTimestamp(ns3::Time t) { m_ts = t; }                        \
    ns3::Vector GetPosition() const { return m_pos; }                   \
    void SetPosition(ns3::Vector v) { m_pos = v; }                      \
    ns3::Vector GetVelocity() const { return m_vel; }                   \
    void SetVelocity(ns3::Vector v) { m_vel = v; }                      \
private:                                                                 \
    uint32_t    m_nodeId = 0;                                            \
    uint32_t    m_portId = 0;                                            \
    ns3::Time   m_ts;                                                    \
    ns3::Vector m_pos;                                                   \
    ns3::Vector m_vel;                                                   \
};                                                                       \
NS_OBJECT_ENSURE_REGISTERED(ClassName);

// CustomDataUnicastTag needs SetsenderId, template SetNodeId, Setposition/velocity/accel
// Cannot use DEFINE_STUB_TAG (SetNodeId takes uint32_t* at call sites).
class CustomDataUnicastTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomDataUnicastTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomDataUnicastTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "DataUnicast"; }
    // Scalar accessors (for code that uses scalars)
    uint32_t GetNodeId() const { return m_nodeId; }
    uint32_t GetPortId() const { return m_portId; }
    ns3::Time GetTimestamp() const { return m_ts; }
    ns3::Vector GetPosition() const { return m_pos; }
    ns3::Vector GetVelocity() const { return m_vel; }
    ns3::Vector GetAcceleration() const { return m_acc; }
    void SetPosition(ns3::Vector v) { m_pos = v; }
    void SetVelocity(ns3::Vector v) { m_vel = v; }
    void SetTimestamp(ns3::Time t)  { m_ts = t; }
    // Setters needed by 11_routing (take arrays/pointers)
    void SetsenderId(uint32_t id)                  { m_nodeId = id; }
    template<typename T> void SetNodeId(T*)        {}
    template<typename T> void SetPortId(T*)        {}
    template<typename T> void Setposition(T*)      {}
    template<typename T> void Setvelocity(T*)      {}
    template<typename T> void Setacceleration(T*)  {}
    template<typename T> void SetTimestamp(T*)     {}
    void SetdestinationId(uint32_t id)             { m_portId = id; }
private:
    uint32_t    m_nodeId = 0, m_portId = 0;
    ns3::Time   m_ts;
    ns3::Vector m_pos, m_vel, m_acc;
};
NS_OBJECT_ENSURE_REGISTERED(CustomDataUnicastTag);

// ── CustomDataTag1..25, CustomDataTagmax ──────────────────────────────────
// Used in dsrc_data_broadcast() with SetNeighborids(uint32_t*), SetPosition, etc.
#define DEFINE_CUSTOM_DATA_TAG(N)                                                          \
class CustomDataTag##N : public ns3::Tag {                                                 \
public:                                                                                    \
    static ns3::TypeId GetTypeId() {                                                       \
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomDataTag" #N)                     \
            .SetParent<ns3::Tag>().AddConstructor<CustomDataTag##N>();                     \
        return tid;                                                                        \
    }                                                                                      \
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }                 \
    uint32_t GetSerializedSize() const override { return 4; }                              \
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }                    \
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }                           \
    void Print(std::ostream &os) const override { os << "DataTag" #N; }                   \
    void SetNodeId(uint32_t id)           { m_nodeId = id; }                              \
    uint32_t GetNodeId() const            { return m_nodeId; }                            \
    template<typename T> void SetNeighborids(T*) {}                                       \
    void SetPosition(ns3::Vector v)       { m_pos = v; }                                  \
    void SetVelocity(ns3::Vector v)       { m_vel = v; }                                  \
    void SetAcceleration(ns3::Vector v)   { m_acc = v; }                                  \
    void SetTimestamp(ns3::Time t)        { m_ts = t; }                                   \
    ns3::Vector GetPosition() const  { return m_pos; }                                    \
    ns3::Vector GetVelocity() const  { return m_vel; }                                    \
    ns3::Time   GetTimestamp() const { return m_ts; }                                     \
private:                                                                                   \
    uint32_t    m_nodeId = 0;                                                              \
    ns3::Vector m_pos, m_vel, m_acc;                                                       \
    ns3::Time   m_ts;                                                                      \
};                                                                                         \
NS_OBJECT_ENSURE_REGISTERED(CustomDataTag##N);

DEFINE_CUSTOM_DATA_TAG(1)  DEFINE_CUSTOM_DATA_TAG(2)  DEFINE_CUSTOM_DATA_TAG(3)
DEFINE_CUSTOM_DATA_TAG(4)  DEFINE_CUSTOM_DATA_TAG(5)  DEFINE_CUSTOM_DATA_TAG(6)
DEFINE_CUSTOM_DATA_TAG(7)  DEFINE_CUSTOM_DATA_TAG(8)  DEFINE_CUSTOM_DATA_TAG(9)
DEFINE_CUSTOM_DATA_TAG(10) DEFINE_CUSTOM_DATA_TAG(11) DEFINE_CUSTOM_DATA_TAG(12)
DEFINE_CUSTOM_DATA_TAG(13) DEFINE_CUSTOM_DATA_TAG(14) DEFINE_CUSTOM_DATA_TAG(15)
DEFINE_CUSTOM_DATA_TAG(16) DEFINE_CUSTOM_DATA_TAG(17) DEFINE_CUSTOM_DATA_TAG(18)
DEFINE_CUSTOM_DATA_TAG(19) DEFINE_CUSTOM_DATA_TAG(20) DEFINE_CUSTOM_DATA_TAG(21)
DEFINE_CUSTOM_DATA_TAG(22) DEFINE_CUSTOM_DATA_TAG(23) DEFINE_CUSTOM_DATA_TAG(24)
DEFINE_CUSTOM_DATA_TAG(25)

// CustomDataTagmax — "default" case when size exceeds 25 neighbors
class CustomDataTagmax : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomDataTagmax")
            .SetParent<ns3::Tag>().AddConstructor<CustomDataTagmax>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "DataTagmax"; }
    void SetNodeId(uint32_t id)           { m_nodeId = id; }
    uint32_t GetNodeId() const            { return m_nodeId; }
    template<typename T> void SetNeighborids(T*) {}
    void SetPosition(ns3::Vector v)       { m_pos = v; }
    void SetVelocity(ns3::Vector v)       { m_vel = v; }
    void SetAcceleration(ns3::Vector v)   {}
    void SetTimestamp(ns3::Time t)        { m_ts = t; }
    ns3::Vector GetPosition() const  { return m_pos; }
    ns3::Time   GetTimestamp() const { return m_ts; }
private:
    uint32_t    m_nodeId = 0;
    ns3::Vector m_pos, m_vel;
    ns3::Time   m_ts;
};
NS_OBJECT_ENSURE_REGISTERED(CustomDataTagmax);

// ── CustomDataUnicastTag1..25, CustomDataUnicastTag_Routing ──────────────
// Used in send_dsrc_data_unicast(); SetNodeId/SetPortId/Setposition/etc. take arrays.
#define DEFINE_DATA_UNICAST_TAG(N)                                                         \
class CustomDataUnicastTag##N : public ns3::Tag {                                          \
public:                                                                                    \
    static ns3::TypeId GetTypeId() {                                                       \
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomDataUnicastTag" #N)              \
            .SetParent<ns3::Tag>().AddConstructor<CustomDataUnicastTag##N>();              \
        return tid;                                                                        \
    }                                                                                      \
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }                 \
    uint32_t GetSerializedSize() const override { return 4; }                              \
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }                    \
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }                           \
    void Print(std::ostream &os) const override { os << "DataUnicastTag" #N; }            \
    void SetsenderId(uint32_t id) { m_senderId = id; }                                    \
    uint32_t GetsenderId() const  { return m_senderId; }                                  \
    template<typename T> void SetNodeId(T* p)        {}                                   \
    template<typename T> void SetPortId(T* p)        {}                                   \
    template<typename T> void Setposition(T* p)      {}                                   \
    template<typename T> void Setvelocity(T* p)      {}                                   \
    template<typename T> void Setacceleration(T* p)  {}                                   \
    template<typename T> void SetTimestamp(T* p)     {}                                   \
private:                                                                                   \
    uint32_t m_senderId = 0;                                                               \
};                                                                                         \
NS_OBJECT_ENSURE_REGISTERED(CustomDataUnicastTag##N);

DEFINE_DATA_UNICAST_TAG(1)  DEFINE_DATA_UNICAST_TAG(2)  DEFINE_DATA_UNICAST_TAG(3)
DEFINE_DATA_UNICAST_TAG(4)  DEFINE_DATA_UNICAST_TAG(5)  DEFINE_DATA_UNICAST_TAG(6)
DEFINE_DATA_UNICAST_TAG(7)  DEFINE_DATA_UNICAST_TAG(8)  DEFINE_DATA_UNICAST_TAG(9)
DEFINE_DATA_UNICAST_TAG(10) DEFINE_DATA_UNICAST_TAG(11) DEFINE_DATA_UNICAST_TAG(12)
DEFINE_DATA_UNICAST_TAG(13) DEFINE_DATA_UNICAST_TAG(14) DEFINE_DATA_UNICAST_TAG(15)
DEFINE_DATA_UNICAST_TAG(16) DEFINE_DATA_UNICAST_TAG(17) DEFINE_DATA_UNICAST_TAG(18)
DEFINE_DATA_UNICAST_TAG(19) DEFINE_DATA_UNICAST_TAG(20) DEFINE_DATA_UNICAST_TAG(21)
DEFINE_DATA_UNICAST_TAG(22) DEFINE_DATA_UNICAST_TAG(23) DEFINE_DATA_UNICAST_TAG(24)
DEFINE_DATA_UNICAST_TAG(25)

// CustomDataUnicastTag_Routing — routing unicast with getters returning pointers
class CustomDataUnicastTag_Routing : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomDataUnicastTag_Routing")
            .SetParent<ns3::Tag>().AddConstructor<CustomDataUnicastTag_Routing>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "DataUnicastTagRouting"; }
    void SetsenderId(uint32_t id)              { m_senderId = id; }
    uint32_t GetsenderId() const               { return m_senderId; }
    void SetdestinationId(uint32_t id)         { m_destId = id; }
    uint32_t GetdestinationId() const          { return m_destId; }
    template<typename T> void SetNodeId(T* p)        {}
    template<typename T> void SetPortId(T* p)        {}
    template<typename T> void Setposition(T* p)      {}
    template<typename T> void Setvelocity(T* p)      {}
    template<typename T> void Setacceleration(T* p)  {}
    template<typename T> void SetTimestamp(T* p)     {}
    // Pointer getters (uint32_t* source = tag.GetNodeId() pattern)
    uint32_t*    GetNodeId()       { return &m_nodeId; }
    uint32_t*    GetPortId()       { return &m_portId; }
    // Vector/Time getters return pointers
    ns3::Vector* Getposition()     { return &m_pos; }
    ns3::Vector* Getvelocity()     { return &m_vel; }
    ns3::Vector* Getacceleration() { return &m_acc; }
    ns3::Time*   GetTimestamp()    { return &m_ts; }
private:
    uint32_t    m_senderId = 0, m_destId = 0;
    uint32_t    m_nodeId = 0,   m_portId = 0;
    ns3::Vector m_pos, m_vel, m_acc;
    ns3::Time   m_ts;
};
NS_OBJECT_ENSURE_REGISTERED(CustomDataUnicastTag_Routing);
// CustomDeltavaluesDownlinkUnicastTag needs extra methods; cannot use DEFINE_STUB_TAG.
class CustomDeltavaluesDownlinkUnicastTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomDeltavaluesDownlinkUnicastTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomDeltavaluesDownlinkUnicastTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "DeltaDownlink"; }
    uint32_t GetNodeId() const { return m_nodeId; }
    void SetNodeId(uint32_t id) { m_nodeId = id; }
    void Setnodeid(uint32_t id)             { m_nodeId = id; }
    template<typename T> void Setdeltas(T*)       {}
    template<typename T> void Setsources(T*)      {}
    template<typename T> void Setdestinations(T*) {}
    template<typename T> void Setflow_ids(T*)     {}
    template<typename T> void Setflow_sizes(T*)   {}
    template<typename T> void Setload(T*)         {}
private:
    uint32_t m_nodeId = 0;
};
NS_OBJECT_ENSURE_REGISTERED(CustomDeltavaluesDownlinkUnicastTag);
DEFINE_STUB_TAG(CustomFlowDataUplinkTag,             "ns3::CustomFlowDataUplinkTag")
// CustomHMACTag needs SetHMAC, Setsize, SetsenderId, Setposition/velocity/accel
class CustomHMACTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomHMACTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomHMACTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "HMACTag"; }
    uint32_t GetNodeId() const { return m_nodeId; }
    void SetNodeId(uint32_t id) { m_nodeId = id; }
    uint32_t GetPortId() const { return m_portId; }
    void SetPortId(uint32_t id) { m_portId = id; }
    // SetHMAC(uint8_t[64], uint32_t index) — called in loop
    void SetHMAC(uint8_t*, uint32_t)       {}
    void SetHMAC(uint8_t*)                 {}
    void Setsize(uint32_t)                 {}
    void SetsenderId(uint32_t id)          { m_nodeId = id; }
    // Template versions for array/pointer args
    template<typename T> void SetNodeId(T*)        {}
    template<typename T> void SetPortId(T*)        {}
    template<typename T> void Setposition(T*)      {}
    template<typename T> void Setvelocity(T*)      {}
    template<typename T> void Setacceleration(T*)  {}
    template<typename T> void SetTimestamp(T*)     {}
    void SetTimestamp(ns3::Time t) {}
private:
    uint32_t m_nodeId = 0, m_portId = 0;
};
NS_OBJECT_ENSURE_REGISTERED(CustomHMACTag);
// CustomLLDPDownlinkUnicastTag needs extra methods; cannot use DEFINE_STUB_TAG macro.
class CustomLLDPDownlinkUnicastTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomLLDPDownlinkUnicastTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomLLDPDownlinkUnicastTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "LLDPDownlink"; }
    // Basic accessors from DEFINE_STUB_TAG
    uint32_t GetNodeId() const { return m_nodeId; }
    void SetNodeId(uint32_t id) { m_nodeId = id; }
    uint32_t GetPortId() const { return m_portId; }
    void SetPortId(uint32_t id) { m_portId = id; }
    ns3::Time GetTimestamp() const { return m_ts; }
    void SetTimestamp(ns3::Time t) { m_ts = t; }
    ns3::Vector GetPosition() const { return m_pos; }
    void SetPosition(ns3::Vector v) { m_pos = v; }
    ns3::Vector GetVelocity() const { return m_vel; }
    void SetVelocity(ns3::Vector v) { m_vel = v; }
    // Extra LLDP methods used by send_uplink_data_first_time
    void Setrawsrcnodeid(uint8_t*)   {}
    void Setrawsrcportid(uint8_t*)   {}
    void SetStage(uint8_t*)          {}
    void SetHMAC_key(uint8_t*)       {}
    void SetHMAC1(uint8_t*)          {}
    void SetHMAC2(uint8_t*)          {}
    void SetDS_public_key1(uint8_t*) {}
    void SetDS_public_key2(uint8_t*) {}
    void SetDS_public_key3(uint8_t*) {}
    void SetDS1(uint8_t*)            {}
    void SetDS2(uint8_t*)            {}
    template<typename T> void Setsrcnodeid(T*) {}
    template<typename T> void Setsrcportid(T*) {}
    template<typename T> void Setdesportid(T*) {}
    template<typename T> void Setdesnodeid(T*) {}
    // Getters (return empty buffer pointer)
    uint8_t* Getdesnodeid()    { return m_buf; }
    uint8_t* Getrawsrcnodeid() { return m_buf; }
    uint8_t* Getrawsrcportid() { return m_buf; }
    uint8_t* Getsrcnodeid()    { return m_buf; }
    uint8_t* Getsrcportid()    { return m_buf; }
    uint8_t* GetStage()        { return m_buf; }
    uint8_t* GetHMAC()         { return m_buf; }
    uint8_t* GetHMAC1()        { return m_buf; }
    uint8_t* GetHMAC2()        { return m_buf; }
    uint8_t* GetDS1()          { return m_buf; }
    uint8_t* GetDS2()          { return m_buf; }
private:
    uint32_t    m_nodeId = 0, m_portId = 0;
    ns3::Time   m_ts;
    ns3::Vector m_pos, m_vel;
    uint8_t     m_buf[4] = {0};
};
NS_OBJECT_ENSURE_REGISTERED(CustomLLDPDownlinkUnicastTag);
DEFINE_STUB_TAG(CustomMetaDataBroadcastTag,          "ns3::CustomMetaDataBroadcastTag")
// CustomMetaDataDownlinkUnicastTag needs SetZ/SetX; cannot use DEFINE_STUB_TAG.
class CustomMetaDataDownlinkUnicastTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomMetaDataDownlinkUnicastTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomMetaDataDownlinkUnicastTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "MetaDownlink"; }
    uint32_t GetNodeId() const { return m_nodeId; }
    void SetNodeId(uint32_t id) { m_nodeId = id; }
    void SetZ(double v) {}
    void SetX(double v) {}
    ns3::Time GetTimestamp() const { return m_ts; }
    void SetTimestamp(ns3::Time t) { m_ts = t; }
private:
    uint32_t m_nodeId = 0;
    ns3::Time m_ts;
};
NS_OBJECT_ENSURE_REGISTERED(CustomMetaDataDownlinkUnicastTag);
// CustomMetaDataUnicastTag needs Setneighborid; cannot use DEFINE_STUB_TAG.
class CustomMetaDataUnicastTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomMetaDataUnicastTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomMetaDataUnicastTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "MetaUnicast"; }
    uint32_t GetNodeId() const { return m_nodeId; }
    void SetNodeId(uint32_t id) { m_nodeId = id; }
    uint32_t GetPortId() const { return m_portId; }
    void SetPortId(uint32_t id) { m_portId = id; }
    ns3::Time GetTimestamp() const { return m_ts; }
    void SetTimestamp(ns3::Time t) { m_ts = t; }
    template<typename T> void Setneighborid(T*) {}
private:
    uint32_t m_nodeId = 0, m_portId = 0;
    ns3::Time m_ts;
};
NS_OBJECT_ENSURE_REGISTERED(CustomMetaDataUnicastTag);
DEFINE_STUB_TAG(CustomStatusDataUplinkTag,           "ns3::CustomStatusDataUplinkTag")

// ── Legacy LLDP tag stubs for 07_security.h / 08_lldp_handlers.h ──────────
// Remove in Stage 4 when 08_lldp_handlers.h is replaced with 08_beacon_handlers.h.
// All DS/HMAC fields are uint8_t* as in the original LDA codebase.
class CustomLLDP_DP_UnicastTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomLLDP_DP_UnicastTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomLLDP_DP_UnicastTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "LLDP_DP"; }

    uint8_t* GetHMAC()           { return m_hmac; }
    uint8_t* GetHMAC1()          { return m_hmac; }
    uint8_t* GetDS_public_key1() { return m_dpk1; }
    uint8_t* GetDS_public_key2() { return m_dpk2; }
    uint8_t* GetDS_public_key3() { return m_dpk3; }
    uint8_t* GetDS1()            { return m_ds1; }
    uint8_t* GetDS2()            { return m_ds2; }
    uint8_t* Getsrcnodeid()      { return &m_srcnid; }
    uint8_t* Getsrcportid()      { return &m_srcpid; }
    uint8_t* Getdesnodeid()      { return &m_desnid; }

    void SetHMAC(uint8_t*)       {}
    void SetHMAC1(uint8_t*)      {}
    void SetDS_public_key1(uint8_t*) {}
    void SetDS_public_key2(uint8_t*) {}
    void SetDS_public_key3(uint8_t*) {}
    void SetDS1(uint8_t*)        {}
    void SetDS2(uint8_t*)        {}
    void Setsrcnodeid(uint8_t*)  {}
    void Setsrcportid(uint8_t*)  {}
    template<typename T> void Setdesnodeid(T*) {}
    template<typename T> void Setdesportid(T*) {}
private:
    uint8_t m_hmac[81]={}, m_dpk1[256]={}, m_dpk2[1280]={}, m_dpk3[1280]={};
    uint8_t m_ds1[16]={}, m_ds2[16]={};
    uint8_t m_srcnid=0, m_srcpid=0, m_desnid=0;
};
NS_OBJECT_ENSURE_REGISTERED(CustomLLDP_DP_UnicastTag);

class CustomLLDP_uplink_UnicastTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomLLDP_uplink_UnicastTag")
            .SetParent<ns3::Tag>().AddConstructor<CustomLLDP_uplink_UnicastTag>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "LLDP_uplink"; }

    void SetStage(uint8_t*)          {}
    void SetHMAC_key(uint8_t*)       {}
    void SetHMAC1(uint8_t*)          {}
    void SetHMAC2(uint8_t*)          {}
    void SetDS_public_key1(uint8_t*) {}
    void SetDS_public_key2(uint8_t*) {}
    void SetDS_public_key3(uint8_t*) {}
    void SetDS1(uint8_t*)            {}
    void SetDS2(uint8_t*)            {}
    template<typename T> void Setsrcnodeid(T*) {}
    template<typename T> void Setsrcportid(T*) {}
    template<typename T> void Setdesportid(T*) {}
    template<typename T> void Setdesnodeid(T*) {}
    uint8_t* GetHMAC1() { return m_buf; }
    uint8_t* GetHMAC2() { return m_buf; }
    uint8_t* GetHMAC()  { return m_buf; }
private:
    uint8_t m_buf[4] = {0};
};
NS_OBJECT_ENSURE_REGISTERED(CustomLLDP_uplink_UnicastTag);

// ── CustomDataUnicastTag_ModifiedRouting ──────────────────────────────────
// Used in send_dsrc_data_unicast (modified routing path).
class CustomDataUnicastTag_ModifiedRouting : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomDataUnicastTag_ModifiedRouting")
            .SetParent<ns3::Tag>().AddConstructor<CustomDataUnicastTag_ModifiedRouting>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "ModifiedRouting"; }
    void SetflowId(uint32_t id)                    { m_flowId = id; }
    uint32_t GetflowId() const                     { return m_flowId; }
    void SetpacketId(uint32_t id)                  { m_pktId = id; }
    uint32_t GetpacketId() const                   { return m_pktId; }
    void SetchannelId(uint32_t id)                 { m_chanId = id; }
    uint32_t GetchannelId() const                  { return m_chanId; }
    void Setprevious_senderId(uint32_t id)         { m_prevSender = id; }
    uint32_t Getprevious_senderId() const          { return m_prevSender; }
    void Setprevious_timestamp(ns3::Time t)        { m_prevTs = t; }
    ns3::Time Getprevious_timestamp() const        { return m_prevTs; }
    void Setoriginal_timestamp(ns3::Time t)        { m_origTs = t; }
    ns3::Time Getoriginal_timestamp() const        { return m_origTs; }
private:
    uint32_t  m_flowId = 0, m_pktId = 0, m_chanId = 0, m_prevSender = 0;
    ns3::Time m_prevTs, m_origTs;
};
NS_OBJECT_ENSURE_REGISTERED(CustomDataUnicastTag_ModifiedRouting);

// ── CustomStatusDataUplinkTag1 ────────────────────────────────────────────
class CustomStatusDataUplinkTag1 : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomStatusDataUplinkTag1")
            .SetParent<ns3::Tag>().AddConstructor<CustomStatusDataUplinkTag1>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "StatusUplink1"; }
    template<typename T> void SetNodeId(T*)       {}
    template<typename T> void Setposition(T*)     {}
    template<typename T> void Setvelocity(T*)     {}
    template<typename T> void Setacceleration(T*) {}
    void SetsenderId(uint32_t id)                 { m_id = id; }
    void SetdestinationId(uint32_t id)            {}
private:
    uint32_t m_id = 0;
};
NS_OBJECT_ENSURE_REGISTERED(CustomStatusDataUplinkTag1);

// ── CustomFlowDataUplinkTag1 ──────────────────────────────────────────────
class CustomFlowDataUplinkTag1 : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId() {
        static ns3::TypeId tid = ns3::TypeId("ns3::CustomFlowDataUplinkTag1")
            .SetParent<ns3::Tag>().AddConstructor<CustomFlowDataUplinkTag1>();
        return tid;
    }
    ns3::TypeId GetInstanceTypeId() const override { return GetTypeId(); }
    uint32_t GetSerializedSize() const override { return 4; }
    void Serialize(ns3::TagBuffer i) const override { i.WriteU32(0); }
    void Deserialize(ns3::TagBuffer i) override { i.ReadU32(); }
    void Print(std::ostream &os) const override { os << "FlowUplink1"; }
    template<typename T> void Setsource(T*)      {}
    template<typename T> void Setdestination(T*) {}
    template<typename T> void SetX(T*)           {}
    template<typename T> void SetP(T*)           {}
    template<typename T> void SetQ(T*)           {}
};
NS_OBJECT_ENSURE_REGISTERED(CustomFlowDataUplinkTag1);

#endif // MPTD_PQS_PACKET_TAGS_H
