// ============================================================
// 03_packet_tags.h — MPTD-PQS Packet Tags (Stage 10B cleanup)
// ============================================================
// Retained: BsmBeaconTag — Primary BSM beacon (paper §3.4.4 Eq. 3.9)
//           b_i(t) = (p_i(t), s_i(t), θ_i(t), a_i(t), t, ID_i)
//
// Removed:  CustomDataTag, 26 CustomMetaDataUnicastTag variants,
//           25 CustomDataUnicastTag variants, LLDP/flow/HMAC tags
//           (all were used only by LDA routing code in 07_security.h
//           and 11_blockchain_transmission.h, now replaced with stubs)
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
    void SetHeading(double h)              { m_heading = h; }
    void SetAcceleration(double a)         { m_accel = a; }
    void SetTimestamp(double t)            { m_timestamp = t; }
    void SetVehicleId(uint32_t id)         { m_vehicle_id = id; }
    void SetIsPoisoned(bool p)             { m_is_poisoned = p; }
    void SetAttackType(uint32_t at)        { m_attack_type = at; }
    void SetSigViolated(uint32_t sv)       { m_sig_violated = sv; }  // bitmask: bit0=TP-S1 .. bit8=MP-S4

    // Getters
    double   GetPosX()         const { return m_pos_x; }
    double   GetPosY()         const { return m_pos_y; }
    double   GetSpeed()        const { return m_speed; }
    double   GetHeading()      const { return m_heading; }
    double   GetAcceleration() const { return m_accel; }
    double   GetTimestamp()    const { return m_timestamp; }
    uint32_t GetVehicleId()    const { return m_vehicle_id; }
    bool     GetIsPoisoned()   const { return m_is_poisoned; }
    uint32_t GetAttackType()   const { return m_attack_type; }
    uint32_t GetSigViolated()  const { return m_sig_violated; }

private:
    double   m_pos_x        = 0.0;
    double   m_pos_y        = 0.0;
    double   m_speed        = 0.0;   // m/s
    double   m_heading      = 0.0;   // radians
    double   m_accel        = 0.0;   // m/s²
    double   m_timestamp    = 0.0;   // simulation seconds
    uint32_t m_vehicle_id   = 0;
    bool     m_is_poisoned  = false;
    uint32_t m_attack_type  = 0;     // 1-7 matching attack_number
    uint32_t m_sig_violated = 0;     // bitmask: bit0=TP-S1 .. bit8=MP-S4
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
    return 6 * sizeof(double) + 3 * sizeof(uint32_t) + sizeof(bool);
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
    m_pos_x       = i.ReadDouble();
    m_pos_y       = i.ReadDouble();
    m_speed       = i.ReadDouble();
    m_heading     = i.ReadDouble();
    m_accel       = i.ReadDouble();
    m_timestamp   = i.ReadDouble();
    m_vehicle_id  = i.ReadU32();
    m_is_poisoned = (i.ReadU8() != 0);
    m_attack_type  = i.ReadU32();
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

#endif // MPTD_PQS_PACKET_TAGS_H
