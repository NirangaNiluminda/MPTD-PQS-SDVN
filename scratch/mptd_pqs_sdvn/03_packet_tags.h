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
    void SetRsuId(uint32_t id)             { m_rsu_id = id; }        // RSU that relayed this beacon (Option B)

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
    uint32_t GetRsuId()        const { return m_rsu_id; }

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
    uint32_t m_rsu_id       = 0;     // RSU index that relayed this beacon (Option B DSRC path)
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
    return 6 * sizeof(double) + 4 * sizeof(uint32_t) + sizeof(bool);
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
    i.WriteU32(m_rsu_id);
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
    m_rsu_id       = i.ReadU32();
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
// DownlinkControlTag — Management → RSU → Vehicle control response
// Professor's terms: centralized_dsrc_data_broadcast (all vehicles)
//                    centralized_dsrc_data_unicast   (specific vehicle)
//
// Sequence (Steps 6-8 in paper Figures 3.1-3.7):
//   HandleBeaconReceived() → [DL-MGT-TX] → RSU CSMA:8888
//   handle_downlink_at_rsu() → [DL-RSU-FWD] → DSRC:9999
//   HandleReadTwo() → [DL-VEH-RX]
//
// alert_type values:
//   0 = CLEAN_ROUTING   — no attack, forward normal routing advice
//   1 = ATTACK_DETECTED — anomaly found, send safety speed advisory
//   2 = WRONG_ROUTING   — controller malicious (attacks 5 & 7): sends wrong instructions
// ============================================================
class DownlinkControlTag : public ns3::Tag {
public:
    static ns3::TypeId GetTypeId(void);
    virtual ns3::TypeId GetInstanceTypeId(void) const;
    virtual uint32_t GetSerializedSize(void) const;
    virtual void Serialize(ns3::TagBuffer i) const;
    virtual void Deserialize(ns3::TagBuffer i);
    virtual void Print(std::ostream &os) const;

    DownlinkControlTag() {}

    void SetVehicleId  (uint32_t id) { m_vehicle_id  = id; }  // 0 = all vehicles (broadcast)
    void SetAlertType  (uint8_t  a)  { m_alert_type  = a;  }
    void SetSpeedAdvice(double   s)  { m_speed_advice = s; }
    void SetTimestamp  (double   t)  { m_timestamp   = t;  }
    void SetRsuId      (uint32_t r)  { m_rsu_id      = r;  }

    uint32_t GetVehicleId()   const { return m_vehicle_id;   }
    uint8_t  GetAlertType()   const { return m_alert_type;   }
    double   GetSpeedAdvice() const { return m_speed_advice; }
    double   GetTimestamp()   const { return m_timestamp;    }
    uint32_t GetRsuId()       const { return m_rsu_id;       }

private:
    uint32_t m_vehicle_id   = 0;
    uint8_t  m_alert_type   = 0;   // 0=CLEAN, 1=ATTACK_DETECTED, 2=WRONG_ROUTING
    double   m_speed_advice = 0.0; // suggested speed (m/s)
    double   m_timestamp    = 0.0;
    uint32_t m_rsu_id       = 0;
};

NS_OBJECT_ENSURE_REGISTERED(DownlinkControlTag);

ns3::TypeId DownlinkControlTag::GetTypeId(void) {
    static ns3::TypeId tid = ns3::TypeId("ns3::DownlinkControlTag")
        .SetParent<ns3::Tag>()
        .AddConstructor<DownlinkControlTag>();
    return tid;
}
ns3::TypeId DownlinkControlTag::GetInstanceTypeId(void) const {
    return DownlinkControlTag::GetTypeId();
}
uint32_t DownlinkControlTag::GetSerializedSize(void) const {
    return sizeof(uint32_t) + sizeof(uint8_t) + 2 * sizeof(double) + sizeof(uint32_t);
}
void DownlinkControlTag::Serialize(ns3::TagBuffer i) const {
    i.WriteU32(m_vehicle_id);
    i.WriteU8(m_alert_type);
    i.WriteDouble(m_speed_advice);
    i.WriteDouble(m_timestamp);
    i.WriteU32(m_rsu_id);
}
void DownlinkControlTag::Deserialize(ns3::TagBuffer i) {
    m_vehicle_id   = i.ReadU32();
    m_alert_type   = i.ReadU8();
    m_speed_advice = i.ReadDouble();
    m_timestamp    = i.ReadDouble();
    m_rsu_id       = i.ReadU32();
}
void DownlinkControlTag::Print(std::ostream &os) const {
    const char* a = (m_alert_type == 0) ? "CLEAN_ROUTING" :
                    (m_alert_type == 1) ? "ATTACK_DETECTED" : "WRONG_ROUTING";
    os << "DL[vid=" << m_vehicle_id
       << " alert=" << a
       << " spd_adv=" << m_speed_advice
       << " t=" << m_timestamp
       << " rsu=" << m_rsu_id << "]";
}

#endif // MPTD_PQS_PACKET_TAGS_H
