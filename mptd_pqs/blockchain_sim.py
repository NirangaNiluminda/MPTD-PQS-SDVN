"""
Blockchain Simulation — SC-Trust EMA + SC-Revoke BFT
=====================================================
Implements Equations 3.58–3.67 from Section 3.5 of the paper.

Components:
  SC-Trust  : EMA trust score per RSU (Eq 3.66)
              τ_r(t) = α · τ_r(t-1) + (1-α) · event_score(t)
  SC-Revoke : BFT revocation committee vote (Eq 3.67)
              Revoke if votes ≥ ⌈(n_committee + 1) / 2⌉ (t-of-n BFT)
  Post-Quantum TRS: Threshold Ring Signature (CRYSTALS-Dilithium stub)
                    (Eq 3.58–3.60) — simulated as HMAC chain
  FHE       : Privacy-preserving I2I stub (Eq 3.61–3.65)

Hyperledger Fabric simulation:
  - Records stored as append-only ledger
  - Off-chain data referenced by content hash (IPFS stub)
  - Smart contract execution simulated synchronously
"""

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict


# ── Parameters (from Section 3.5) ────────────────────────────────────────────
TRUST_ALPHA      = 0.7    # EMA decay factor α
TRUST_INIT       = 0.5    # initial trust score
TRUST_THRESHOLD  = 0.3    # below this → RSU is suspect
N_COMMITTEE      = 5      # RSU committee size for BFT vote
REVOKE_THRESHOLD = math.ceil((N_COMMITTEE + 1) / 2)  # majority


@dataclass
class BlockchainRecord:
    """Simulates one on-chain record (off-chain hash → IPFS stub)."""
    record_id: str
    vehicle_id: str
    rsu_id: str
    timestamp: float
    pos_x: float
    pos_y: float
    vel_x: float
    vel_y: float
    acc_x: float
    acc_y: float
    is_poisoned: bool
    content_hash: str = ""
    trs_signature: str = ""   # CRYSTALS-Dilithium stub
    block_index: int = 0

    def __post_init__(self):
        if not self.content_hash:
            payload = json.dumps({
                "vid": self.vehicle_id, "rid": self.rsu_id,
                "t": round(self.timestamp, 4),
                "px": round(self.pos_x, 4), "py": round(self.pos_y, 4),
            }, sort_keys=True)
            self.content_hash = hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class TrustEntry:
    rsu_id: str
    trust_score: float = TRUST_INIT
    update_count: int = 0
    last_updated: float = 0.0
    revoked: bool = False


@dataclass
class RevocationVote:
    rsu_id: str
    voter_rsu_id: str
    reason: str
    timestamp: float


class BlockchainSim:
    """
    Simulates the Hyperledger Fabric permissioned consortium chain.
    Implements SC-Trust (EMA trust scoring) and SC-Revoke (BFT voting).
    """

    def __init__(self, alpha: float = TRUST_ALPHA,
                 trust_threshold: float = TRUST_THRESHOLD,
                 n_committee: int = N_COMMITTEE):
        self.alpha = alpha
        self.trust_threshold = trust_threshold
        self.n_committee = n_committee
        self.revoke_threshold = math.ceil((n_committee + 1) / 2)

        # Ledger (append-only, keyed by record_id)
        self._ledger: List[BlockchainRecord] = []
        self._block_index = 0

        # SC-Trust: per-RSU trust scores
        self._trust: Dict[str, TrustEntry] = {}

        # SC-Revoke: pending votes per RSU
        self._votes: Dict[str, List[RevocationVote]] = defaultdict(list)

        # Revoked RSUs
        self._revoked: Set[str] = set()

        # LKH key ring (simulated — just store key IDs)
        self._rsu_ring_keys: Dict[str, str] = {}
        self._vehicle_session_keys: Dict[str, str] = {}

    # ── Key Management (LKH stub) ──────────────────────────────────────────────
    def issue_vehicle_session_key(self, vehicle_id: str) -> str:
        """Issue a session key for vehicle (LKH leaf node stub)."""
        key = hashlib.sha256(f"session_{vehicle_id}_{time.time()}".encode()).hexdigest()[:32]
        self._vehicle_session_keys[vehicle_id] = key
        return key

    def issue_rsu_ring_key(self, rsu_id: str) -> str:
        """Issue a ring key for RSU (LKH internal node stub)."""
        key = hashlib.sha256(f"ring_{rsu_id}_{time.time()}".encode()).hexdigest()[:32]
        self._rsu_ring_keys[rsu_id] = key
        return key

    # ── TRS Signature (CRYSTALS-Dilithium stub) ────────────────────────────────
    def _trs_sign(self, rsu_id: str, content_hash: str) -> str:
        """
        Simulate CRYSTALS-Dilithium threshold ring signature (Eq 3.58–3.60).
        Real implementation would use liboqs or pqcrypto.
        """
        ring_key = self._rsu_ring_keys.get(rsu_id, "no_key")
        payload = f"{rsu_id}|{content_hash}|{ring_key}"
        return "TRS_" + hashlib.sha256(payload.encode()).hexdigest()[:16]

    # ── Ledger Operations ─────────────────────────────────────────────────────
    def store_trajectory(self, vehicle_id: str, rsu_id: str,
                         timestamp: float, pos_x: float, pos_y: float,
                         vel_x: float, vel_y: float,
                         acc_x: float, acc_y: float,
                         is_poisoned: bool = False) -> BlockchainRecord:
        """
        Store a trajectory record on-chain.
        RSU signs with TRS; record includes IPFS content hash.
        """
        # Ensure RSU has a ring key
        if rsu_id not in self._rsu_ring_keys:
            self.issue_rsu_ring_key(rsu_id)

        rid = f"{vehicle_id}_{rsu_id}_{self._block_index}"
        rec = BlockchainRecord(
            record_id=rid,
            vehicle_id=vehicle_id,
            rsu_id=rsu_id,
            timestamp=timestamp,
            pos_x=pos_x, pos_y=pos_y,
            vel_x=vel_x, vel_y=vel_y,
            acc_x=acc_x, acc_y=acc_y,
            is_poisoned=is_poisoned,
            block_index=self._block_index,
        )
        rec.trs_signature = self._trs_sign(rsu_id, rec.content_hash)
        self._ledger.append(rec)
        self._block_index += 1

        # Initialize trust entry if new RSU
        if rsu_id not in self._trust:
            self._trust[rsu_id] = TrustEntry(rsu_id=rsu_id)

        return rec

    # ── SC-Trust: EMA trust scoring ───────────────────────────────────────────
    def update_trust(self, rsu_id: str, event_score: float, timestamp: float = 0.0):
        """
        SC-Trust EMA update (Eq 3.66):
          τ_r(t) = α · τ_r(t-1) + (1-α) · event_score
        event_score: 1.0 = honest behavior, 0.0 = detected attack
        """
        if rsu_id not in self._trust:
            self._trust[rsu_id] = TrustEntry(rsu_id=rsu_id)

        entry = self._trust[rsu_id]
        entry.trust_score = (self.alpha * entry.trust_score +
                             (1.0 - self.alpha) * event_score)
        entry.update_count += 1
        entry.last_updated = timestamp

        # Trigger revocation if trust falls below threshold
        if entry.trust_score < self.trust_threshold and not entry.revoked:
            self._auto_revoke(rsu_id, f"Trust score {entry.trust_score:.3f} < {self.trust_threshold}")

    def get_trust(self, rsu_id: str) -> float:
        if rsu_id not in self._trust:
            return TRUST_INIT
        return self._trust[rsu_id].trust_score

    # ── SC-Revoke: BFT voting ─────────────────────────────────────────────────
    def cast_revocation_vote(self, rsu_id: str, voter_rsu_id: str,
                             reason: str, timestamp: float = 0.0):
        """
        Cast a revocation vote for rsu_id from voter_rsu_id (Eq 3.67).
        Revokes when votes ≥ ⌈(n+1)/2⌉.
        """
        # Prevent duplicate votes from same voter
        existing = [v.voter_rsu_id for v in self._votes[rsu_id]]
        if voter_rsu_id in existing:
            return

        vote = RevocationVote(
            rsu_id=rsu_id,
            voter_rsu_id=voter_rsu_id,
            reason=reason,
            timestamp=timestamp,
        )
        self._votes[rsu_id].append(vote)

        # Check if threshold reached
        if len(self._votes[rsu_id]) >= self.revoke_threshold:
            self._execute_revocation(rsu_id)

    def _auto_revoke(self, rsu_id: str, reason: str):
        """Automatic revocation via SC-Trust threshold breach."""
        self._execute_revocation(rsu_id, reason)

    def _execute_revocation(self, rsu_id: str, reason: str = "BFT_VOTE"):
        """Execute RSU revocation: invalidate ring key, update ledger."""
        if rsu_id in self._revoked:
            return
        self._revoked.add(rsu_id)
        if rsu_id in self._trust:
            self._trust[rsu_id].revoked = True
        # Invalidate ring key
        if rsu_id in self._rsu_ring_keys:
            del self._rsu_ring_keys[rsu_id]

    def is_revoked(self, rsu_id: str) -> bool:
        return rsu_id in self._revoked

    # ── FHE I2I stub (Eq 3.61–3.65) ──────────────────────────────────────────
    def fhe_encrypt(self, data: dict) -> str:
        """
        Simulate FHE encryption for infrastructure-to-infrastructure (I2I).
        Real implementation: OpenFHE with CKKS scheme.
        """
        payload = json.dumps(data, sort_keys=True).encode()
        return "FHE_" + hashlib.sha256(payload).hexdigest()[:32]

    def fhe_decrypt(self, ciphertext: str) -> str:
        """Stub: in real system, FHE decryption requires secret key."""
        return f"[FHE_DECRYPTED:{ciphertext[:16]}...]"

    # ── Ledger queries ────────────────────────────────────────────────────────
    def get_records_for_vehicle(self, vehicle_id: str) -> List[BlockchainRecord]:
        return [r for r in self._ledger if r.vehicle_id == vehicle_id]

    def get_records_for_rsu(self, rsu_id: str) -> List[BlockchainRecord]:
        return [r for r in self._ledger if r.rsu_id == rsu_id]

    def get_poisoned_records(self) -> List[BlockchainRecord]:
        return [r for r in self._ledger if r.is_poisoned]

    def stats(self) -> dict:
        total = len(self._ledger)
        poisoned = sum(1 for r in self._ledger if r.is_poisoned)
        return {
            "total_records": total,
            "poisoned_records": poisoned,
            "honest_records": total - poisoned,
            "revoked_rsus": list(self._revoked),
            "trust_scores": {k: round(v.trust_score, 4)
                             for k, v in self._trust.items()},
        }


if __name__ == "__main__":
    bc = BlockchainSim()

    # Store some trajectories
    bc.store_trajectory("V0", "RSU0", 9.0, 800.0, 1200.0, 10.0, 0.0, 0.5, 0.0, False)
    bc.store_trajectory("V1", "RSU1", 9.1, 1200.0, 1200.0, 11.0, 0.0, 0.3, 0.0, False)
    # Malicious record
    bc.store_trajectory("V0", "RSU0", 9.3, 500.0, 500.0, 35.0, 0.0, 5.0, 0.0, True)

    # Trust updates: RSU0 detected as attacker
    bc.update_trust("RSU0", event_score=0.0, timestamp=9.3)  # attack event
    bc.update_trust("RSU0", event_score=0.0, timestamp=9.6)  # second event
    bc.update_trust("RSU0", event_score=0.0, timestamp=9.9)  # third event

    print("Blockchain Stats:", bc.stats())
    print(f"RSU0 trust: {bc.get_trust('RSU0'):.4f}")
    print(f"RSU0 revoked: {bc.is_revoked('RSU0')}")

    # BFT vote
    for voter in ["RSU1", "RSU2", "RSU3"]:
        bc.cast_revocation_vote("RSU0", voter, "anomalous_trajectory", timestamp=10.0)
    print(f"RSU0 revoked after BFT: {bc.is_revoked('RSU0')}")
