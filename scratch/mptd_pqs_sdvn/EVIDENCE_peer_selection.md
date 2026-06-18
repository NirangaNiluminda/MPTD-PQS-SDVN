# Evidence — RSU peer role, trust-based selection, demotion & revocation

Each claim below maps to the **exact source location** and the **unit test** that
proves it. All tests pass (`go test`): **27 test functions, 81.5% statement
coverage**. Repo: `chaincode/chaincode/smartcontract.go` (chaincode) +
`scratch/mptd_pqs_sdvn/` (NS-3 side). Commit `0126ea9`.

---

## 1. Peer role is set by the certificate (static Fabric role)

| Claim | Where | Proof |
|-------|-------|-------|
| Role decided by cert **OU** tag via NodeOUs | `fabric_net/generated/.../config.yaml` → `NodeOUs: { PeerOUIdentifier: OU=peer, ClientOUIdentifier: OU=client, OrdererOUIdentifier: OU=orderer }` | config file |
| One Fabric **peer per RSU**, peer org | `fabric_net/gen_network.sh:99` → `crypto-config-rsu.yaml` with `EnableNodeOUs: true`, `Template.Count = N` (peer0..peer(N-1)) | script |
| Only RSU **peers** may endorse | `gen_network.sh:163` → `Endorsement: OR('RSUMSP.peer')` | channel policy |
| Controllers are **orderers, not peers** | `gen_network.sh:111-123` separate `ordererOrganizations` | script + paper §3.5.5 (`main.tex:3547`: "RSUs as endorsing peers and the controller as the ordering service") |

---

## 2. Trust-based selection at runtime (who actually endorses)

| Claim | Where | Proof |
|-------|-------|-------|
| Pick **top-trust 2f+1** RSUs to endorse, not everyone | `11_blockchain_setup.h` → `select_endorsers_trust_ranked()` (stable-sort by τ desc) | code |
| Re-checked **~1 Hz** from live on-chain trust | `11_blockchain_setup.h` → `refresh_endorsement_committee()` → `CallSCGetAllRSUTrustScores()` | code + runtime log `[PEER-SELECT] … committee[2f+1]={…}` |
| **Bootstrap**: all-equal trust at boot → random | `select_endorsers_trust_ranked()` pre-shuffle + fallback to `random_endorser_sample()` | code |
| Chaincode reads all RSU trust | `smartcontract.go:1869` `GetAllRSUTrustScores` | code |

---

## 3. Demotion — low trust → CLIENT (loses endorse/vote rights)

| Claim | Where | Proof |
|-------|-------|-------|
| EMA trust update `τ = α·τ + (1-α)(1-mⱼ)` | `smartcontract.go:1751` (`updateRSUTrust`) | code |
| `τ < τ_th` → **TRUSTED → CLIENT** demotion | `smartcontract.go:1818` (`case rec.TrustScore < cfg.TauThreshold`) emits `RSUDemoted` | **test:** `TestSCRSUFinalizeEpoch/demotion_TRUSTED→CLIENT_below_tau_th` ✅ |
| Only **TRUSTED** RSUs count toward quorum | `smartcontract.go:692` `isTrustedRSU()`; used in revoke tally `1462-1477` | code + test |

---

## 4. Revocation — persistent bad → permanent ban (BFT)

| Claim | Where | Proof |
|-------|-------|-------|
| `T_rev` consecutive low epochs → **SC-Revoke**, status REVOKED | `smartcontract.go:1788` (`case rec.ConsecutiveLowEpochs >= cfg.TRev`) emits `RSURevoke` | **test:** `TestSCRSUFinalizeEpoch/T_rev_consecutive-low_→_SC-Revoke_+_status_REVOKED` ✅ |
| Vehicle revoke needs **2f+1 distinct RSU votes** | `smartcontract.go:1480` `threshold := 2*f + 1`; tally counts only TRUSTED voters | **test:** `TestSCRevokeVote/2f+1_distinct_votes_revoke_+_flip_status` ✅ |
| Revoked identity is excluded from all future submissions | `requireActive` gate; `TestSCRevokeVote/vote_after_revoke_bounces_on_gate` ✅ | test |
| **BFT floor guard**: never drop trusted set below 3f+1 | `smartcontract.go:1769` (`floorWouldBreak`) holds demotion as probationary | **test:** `TestSCRSUFinalizeEpoch/BFT_floor_guard_holds_demotion_as_probationary` ✅ |

---

## How to verify

```bash
cd chaincode/chaincode
go test -cover ./...        # → ok, coverage: 81.5% of statements
go test -v -run 'TestSCRSUFinalizeEpoch|TestSCRevokeVote|TestSCRegister|TestCPDetect' ./...
```

Expected (abridged):

```
--- PASS: TestSCRegister_Happy
--- PASS: TestSCRegister_Rejections        (incl. insufficient_endorsements)
--- PASS: TestCPDetectCheck                (controller conflict → flag)
--- PASS: TestCPDetectExcludesAndReassigns
--- PASS: TestSCRevokeVote                 (incl. 2f+1_distinct_votes_revoke)
--- PASS: TestSCRSUFinalizeEpoch           (demotion + T_rev revoke + floor guard)
PASS
ok  github.com/hyperledger/fabric-samples/trajectory-chaincode/chaincode
```

**Summary:** the certificate makes an RSU *eligible* to be a peer (static);
the smart contract decides *who actually endorses* (trust-ranked selection),
*demotes* low-trust RSUs to CLIENT so their votes are rejected, and
*permanently revokes* persistently-bad ones by 2f+1 BFT vote — all unit-tested.
