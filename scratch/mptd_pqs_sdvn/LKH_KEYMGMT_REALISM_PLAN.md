# LKH Key Management — Paper-Conformance & SUMO-Scaling Plan

**Status date:** 2026-06-06
**Owner:** G.W.N. Niluminda
**Trigger:** Review question — "is the crypto a hardcoded simulation, and how does key
management work once we connect SUMO?" The clicked lines (SHA-256 round constants) were a
false alarm, but the review surfaced two real issues: (1) hardcoded master secrets, and
(2) a static, capped, single-tree LKH that cannot scale or do dynamic membership.

> **Ground rule:** paper is authority. This plan is written **after** verifying §3.5.2
> (paper pp.50–52, read 2026-06-06). Paper claims below are quoted/cited; engineering
> gaps the paper leaves open are marked **[DECISION]**.

---

## A. Authoritative paper findings (§3.5.2, pp.50–52)

1. **Dynamic by design.** Opening sentence: LKH must "manage both classes efficiently
   under **vehicle join, leave, and RSU membership changes**." (vehicle session keys
   {K_i} for HMAC Eq 3.37; RSU ring keys {sk_j} for TRS Eq 3.49).
2. **Two tree structures, two authorities:**
   - **Per-RSU-zone vehicle subtree, managed by the RSU.** "When vehicle v_i registers
     with RSU r_j, it is assigned a leaf node u_i in a **local LKH subtree maintained per
     RSU coverage zone**. The RSU derives v_i's session key…"
   - **Separate RSU-ring subtree, managed by the SDN controller.** "The n RSUs in the TRS
     signing ring R form a **separate LKH subtree managed by the SDN controller**."
3. **K_root is a mutable group key**, not a constant: "The root key K_root serves as the
   **current group key** shared among all active members… rekeying only requires updating
   nodes on one root path." Changes on every membership event.
4. **Per-RSU-contact session keys** (forward secrecy across handoff): Eq 3.22
   `K_i = KDF(K_{u_i}, η_i, ID_i)` → "a per-session HMAC key unique to each vehicle
   registration, ensuring that a session key compromised at one RSU contact cannot be
   reused to forge authenticated beacons at subsequent RSU contacts **after the vehicle
   moves on**."
5. **Rekey cost over live zone population:** Eq 3.23 `N_rekey = log₂|V_j|`, |V_j| =
   "current number of vehicles in the RSU zone." Sold as "the only scalable option for
   **high-density urban deployments**" vs O(|V_j|) unicast.
6. **RSU ring rekey:** Eq 3.24 `N_ring = (n−1)`; Eq 3.25 `sk_j = KDF(K_{u_j}, K_ring,
   ID_{r_j})`; FHE shares {sk_j^share} distributed over the same authenticated ring
   channel (already implemented, P1).
7. **Leaf key K_{u_i} is RSU-assigned within the zone subtree** — NOT derived from the
   Fabric-CA enrollment secret. (Fabric-CA = blockchain identity / SC-Register, a separate
   mechanism. Earlier idea to fuse them was rejected after this read.)

---

## B. Current-code deviations (`00_lkh_keys.h`)

| # | Paper (§3.5.2) | Code today | Severity |
|---|----------------|------------|----------|
| 1 | Per-zone vehicle subtrees + separate controller ring subtree | One **flat global tree**; RSU keys faked `root XOR idx` (`:402-404`) | High — wrong topology |
| 2 | `K_root` mutable group key, rekeyed on membership | **Hardcoded** `LKH_ROOT_SEED`, `LKH_K_RING` (`:113-126`) | High — provisioning realism |
| 3 | Dynamic join/leave as vehicles cross RSU zones | Tree built **once** (`lkh_init_all`, `12_main.h:2102`) | High — no dynamic membership |
| 4 | `K_i` re-derived per RSU contact | Derived once at init, never on handoff | Medium |
| 5 | Scales to high-density urban (|V_j| dynamic) | Hard cap `LKH_MAX_VEH=32`; >32 → tree silently NOT built (`:305`) → all-zero keys | High — silent insecurity at scale |
| 6 | Vehicle keyed by identity within zone | `veh_idx = nid − 2` static contiguous map (`:617`) | Medium |

The real crypto **primitive** (HMAC-SHA256, KDF) is correct FIPS — not stubbed. The issue
is **key provisioning + membership model**, not faked math. (Distinct from a forbidden
"simulated primitive.")

---

## C. Paper gaps → **[DECISION]** items

- **D-LKH-1 — Secure delivery of the leaf key K_{u_i} to a joining vehicle.** Paper says
  the RSU "assigns" a leaf but does not specify the secure channel for first delivery.
  Code comment (`:39-42`) already flags the current in-packet plaintext key as NOT REAL.
  Options: (a) wrap K_leaf under the joining vehicle's enrollment/public key (real, ties to
  existing Fabric-CA cert as a *transport* key — distinct from item A.7); (b) out-of-band
  pre-shared per-vehicle bootstrap key; (c) keep sim-channel isolation, document as the one
  acknowledged abstraction. **Recommend (a).**
- **D-LKH-2 — Initial root-key generation.** Paper: K_root is a runtime group key; silent
  on first-generation. Recommend per-zone CSPRNG at RSU bring-up; controller CSPRNG for the
  ring root. (Removes the hardcoded seeds.) **Recommend: CSPRNG at bootstrap.**
- **D-LKH-3 — Scale strategy at SUMO density.** Paper implies per-zone bound |V_j|.
  Options: (a) unbounded per-zone subtree that grows/shrinks with |V_j|; (b) bounded reuse
  pool per zone (mirrors the SC-Register leased-identity-pool model, IEEE 1609.2/SCMS V2X
  pseudonym pattern). **Recommend (a)** for paper-faithfulness (Eq 3.23 wants real log₂|V_j|);
  (b) only if memory/perf forces it.

---

## D. Proposed implementation (phased) — supersedes the flat "P1 done"

> Membership events = **RSU-zone entry/exit (geometric handoff)**, detected at beacon time
> by RSU range checks. This works under the *current* static-node `sumo_trace` mode (nodes
> pre-created, trace drives positions) — full TraCI node lifecycle is NOT required.

- **P1b-1 — De-hardcode roots. ✅ DONE (2026-06-06).** Removed `LKH_ROOT_SEED`/`LKH_K_RING`
  ASCII-string constants; `K_root`+`K_ring` now filled from OS CSPRNG (getrandom(2),
  std::random_device fallback) by idempotent `lkh_init_master_keys()`, called from both
  `lkh_init_all()` and `initialize_crypto_backends()` (TRS ring-poly consumer runs first).
  External refs updated in 06b1 + 11. Tested 9/9 standalone; full waf build clean. Per
  D-LKH-2. (NOTE: currently a single global root, not yet per-zone — that's P1b-2.)
- **P1b-B — Lift the 32-vehicle cap. ✅ DONE (2026-06-06).** `LKH_MAX_VEH` 32→1024,
  `LKH_MAX_NODES` 64→2048; `lkh_build_tree` silent `>cap → return` (which left all-zero
  keys = silent insecurity, item B.5) replaced with a loud stderr clamp. Tested @256
  vehicles standalone; full waf build clean. (Interim bounded ceiling per D-LKH-3b; the
  true dynamic/per-zone |V_j| model is still P1b-2/3.)
- **P1b-2 — Per-zone + ring topology. ✅ DONE (2026-06-06).** Single flat `g_lkh_tree`
  replaced by `g_lkh_zone[]` (one subtree per RSU, CSPRNG K_root each) + `g_lkh_ring_tree`
  (controller-managed). `root XOR idx` shortcut removed; sk_j now derived from the ring
  subtree leaf (Eq 3.25). Files: 00 (rewrite), 06b1/11 refs already updated in P1b-A.
- **P1b-3 — Dynamic membership API. ✅ DONE (2026-06-06).** `lkh_zone_join`,
  `lkh_zone_handoff_leave`, `lkh_on_beacon_at_rsu` (the 08 hook), `lkh_rekey_on_revoke`
  (zone-scoped, fills `g_lkh_affected_members`), `lkh_vehicle_install_leaf` (07).
  Per-RSU-contact K_i re-derivation on handoff (Eq 3.22). Wired into 08 (verify-then-
  migrate, after the HMAC gate) + 07 (rekey receive).
- **P1b-4 — Containers / cap.** Zone subtrees are `std::vector`-backed and **grow on
  demand** (`lkh_zone_grow`, base cap 16, doubles). The silent `>cap` failure was already
  fixed in P1b-B. Per-vehicle state still fixed `[LKH_MAX_VEH=1024]` arrays (ample;
  revisit only if a scenario needs >1024 distinct vehicles).
- **P1b-5 — Membership ↔ mobility. ✅ DONE.** Driven by the existing geographic filter
  (`nearest_rsu_for_position`, 08:2193) — each beacon is processed by exactly one RSU =
  the zone, so join/handoff is unambiguous and there is no cross-RSU key race. Works under
  the current static-node `sumo_trace` mode; TraCI node-lifecycle is future.
- **P1b-6 — Secure leaf-key delivery (D-LKH-1).** DEFERRED/abstracted: the single-process
  sim shares `g_vehicle_session_key` (implicit authenticated delivery). Documented in the
  00 header. Real cert-wrapped delivery is the tracked follow-up.
- **P1b-7 — Validation. ✅ DONE.** Standalone C1 test 20/20 (join/handoff/per-contact-key/
  zone-scoped-revoke/grow/ring). Full `waf build` clean. Runtime smoke (16 veh, 6 s):
  4 zones init, **0 HMAC failures** (seamless join+handoff), no crash.

### Validation status (2026-06-06)
P1b-A, P1b-B, P1b-2/3/5/7 all complete + tested. The per-zone topology, dynamic
membership, zone-scoped revocation rekey, and ring subtree are live and build/run clean.
Deferred (documented): D-LKH-1 real cert-wrapped first-delivery (P1b-6).

---

## E. Sequencing

This is a re-scope of P1 (which delivered a *flat* LKH that is correct crypto but wrong
topology/membership vs paper). Two viable orders:
- **(i) Do P1b before P5 final wiring** — key management is paper-faithful before metrics
  capture. Cleaner story for the supervisor.
- **(ii) Finish Task ② crypto (P5) green first, then P1b** — threshold-FHE + Dilithium
  backends are already written; get them building/tested, then return to LKH realism.

**Recommend (i)** if the supervisor will scrutinise key management; **(ii)** if the
immediate goal is a green Task ② crypto demo. Needs user call.
