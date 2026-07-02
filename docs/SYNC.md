# Zero-Trust Vault — MeshSync Design

Version: v0.5.0-hardened  
Date: 2026-06-29  
Implementation Status: Local file relay backend implemented. Cloud blind relay and OneDrive/GDrive backends are designed but not yet implemented as of v0.5.0.

---

## 1. Overview

MeshSync is ZTV's optional vault synchronization layer. It is designed as an encrypted, append-only event log with hybrid logical clock ordering, device-signed events, and a hash chain for tamper detection. The sync relay is treated as an untrusted courier: it receives and stores ciphertext only and cannot read any credential data.

Sync is opt-in. A vault without sync configured operates identically to v1 (single-machine only).

---

## 2. Event Log Model

The vault is not synchronized as a whole file. Instead, every modification to the vault produces a signed, encrypted event that is appended to the event log. Remote devices consume these events and replay them locally. This approach:

- Minimizes the data transmitted per sync cycle (only new events, not the full vault)
- Provides a complete audit trail of vault modifications
- Enables conflict detection based on event causality
- Keeps the relay blind (events are ciphertext)

---

## 3. Event Structure

Each event in the log has the following JSON structure. Fields marked [plaintext] are stored unencrypted on the relay (for routing and ordering). Fields marked [ciphertext] are AES-256-GCM encrypted before leaving the device.

```json
{
  "schemaVersion": 1,
  "vaultId":        "<uuid>",           // [plaintext] vault identifier
  "eventId":        "<uuid>",           // [plaintext] unique event identifier (uuid v4)
  "deviceId":       "<sha256-hex>",     // [plaintext] originating device identifier
  "epoch":          42,                 // [plaintext] device epoch (rotated on device removal)
  "hlc":            "1751234567890.003",// [plaintext] Hybrid Logical Clock timestamp
  "previousHash":   "<sha256-hex>",     // [plaintext] SHA-256 of the previous event's canonical form
  "eventType":      "AddCredential",    // [plaintext] event type tag
  "encryptedPayload": "<base64>",       // [ciphertext] AES-256-GCM encrypted payload
  "nonce":          "<base64>",         // [plaintext] 96-bit nonce for encryptedPayload
  "tag":            "<base64>",         // [plaintext] 128-bit GCM authentication tag
  "signature":      "<base64>",         // [plaintext] ECDSA P-256 signature over canonical event form
  "signatureAlg":   "ES256"            // [plaintext]
}
```

**Canonical event form for signing:**  
`schemaVersion || vaultId || eventId || deviceId || epoch || hlc || previousHash || eventType || encryptedPayload`  
All fields concatenated as UTF-8 bytes with `||` as separator byte `0x7C`. The signature is over the SHA-256 hash of this concatenation.

---

## 4. Event Types

The following 13 event types are defined. Each has a distinct encrypted payload schema.

| # | Event Type | Encrypted Payload Fields | Description |
|---|-----------|--------------------------|-------------|
| 1 | `AddCredential` | `{itemId, origin, username, password, label, createdAt}` | New credential added to vault |
| 2 | `UpdateCredential` | `{itemId, fields: {username?, password?, label?}, updatedAt}` | Credential fields updated |
| 3 | `DeleteCredential` | `{itemId, deletedAt}` | Credential soft-deleted |
| 4 | `AddTotpSeed` | `{itemId, totpSeed, totpAlgorithm, totpDigits, totpPeriod}` | TOTP seed added to a credential |
| 5 | `RemoveTotpSeed` | `{itemId, removedAt}` | TOTP seed removed from a credential |
| 6 | `EnrollDevice` | `{deviceId, devicePublicKey, deviceLabel, enrolledAt, enrolledByDeviceId}` | New device added to device graph |
| 7 | `RemoveDevice` | `{deviceId, removedAt, removedByDeviceId, newEpoch}` | Device removed; epoch rotated |
| 8 | `RotateEpochKey` | `{newEpoch, encryptedNewEpochKeyPerDevice: [{deviceId, encryptedKey}]}` | Epoch key rotation (after device removal) |
| 9 | `UpdateSettings` | `{settingsKey, settingsValue}` | Vault-level settings change |
| 10 | `CreateVault` | `{vaultId, vaultLabel, createdAt, creatorDeviceId}` | Initial vault creation event (always first) |
| 11 | `BackupCheckpoint` | `{checkpointEventId, backupLocation, backupAt}` | Records that a backup was made at this event position |
| 12 | `RecoveryKitCreated` | `{kitCreatedAt, sharesCount, threshold}` | Records that a recovery kit was generated (no share data stored in event) |
| 13 | `PasswordRotationChecklist` | `{triggeredByEventId, credentialIds: [], generatedAt}` | Generated after `RemoveDevice`; lists credentials that should be rotated |

---

## 5. Hybrid Logical Clock (HLC)

ZTV uses a Hybrid Logical Clock (Kulkarni & Demirbas, 2014) for event ordering across devices.

**HLC format:** `<physical_ms>.<logical_counter>` where:
- `physical_ms` is the device's local Unix timestamp in milliseconds
- `logical_counter` is a non-negative integer that advances within the same millisecond

**HLC rules:**
- On send: `hlc = max(currentHlc, wallClock_ms) with counter advanced if same ms`
- On receive: `hlc = max(currentHlc, receivedHlc, wallClock_ms) with counter advanced`
- HLC is monotonically non-decreasing on each device
- HLC is not trusted for security decisions; it is used for event ordering only
- Conflicts (same HLC from different devices) are resolved by `eventId` lexicographic order as a tiebreaker

---

## 6. Event Hash Chain

Events are linked via `previousHash`:

```
previousHash = SHA-256(canonicalForm(previousEvent))
```

The first event (`CreateVault`) has `previousHash = "0000...0000"` (32 zero bytes, hex-encoded).

**Tamper detection:**  
Each device, when consuming events, verifies the hash chain from the last known good event. A `previousHash` mismatch causes the chain to be considered broken (`ERR_CHAIN_BROKEN`). The device will not apply events from a broken chain without user confirmation.

**Chain root storage:**  
Each device stores the SHA-256 of the last verified event in local tamper-evident storage (protected by AES-256-GCM under the device's EventMacKey). This "local root hash" enables split-view detection.

---

## 7. Blind Relay Server Model

The relay server (in whatever form — local file, cloud service, NAS) is treated as untrusted.

**The relay:**
- Stores event blobs (ciphertext) identified by `vaultId` and `eventId`
- Provides ordered retrieval by `hlc` within a `vaultId`
- Cannot decrypt any event payload
- Cannot forge events (lacks device signing keys)
- Cannot produce events that pass signature verification on clients

**The relay does NOT:**
- Have access to any decryption keys
- Perform any key exchange
- Authenticate devices (device authentication is done client-side via the device graph)
- Enforce access control beyond vaultId-based partitioning

**Threat from relay:** A malicious relay can drop events (denial of service) or replay old events. Drop is detected by gap analysis in HLC. Replay of old events is detected by HLC sequence checking on the receiving device.

---

## 8. Conflict Policy

When two devices produce conflicting events (e.g., both update the same credential while offline), ZTV uses the following policy:

- **Never silently overwrite.** Conflicting updates are both retained as separate versions.
- **UI notification.** The user is shown a conflict resolution UI with both versions displayed.
- **User resolves.** The user selects which version to keep, or merges manually.
- **Resolution event.** A `UpdateCredential` event is appended with the resolved values and a `conflictResolutionOf` field referencing both conflicting `eventId`s.

This is more conservative than last-write-wins and ensures no credential data is silently lost in a conflict.

---

## 9. Device Graph

The device graph is maintained in vault.json (encrypted) and in the event log.

**Device graph fields (per device):**
```json
{
  "deviceId":       "<sha256-hex>",
  "publicKey":      "<DER base64>",
  "label":          "My Laptop",
  "enrolledAt":     1751234567,
  "enrolledBy":     "<deviceId>",
  "status":         "active",    // "active" | "removed"
  "removedAt":      null,
  "lastSeenHlc":    "1751234567890.000"
}
```

**Adding a device (QR/SAS pairing):**
1. New device generates a fresh ECDSA P-256 key pair (non-exportable CNG platform key).
2. New device displays its public key as a QR code.
3. Existing enrolled device scans QR code and verifies the Short Authentication String (SAS) displayed on both screens.
4. Existing enrolled device creates an `EnrollDevice` event signed by its key, including the new device's public key.
5. New device receives the event, verifies its own public key is included, and begins consuming historical events.
6. New device cannot decrypt historical events until the existing device re-encrypts relevant keys for the new device (epoch key distribution).

**Removing a device:**
1. Any enrolled device can create a `RemoveDevice` event.
2. `RemoveDevice` event triggers a `RotateEpochKey` event on remaining devices.
3. New epoch key is encrypted individually for each remaining device.
4. A `PasswordRotationChecklist` event is generated listing all credentials the removed device had access to.
5. The removed device is marked `status: "removed"` in the device graph.
6. Events signed by the removed device are no longer accepted by remaining devices after the `RemoveDevice` event's HLC.

---

## 10. Epoch Key Rotation

The epoch key is a per-device-set symmetric key used to encrypt event payloads for a specific set of enrolled devices.

**On device removal:**
1. Remaining devices agree on a new epoch number (`newEpoch = currentEpoch + 1`).
2. One device generates a new random 256-bit epoch key.
3. The new epoch key is encrypted individually for each remaining device using that device's public key (ECIES or ECDH + HKDF hybrid encryption — exact scheme to be specified in a future revision; as of v0.5.0, the epoch key is encrypted with the remaining devices' VaultRootKey-derived per-device share keys).
4. A `RotateEpochKey` event is created with the per-device encrypted key bundle.
5. All future event payloads use the new epoch key for encryption.
6. The removed device cannot decrypt events encrypted with the new epoch key.

---

## 11. Transparency and Split-View Detection

**Local root hash storage:**  
Each device maintains a locally stored SHA-256 of the last verified event in the chain. This value is stored encrypted (under EventMacKey) in the device's local state.

**Split-view detection:**  
When two devices compare their local root hashes (via gossip or manual comparison), a discrepancy indicates that one device has seen a different event history than the other. This can result from a relay that serves different data to different clients (split-view attack by a malicious relay).

**Gossip:**  
When two enrolled devices are online simultaneously (or connected via local network), they may gossip their local root hashes directly to each other. A mismatch triggers a warning to the user.

**User notification:**  
ZTV displays a warning badge in the popup if the event chain cannot be verified or if a potential split-view is detected. The user is prompted to review the event log.

---

## 12. Supported Backends

| Backend | Status | Description |
|---------|--------|-------------|
| Local file relay | Implemented | A directory on the local file system or a UNC path serves as the relay. Useful for LAN sync via a shared folder (NAS, mapped drive). |
| Blind relay cloud | Designed, not yet implemented | A minimal HTTPS server (REST API) that stores and retrieves event blobs by `vaultId/eventId`. Server code is not part of this repository. |
| OneDrive / Google Drive | Designed, not yet implemented | Uses the cloud storage provider's file API as a dumb blob store. The relay interface is the same; only the backend adapter differs. |

The relay interface is defined as a C# interface (`IRelayBackend`) in the native host. Adding a new backend requires implementing this interface. The blind relay cloud specification will be published separately.

---

## 13. Sync Security Summary

| Property | Enforcement |
|----------|------------|
| Relay cannot read events | AES-256-GCM encryption before transmission |
| Relay cannot forge events | ECDSA P-256 device signatures |
| Tampered events rejected | Signature verification on receive |
| Dropped events detected | HLC gap analysis |
| Replayed events detected | HLC monotonic check on receive |
| Removed device cannot read new events | Epoch key rotation |
| Conflicts never silently overwritten | UI-driven conflict resolution |
| Chain integrity | SHA-256 hash chain with local root hash |
