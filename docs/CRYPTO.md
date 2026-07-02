# Zero-Trust Vault — Cryptographic Specification

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## 1. Overview

All cryptographic operations in ZTV use Windows CNG (Cryptography API: Next Generation) unless otherwise noted. CNG is the FIPS 140-2 validated cryptographic API on Windows. No custom cryptographic algorithms are implemented. No third-party cryptographic libraries are used for symmetric or asymmetric operations.

**Forbidden in release builds:**
- Custom cryptographic algorithm implementations
- Nonce reuse under any key
- Using the same AAD structure for different object types
- DPAPI fallback when TPM is unavailable
- `eval()` or dynamic code generation in the extension
- Non-constant-time comparison for MAC or AEAD tag verification

---

## 2. Root Key Material

### 2.1 VaultRootKey

- **Type:** 256-bit random symmetric key
- **Generation:** `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` — 32 bytes of cryptographically secure random data
- **Storage:** Stored as a CNG platform key (non-exportable, hardware-backed by Windows TPM where available)
  - CNG key storage provider: `MS_PLATFORM_CRYPTO_PROVIDER` (TPM) or `MS_KEY_STORAGE_PROVIDER` (software KSP as fallback when TPM is absent — see note below)
  - Key name: `ZeroTrustVault_Root_{VaultId}`
  - NCRYPT_ALLOW_PERSIST_KEY flag set; NCRYPT_EXPORT_POLICY_PROPERTY set to prohibit export
- **Access gate:** Every CNG key operation that requires the VaultRootKey triggers a Windows Hello prompt (biometric, PIN, or security key)
- **Note:** If a TPM module is not present, the software KSP is used. In this case, key protection is reduced to the Windows user profile security boundary, not hardware. The UI warns the user if no TPM is detected.

### 2.2 VaultId

- **Type:** 128-bit random identifier (UUID v4 format for readability)
- **Generation:** `BCryptGenRandom` — 16 bytes, formatted as UUID
- **Purpose:** Public vault identifier used in AAD structures and event chain fields. Not a secret.
- **Storage:** Plaintext in vault.json header.

### 2.3 DeviceId

- **Type:** 256-bit value derived from the device's signing key
- **Derivation:** `DeviceId = SHA-256(DeviceSigningPublicKey)` where `DeviceSigningPublicKey` is the DER-encoded P-256 public key
- **Purpose:** Identifies a device in the device graph and in event signatures. Not a secret.

### 2.4 RecoveryRootSecret

- **Type:** 256-bit random value
- **Generation:** `BCryptGenRandom` — 32 bytes
- **Purpose:** Split into 5 Shamir shares; only 3 are needed to reconstruct. Used to derive recovery keys for vault re-keying.
- **Lifetime:** Generated once during recovery kit creation. Immediately split into shares; the original is zeroed from memory. The native host does not retain the RecoveryRootSecret after kit creation.

---

## 3. Subkey Derivation (HKDF-SHA256)

All subkeys are derived from VaultRootKey using HKDF-SHA256 (RFC 5869). The IKM is always VaultRootKey (256 bits). The salt is the VaultId (128 bits, left-padded to SHA-256 block size). Each subkey is 256 bits.

The `info` string distinguishes each subkey purpose. All `info` strings are ASCII; no variable content is included in the `info` string (variable context goes into AAD).

| Subkey | Info String | Purpose |
|--------|-------------|---------|
| `CredentialEncKey` | `"ZTV/v1/CredentialEncKey"` | AES-256-GCM key for encrypting credential records |
| `TotpEncKey` | `"ZTV/v1/TotpEncKey"` | AES-256-GCM key for encrypting TOTP seeds |
| `MetadataEncKey` | `"ZTV/v1/MetadataEncKey"` | AES-256-GCM key for encrypting item metadata |
| `OriginHashKey` | `"ZTV/v1/OriginHashKey"` | HMAC-SHA256 key for hashing origin strings |
| `EventEncKey` | `"ZTV/v1/EventEncKey"` | AES-256-GCM key for encrypting sync event payloads |
| `EventMacKey` | `"ZTV/v1/EventMacKey"` | HMAC-SHA256 key for event chain MAC |
| `BackupKey` | `"ZTV/v1/BackupKey"` | AES-256-GCM key for encrypting backup files |
| `BackupMacKey` | `"ZTV/v1/BackupMacKey"` | HMAC-SHA256 key for backup file integrity MAC |

The same `info` string is never reused for different subkeys. The same subkey is never used for both encryption and MAC operations.

**HKDF implementation:** Uses Windows CNG `BCryptDeriveKey` with `BCRYPT_KDF_SP80056A_CONCAT` or a hand-rolled HKDF using `BCryptCreateHash(BCRYPT_SHA256_ALGORITHM)` for HMAC extract and expand steps.

---

## 4. AES-256-GCM Encryption

All symmetric encryption in ZTV uses AES-256-GCM via Windows CNG (`BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_GCM`).

### 4.1 Parameters

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits |
| Nonce (IV) size | 96 bits (12 bytes) |
| Authentication tag size | 128 bits (16 bytes) |
| AAD | See Section 4.3 |
| Library | Windows CNG `BCryptEncrypt`/`BCryptDecrypt` |

### 4.2 Nonce Generation

Each encryption operation generates a fresh 96-bit nonce using `BCryptGenRandom`. Nonces are stored alongside the ciphertext in the vault record (not derived from a counter or sequence number). The nonce is included in the vault record's JSON field as a base64url-encoded string.

Nonce reuse under a given key is forbidden. Since nonces are random (not counter-based), the probability of collision under a given key after N operations is approximately N²/2^96. For typical vault sizes (fewer than 10,000 records), this is negligible (< 2^{-83}). For very large vaults, the native host logs a warning if the record count approaches 2^32.

### 4.3 AEAD Additional Authenticated Data (AAD)

The AAD is a fixed-format binary structure that binds each ciphertext to its context. The AAD is authenticated but not encrypted. If any AAD field is modified, decryption fails.

**AAD structure (all fields big-endian):**

```
schemaVersion (2 bytes, uint16)  ||
vaultId       (16 bytes, UUID)   ||
itemId        (16 bytes, UUID)   ||
originHash    (32 bytes, HMAC)   ||
deviceEpoch   (8 bytes, uint64)  ||
purpose       (4 bytes, ASCII)
```

| Field | Description |
|-------|-------------|
| `schemaVersion` | Current vault schema version (e.g., `0x0001`). Prevents cross-version ciphertext reuse. |
| `vaultId` | The VaultId of the vault this record belongs to. Prevents cross-vault ciphertext copy. |
| `itemId` | The unique identifier of this credential item. Prevents copying a ciphertext from one slot to another. |
| `originHash` | HMAC-SHA256 of the origin string (see Section 5). Binds the ciphertext to a specific origin. |
| `deviceEpoch` | Monotonically increasing epoch counter for this device. Prevents replay of old ciphertexts after epoch rotation. |
| `purpose` | ASCII purpose code (4 bytes): `CRED` for credentials, `TOTP` for TOTP seeds, `META` for metadata, `EVNT` for events, `BACK` for backup. Prevents cross-purpose ciphertext substitution. |

The same AAD structure is never used for different `purpose` values.

---

## 5. Origin Hashing (HMAC-SHA256)

The origin of a credential is stored as an HMAC, not as a plaintext string, in the vault record.

```
originHash = HMAC-SHA256(OriginHashKey, canonicalOrigin)
```

where `canonicalOrigin` is the exact origin string as stored, e.g. `"https://example.com"` or `"https://example.com:8443"`.

**Canonical form rules:**
- Scheme: always `https` (lowercase)
- Host: lowercase ASCII (punycode-normalized if IDN is enabled)
- Port: omitted if 443 (default HTTPS port); included if non-default
- No path, query, or fragment
- No trailing slash

**Purpose:** The originHash binds the ciphertext to the exact origin via AAD. An attacker who modifies the origin field in vault.json will cause AAD mismatch and decryption failure. HMAC also prevents an attacker who can read vault.json from learning the plaintext origin strings (they learn only the HMAC).

---

## 6. TOTP Generation (RFC 6238)

TOTP is implemented inside the native host only. The TOTP seed never leaves the native host process.

| Parameter | Value |
|-----------|-------|
| Algorithm | HMAC-SHA1 (RFC 6238 default; SHA-256/SHA-512 not yet supported) |
| Time step | 30 seconds |
| Digits | 6 |
| Epoch | Unix epoch (seconds) |
| Window | Current time step only (no ±1 step tolerance by default) |
| Seed storage | Encrypted with TotpEncKey (AES-256-GCM) in vault.json |
| Seed format | Base32-encoded per Google Authenticator convention; stored as raw bytes after base32 decoding |

**Generation procedure:**
1. Native host receives `generateTotp` command with `itemId`.
2. Windows Hello prompt triggered.
3. On success: TOTP seed decrypted from vault.
4. `T = floor(currentUnixTime / 30)`
5. `hmac = HMAC-SHA1(seed, T)` where T is encoded as big-endian 64-bit integer
6. `offset = hmac[19] & 0x0F`
7. `code = (hmac[offset] & 0x7F) << 24 | hmac[offset+1] << 16 | hmac[offset+2] << 8 | hmac[offset+3]`
8. `totp = code % 1_000_000`, zero-padded to 6 digits
9. Seed bytes zeroed from memory immediately after step 8.
10. Returns `totp` (string) and `remainingSeconds = 30 - (currentUnixTime % 30)` to caller.

---

## 7. Shamir's Secret Sharing (Recovery Kit)

The recovery kit uses Shamir's Secret Sharing over GF(256) to split the RecoveryRootSecret into 5 shares, of which any 3 can reconstruct the secret.

| Parameter | Value |
|-----------|-------|
| Field | GF(2^8) — Galois Field of order 256 |
| Primitive polynomial | x^8 + x^4 + x^3 + x + 1 (0x11B — the AES primitive polynomial) |
| Threshold (k) | 3 |
| Total shares (n) | 5 |
| Secret size | 256 bits (32 bytes) — processed as 32 independent GF(256) polynomials |
| Share encoding | Each share: share_index (1 byte, 1–5) || share_bytes (32 bytes) |
| Output format | 33 bytes per share, encoded as hex string for human-readable export |

**Implementation note:** ZTV implements SSS from scratch over GF(256). The implementation must be reviewed against a known-good reference (e.g., the Daan Sprenkels sss library's test vectors) before production use. The polynomial evaluation uses constant-time GF(256) multiplication to avoid timing side channels on the share reconstruction path.

**Recovery kit file format (per share):**
```
ZTV-RECOVERY-SHARE-V1
VaultId: <uuid>
ShareIndex: <1-5>
ShareData: <66-char hex string>
Checksum: <SHA-256 of "VaultId || ShareIndex || ShareData">
```

---

## 8. Device Signing Key (ECDSA P-256)

Each enrolled device has an ECDSA P-256 signing key pair.

| Parameter | Value |
|-----------|-------|
| Algorithm | ECDSA with SHA-256 (NIST P-256) |
| Key storage | CNG platform key, non-exportable |
| Key name | `ZeroTrustVault_Device_{VaultId}_{DeviceId}` |
| Public key | DER-encoded, stored in the device graph in vault.json (plaintext — it is a public key) |
| Signing | `BCryptSignHash` with `BCRYPT_PAD_PKCS1` (for SHA-256 hash over the event payload) |
| Verification | `BCryptVerifySignature` on event receive |
| Access gate | Windows Hello challenge required for signing operations |

---

## 9. Backup File Integrity (HMAC-SHA256)

Each backup file has an HMAC-SHA256 integrity tag computed over the unencrypted header fields and the encrypted content.

```
BackupMAC = HMAC-SHA256(BackupMacKey, vaultId || checkpoint || encryptedContent)
```

where:
- `vaultId` is the 16-byte UUID
- `checkpoint` is the 8-byte uint64 event log position at backup time
- `encryptedContent` is the full AES-256-GCM ciphertext (nonce prepended)

The MAC is verified before any decryption attempt during restore. A MAC mismatch aborts the restore with `ERR_BACKUP_MAC_FAILED`.

---

## 10. Constant-Time Comparison

All MAC and AEAD tag verification operations must use constant-time comparison. Using `string.Equals`, `Array.Equals`, or `==` for comparing authentication tags is forbidden, as these short-circuit on the first differing byte and enable timing side-channel attacks.

**Required for:**
- HMAC-SHA256 backup MAC verification
- HMAC-SHA256 event chain MAC verification
- AEAD authentication tag comparison (handled by CNG's `BCryptDecrypt` internally — this is enforced by CNG's GCM mode; do not extract and re-compare the tag manually)
- Shamir share reconstruction checksum verification

**Implementation:** Use `CryptographicOperations.FixedTimeEquals(ReadOnlySpan<byte>, ReadOnlySpan<byte>)` from `System.Security.Cryptography` (.NET 5+) for all MAC comparisons outside of CNG primitives.

---

## 11. Forbidden Practices

The following are explicitly forbidden in ZTV release builds. A pre-release scan (see RELEASE_CHECKLIST.md) checks for these patterns:

| Forbidden Pattern | Reason |
|------------------|--------|
| `DEV_BYPASS` or `devBypass` string in native host source | Development bypass that disables Hello or validation |
| `DPAPI_FALLBACK` | DPAPI protection is weaker than TPM; not a release option |
| `TEST_KEY` | Hardcoded test keys |
| Nonce derived from record index or sequence number | Deterministic nonces enable nonce reuse attacks |
| Same `info` string for two different HKDF subkeys | Subkey collision |
| Same `purpose` field (AAD) for different record types | Cross-purpose ciphertext substitution |
| `Array.Equals` or `==` on authentication tags | Non-constant-time comparison |
| Sending TOTP seed bytes outside native host process | Seed must never leave native host |
| Writing any plaintext secret to vault.json | Vault must contain only ciphertext |
| `eval()` in any extension JavaScript file | MV3 CSP prohibition |
