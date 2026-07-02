# Zero-Trust Vault — Architecture

Version: v0.5.0-hardened  
Date: 2026-06-29

---

## 1. System Overview

Zero-Trust Vault is a two-process system: a Chrome MV3 extension (running inside the Chrome browser) and a C# .NET 9 native host process (running as a standard Windows user process). Communication between the two is strictly through Chrome's native messaging protocol. All cryptographic operations occur in the native host; the extension is a UI front-end only.

---

## 2. ASCII Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CHROME BROWSER PROCESS                                                     │
│                                                                             │
│  ┌───────────────────────────────────┐   ┌──────────────────────────────┐  │
│  │  Extension: Service Worker        │   │  Extension: Popup Window     │  │
│  │  (service_worker.js)              │   │  (popup.html / popup.js)     │  │
│  │                                   │   │                              │  │
│  │  - Session timeout (alarms)       │   │  - Credential selector UI    │  │
│  │  - Tab origin extraction          │   │  - TOTP display (code only,  │  │
│  │  - Native messaging gateway       │   │    never seed)               │  │
│  │  - Message routing                │   │  - Fill trigger              │  │
│  │  - No secrets stored              │   │  - Settings UI               │  │
│  └──────────────┬────────────────────┘   └──────────────────────────────┘  │
│                 │  chrome.runtime messages                                   │
│  ┌──────────────▼────────────────────┐                                      │
│  │  Extension: Content Script        │                                      │
│  │  (content.js)                     │                                      │
│  │                                   │                                      │
│  │  - Form field detection only      │                                      │
│  │  - Notifies SW of field presence  │                                      │
│  │  - Performs DOM fill on command   │                                      │
│  │  - NEVER requests secrets         │                                      │
│  │  - NEVER talks to native host     │                                      │
│  │  - LOWEST TRUST COMPONENT         │                                      │
│  └───────────────────────────────────┘                                      │
│                                                                             │
│  ════════════════  CHROME SECURITY BOUNDARY  ════════════════════════════   │
│  │  Chrome Native Messaging Channel                                    │    │
│  │  allowed_origins: [ "chrome-extension://<ZTV_ID>/" ]               │    │
│  │  4-byte LE length prefix + JSON payload                             │    │
│  ════════════════════════════════════════════════════════════════════════   │
└─────────────────────────────────────────────────────────────────────────────┘
                          │
                          │ stdin / stdout
                          │ (4-byte LE length + JSON)
                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  NATIVE HOST PROCESS: ZeroTrustVault.Host.exe (.NET 9)                      │
│  ══════════════════════════════════════════════════════════════════════════  │
│  SECURITY BOUNDARY — all crypto, validation, and secrets live here          │
│  ══════════════════════════════════════════════════════════════════════════  │
│                                                                             │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌──────────────────┐   │
│  │  Request Router     │  │  Origin Validator    │  │  Rate Limiter    │   │
│  │                     │  │                      │  │                  │   │
│  │  - Schema validate  │  │  - HTTPS enforce     │  │  - Per-origin    │   │
│  │  - Command dispatch │  │  - IDN reject        │  │    fill limits   │   │
│  │  - Response format  │  │  - Exact match HMAC  │  │  - Backoff       │   │
│  └──────────┬──────────┘  └─────────────────────┘  └──────────────────┘   │
│             │                                                               │
│  ┌──────────▼──────────────────────────────────────────────────────────┐   │
│  │  Vault Engine                                                        │   │
│  │                                                                      │   │
│  │  - HKDF-SHA256 subkey derivation                                    │   │
│  │  - AES-256-GCM encrypt/decrypt (via Windows CNG)                    │   │
│  │  - AEAD with per-record AAD                                         │   │
│  │  - TOTP generation (RFC 6238, HMAC-SHA1)                            │   │
│  │  - Shamir's Secret Sharing (GF(256), 3-of-5)                       │   │
│  │  - Event chain hash verification                                    │   │
│  └──────────┬──────────────────────────────────────────────────────────┘   │
│             │                                                               │
│  ┌──────────▼──────────┐  ┌─────────────────────┐  ┌──────────────────┐   │
│  │  Windows Hello /    │  │  Vault File          │  │  Event Log       │   │
│  │  TPM (CNG)          │  │  (vault.json)        │  │  (events.json)   │   │
│  │                     │  │                      │  │                  │   │
│  │  - VaultRootKey     │  │  - Encrypted creds   │  │  - Append-only   │   │
│  │    (platform key,   │  │  - Encrypted TOTP    │  │  - Signed events │   │
│  │    non-exportable)  │  │    seeds             │  │  - HLC ordering  │   │
│  │  - Device sign key  │  │  - Item metadata     │  │  - Hash chain    │   │
│  │    (ECDSA P-256)    │  │  - No plaintext      │  │                  │   │
│  └─────────────────────┘  └─────────────────────┘  └──────────────────┘   │
│                                                                             │
│  ┌─────────────────────┐  ┌─────────────────────────────────────────────┐  │
│  │  Recovery Kit       │  │  Sync Module (designed; local relay impl.)  │  │
│  │  (5 Shamir shares)  │  │                                             │  │
│  │                     │  │  - Event serialization                      │  │
│  │  - User exports     │  │  - Relay upload/download                    │  │
│  │    to files/print   │  │  - Signature attach                         │  │
│  │  - 3-of-5 needed    │  │  - HLC management                          │  │
│  └─────────────────────┘  └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Security Boundaries

| Boundary | Description |
|----------|-------------|
| **Chrome renderer ↔ service worker** | Chrome IPC; service_worker.js validates message origin (`chrome.runtime.onMessage`) |
| **Extension ↔ native host** | Chrome native messaging; `allowed_origins` restricts to the single ZTV extension ID |
| **Native host ↔ CNG/TPM** | Windows CNG API; VaultRootKey is a platform key (CNG_ALLOW_PERSIST_KEY, non-exportable) |
| **Native host ↔ vault file** | File system; vault.json is ciphertext; read/write only by the native host process |
| **Native host ↔ sync relay** | HTTPS; all payloads are ciphertext before transmission |

---

## 4. Component Responsibilities

### 4.1 service_worker.js

- Maintains the extension's runtime lifecycle (MV3 service worker).
- Extracts the current tab's origin using `chrome.tabs.query`.
- Proxies fill requests from the popup to the native host.
- Proxies fill commands to content.js via `chrome.tabs.sendMessage`.
- Manages session timeout using `chrome.alarms` (survives service worker restarts).
- Never stores secrets in `chrome.storage` or in-memory beyond the fill transaction.

### 4.2 popup.html / popup.js

- Renders the credential selector and TOTP code display.
- Receives the list of matching credential names (not values) from service_worker.js.
- Sends a user-selected fill command to service_worker.js.
- Displays TOTP codes (6-digit codes only; never displays TOTP seeds).
- Runs in a detached window created with `chrome.windows.create` to survive Windows Hello focus changes.

### 4.3 content.js

- Runs in the page renderer process; treated as potentially compromised.
- Detects login form fields (`input[type=password]`, associated username fields) and notifies service_worker.js.
- On fill command from service_worker.js: sets `element.value`, dispatches `InputEvent` and `ChangeEvent`.
- Never sends messages to the native host.
- Never receives secrets in plain form from service_worker.js (receives only the command to fill, with the value injected by service_worker.js after it receives it from the native host — see Fill Flow below).
- Never fills into HTTP iframes or cross-origin iframes.

### 4.4 Native Host (ZeroTrustVault.Host.exe)

- The sole trusted component. All crypto operations, origin validation, and TOTP generation are here.
- Reads commands from stdin; writes responses to stdout.
- Validates command schema before acting.
- Validates origin (HTTPS-only, IDN-reject, exact HMAC match).
- Requires a Windows Hello challenge for every credential release.
- Stores all secrets in vault.json as AES-256-GCM ciphertext.
- Generates TOTP codes (RFC 6238) internally; never sends TOTP seeds to the extension.

### 4.5 vault.json

- Location: `%LOCALAPPDATA%\ZeroTrustVault\vault.json`
- Contains: encrypted credential records, encrypted TOTP seeds, item metadata, device graph.
- Format: JSON envelope with per-record AEAD ciphertext fields.
- No plaintext credential data anywhere in the file.

### 4.6 events.json (Sync Event Log)

- Location: `%LOCALAPPDATA%\ZeroTrustVault\events.json`
- Append-only log of vault modification events.
- Each event is signed by the device key and chained via `previousHash`.
- Encrypted event payloads only; no plaintext on disk.

---

## 5. Data Flows

### 5.1 Unlock Flow

```
User opens popup
  → popup.js sends "getStatus" to service_worker.js
  → service_worker.js sends {"command": "status"} to native host
  → native host checks if session is active
  → if locked: returns {"status": "locked"}
  → popup shows "Vault Locked — Unlock with Windows Hello"
  → user clicks Unlock
  → service_worker.js sends {"command": "unlock"} to native host
  → native host calls CNG Hello challenge (Windows Hello UI appears)
  → on success: native host returns {"status": "unlocked", "sessionExpiry": <epoch>}
  → popup updates to show credential list (names only)
```

### 5.2 Fill Flow

```
content.js detects login form → sends "formDetected" to service_worker.js
  → service_worker.js sends {"command": "fillRequest", "origin": "https://host:port"} to native host
  → native host validates origin (HTTPS, not IDN, HMAC lookup)
  → native host triggers fresh Windows Hello prompt
  → on Hello success: native host decrypts matching credential
  → native host returns {"username": "...", "password": "..."} to service_worker.js
  → service_worker.js sends fill command to content.js: {"command": "fill", "username": "...", "password": "..."}
  → content.js sets element.value and dispatches events
  → service_worker.js zeroes its in-memory credential reference
  → native host zeroes decrypted plaintext buffers
```

Note: The decrypted credential travels from native host → service_worker.js → content.js over Chrome IPC (shared memory within the browser process). This is the narrowest window of plaintext exposure in the fill flow.

### 5.3 Add Credential Flow

```
User enters credential in popup
  → popup.js sends {"command": "addCredential", "origin": "...", "username": "...", "password": "...", "totp": "..."} to service_worker.js
  → service_worker.js forwards to native host
  → native host validates origin
  → native host triggers Windows Hello
  → on success: native host encrypts credential with AES-256-GCM (see CRYPTO.md)
  → native host writes encrypted record to vault.json
  → native host appends AddCredential event to events.json
  → native host returns {"result": "ok", "itemId": "..."} to service_worker.js
  → popup confirms to user
```

### 5.4 TOTP Generate Flow

```
User selects credential with TOTP in popup
  → popup.js sends "generateTotp" request to service_worker.js
  → service_worker.js sends {"command": "generateTotp", "itemId": "..."} to native host
  → native host triggers Windows Hello (fresh prompt)
  → on success: native host decrypts TOTP seed from vault
  → native host computes HMAC-SHA1(seed, floor(unixTime / 30)) per RFC 6238
  → native host returns {"totp": "123456", "remainingSeconds": 14} to service_worker.js
  → service_worker.js returns to popup
  → popup displays 6-digit code
  → TOTP seed never leaves native host
```

### 5.5 Backup Flow

```
User runs backup-vault.ps1 (or automated task fires)
  → script invokes native host with {"command": "backup", "destination": "path"}
  → native host triggers Windows Hello
  → on success: native host reads vault.json
  → native host derives BackupKey from VaultRootKey via HKDF
  → native host encrypts vault content with AES-256-GCM
  → native host computes HMAC-SHA256 over (vaultId || checkpoint || ciphertext)
  → native host writes: version_header || vaultId || checkpoint || MAC || ciphertext
  → native host returns {"result": "ok", "backupPath": "..."}
```

### 5.6 Recovery Flow

```
User installs ZTV on new machine
  → user runs recovery wizard
  → wizard prompts for 3-of-5 Shamir shares
  → native host reconstructs RecoveryRootSecret from shares
  → native host derives new VaultRootKey from RecoveryRootSecret
  → native host creates new CNG platform key (wraps VaultRootKey under new TPM)
  → native host re-encrypts vault.json content under new VaultRootKey
  → native host appends DeviceEnrolled event
  → recovery wizard confirms success
  → user performs Hello setup (new device's Windows Hello)
```

### 5.7 Sync Flow (Local File Relay — Implemented; Cloud Relay — Designed)

```
Device A modifies vault
  → native host creates signed event (see SYNC.md)
  → native host encrypts event payload
  → native host appends event to events.json
  → sync module writes event to local relay path (or uploads to blind relay)

Device B (on next sync check)
  → sync module reads new events from relay
  → native host verifies event signatures
  → native host verifies hash chain
  → native host applies events to local vault
  → on conflict: keeps both versions (no silent overwrite)
```

---

## 6. Native Messaging Protocol

All communication between the extension and the native host uses Chrome's native messaging framing:

```
[ 4-byte Little-Endian unsigned int (message length) ][ JSON message bytes ]
```

- Messages are UTF-8 JSON objects.
- The native host reads the 4-byte length from stdin, then reads exactly that many bytes of JSON.
- The native host writes the 4-byte length to stdout, then writes the JSON response.
- Maximum message size: 1 MB (Chrome enforces this limit).
- Newline characters within JSON strings are escaped; the framing does not use newline delimiters.

**Example Request (fill request):**
```json
{
  "command": "fillRequest",
  "requestId": "uuid-v4",
  "origin": "https://example.com",
  "timestamp": 1751234567
}
```

**Example Response (fill response):**
```json
{
  "requestId": "uuid-v4",
  "result": "ok",
  "username": "user@example.com",
  "password": "s3cr3t!"
}
```

**Error Response:**
```json
{
  "requestId": "uuid-v4",
  "result": "error",
  "errorCode": "ERR_HTTP_REJECTED",
  "errorMessage": "Origin must use HTTPS"
}
```

---

## 7. Key Error Codes

| Code | Meaning |
|------|---------|
| `ERR_HTTP_REJECTED` | Origin does not begin with `https://` |
| `ERR_IDN_REJECTED` | Origin contains IDN/punycode labels and IDN opt-in is disabled |
| `ERR_ORIGIN_NO_MATCH` | No credential stored for this exact origin |
| `ERR_HELLO_FAILED` | Windows Hello challenge failed or was cancelled |
| `ERR_RATE_LIMITED` | Too many fill requests in the allowed window |
| `ERR_VAULT_LOCKED` | Vault is locked; call `unlock` first |
| `ERR_SIG_INVALID` | Event signature verification failed |
| `ERR_CHAIN_BROKEN` | Event hash chain integrity check failed |
| `ERR_SCHEMA_INVALID` | Command JSON did not pass schema validation |
