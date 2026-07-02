# Known Limitations

This document is deliberately blunt. It lists what is **implemented and tested**,
what is **scaffolded / partial**, and what is **not started**. Nothing here is
hidden from the auditor.

## Implemented and tested (this milestone)

- **Local vault**: AES-256-GCM item encryption, HKDF subkey derivation, root key
  wrapped to a non-exportable CNG key, Windows Hello (UserConsentVerifier) gating
  every unlock and every fill.
- **Corrupt-vault safety** (`VaultIntegrity`, `VaultCommands.HandleCorruptVault`):
  - wrappedRootKey is classified (Missing/Empty/TooShort/InvalidBase64/Valid);
  - a corrupt vault is **quarantined** (copied, never deleted) to
    `%LOCALAPPDATA%\ZeroTrustVault\quarantine\` with a non-secret diagnostic JSON;
  - **Case A** (no user data) → reset to a fresh vault after quarantine;
  - **Case B** (has user data) → **never** overwritten; returns a typed error
    (`VaultCorruptRecoveryRequired` / `VaultCorruptNoRecovery`);
  - quarantine failure → `VaultCorruptQuarantineFailed`, vault untouched.
  - Covered by `VaultIntegrityTests` (17 tests).
- **Hello availability casing**: native host returns a canonical vocabulary
  (`Available`/`DeviceNotPresent`/`NotConfigured`/`DisabledByPolicy`/`Unavailable`/
  `Unknown`); popup classifies case-insensitively. No false "not ready: available".
- **Release-safe diagnostic logging** (`DiagnosticLog`): writes only in Debug or
  with explicit `ZTV_DEBUG_LOG=1`; redaction backstop; release builds are no-ops.
  Build emits `build-info.json`; `verify-release.ps1` fails if logging is enabled.
- **Signed/hash-chained event crypto** (`MeshEventCrypto`, `CanonicalJson`):
  canonical JSON, ECDSA P-256 sign/verify, SHA-256 hash chain, removed/unknown
  device rejection, tamper detection. Covered by `MeshEventCryptoTests` (11 tests).
- **Device identity primitives** (`DeviceIdentity`): `DeviceId = base64url(SHA-256(pubkey))`,
  order-independent SAS with MITM-mismatch property. Covered by `DeviceIdentityTests`.
- **SAS-verified device pairing** (`DeviceCommands.ApproveDevicePairingAsync`):
  approval requires a shared pairing code **and** a fresh Windows Hello **and** a
  matching Short Authentication String. The host recomputes the SAS over the exact
  signing+encryption keys it is about to wrap to and rejects on mismatch
  (`SAS_MISMATCH`), binding the user's confirmation to the real key material. The
  root key is re-wrapped to the joiner's public encryption key (RSA-OAEP-SHA256);
  duplicate devices are rejected; a signed `DeviceAdded` event is appended.
- **Cryptographic epoch rotation on device removal** (`VaultRekey.RotateRoot`,
  `DeviceCommands.RemoveDeviceAsync`): removal generates a **new random
  VaultRootKey**, **re-encrypts every item** under it, recomputes origin hashes,
  bumps the epoch, re-wraps the new root to the local CNG/TPM key and to each
  remaining active device, and strips the removed device's wrap. A device holding
  only the old root can no longer decrypt the re-encrypted vault. Fail-closed: the
  vault is only persisted on full success. Covered by `VaultRekeyTests` (4 tests).
- **MeshSync acceptance checks** (`EventLogManager.AcceptMeshEvents` +
  `MeshAuthorization` + `MeshConflictResolver`): incoming events are checked for
  identity, signature, hash-chain/fork, epoch, replay, payload presence, and now
  **authority** (membership events require owner/admin) and **conflict preservation**
  (concurrent edits keep-both; delete-vs-edit resurrects). Covered by
  `MeshAuthorizationTests`, `MeshConflictResolverTests`, `MeshEventCryptoTests`.
- **Recovery drill** (`RecoveryDrillTests`): 2 Shamir shares fail, 3 succeed, the
  reconstructed root decrypts pre-disaster credentials, and recovery rotates the epoch.

### This hardening pass (native-host caller authentication through final gates)

- **Native-host caller authentication** (`ExtensionIdentity`): the host no longer
  trusts the caller-supplied `extensionId` field. The expected id is loaded from the
  native-messaging manifest co-located with the host exe at startup; a missing,
  malformed, or mismatching id is rejected for every non-diagnostic command. Only
  "identity unverifiable" (e.g. running the exe directly from a build output dir) is
  relaxed, and only in Debug builds. Covered by `ExtensionIdentityTests` (12 tests) and
  `CommandRouterTests` (7 tests).
- **Centralized command authorization** (`CommandContext` + `OperationAuthorization`):
  session validation and fresh-Hello verification are each implemented exactly once,
  behind opaque `SessionAuthorization`/`FreshHelloAuthorization` tokens that are the
  ONLY way to obtain the root key (`UnwrapCurrentRootKey` takes a token parameter —
  there is no overload that skips the check, so a future handler that forgets to
  authorize simply cannot compile a call to unwrap the key). This replaced four
  independently-drifting copies of session/Hello-error handling across
  VaultCommands/TotpCommands/RecoveryCommands/DeviceCommands. Fixed a real gap in the
  process: `syncPullEvents`/`syncPushEvents`/`verifyEventLog` previously let a missing
  session through unchecked (`sessionEntry is null && !string.IsNullOrEmpty(sessionId)`
  is false when sessionId is null/empty). Covered by `VaultCommandsAuthorizationTests`
  (10 tests) and `SyncCommandsAuthorizationTests` (15 tests).
- **Root-key lifetime**: there is no session-level cache of the unwrapped root key
  anywhere in the codebase. Every command that needs it unwraps fresh via
  `CommandContext.UnwrapCurrentRootKey` and zeroizes in a `finally` block immediately
  after use, bounding plaintext exposure to a single request instead of the ~15-minute
  session window. `deleteCredential`/`deleteCredentialTombstone` were also hardened to
  require fresh Hello (previously they did not). Covered by `RootKeyLifetimeTests`
  (11 tests) proving zeroization after unlock/list/add/reveal/update/delete/fill/TOTP.
- **Fill vs. reveal path separation**: autofill now calls a dedicated
  `fillCredentialForExactOrigin` command, distinct from the generic
  `decryptSelectedCredentialForExactOrigin` reveal command, and the native host itself
  (not just extension JS) requires `tabId`/`windowId` to be present for fill —
  `FILL_CONTEXT_REQUIRED` otherwise, checked before any root-key unwrap. Reveal stays
  reserved for a future explicit "show password" affordance and is not currently
  invoked by autofill. Covered by `FillRevealSeparationTests` (4) and
  `RootKeyLifetimeTests` fill-specific cases (3).
- **Vault structural invariants** (`VaultInvariants`): a pure, side-effect-free checker
  for duplicate item/device ids, missing/invalid wraps, broken ciphertext-blob fields,
  item epoch exceeding vault epoch, and malformed recovery-kit shape. Run on every
  `unlockOrigin` existing-vault load, before the root key is unwrapped; any violation
  routes through the existing quarantine-first corrupt-vault handling rather than
  silently trusting a tampered-but-parseable file. Covered by `VaultInvariantsTests`
  (16 tests) and `VaultCorruptionAndRollbackTests` (integration, 3 tests).
- **Anti-rollback** (`EpochRollbackGuard`): a sidecar marker file tracks the highest
  epoch seen per vault id; a vault.json restored from an older, still-valid snapshot
  (e.g. undoing a device revocation) is detected and fails closed through the same
  quarantine path. Honestly a local-filesystem sidecar, not a hardware monotonic
  counter — see "Known gaps" below. Covered by `EpochRollbackGuardTests` (7 tests).
- **Recovery rotates root again** (`RecoveryCommands.RecoverVaultAsync`): previously,
  successful recovery re-wrapped the *same* reconstructed root key to a new device —
  meaning the shares just used (and any leaked copy of them) stayed valid forever, and
  a previously-revoked device holding a wrap of that same root would regain access.
  Recovery now generates a brand-new root, calls `VaultRekey.RotateRoot`, marks every
  other device Removed, and invalidates the old recovery kit (a new one must be
  created). Reused/stale shares now fail with `RECOVERY_FAILED` (the AEAD tag no
  longer authenticates once the root has moved on). Covered by `RecoveryRootRotationTests`
  (4 tests).
- **Device pairing replay protection** (`DeviceCommands.ApproveDevicePairingAsync`):
  previously an approved pairing stayed in `vault.PendingPairings` with only an
  `Approved=true` flag (never removed), and the approval lookup fell back to that same
  list — so a captured pairingId+code+SAS could be replayed. Approved pairings are now
  removed outright, and pending pairings expire after 10 minutes. Covered by
  `DevicePairingReplayTests` (5 tests) — this was previously the only pairing-approval
  code path with **zero** command-level test coverage at all.
- **Installer/registry health reporting** (`InstallationHealthCheck`): `securityHealthCheck`
  now reports HKLM-vs-HKCU registration mode, whether the registry-pointed manifest path
  matches the one co-located with the running exe, whether the manifest's declared exe
  path matches the running process, and a degraded/hijack-indicator reason when any of
  these disagree. Covered by `InstallationHealthCheckTests` (8 tests) against the pure
  classification logic.
- **Manifest/version drift guards**: `tools/audit-extension-csp.ps1` now fails on any
  `permissions[]` entry or `optional_host_permissions` entry beyond the reviewed,
  justified baseline (documented inline: nativeMessaging/activeTab/scripting/storage —
  needed outright; alarms — MV3 service workers are non-persistent, session timeout
  needs an alarm not a `setTimeout`; tabs/windows — fill-binding re-validates the target
  tab via `chrome.tabs.get`, which `activeTab` alone cannot do). `tools/verify-version-truth.ps1`
  compares manifest.json/csproj build-info targets/`VaultManager.CodeVersion`/
  AUDIT_PACKAGE docs/README title and fails on any disagreement — it caught a real
  drift (README.md and IMPLEMENTATION_STATUS.md still said v0.5.0 while the shipped
  code was already v2.0.0 everywhere else), now fixed. `tools/run-all-security-gates.ps1`
  runs every gate (tests, JS syntax check, CSP/permission audit, forbidden-string scan,
  extension integrity, dependency scan, version truth) as one command.
- **Log redaction, exercised end-to-end**: beyond `DiagnosticLogTests` unit-testing
  `DiagnosticLog.Redact()` directly, `SecretRedactionIntegrationTests` runs a realistic
  unlock→add→reveal→TOTP→recovery-kit sequence with unique, distinctive secret values
  and asserts none of them appear in the actual diagnostic log file — proving the real
  command handlers never hand plaintext to logging, not just that the redaction
  function works when fed a secret-shaped string.
- **Test-isolation bug found and fixed**: `CommandRouterTests` used `new VaultManager()`
  — the default, *real* `%LOCALAPPDATA%\ZeroTrustVault` path — instead of an isolated
  temp directory. Every test run could create/mutate/reset the actual developer's real
  vault file, and it raced with other test classes touching that same path under
  xUnit's default class-level parallelism (observed directly: `LockVault_EmptyPayload_ReturnsOk`
  failed only when the full suite ran, never in isolation). Fixed to use a temp
  directory like every other test class.

## Scaffolded / partial — NOT production-complete

- **Live MeshSync transport**: the accept/verify/authority/conflict logic and the
  signed/encrypted `MeshEvent` primitives are implemented and tested, but there is
  **no blind-relay server** and no end-to-end pull/push wiring over a network. The
  payload **apply-to-vault** step (decrypt event payload → mutate items using the
  conflict policy) is modeled and unit-tested at the policy level but is not yet the
  live write path. Multi-device sync should still be treated as **not production**.
- **Device pairing transport**: pairing assembles a verified device entry locally
  (SAS, keys, wrap) but does not yet move the signed `AddDevice` event to the joining
  device over a real channel for end-to-end verification.
- **Recovery kit after rotation**: a device removal rotates the root and therefore
  **invalidates the existing Shamir recovery kit** (the old shares encode the old
  root). The host clears the kit and instructs the user to create a new one. This is
  correct but means a recovery kit must be re-created after each removal.
- **Anti-rollback is a local sidecar, not a hardware counter**: `EpochRollbackGuard`
  detects a vault.json swapped for an older snapshot by comparing against a marker
  file in the same directory. An attacker capable of overwriting `vault.json` can
  typically also delete or roll back that marker file unless the folder ACLs
  specifically prevent it. This raises the bar against a copy-vault-only attack; it is
  not equivalent to a TPM monotonic counter, which would be required for a rollback
  guarantee that survives a fully compromised local filesystem.
- **Vault invariant checking runs on load, not on every write**: `VaultInvariants.Check`
  is wired into `unlockOrigin`'s existing-vault path (the natural place secrets first
  get trusted each session), not into every individual `Save()` call across
  Add/Update/Delete/DeviceCommands/RecoveryCommands. A structural bug introduced by one
  of those write paths would be caught at the *next* unlock, not at write time.
- **Installer ACL status is not yet surfaced in the health check**: `install.ps1`
  already sets restrictive ACLs on the install/vault directories and prefers HKLM with
  an HKCU fallback; `InstallationHealthCheck` reports registration mode and
  manifest/exe path agreement, but does not yet read back and report the *current* ACL
  state of those directories at runtime.
- **SyncCommands session check is origin-agnostic by design, not per-payload**: sync
  commands now require *a* valid, unexpired session (fixing the previous unauthenticated
  bypass), but do not re-verify per-event authorization beyond what
  `EventLogManager.AcceptMeshEvents`/`MeshAuthorization` already do at the payload
  level — this pass did not re-audit that payload-level logic (it was built and tested
  in an earlier session) for every scenario in the mission's threat list (concurrent
  edit conflict, malicious relay reordering, etc.); it was not re-verified here.
- **SecurityEventLog is not directory-injectable**: unlike `VaultManager` (which
  supports a custom directory for testing), `SecurityEventLog` always appends to the
  real `%LOCALAPPDATA%\ZeroTrustVault\security-events.log`. Test runs append non-secret
  event metadata (session ids, origins, credential ids — never passwords) to that real
  file. Lower severity than the `VaultManager` test-isolation bug fixed this pass (it
  cannot reset or corrupt vault data, only append log lines), but it is the same class
  of issue and was not fixed here.

## Managed-runtime memory risk (Section S)

The native host is C#/.NET — secrets pass through the garbage-collected heap as
managed objects at several points, and the CLR does not guarantee those objects are
never copied, promoted between generations, or paged to disk before a `SecureClear`
call runs. This is a real, structural residual risk of choosing a managed runtime
over a native one, and it is not eliminated by anything in this codebase.

Where secrets become managed **strings** (harder to zero deterministically than
`byte[]`, since .NET strings are immutable and interning/literal pooling can create
copies outside the caller's control):

- `password`, `usernameOrEmail`, `totpSecret`, `notes` fields of `VaultPayload` —
  materialized as strings by `System.Text.Json` deserialization on add/update, and by
  decryption on reveal/fill/TOTP generation.
- The Shamir recovery shares themselves arrive as base64 **strings** from the request
  payload (`RecoverVaultAsync`) before being decoded to `byte[]`.
- `HelloResult`/error messages are never secret, but the JSON request/response
  envelope itself passes through `JsonDocument`/`JsonElement`, which hold the raw
  request text (including plaintext `password`/`totpSecret` on add/update) as string
  data until the `JsonDocument` is disposed by the framework's own request-handling
  scope.

Where secrets are `byte[]` (zeroizable, and actually zeroized via
`VaultCrypto.SecureClear` in every command handler's `finally` block): the root key
itself, derived subkeys (`SubkeyDerivation.Derive*`), and Shamir share values after
base64 decoding.

What this codebase does to reduce (not eliminate) the risk:
- Root key lifetime is minimized to a single operation (Section M) — it exists as a
  `byte[]` for the shortest practical window and is zeroized immediately after use,
  reducing the odds it survives a GC compaction/promotion cycle while live.
- Vault payload strings (`password`, etc.) are not stored in any long-lived field,
  static, or cache — they are local variables scoped to a single request, eligible for
  collection as soon as the response is constructed.
- No secret is ever serialized back out in a log line (see log redaction, above).

What is **not** done and would need to be, for a stronger guarantee:
- Vault item payloads are not converted to `SecureString`/pinned/protected-memory
  buffers; they rely on GC scoping alone.
- The JSON request/response pipeline is not restructured to avoid materializing
  secret-bearing strings during (de)serialization.
- No static/scan tooling currently enforces "no `string` field on any class holds a
  decrypted secret longer than one method scope" — this is a code-review convention,
  not a machine-checked one.

Honest bottom line: a memory-scraping attack against a live, unlocked host process
(e.g. reading process memory of a compromised/debugged host) could plausibly recover a
plaintext secret that was in scope moments earlier, even though every code path
correctly zeroizes its *own* copy on the way out. This is a known, documented, and
unresolved limitation of running this design on a managed runtime rather than native
code with mlock/VirtualLock-protected memory.

## Not started / external (cannot be self-certified)

- Blind-relay server implementation and its API contract (documented intent only).
- Signed release with a **real** CA-issued code-signing certificate (current signing
  is self-signed/dev; `verify-release.ps1 -RequireSignature` fails without a cert).
- Chrome Web Store / Edge Add-ons distribution (requires a developer account + review).
- **External third-party security audit** — none has occurred; status is audit-ready only.

## Honest one-line summary

A strong, well-tested **local** Windows-Hello vault with **real** SAS-verified
pairing, **real** cryptographic device revocation (root rotation + re-encrypt),
**centralized command authorization with compile-time-enforced root-key access**,
**vault structural-integrity and anti-rollback checks**, **replay-safe device pairing**,
and **recovery that actually rotates the root** — but the **live sync relay/transport,
a real signed release, external audit, and full managed-memory secret-lifetime
hardening are still missing**.
