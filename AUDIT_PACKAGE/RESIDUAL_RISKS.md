# Residual Risks

Risks that remain even with the current controls in place. Stated plainly.

## Cryptographic / key management
- **Root key unwrap depends on a single non-exportable CNG key.** If the TPM/CNG
  key is lost (hardware failure, profile reset) and no recovery kit exists, the
  vault is unrecoverable. The corrupt-vault path quarantines but cannot recover
  without recovery material. Mitigation: create and verify a recovery kit; this is
  surfaced in the health dashboard but not enforced.
- **Device removal re-keys the vault, but cannot un-see already-read secrets.**
  Removal now generates a new root key and re-encrypts all items
  (`VaultRekey.RotateRoot`), so a removed device loses *future* access. It may
  still possess any secret it decrypted and exfiltrated *before* removal — that is
  an inherent residual, mitigated by the password-rotation checklist returned on
  removal. Removal also **invalidates the existing recovery kit** (its shares
  encode the old root); the user must create a new kit afterward.

## Sync / multi-device (logic real, transport not wired)
- **No live sync relay yet.** The accept/verify/authority/conflict logic and the
  signed/encrypted `MeshEvent` primitives are implemented and unit-tested, but
  there is no blind-relay server and no network pull/push, and the payload
  apply-to-vault write path is policy-tested rather than live. Do not rely on
  multi-device sync in production.
- **Pairing is SAS-verified locally but not yet transported end-to-end.** Approval
  now enforces a matching Short Authentication String over the real key material
  (`SAS_MISMATCH` on mismatch) plus a fresh Hello, so an intercepted pairing code
  alone cannot enroll a device. The joining device does not yet verify the signed
  `AddDevice` event over a live channel — that final hop remains to be wired.

## Platform / host
- **Native messaging trust boundary.** Any process that can write the native
  messaging manifest registry key or replace the host binary can intercept
  requests. Mitigations: HKLM registration, directory ACLs to current user+SYSTEM,
  thumbprint pinning in the installer. Thumbprint verification is **skipped** if
  `thumbprint.txt` is absent — acceptable only for dev, not production.
- **Diagnostic logging in dev builds.** Debug builds (or `ZTV_DEBUG_LOG=1`) write
  `%TEMP%\ztv_diag.txt`. Output is redacted as a backstop, but the file should be
  cleaned (`tools/clean-debug-logs.ps1`) and must never ship enabled
  (`verify-release.ps1` enforces this).

## Extension
- **Unpacked/dev-mode extension is not tamper-proof.** Integrity hashes catch
  post-install file edits, but an unpacked extension is not store-signed. The
  health dashboard must report the true distribution state, never a false green.

## Process
- **No external audit.** All assurance to date is self-review + automated tests.
  See `EXTERNAL_AUDIT_REQUEST.md`.
