# Production Readiness Gate

This checklist must be complete before public release or use with high-value credentials.

## Security Posture

- [ ] Confirm the product is positioned as local-only and Windows-first, not a universal Bitwarden replacement.
- [ ] Confirm no cloud sync, telemetry, analytics, remote config, or remote code exists.
- [ ] Confirm no cookie, OAuth token, session token, passkey private key, or browser session export exists.
- [ ] Confirm Release builds ignore `ZTV_DEV_BYPASS`.
- [ ] Confirm Release builds do not use `ZTV_ALLOW_GESTURE_ONLY_KEK`.
- [ ] Confirm new vaults use `TpmHelloGesture`.
- [ ] Confirm existing `TpmHelloStrict` vaults migrate to `TpmHelloGesture` after one successful unlock.
- [ ] Confirm root key memory is wiped after unlock/list, fill, save, and delete.

## Windows Validation

- [ ] Test on Windows 10 with Windows Hello PIN.
- [ ] Test on Windows 11 with Windows Hello PIN.
- [ ] Test fingerprint flow on supported hardware.
- [ ] Test face unlock flow on supported hardware if supported.
- [ ] Confirm Windows Hello prompts are shown without a recurring CNG key-password dialog.
- [ ] Confirm vault creation fails closed if TPM/CNG key wrapping is unavailable.
- [ ] Confirm DPAPI fallback is not used in production.

## Extension Validation

- [ ] Load unpacked in Chrome stable.
- [ ] Load unpacked in Edge stable.
- [ ] Confirm no mandatory host permissions.
- [ ] Confirm optional HTTPS host permission is requested only when detector mode is enabled.
- [ ] Confirm content scripts cannot read `chrome.storage.local`.
- [ ] Confirm CSP blocks extension-page network fetches.
- [ ] Confirm no auto-submit path exists.
- [ ] Confirm no password reveal path exists.
- [ ] Confirm no clipboard password-copy path exists.

## Native Host Validation

- [ ] Confirm invalid extension IDs are rejected.
- [ ] Confirm native messaging `allowed_origins` contains only the installed extension ID.
- [ ] Confirm unknown top-level request fields are rejected.
- [ ] Confirm unknown payload fields are rejected.
- [ ] Confirm forbidden commands are rejected.
- [ ] Confirm oversized messages are rejected.
- [ ] Confirm stdout/stderr never contain secrets.
- [ ] Confirm native host opens no TCP, HTTP, WebSocket, or named-pipe control plane.
- [ ] Confirm vault and host install directories have current-user ACLs.

## Autofill Safety

- [ ] HTTP origin blocked.
- [ ] Punycode/IDN origin blocked.
- [ ] Cross-frame fill blocked.
- [ ] Hidden/tiny/offscreen/disabled/readonly fields blocked.
- [ ] Form mutation between approval and fill blocked.
- [ ] Multiple visible password fields blocked.
- [ ] Signup/register forms blocked.
- [ ] Password reset/change forms blocked.
- [ ] Target tab/window focus change blocks fill.

## Release Engineering

- [ ] Use a clean Release build.
- [ ] Run `dotnet build -c Release`.
- [ ] Run JS syntax checks for all extension scripts.
- [ ] Run native smoke test.
- [ ] Run Debug throwaway-vault round-trip test.
- [ ] Generate release zip.
- [ ] Generate SHA-256 hashes for every release artifact.
- [ ] Sign `ZeroTrustVaultHost.exe`.
- [ ] Sign installer scripts or package inside a signed installer.
- [ ] Package/sign extension for Chrome Web Store or enterprise deployment.
- [ ] Archive exact source tree used for release.

## External Review

- [ ] Static analysis review.
- [ ] Dependency vulnerability scan.
- [ ] Threat-model review.
- [ ] Cryptography review.
- [ ] Native host abuse/fuzz testing.
- [ ] Browser extension security review.
- [ ] Independent penetration test.
- [ ] Public audit report or internal release sign-off.

## Release Decision

Do not call this production-ready until all required checks above are complete and signed off.
