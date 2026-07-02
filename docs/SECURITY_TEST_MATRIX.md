# Security Test Matrix v0.2.0

| Area | Test | Expected result |
|---|---|---|
| Crypto | Wrong key decrypt attempt | Authenticated decryption fails |
| Crypto | Tampered ciphertext/tag | Decrypt rejected |
| Crypto | Nonce uniqueness review | No duplicate item nonce for same root/item context |
| Origin | `example.com.evil.com` | Does not match `example.com` |
| Origin | `http://` vs `https://` | Different origins; HTTP blocked for save/fill |
| Origin | Punycode/IDN | Save/fill/unlock blocked |
| DOM | Hidden password field | Rejected by detector |
| DOM | Tiny/offscreen/disabled/readonly field | Rejected by detector |
| DOM | Cross-origin iframe | Not injected; fill rejects frames |
| DOM | Mutation after prepare-fill | Fill cancelled |
| Extension | Secure Mode default | No static `content_scripts`; no broad host permissions |
| Extension | Convenience Mode | HTTPS host permission requested explicitly |
| Extension | CSP fetch attempt | Blocked by CSP `connect-src 'none'` |
| Native | Wrong extension ID | Rejected when Chrome launch origin is known |
| Native | Unknown command | Rejected |
| Native | Forbidden command | Rejected |
| Native | Unknown top-level JSON field | Rejected |
| Native | Unknown payload field | Rejected |
| Native | Oversized message/string | Rejected |
| Native | Arbitrary file path command | No such command exists; rejected |
| UX | Fill default | Fill only; no submit |
| UX | Fill + Sign in | Hidden until per-site enabled; blocked on high-risk sites |
| UX | Auto prompt | Per-site only; blocked on HTTP/IDN/high-risk/background tabs |
| Sync | Cloud plaintext | No sync exists in this MVP |

## v0.3.0 additional hardening tests

| Area | Test Case | Expected Result |
|---|---|---|
| KEK | New vault created on Windows Hello-capable TPM machine | `protectionMode` becomes `TpmHello` |
| KEK | Use root key after lock/restart | Windows Security / Hello consent is required by CNG private-key use |
| KEK | Legacy `Tpm` vault unlock | Unlock succeeds, vault header migrates to `TpmHello` |
| KEK | No TPM/Hello and no `ZTV_ALLOW_DPAPI_FALLBACK` | New vault creation fails closed |
| Dev bypass | `ZTV_DEV_BYPASS=1` in Release build | Ignored; no bypass |
| Origin auth | Edit `normalizedOrigin` only in vault JSON | Record is not listed/decrypted after unlock |
| Origin auth | Edit `normalizedOrigin` and `aad` to new origin | AEAD decrypt fails; record rejected |
| Origin auth | Edit ciphertext/tag | Decrypt rejected as `TAMPERED_RECORD` |
| Session | Unlock for `https://a.example:443`, then list/decrypt for `https://b.example:443` with same session | Rejected as locked/origin-bound session mismatch |
| Permissions | Inspect extension manifest | `tabs` is optional, not mandatory |


## v0.3.1 Windows Hello prompt regression tests

| Area | Test Case | Expected Result |
|---|---|---|
| Windows Hello UX | New vault unlock on Windows Hello-enabled device | One Windows Hello/fingerprint prompt, no second CNG key-password prompt. |
| Windows Hello UX | Save first credential into new vault | One Windows Hello/fingerprint prompt, no second CNG key-password prompt. |
| Migration | Existing v0.3.0 `TpmHello` vault unlock | May require old CNG key password once, then rewraps to `TpmHelloGesture`. |
| Migration | Unlock after successful v0.3.0 -> v0.3.1 migration | Fingerprint-only Windows Hello prompt, no second key-password prompt. |
| Reset | Run `reset-test-vault.ps1` then create new vault | New vault uses `TpmHelloGesture`. |

## v0.4.0 Ultra Security tests

| Area | Test Case | Expected Result |
|---|---|---|
| UX | Auto-submit path | No Fill + Sign in button exists; service worker and content script never submit. |
| UX | Fill click | Native host asks for fresh Windows Hello before decrypting selected credential. |
| Session | Wait more than 45 seconds after unlock | List/decrypt rejected as locked. |
| Metadata privacy | Save new credential, inspect `vault.json` | No plaintext `normalizedOrigin`, `maskedLabel`, `createdAt`, `updatedAt`, or `lastUsedAt` in v2 record. |
| Metadata privacy | Locked `countCredentialsForOrigin` | Returns `privateMetadata: true` and does not reveal saved-site count. |
| Migration | Unlock v0.3.x vault | Records migrate to v2 and plaintext metadata is removed. |
| Migration | Tampered v0.3.x record | Invalid legacy record is not carried forward with plaintext metadata. |
| Origin privacy | Copy v2 record to another origin context | Record is not found/decrypted because origin HMAC and AAD are origin-bound. |
| Origin privacy | Modify `originHashB64` | Record is not listed/decrypted. |
| Origin privacy | Modify ciphertext/tag | Decrypt rejected as `TAMPERED_RECORD`. |
