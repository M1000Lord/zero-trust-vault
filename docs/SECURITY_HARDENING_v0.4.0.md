# Zero-Trust Vault v0.4.0 — Ultra Security Hardening

Goal: optimize for a single-user, local-only Windows vault with stricter safety than normal convenience-first password-manager behavior.

## Changes

### 1. No auto-submit
- Removed Fill + Sign in from the popup.
- The service worker ignores submitAfterFill and always sends `submitAfterFill: false` to the content script.
- The content script never clicks a submit/login button.

### 2. Fresh Windows Hello before every credential release
- Unlock lists accounts for the current exact origin only.
- Selecting Fill triggers another native Windows Hello approval before the selected credential is decrypted and released to the page.
- Session TTL reduced to 45 seconds.

### 3. Encrypted/private vault metadata
New v2 records no longer store these fields in plaintext:
- normalizedOrigin
- display label / masked label
- username preview
- createdAt / updatedAt / lastUsedAt
- AAD containing the origin

Instead, the vault stores:
- `originHashB64 = HMAC-SHA256(originIndexKey, normalizedOrigin)`
- ciphertext payload containing origin, username, password, label, and timestamps

The origin index key is derived from the root vault key with HKDF, so a stolen `vault.json` cannot enumerate saved websites without first unlocking the vault key.

### 4. Legacy migration
On the next successful unlock, v0.3.x records are migrated to v2:
- legacy plaintext origin/label/timestamps move into the encrypted payload
- v1 AAD is removed
- invalid legacy records are discarded instead of being carried forward with leaked metadata

### 5. Locked count privacy
`countCredentialsForOrigin` no longer reveals whether a locked vault has records for a site. It returns `privateMetadata: true`.

## Security tradeoff
Because locked metadata is private, the extension cannot reliably know whether a site has saved credentials before Windows Hello unlock. This intentionally sacrifices convenience for privacy.

## Remaining limits
- A malicious page can still read values after they are filled into the DOM.
- A RAT or admin-level malware on the same machine can still observe screen/DOM/memory after user approval.
- This build is not externally audited or signed in this sandbox output.
