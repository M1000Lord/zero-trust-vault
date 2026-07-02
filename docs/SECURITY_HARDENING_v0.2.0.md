# Zero-Trust Vault v0.2.0 Security Hardening

This build changes the extension from convenience-first to security-first while keeping convenience as explicit opt-in.

## Default policy

- Secure Mode is the default.
- No broad host permission by default.
- No static content script on every site by default.
- Manual popup + manual Windows Hello + manual Fill is the default.
- Fill + Sign in is disabled by default.

## Optional Convenience Mode

Convenience detection can be enabled from the popup settings. It requests only HTTPS host permission and registers a dynamic content script for login-field detection.

Auto Windows Hello is still per-site only. It is blocked on:

- HTTP
- punycode / IDN origins
- high-risk identity, finance, payment and crypto surfaces
- background tabs
- repeated prompt cooldown windows

## Fill + Sign in policy

The default account action is `Fill` only.

`Fill + Sign in` appears only when enabled per exact origin and is still blocked on:

- HTTP
- punycode / IDN origins
- high-risk identity, finance, payment and crypto surfaces
- changed target tab/origin
- changed login DOM between approval and fill

## Native-host hardening

- Strict top-level native-message schema.
- Rejects unknown top-level fields.
- Rejects malformed protocol versions, command names, oversized strings and non-object payloads.
- Validates extension identity against the Chrome native-messaging launch origin when available.
- Rejects unknown commands and known-dangerous commands.
- Rejects unexpected command-specific payload fields.
- Adds unlock/save rate limiting after repeated Windows Hello failures.
- Blocks credential release/save for HTTP and punycode / IDN origins.

## DOM hardening

- Content script remains low-trust.
- Content script cannot read vault or native host.
- Cross-origin/frame fills are rejected.
- Hidden/tiny/disabled/offscreen fields are rejected.
- Service worker asks the page for a prepare-fill mutation epoch before decrypting.
- If the DOM mutates between prepare and fill, fill is cancelled.

## Remaining non-goals

This build still cannot defeat:

- admin/root malware on the local OS
- malicious updates to the extension/native host
- a real website compromised after credentials are filled
- JavaScript on the target page reading the values after they are written to DOM inputs

Production still needs code signing, external audit, fuzzing and a Rust/Go or formally reviewed native-host implementation.
