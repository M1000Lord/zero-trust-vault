# Release Process

How a Zero-Trust Vault release is built, stamped, scanned, and verified. The goal
is that a release artifact is reproducible, contains no developer bypasses, no
build junk, and no debug logging, and that its extension integrity map matches
the files it ships.

> Honesty note: signing currently uses a self-signed / development certificate
> unless you pass a real code-signing `-CertThumbprint`. Until a real certificate
> is used and an external audit report exists, this is a **release-engineering**
> process, not a statement that the build is independently audited. See
> `AUDIT_PACKAGE/`.

---

## One-shot build

```powershell
# Dev build (unsigned allowed, loud warnings, do not ship):
powershell -ExecutionPolicy Bypass -File tools\build-release.ps1 -DevMode

# Production build (requires a real code-signing cert thumbprint):
powershell -ExecutionPolicy Bypass -File tools\build-release.ps1 -CertThumbprint <THUMBPRINT>
```

`build-release.ps1` runs these steps and aborts on the first failure:

1. **Forbidden-string scan** (`check-forbidden-strings.ps1`) over extension files.
2. **Build** the native host from source in Release mode (`dotnet publish`).
3. **Scan the built binary** for hard bypass strings.
4. **Sign** the host exe. In production a non-`Valid` signature aborts the build;
   in `-DevMode` it warns and continues.
5. **Stamp + verify extension integrity** — runs
   `update-extension-hashes.ps1` then `verify-extension-integrity.ps1`. If the
   stamp and the files disagree, the build aborts.
6. **Generate SBOM** (`generate-sbom.ps1`) when present.
7. **Generate the release manifest** — SHA-256 of every artifact plus a
   deterministic source hash, certificate subject/thumbprint, and signature
   status.
8. **Package the ZIP** into `dist\` (and to the Desktop only with
   `-CopyToDesktop`). `.pdb` files are stripped.

---

## Extension integrity: regenerating hashes after a source change

Any edit to a checked extension file (`manifest.json`, `popup.html`, `popup.js`,
`popup.css`, `content.js`) **invalidates** the integrity map embedded in
`service_worker.js`. The build does this for you, but during development run it
manually:

```powershell
# Re-stamp the map from the current files (idempotent):
powershell -ExecutionPolicy Bypass -File tools\update-extension-hashes.ps1

# Verify the stamped map matches the files on disk:
powershell -ExecutionPolicy Bypass -File tools\verify-extension-integrity.ps1
```

Then reload the extension in `chrome://extensions`. The verifier reads the map
the service worker will **actually enforce** at runtime, so a green verify means
the loaded extension will not show the integrity badge. CI runs the same verifier
as a gate.

`service_worker.js` itself is **not** in the map (it cannot hash itself); the
store signature / unpacked-load trust boundary covers it.

---

## What a release package must NOT contain

The cleanliness rule (enforced by `verify-release.ps1` and the package-cleanliness
check in CI): no `bin/`, `obj/`, `.pdb` (outside a separate symbol package),
`%TEMP%` logs, `ztv_diag.txt`, user vaults, quarantined vaults, recovery shares,
test artifacts, local-machine data, dev certificates/keys, stale generated files,
or old extension copies.

---

## Verifying a built release

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify-release.ps1 `
  -HostDir <publishDir> -RequireSignature
```

`verify-release.ps1` fails the release if:

- `build-info.json` reports `diagnosticLogging=enabled` (a debug build),
- manifest artifact hashes do not match the files,
- `-RequireSignature` is set and the exe is not validly signed,
- forbidden bypass strings appear in the binaries.

Distribute the **manifest SHA-256 out-of-band** from the ZIP so a recipient can
confirm they received the intended build.

---

## Versioning

The version is read from `extension/manifest.json` unless `-Version` is passed.
Bump the manifest version for every shipped change so the integrity map and the
release manifest are tied to a specific version.
