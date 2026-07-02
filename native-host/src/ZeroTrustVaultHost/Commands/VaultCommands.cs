using System.Security.Cryptography;
using System.Text.Json;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.Diagnostics;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Handles all credential vault commands: unlock, list, fill, add, update, delete, lock, count.
///
/// Root-key lifetime (see AUDIT_PACKAGE/KNOWN_LIMITATIONS.md "root-key
/// lifetime"): there is NO session-level cache of the unwrapped root key
/// anywhere in this class. SessionManager binds a session to an ORIGIN only
/// (see <see cref="GetValidSession"/>) — never to key material. Every method
/// that needs the root key unwraps it fresh via
/// <see cref="CommandContext.UnwrapCurrentRootKey"/> for the narrow duration
/// of that one operation, then zeroizes it in a finally block before
/// returning. This bounds the plaintext root key's lifetime in managed memory
/// to a single request/response cycle instead of the full ~15-minute session
/// window, and means a stolen-but-still-unlocked device only exposes the key
/// for the instant a command is actually executing, not for the whole time
/// the vault shows as "unlocked" in the UI.
///
/// Freshness tiers: listing/count only require a *valid* (origin-bound,
/// unexpired) session. Anything that releases or mutates a secret — reveal,
/// add, update, delete, TOTP, recovery, device pairing/removal — additionally
/// requires a FRESH Windows Hello proof obtained immediately before the
/// operation (a new prompt, not a cached one), enforced per-call in each
/// handler below.
/// </summary>
public sealed class VaultCommands
{
    private readonly CommandContext _ctx;

    public VaultCommands(CommandContext ctx) => _ctx = ctx;

    // ---- unlockOrigin ----

    public async Task<NativeResponse> UnlockAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required for unlockOrigin.");

        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // Rate limit Hello prompts
        var rateLimit = _ctx.RateLimiter.CheckHelloPrompt();
        if (rateLimit is not null)
        {
            _ctx.SecurityEventLog.LogRateLimited(null, "unlockOrigin");
            return new NativeResponse
            {
                RequestId = request.RequestId,
                Status = "error",
                Error = new NativeMessaging.NativeError
                {
                    Code = rateLimit.Code,
                    SafeMessage = rateLimit.SafeMessage,
                    RetryAfterSeconds = rateLimit.RetryAfterSeconds,
                }
            };
        }

        // Check if vault exists; if not, create it after Hello verification
        bool vaultExists = _ctx.VaultManager.VaultExists();

        if (VaultMigration.IsMigrationNeeded(VaultManager.VaultFilePath))
        {
            // Trigger migration before unlock
            var (migHelloErr, _) = await _ctx.RequireFreshHelloAsync(
                "Zero Trust Vault: Verify to migrate vault", null, normalizedOrigin, request.RequestId);
            if (migHelloErr is not null) return migHelloErr;

            byte[] newRootKeyForMigration = HelloManager.GenerateRootKey();
            try
            {
                byte[] wrappedKey = _ctx.HelloManager.WrapRootKey(newRootKeyForMigration);
                VaultMigration.Migrate(
                    VaultManager.VaultFilePath,
                    Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                    Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
                    wrappedKey);
            }
            finally
            {
                VaultCrypto.SecureClear(newRootKeyForMigration);
            }
            _ctx.SecurityEventLog.LogMigration("Vault migrated to schema v3 during unlock");
        }

        // Windows Hello verification (fresh proof required to unlock)
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Unlock", null, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        VaultFile vault;
        byte[] rootKey;
        bool vaultWasReset = false;

        if (!vaultExists)
        {
            // Create new vault
            byte[] newRootKey = HelloManager.GenerateRootKey();
            byte[] wrapped = _ctx.HelloManager.WrapRootKey(newRootKey);
            vault = _ctx.VaultManager.CreateNew(wrapped);
            rootKey = newRootKey;
            EpochRollbackGuard.Reset(_ctx.VaultManager.VaultDirectory, vault);
        }
        else
        {
            vault = _ctx.VaultManager.Load();

            // ---- Corrupt-vault safety gate -------------------------------------
            // Classify the wrappedRootKey. If it is anything other than Valid, the
            // vault cannot be unwrapped. We NEVER blindly overwrite: quarantine
            // first, then only reset when there is no user data to lose.
            var keyStatus = VaultIntegrity.ClassifyWrappedRootKey(vault.WrappedRootKey);
            if (keyStatus != WrappedKeyStatus.Valid)
            {
                var (recovered, errorResponse) =
                    HandleCorruptVault(request.RequestId, vault, VaultIntegrity.ToReason(keyStatus));
                if (errorResponse is not null) return errorResponse;   // Case B / quarantine failure
                vault = recovered!.Vault;
                rootKey = recovered.RootKey;
                vaultWasReset = true;
            }
            else
            {
                // ---- Structural invariant gate (Section B) ---------------------
                // Catches corruption/tampering that still parses as valid JSON —
                // duplicate ids, broken/missing ciphertext fields, epoch stamps
                // that don't add up — BEFORE we ever unwrap the root key.
                var invariantViolations = VaultInvariants.Check(vault);

                // ---- Anti-rollback gate (Section B) -----------------------------
                // Detects a valid-looking but STALE snapshot substituted for the
                // current vault (e.g. restored from before a device revocation),
                // which would otherwise silently undo that revocation.
                var rollbackCheck = invariantViolations.Count == 0
                    ? EpochRollbackGuard.CheckAndAdvance(_ctx.VaultManager.VaultDirectory, vault)
                    : null;

                if (invariantViolations.Count > 0)
                {
                    DiagnosticLog.Write("VAULT", $"Invariant violation(s) detected: {invariantViolations.Count} (e.g. {invariantViolations[0].Code}).");
                    var (recovered, errorResponse) =
                        HandleCorruptVault(request.RequestId, vault, CorruptReason.InvariantViolation);
                    if (errorResponse is not null) return errorResponse;
                    vault = recovered!.Vault;
                    rootKey = recovered.RootKey;
                    vaultWasReset = true;
                }
                else if (rollbackCheck!.RollbackDetected)
                {
                    DiagnosticLog.Write("VAULT", $"Rollback detected: vault epoch {vault.Epoch} is older than last-seen epoch {rollbackCheck.LastSeenEpoch}.");
                    var (recovered, errorResponse) =
                        HandleCorruptVault(request.RequestId, vault, CorruptReason.RollbackDetected);
                    if (errorResponse is not null) return errorResponse;
                    vault = recovered!.Vault;
                    rootKey = recovered.RootKey;
                    vaultWasReset = true;
                }
                else
                {
                    // Unwrap root key — in production this uses the CNG-stored device wrapping key.
                    try
                    {
                        rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
                    }
                    catch (Exception ex)
                    {
                        // Base64 was valid and long enough, but the device key could not
                        // unwrap it (e.g. wrong/rotated CNG key, bit-rot). Treat as corrupt.
                        DiagnosticLog.Write("VAULT", $"Root key unwrap failed: {ex.GetType().Name}");
                        var (recovered, errorResponse) =
                            HandleCorruptVault(request.RequestId, vault, CorruptReason.RootKeyUnwrapFailed);
                        if (errorResponse is not null) return errorResponse;
                        vault = recovered!.Vault;
                        rootKey = recovered.RootKey;
                        vaultWasReset = true;
                    }
                }
            }
        }

        try
        {
            // Session binds ONLY to the origin — never to key material. This is
            // what makes it safe for listing to reuse the session without
            // re-prompting Hello: the session proves "this origin already
            // completed an unlock," not "here is a live key."
            string sessionId = _ctx.SessionManager.CreateSession(normalizedOrigin);

            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            var accounts = BuildAccountSummaries(vault, rootKey, originHash);

            string presenceMode = await _ctx.HelloManager.GetPresenceAvailabilityAsync();
            _ctx.SecurityEventLog.LogUnlock(sessionId, normalizedOrigin);
            _ctx.EventLogManager.Append(SyncEventType.VaultUnlocked, vault.DeviceId, vault.Epoch, null,
                GetAuditMacKey(rootKey));

            return NativeResponse.Ok(request.RequestId, new
            {
                sessionId,
                accounts,
                presenceMode,
                vaultWasReset,
                notice = vaultWasReset
                    ? "The previous vault file was corrupted and empty. A protected copy was saved to the quarantine folder and a fresh vault was created."
                    : null,
            });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- Corrupt-vault handling -------------------------------------------------

    /// <summary>
    /// Holds a freshly reinitialized vault + its root key for the Case A reset path.
    /// The caller is responsible for zeroizing RootKey once it is done with it.
    /// </summary>
    private sealed record CorruptVaultRecovery(VaultFile Vault, byte[] RootKey);

    /// <summary>
    /// Safely handles a vault whose root key cannot be unwrapped.
    ///
    /// Always quarantines a copy first (never deletes/overwrites the original at
    /// this point). Then:
    ///   * Case A — no user data: reinitialize a fresh vault and return it.
    ///   * Case B — has user data: do NOT reset; return a typed recoverable error
    ///     (RecoveryRequired if a recovery kit exists, otherwise NoRecovery).
    ///   * Quarantine failure: return QuarantineFailed; the vault is left untouched.
    ///
    /// Returns exactly one of (recovery, null) for Case A or (null, errorResponse)
    /// for Case B / quarantine failure.
    /// </summary>
    private (CorruptVaultRecovery? recovery, NativeResponse? error) HandleCorruptVault(
        string requestId, VaultFile loadedVault, CorruptReason reason)
    {
        bool hasData = VaultIntegrity.HasUserData(loadedVault);

        var q = VaultIntegrity.Quarantine(
            VaultManager.VaultFilePath,
            VaultManager.QuarantineDirectory,
            reason,
            loadedVault,
            VaultManager.CodeVersion);

        if (!q.Success)
        {
            // Could not protect a copy — refuse to touch the vault.
            _ctx.SecurityEventLog.LogVaultQuarantined($"{reason}:QUARANTINE_FAILED");
            return (null, NativeResponse.Err(requestId, VaultCorruptCode.QuarantineFailed,
                "Vault file appears corrupted, and a protected copy could NOT be created, so no changes were made. " +
                "Check disk space and folder permissions, then try again. Your data has not been altered."));
        }

        _ctx.SecurityEventLog.LogVaultQuarantined(reason.ToString());

        if (hasData)
        {
            // Case B — never auto-reset a vault that holds user data.
            bool hasRecovery = loadedVault.RecoveryKit is not null;
            if (hasRecovery)
            {
                return (null, NativeResponse.Err(requestId, VaultCorruptCode.RecoveryRequired,
                    "Vault file is corrupted: wrappedRootKey is missing or invalid. " +
                    "A protected copy was created. Use Recovery or restore from backup."));
            }
            return (null, NativeResponse.Err(requestId, VaultCorruptCode.NoRecovery,
                "Vault file is corrupted and no recovery kit exists. A protected copy was saved to the quarantine " +
                "folder — preserve it and restore from a backup. Do NOT delete the quarantined copy."));
        }

        // Case A — empty/corrupt with no user data: safe to reinitialize.
        byte[] newRootKey = HelloManager.GenerateRootKey();
        byte[] wrapped = _ctx.HelloManager.WrapRootKey(newRootKey);
        var freshVault = _ctx.VaultManager.CreateNew(wrapped);
        EpochRollbackGuard.Reset(_ctx.VaultManager.VaultDirectory, freshVault); // new vault id — start fresh tracking
        _ctx.SecurityEventLog.LogVaultReset("Corrupt empty vault reinitialized after quarantine.");
        return (new CorruptVaultRecovery(freshVault, newRootKey), null);
    }

    // ---- listSummariesForOrigin ----
    // Low-risk tier: valid session only, NO fresh Hello required (the initial
    // unlock's Hello proof already covers "may see which accounts exist for
    // this origin"). Root key is still unwrapped fresh and zeroized — never
    // cached — for the single call.

    public async Task<NativeResponse> ListCredentialSummariesAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out var sessionProof);
        if (sessionErr is not null) return sessionErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, sessionProof!);
        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            var accounts = BuildAccountSummaries(vault, rootKey, originHash);

            await Task.CompletedTask;
            return NativeResponse.Ok(request.RequestId, new { accounts });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- decryptSelectedCredentialForExactOrigin (reveal) ----
    // High-risk tier: valid session AND a FRESH Hello proof required.

    public Task<NativeResponse> DecryptCredentialAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct) =>
        DecryptCredentialCoreAsync(
            request, normalizedOrigin,
            requireFillContext: false,
            helloPrompt: "Zero Trust Vault: Reveal password",
            rateLimitLabel: "decryptSelectedCredentialForExactOrigin",
            ct);

    // ---- fillCredentialForExactOrigin (autofill) ----
    // High-risk tier, same as reveal, PLUS a mandatory tab/window binding
    // check enforced by the native host itself (Section P). Previously
    // autofill reused the generic reveal command, which never validated
    // request.TabId/WindowId even though the wire protocol carries them —
    // the ONLY enforcement of "this fill belongs to this browser tab" lived
    // in extension JS, which a compromised/buggy service worker could skip
    // by simply not attaching a tab object to the native call. This command
    // is the one the extension's autofill path must use; the plain reveal
    // command above stays reserved for a future explicit "show password"
    // affordance and does not require tab context.

    public Task<NativeResponse> FillCredentialAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct) =>
        DecryptCredentialCoreAsync(
            request, normalizedOrigin,
            requireFillContext: true,
            helloPrompt: "Zero Trust Vault: Fill password",
            rateLimitLabel: "fillCredentialForExactOrigin",
            ct);

    private async Task<NativeResponse> DecryptCredentialCoreAsync(
        NativeRequest request, string? normalizedOrigin,
        bool requireFillContext, string helloPrompt, string rateLimitLabel, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string?[] allowed = { "credentialId" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed!);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        if (!CommandRouter.TryGetString(request.Payload, "credentialId", out string credentialId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "credentialId is required.");

        if (requireFillContext && (request.TabId is null || request.WindowId is null))
            return NativeResponse.Err(request.RequestId, "FILL_CONTEXT_REQUIRED",
                "Fill requires a bound browser tab and window.");

        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        // Rate limit secret reveals
        var rateLimit = _ctx.RateLimiter.CheckSecretReveal(request.SessionId!);
        if (rateLimit is not null)
        {
            _ctx.SecurityEventLog.LogRateLimited(request.SessionId, rateLimitLabel);
            return new NativeResponse
            {
                RequestId = request.RequestId,
                Status = "error",
                Error = new NativeMessaging.NativeError
                {
                    Code = rateLimit.Code,
                    SafeMessage = rateLimit.SafeMessage,
                    RetryAfterSeconds = rateLimit.RetryAfterSeconds,
                }
            };
        }

        // Fresh Windows Hello required
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            helloPrompt, request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == credentialId && !i.Deleted);
        if (item is null)
            return NativeResponse.Err(request.RequestId, "NOT_FOUND", "Credential not found.");

        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        try
        {
            // Verify origin hash matches
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            if (Convert.ToBase64String(originHash) != item.OriginHash)
                return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", "Credential does not belong to this origin.");

            var payload = DecryptItemPayload(rootKey, vault, item);

            _ctx.RateLimiter.RecordSecretReveal(request.SessionId!);
            _ctx.SecurityEventLog.LogCredentialRevealed(request.SessionId!, normalizedOrigin, credentialId);

            return NativeResponse.Ok(request.RequestId, new
            {
                usernameOrEmail = payload.UsernameOrEmail,
                password = payload.Password,
            });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- addCredentialForExactOrigin ----
    // High-risk tier: fresh Hello required.

    public async Task<NativeResponse> AddCredentialAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string[] allowed = { "usernameOrEmail", "password", "totpSecret", "label", "displayLabel", "notes", "origin" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        string? originErr = ValidatePayloadOriginIfPresent(request.Payload, normalizedOrigin);
        if (originErr is not null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", originErr);

        if (!CommandRouter.TryGetString(request.Payload, "usernameOrEmail", out string username))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "usernameOrEmail is required.");

        if (!CommandRouter.TryGetString(request.Payload, "password", out string password))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "password is required.");

        CommandRouter.TryGetString(request.Payload, "label", out string label);
        if (string.IsNullOrEmpty(label))
            CommandRouter.TryGetString(request.Payload, "displayLabel", out label);
        CommandRouter.TryGetString(request.Payload, "totpSecret", out string totpSecret);
        CommandRouter.TryGetString(request.Payload, "notes", out string notes);

        // Fresh Hello required
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Add credential", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        VaultFile vault;
        byte[] rootKey;

        if (!_ctx.VaultManager.VaultExists())
        {
            // Create vault on first add
            byte[] newKey = HelloManager.GenerateRootKey();
            byte[] wrapped = _ctx.HelloManager.WrapRootKey(newKey);
            vault = _ctx.VaultManager.CreateNew(wrapped);
            rootKey = newKey;
        }
        else
        {
            vault = _ctx.VaultManager.GetOrLoad();
            rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        }

        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            string itemId = Guid.NewGuid().ToString("D");

            var itemPayload = new VaultPayload
            {
                UsernameOrEmail = username,
                Password = password,
                TotpSecret = totpSecret,
                Label = string.IsNullOrEmpty(label) ? username : label,
                Notes = notes,
            };
            var itemMetadata = new VaultMetadata
            {
                Origin = normalizedOrigin,
                CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
                UpdatedAt = DateTimeOffset.UtcNow.ToString("O"),
            };

            var encryptedPayload = EncryptItemPayload(rootKey, vault, itemId, originHash, itemPayload);
            var encryptedMetadata = EncryptItemMetadata(rootKey, vault, itemId, originHash, itemMetadata);

            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var item = new VaultItemV3
            {
                ItemId = itemId,
                OriginHash = Convert.ToBase64String(originHash),
                EncryptedPayload = encryptedPayload,
                EncryptedMetadata = encryptedMetadata,
                CreatedByDeviceId = vault.DeviceId,
                CreatedAtLogical = now,
                UpdatedAtLogical = now,
                Deleted = false,
                Version = 1,
                Epoch = vault.Epoch,
            };

            _ctx.VaultManager.UpsertItem(item);

            // Session binds to origin only — never to key material. Reuse the
            // caller's session only if it actually validates (exists, right
            // origin, not expired) for this origin; otherwise mint a new one
            // (e.g. first-ever add with no prior unlock call, or a stale/
            // cross-origin session id the caller happened to still be holding).
            bool callerSessionValid =
                _ctx.SessionManager.Validate(request.SessionId, normalizedOrigin) == SessionValidationResult.Valid;
            string sessionId = callerSessionValid ? request.SessionId! : _ctx.SessionManager.CreateSession(normalizedOrigin);

            string presenceMode = await _ctx.HelloManager.GetPresenceAvailabilityAsync();
            _ctx.SecurityEventLog.LogCredentialAdded(sessionId, normalizedOrigin, itemId);
            _ctx.EventLogManager.Append(SyncEventType.CredentialAdded, vault.DeviceId, vault.Epoch, itemId,
                GetAuditMacKey(rootKey));

            return NativeResponse.Ok(request.RequestId, new
            {
                sessionId,
                presenceMode,
            });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- deleteCredential (legacy v1) ----
    // High-risk tier: fresh Hello required (deletion is destructive and, per
    // the hardening brief, must not be gated by session validity alone).

    public async Task<NativeResponse> DeleteCredentialAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string[] allowed = { "credentialId" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        if (!CommandRouter.TryGetString(request.Payload, "credentialId", out string credentialId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "credentialId is required.");

        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        // Fresh Hello required for deletion
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Delete credential", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == credentialId && !i.Deleted);
        if (item is null)
            return NativeResponse.Err(request.RequestId, "NOT_FOUND", "Credential not found.");

        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            if (Convert.ToBase64String(originHash) != item.OriginHash)
                return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", "Credential does not belong to this origin.");

            item.Deleted = true;
            item.UpdatedAtLogical = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _ctx.VaultManager.Save(vault);

            _ctx.SecurityEventLog.LogCredentialDeleted(request.SessionId!, normalizedOrigin, credentialId);
            _ctx.EventLogManager.Append(SyncEventType.CredentialDeleted, vault.DeviceId, vault.Epoch, credentialId,
                GetAuditMacKey(rootKey));

            await Task.CompletedTask;
            return NativeResponse.Ok(request.RequestId, new { });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- lockOriginSession ----

    public async Task<NativeResponse> LockVaultAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // No session-level root key store to clear anymore — sessions never
        // held key material. Clearing sessions still revokes origin binding
        // immediately.
        _ctx.SessionManager.ClearAll();
        _ctx.VaultManager.Invalidate();

        _ctx.SecurityEventLog.LogLock(request.SessionId);
        _ctx.EventLogManager.Append(SyncEventType.VaultLocked, "unknown", 0, null, null);

        await Task.CompletedTask;
        return NativeResponse.Ok(request.RequestId, new { });
    }

    // ---- countCredentialsForOrigin ----
    // Low-risk tier: valid session only.

    public async Task<NativeResponse> CountCredentialsAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // countCredentials does NOT require a session (it's safe metadata)
        if (!_ctx.VaultManager.VaultExists())
        {
            await Task.CompletedTask;
            return NativeResponse.Ok(request.RequestId, new { count = 0, privateMetadata = true });
        }

        // We need a root key to compute origin hash — require session
        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out var sessionProof);
        if (sessionErr is not null) return sessionErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, sessionProof!);
        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            int count = VaultManager.GetItemsForOrigin(vault, originHash).Count();

            await Task.CompletedTask;
            return NativeResponse.Ok(request.RequestId, new { count, privateMetadata = true });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- updateCredentialAtomic (v2) ----
    // High-risk tier: fresh Hello required.

    public async Task<NativeResponse> UpdateCredentialAtomicAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string[] allowed = { "credentialId", "usernameOrEmail", "password", "totpSecret", "label", "displayLabel", "notes", "origin" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        string? originErr = ValidatePayloadOriginIfPresent(request.Payload, normalizedOrigin);
        if (originErr is not null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", originErr);

        if (!CommandRouter.TryGetString(request.Payload, "credentialId", out string credentialId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "credentialId is required.");

        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        // Fresh Hello required
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Update credential", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == credentialId && !i.Deleted);
        if (item is null)
            return NativeResponse.Err(request.RequestId, "NOT_FOUND", "Credential not found.");

        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            if (Convert.ToBase64String(originHash) != item.OriginHash)
                return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", "Credential does not belong to this origin.");

            // Decrypt current payload to merge
            var current = DecryptItemPayload(rootKey, vault, item);

            CommandRouter.TryGetString(request.Payload, "usernameOrEmail", out string newUser);
            CommandRouter.TryGetString(request.Payload, "password", out string newPass);
            CommandRouter.TryGetString(request.Payload, "totpSecret", out string newTotp);
            CommandRouter.TryGetString(request.Payload, "label", out string newLabel);
            if (string.IsNullOrEmpty(newLabel))
                CommandRouter.TryGetString(request.Payload, "displayLabel", out newLabel);
            CommandRouter.TryGetString(request.Payload, "notes", out string newNotes);

            var updated = new VaultPayload
            {
                UsernameOrEmail = string.IsNullOrEmpty(newUser) ? current.UsernameOrEmail : newUser,
                Password = string.IsNullOrEmpty(newPass) ? current.Password : newPass,
                TotpSecret = string.IsNullOrEmpty(newTotp) ? current.TotpSecret : newTotp,
                Label = string.IsNullOrEmpty(newLabel) ? current.Label : newLabel,
                Notes = string.IsNullOrEmpty(newNotes) ? current.Notes : newNotes,
            };

            item.EncryptedPayload = EncryptItemPayload(rootKey, vault, credentialId, originHash, updated);
            item.UpdatedAtLogical = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            item.Version++;

            _ctx.VaultManager.UpsertItem(item);
            _ctx.EventLogManager.Append(SyncEventType.CredentialUpdated, vault.DeviceId, vault.Epoch, credentialId,
                GetAuditMacKey(rootKey));

            var accounts = BuildAccountSummaries(vault, rootKey, originHash);
            return NativeResponse.Ok(request.RequestId, new
            {
                sessionId = request.SessionId,
                accounts,
            });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- deleteCredentialTombstone (v2) ----
    // High-risk tier: fresh Hello required (same rationale as legacy delete).

    public async Task<NativeResponse> DeleteCredentialTombstoneAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string[] allowed = { "credentialId" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        if (!CommandRouter.TryGetString(request.Payload, "credentialId", out string credentialId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "credentialId is required.");

        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        // Fresh Hello required for deletion
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Delete credential", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == credentialId);
        if (item is null)
            return NativeResponse.Err(request.RequestId, "NOT_FOUND", "Credential not found.");

        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            if (Convert.ToBase64String(originHash) != item.OriginHash)
                return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", "Credential does not belong to this origin.");

            item.Deleted = true;
            item.UpdatedAtLogical = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _ctx.VaultManager.Save(vault);

            _ctx.EventLogManager.Append(SyncEventType.CredentialTombstoned, vault.DeviceId, vault.Epoch, credentialId,
                GetAuditMacKey(rootKey));

            await Task.CompletedTask;
            return NativeResponse.Ok(request.RequestId, new { });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- Internal helpers ----

    private static object[] BuildAccountSummaries(VaultFile vault, byte[] rootKey, byte[] originHash)
    {
        string hashB64 = Convert.ToBase64String(originHash);
        var items = vault.Items.Where(i => !i.Deleted && i.OriginHash == hashB64);
        var result = new List<object>();
        foreach (var item in items)
        {
            try
            {
                var payload = DecryptItemPayloadStatic(rootKey, vault, item);
                result.Add(new
                {
                    credentialId = item.ItemId,
                    usernameOrEmail = payload.UsernameOrEmail,
                    label = payload.Label,
                });
            }
            catch
            {
                // Skip items that can't be decrypted
            }
        }
        return result.ToArray();
    }

    private static VaultPayload DecryptItemPayload(byte[] rootKey, VaultFile vault, VaultItemV3 item)
        => DecryptItemPayloadStatic(rootKey, vault, item);

    private static VaultPayload DecryptItemPayloadStatic(byte[] rootKey, VaultFile vault, VaultItemV3 item)
    {
        byte[] payloadKey = SubkeyDerivation.DeriveItemEncryptionKey(rootKey);
        byte[] vaultIdBytes = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(item.ItemId);
        byte[] originHashBytes = Convert.FromBase64String(item.OriginHash);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultIdBytes, itemIdBytes, originHashBytes, item.Epoch, "ItemEncryptionKey");

        var result = VaultCrypto.DecryptJson<VaultPayload>(payloadKey, item.EncryptedPayload, aad);
        VaultCrypto.SecureClear(payloadKey);
        return result;
    }

    private static EncryptedBlob EncryptItemPayload(byte[] rootKey, VaultFile vault, string itemId, byte[] originHash, VaultPayload payload)
    {
        byte[] payloadKey = SubkeyDerivation.DeriveItemEncryptionKey(rootKey);
        byte[] vaultIdBytes = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(itemId);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultIdBytes, itemIdBytes, originHash, vault.Epoch, "ItemEncryptionKey");

        var result = VaultCrypto.EncryptJson(payloadKey, payload, aad);
        VaultCrypto.SecureClear(payloadKey);
        return result;
    }

    private static EncryptedBlob EncryptItemMetadata(byte[] rootKey, VaultFile vault, string itemId, byte[] originHash, VaultMetadata metadata)
    {
        byte[] metaKey = SubkeyDerivation.DeriveMetadataEncryptionKey(rootKey);
        byte[] vaultIdBytes = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(itemId);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultIdBytes, itemIdBytes, originHash, vault.Epoch, "MetadataEncryptionKey");

        var result = VaultCrypto.EncryptJson(metaKey, metadata, aad);
        VaultCrypto.SecureClear(metaKey);
        return result;
    }

    private static byte[]? GetAuditMacKey(byte[] rootKey)
    {
        try { return SubkeyDerivation.DeriveAuditLogMacKey(rootKey); }
        catch { return null; }
    }

    private static string? ValidatePayloadOriginIfPresent(JsonElement payload, string normalizedOrigin)
    {
        if (payload.ValueKind != JsonValueKind.Object)
            return null;
        if (!payload.TryGetProperty("origin", out var originProp) || originProp.ValueKind != JsonValueKind.String)
            return null;

        var payloadOrigin = originProp.GetString();
        if (string.IsNullOrWhiteSpace(payloadOrigin))
            return null;

        try
        {
            string normalizedPayloadOrigin = OriginValidator.ValidateAndNormalize(payloadOrigin);
            return OriginValidator.ExactMatch(normalizedPayloadOrigin, normalizedOrigin)
                ? null
                : "Payload origin does not match the verified request origin.";
        }
        catch (ArgumentException)
        {
            return "Payload origin is invalid.";
        }
    }
}
