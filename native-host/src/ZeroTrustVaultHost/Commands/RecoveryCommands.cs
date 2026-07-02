using System.Security.Cryptography;
using System.Text.Json;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Handles createRecoveryKit and recoverVault commands.
/// createRecoveryKit: splits VaultRootKey into 5 Shamir shares (3-of-5 threshold).
/// recoverVault: reconstructs VaultRootKey from 3+ shares, creates new device key.
/// </summary>
public sealed class RecoveryCommands
{
    private readonly CommandContext _ctx;

    private const int ShareCount = 5;
    private const int Threshold = 3;

    public RecoveryCommands(CommandContext ctx) => _ctx = ctx;

    // ---- createRecoveryKit ----

    public async Task<NativeResponse> CreateRecoveryKitAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // Fresh Hello required
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Create Recovery Kit", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        if (!_ctx.VaultManager.VaultExists())
            return NativeResponse.Err(request.RequestId, "VAULT_NOT_FOUND", "No vault exists to create a recovery kit for.");

        var vault = _ctx.VaultManager.GetOrLoad();

        // Recovery model: split the VaultRootKey itself. Shares are the disaster
        // recovery factor; Windows Hello is still required to create a new device wrap.
        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        byte[] secretToSplit = (byte[])rootKey.Clone();

        // Split into 5 shares, 3-of-5 threshold
        var rawShares = ShamirSecretSharing.Split(secretToSplit, Threshold, ShareCount);

        // Encode shares as base64 strings with index prefix
        var shareStrings = rawShares.Select(s =>
            Convert.ToBase64String(new byte[] { (byte)s.Index }.Concat(s.Value).ToArray())
        ).ToArray();

        // Store kit metadata (NOT the shares) in vault
        using var hmac = new HMACSHA256(rootKey);
        string verificationHmac = Convert.ToBase64String(hmac.ComputeHash(secretToSplit));

        vault.RecoveryKit = new RecoveryKitEntry
        {
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            ShareCount = ShareCount,
            Threshold = Threshold,
            VerificationHmac = verificationHmac,
        };
        _ctx.VaultManager.Save(vault);

        VaultCrypto.SecureClear(rootKey);
        VaultCrypto.SecureClear(secretToSplit);

        _ctx.EventLogManager.Append(Sync.SyncEventType.RecoveryKitCreated, vault.DeviceId, vault.Epoch, null, null);

        return NativeResponse.Ok(request.RequestId, new
        {
            shares = shareStrings,
            shareCount = ShareCount,
            threshold = Threshold,
        });
    }

    // ---- recoverVault ----

    public async Task<NativeResponse> RecoverVaultAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string[] allowed = { "shares", "threeShares" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // Parse shares array
        if (!request.Payload.TryGetProperty("shares", out var sharesElement))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "shares array is required.");

        if (sharesElement.ValueKind != JsonValueKind.Array)
            return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "shares must be an array.");

        var shareStrings = new List<string>();
        foreach (var el in sharesElement.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.String)
                return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "Each share must be a string.");
            string? s = el.GetString();
            if (!string.IsNullOrEmpty(s)) shareStrings.Add(s);
        }

        if (shareStrings.Count < Threshold)
            return NativeResponse.Err(request.RequestId, "INSUFFICIENT_SHARES",
                $"At least {Threshold} shares are required for recovery.");

        // Decode shares: each is index(1 byte) || share bytes
        (int Index, byte[] Value)[] shares;
        try
        {
            shares = shareStrings.Select(s =>
            {
                byte[] data = Convert.FromBase64String(s);
                if (data.Length < 2) throw new ArgumentException("Share too short.");
                int index = data[0];
                byte[] value = data[1..];
                return (index, value);
            }).ToArray();
        }
        catch (Exception ex)
        {
            return NativeResponse.Err(request.RequestId, "INVALID_SHARES", $"Could not decode shares: {ex.Message}");
        }

        // Reconstruct the RecoveryRootSecret
        byte[] reconstructed;
        try
        {
            reconstructed = ShamirSecretSharing.Combine(shares);
        }
        catch (Exception ex)
        {
            return NativeResponse.Err(request.RequestId, "RECOVERY_FAILED", $"Share combination failed: {ex.Message}");
        }

        // Verify against stored HMAC (requires vault to exist)
        if (_ctx.VaultManager.VaultExists())
        {
            var vault = _ctx.VaultManager.GetOrLoad();
            if (vault.RecoveryKit is not null)
            {
                using var hmac = new HMACSHA256(reconstructed);
                byte[] actual = hmac.ComputeHash(reconstructed);
                byte[] expected = Convert.FromBase64String(vault.RecoveryKit.VerificationHmac);
                if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
                {
                    VaultCrypto.SecureClear(reconstructed);
                    return NativeResponse.Err(request.RequestId, "RECOVERY_FAILED", "Recovery shares do not match this vault.");
                }
            }

            var (helloErr, _) = await _ctx.RequireFreshHelloAsync(
                "Zero Trust Vault: Recover vault", request.SessionId, normalizedOrigin, request.RequestId);
            if (helloErr is not null)
            {
                VaultCrypto.SecureClear(reconstructed);
                return helloErr;
            }

            // ---- Rotate root again after reconstruction (Section I) ------------
            // `reconstructed` IS the vault's OLD root key — reusing it directly
            // would mean the very shares that were just consumed (and any copy
            // of them an attacker might also hold) stay valid forever, and any
            // previously-revoked device that still holds a wrap of that same
            // old root would regain access. Recovery must behave like a full
            // device-revocation event: generate a brand-new root, re-encrypt
            // every item under it, and treat every other device as untrusted
            // until it re-pairs.
            byte[] newRoot = HelloManager.GenerateRootKey();
            byte[] newDeviceId = RandomNumberGenerator.GetBytes(32);
            try
            {
                int newEpoch;
                try
                {
                    // If these shares are stale (reconstructing an OLD root from
                    // before an earlier recovery/rotation already replaced it),
                    // every item's AEAD tag will fail to authenticate here — the
                    // vault's actual ciphertext no longer matches what these
                    // shares decode to. That failure IS the "old epoch shares
                    // fail" guarantee; surface it as a clean error, not a crash.
                    newEpoch = VaultRekey.RotateRoot(vault, reconstructed, newRoot);
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    return NativeResponse.Err(request.RequestId, "RECOVERY_FAILED",
                        "Recovery shares do not match the current vault (they may be from before a previous recovery or device change).");
                }

                byte[] newWrappedKey = _ctx.HelloManager.WrapRootKey(newRoot);
                vault.DeviceId = Convert.ToBase64String(newDeviceId);
                vault.WrappedRootKey = Convert.ToBase64String(newWrappedKey);

                // Every previously-paired device only ever held a wrap of the OLD
                // root; strip them explicitly so the vault's device list reflects
                // reality and none can be mistaken for still-trusted.
                foreach (var d in vault.Devices)
                {
                    d.Status = "Removed";
                    d.WrappedEpochKey = string.Empty;
                    d.DeviceEpoch = newEpoch;
                }

                // The recovery kit's shares encode the OLD root and can never
                // reconstruct anything useful again; force a new kit.
                vault.RecoveryKit = null;

                _ctx.VaultManager.Save(vault);
                Vault.EpochRollbackGuard.CheckAndAdvance(_ctx.VaultManager.VaultDirectory, vault);

                _ctx.EventLogManager.Append(Sync.SyncEventType.VaultRecovered, vault.DeviceId, vault.Epoch, null, null);
                _ctx.EventLogManager.Append(Sync.SyncEventType.EpochRotated, vault.DeviceId, vault.Epoch, null, null);
            }
            finally
            {
                VaultCrypto.SecureClear(reconstructed);
                VaultCrypto.SecureClear(newRoot);
            }
        }
        else
        {
            VaultCrypto.SecureClear(reconstructed);
            return NativeResponse.Err(request.RequestId, "VAULT_NOT_FOUND", "No vault to recover.");
        }

        await Task.CompletedTask;
        return NativeResponse.Ok(request.RequestId, new
        {
            ok = true,
            rootRotated = true,
            recoveryKitInvalidated = true,
            notice = "Recovery rotated the vault's root key: all previously-paired devices were removed and must re-pair, " +
                     "and this recovery kit is now invalid — create a new one.",
        });
    }
}
