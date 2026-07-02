using System.Security.Cryptography;
using System.Text;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Handles device pairing and removal commands:
/// beginDevicePairing, approveDevicePairing, removeDevice.
/// </summary>
public sealed class DeviceCommands
{
    private readonly CommandContext _ctx;

    // In-memory pending pairing store (pairingId -> PairingCode)
    private readonly Dictionary<string, string> _pendingPairings = new();
    private readonly object _pairingLock = new();

    /// <summary>A pairing code/SAS session not approved within this window can no longer be used (Section G).</summary>
    private static readonly TimeSpan PairingExpiry = TimeSpan.FromMinutes(10);

    public DeviceCommands(CommandContext ctx) => _ctx = ctx;

    // ---- beginDevicePairing ----

    public async Task<NativeResponse> BeginDevicePairingAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // Fresh Hello required
        var (helloErr, _) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Begin Device Pairing", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        string pairingId = Guid.NewGuid().ToString("D");
        string pairingCode = GeneratePairingCode(); // e.g. "ABCD-1234"

        lock (_pairingLock)
            _pendingPairings[pairingId] = pairingCode;

        // Also store in vault
        if (_ctx.VaultManager.VaultExists())
        {
            var vault = _ctx.VaultManager.GetOrLoad();
            vault.PendingPairings.Add(new PendingPairing
            {
                PairingId = pairingId,
                PairingCode = pairingCode,
                InitiatedAt = DateTimeOffset.UtcNow.ToString("O"),
                Approved = false,
            });
            _ctx.VaultManager.Save(vault);
        }

        return NativeResponse.Ok(request.RequestId, new
        {
            pairingCode,
            pairingId,
        });
    }

    // ---- approveDevicePairing ----

    public async Task<NativeResponse> ApproveDevicePairingAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string[] allowed =
        {
            "pairingId", "pairingCode", "deviceName",
            "newDevicePublicSigningKey", "newDevicePublicEncryptionKey",
            "pairingNonce", "pairingSessionId", "sas"
        };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        if (!CommandRouter.TryGetString(request.Payload, "pairingId", out string pairingId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "pairingId is required.");

        CommandRouter.TryGetString(request.Payload, "pairingCode", out string providedCode);
        CommandRouter.TryGetString(request.Payload, "deviceName", out string deviceName);
        if (!CommandRouter.TryGetString(request.Payload, "newDevicePublicSigningKey", out string publicSigningKeyB64))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "newDevicePublicSigningKey is required.");
        if (!CommandRouter.TryGetString(request.Payload, "newDevicePublicEncryptionKey", out string publicEncryptionKeyB64))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "newDevicePublicEncryptionKey is required.");

        // Fresh Hello required
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Approve Device Pairing", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        // Pairing sessions are single-use and time-limited (Section G: replayed
        // pairing must be rejected). The vault's PendingPairings list is
        // authoritative — it survives a host restart, unlike the in-memory
        // dictionary, so it is the only place we check Approved/expiry state.
        if (!_ctx.VaultManager.VaultExists())
            return NativeResponse.Err(request.RequestId, "VAULT_NOT_FOUND", "No vault exists.");

        var vault = _ctx.VaultManager.GetOrLoad();
        var pending = vault.PendingPairings.FirstOrDefault(p => p.PairingId == pairingId);

        if (pending is null)
            return NativeResponse.Err(request.RequestId, "PAIRING_NOT_FOUND", "Pairing session not found.");

        if (pending.Approved)
            return NativeResponse.Err(request.RequestId, "PAIRING_ALREADY_USED",
                "This pairing session has already been used and cannot be replayed.");

        if (DateTimeOffset.TryParse(pending.InitiatedAt, out var initiatedAt)
            && DateTimeOffset.UtcNow - initiatedAt > PairingExpiry)
        {
            vault.PendingPairings.Remove(pending);
            _ctx.VaultManager.Save(vault);
            return NativeResponse.Err(request.RequestId, "PAIRING_EXPIRED", "Pairing session has expired. Start a new pairing.");
        }

        if (!string.Equals(providedCode, pending.PairingCode, StringComparison.Ordinal))
            return NativeResponse.Err(request.RequestId, "PAIRING_CODE_MISMATCH", "Pairing code does not match.");

        byte[] publicSigningKey;
        byte[] publicEncryptionKey;
        try
        {
            publicSigningKey = Convert.FromBase64String(publicSigningKeyB64);
            publicEncryptionKey = Convert.FromBase64String(publicEncryptionKeyB64);
        }
        catch
        {
            return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "Device public keys must be base64.");
        }

        // --- SAS verification (defeats a MITM on the pairing channel) ---
        // The user confirms that the 6-digit code shown on both devices
        // matches; the extension forwards that confirmed code. The host
        // independently recomputes the SAS over the EXACT key material it
        // is about to wrap to and rejects if it disagrees, binding the
        // human confirmation to the real keys. A relay that swapped keys
        // produces a different code and fails here.
        CommandRouter.TryGetString(request.Payload, "pairingSessionId", out string pairingSessionId);
        CommandRouter.TryGetString(request.Payload, "pairingNonce", out string pairingNonceB64);
        CommandRouter.TryGetString(request.Payload, "sas", out string providedSas);

        if (string.IsNullOrWhiteSpace(pairingSessionId) ||
            string.IsNullOrWhiteSpace(pairingNonceB64) ||
            string.IsNullOrWhiteSpace(providedSas))
            return NativeResponse.Err(request.RequestId, "SAS_REQUIRED",
                "pairingSessionId, pairingNonce, and sas are required to verify the device.");

        byte[] pairingNonce;
        try { pairingNonce = Convert.FromBase64String(pairingNonceB64); }
        catch { return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "pairingNonce must be base64."); }
        if (pairingNonce.Length < 16)
            return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "pairingNonce must be at least 16 bytes.");

        string expectedSas;
        try
        {
            expectedSas = DeviceIdentity.ComputeSas(
                pairingSessionId, publicSigningKey, publicEncryptionKey, pairingNonce);
        }
        catch
        {
            return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "Could not compute SAS from the supplied pairing inputs.");
        }

        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(providedSas.Trim()),
                System.Text.Encoding.ASCII.GetBytes(expectedSas)))
            return NativeResponse.Err(request.RequestId, "SAS_MISMATCH",
                "Short Authentication String does not match. Pairing rejected (possible interception).");

        string newDeviceId = DeviceIdentity.ComputeDeviceId(publicSigningKey);
        if (vault.Devices.Any(d => d.DeviceId == newDeviceId && d.Status != "Removed"))
            return NativeResponse.Err(request.RequestId, "DEVICE_ALREADY_EXISTS", "Device is already enrolled.");

        byte[] rootKey = Array.Empty<byte>();
        byte[] wrappedForNewDevice;
        try
        {
            rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicEncryptionKey, out _);
            wrappedForNewDevice = rsa.Encrypt(rootKey, RSAEncryptionPadding.OaepSHA256);
        }
        catch
        {
            return NativeResponse.Err(request.RequestId, "KEY_WRAP_FAILED", "Could not wrap vault key to the new device public key.");
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }

        string now = DateTimeOffset.UtcNow.ToString("O");
        vault.Devices.Add(new VaultDevice
        {
            DeviceId = newDeviceId,
            Name = string.IsNullOrWhiteSpace(deviceName) ? $"Paired Device {vault.Devices.Count + 1}" : deviceName,
            CreatedAt = now,
            AddedAt = now,
            LastSeenAt = now,
            Status = "Active",
            DeviceEpoch = vault.Epoch,
            Permissions = new() { "CredentialReadWrite" },
            DeviceSigningPublicKey = publicSigningKeyB64,
            DeviceEncryptionPublicKey = publicEncryptionKeyB64,
            WrappedEpochKey = Convert.ToBase64String(wrappedForNewDevice),
            PublicKeyBlob = publicSigningKeyB64,
        });

        // Single-use: remove the pending pairing entirely rather than leaving
        // an Approved=true record behind — nothing for a replay to find.
        vault.PendingPairings.Remove(pending);

        _ctx.VaultManager.Save(vault);
        _ctx.EventLogManager.Append(SyncEventType.DeviceAdded, vault.DeviceId, vault.Epoch, newDeviceId, null);

        lock (_pairingLock)
            _pendingPairings.Remove(pairingId);

        return NativeResponse.Ok(request.RequestId, new { ok = true });
    }

    // ---- removeDevice ----

    public async Task<NativeResponse> RemoveDeviceAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string[] allowed = { "deviceId" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        if (!CommandRouter.TryGetString(request.Payload, "deviceId", out string deviceId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "deviceId is required.");

        // Fresh Hello required
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Remove Device", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        if (!_ctx.VaultManager.VaultExists())
            return NativeResponse.Err(request.RequestId, "VAULT_NOT_FOUND", "No vault exists.");

        var vault = _ctx.VaultManager.GetOrLoad();
        var device = vault.Devices.FirstOrDefault(d => d.DeviceId == deviceId);
        if (device is null)
            return NativeResponse.Err(request.RequestId, "DEVICE_NOT_FOUND", "Device not found.");

        // Credential IDs that may need password rotation (captured before re-key).
        var rotateList = vault.Items
            .Where(i => !i.Deleted && i.CreatedByDeviceId == deviceId)
            .Select(i => i.ItemId)
            .ToArray();

        device.Status = "Removed";
        device.LastSeenAt = DateTimeOffset.UtcNow.ToString("O");

        // --- Cryptographic epoch rotation -------------------------------------
        // Generate a fresh VaultRootKey, re-encrypt every item under it, and
        // re-wrap the new root ONLY to the local device (CNG/TPM) and the
        // remaining active devices. The removed device only ever held a wrap of
        // the OLD root, so after this it can no longer decrypt the vault. Fail
        // closed: we only persist after a fully successful re-key; on any failure
        // we discard the in-memory mutation and fall back to administrative
        // removal so the vault on disk is never left half-rotated.
        bool epochRotated = false;
        bool recoveryKitInvalidated = false;
        byte[] oldRoot = Array.Empty<byte>();
        byte[] newRoot = Array.Empty<byte>();
        try
        {
            oldRoot = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
            newRoot = HelloManager.GenerateRootKey();

            int newEpoch = VaultRekey.RotateRoot(vault, oldRoot, newRoot);

            // Re-wrap the new root to the local device via CNG/TPM.
            vault.WrappedRootKey = Convert.ToBase64String(_ctx.HelloManager.WrapRootKey(newRoot));

            // Re-wrap to every remaining active device; strip the removed/inactive ones.
            foreach (var d in vault.Devices)
            {
                bool isRemovedOrInactive = ReferenceEquals(d, device)
                    || !string.Equals(d.Status, "Active", StringComparison.Ordinal);
                if (isRemovedOrInactive)
                {
                    d.WrappedEpochKey = string.Empty; // removed device loses its wrap
                    continue;
                }
                if (string.IsNullOrWhiteSpace(d.DeviceEncryptionPublicKey)) continue;
                try
                {
                    using var rsa = RSA.Create();
                    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(d.DeviceEncryptionPublicKey), out _);
                    d.WrappedEpochKey = Convert.ToBase64String(rsa.Encrypt(newRoot, RSAEncryptionPadding.OaepSHA256));
                    d.DeviceEpoch = newEpoch;
                }
                catch
                {
                    // A device with an unusable encryption key is left without a
                    // wrap; it must re-pair to regain access. Never abort the whole
                    // revocation because one stale device key cannot be re-wrapped.
                    d.WrappedEpochKey = string.Empty;
                }
            }

            device.DeviceEpoch = newEpoch;

            // The recovery kit's Shamir shares encode the OLD root and would no
            // longer reconstruct a usable key. Invalidate it honestly; the user
            // must create a new recovery kit after rotation.
            if (vault.RecoveryKit is not null)
            {
                vault.RecoveryKit = null;
                recoveryKitInvalidated = true;
            }

            _ctx.VaultManager.Save(vault);
            epochRotated = true;
            // Keep anti-rollback tracking current immediately, not just at the
            // next unlock — narrows the window where a substituted pre-rotation
            // snapshot would go undetected until the next unlock cycle.
            Vault.EpochRollbackGuard.CheckAndAdvance(_ctx.VaultManager.VaultDirectory, vault);

            _ctx.EventLogManager.Append(SyncEventType.DeviceRemoved, vault.DeviceId, vault.Epoch, deviceId, null);
            _ctx.EventLogManager.Append(SyncEventType.EpochRotated, vault.DeviceId, vault.Epoch, deviceId, null);
        }
        catch
        {
            // Discard the partially-rotated in-memory vault; disk is untouched
            // because we only Save on success. Reload a pristine copy.
            _ctx.VaultManager.Invalidate();
        }
        finally
        {
            VaultCrypto.SecureClear(oldRoot);
            VaultCrypto.SecureClear(newRoot);
        }

        if (!epochRotated)
        {
            // Administrative-only fallback (re-key unavailable). The device is
            // excluded from the graph but, lacking rotation, is not yet
            // cryptographically denied data it can still obtain ciphertext for.
            var fresh = _ctx.VaultManager.GetOrLoad();
            var freshDevice = fresh.Devices.FirstOrDefault(d => d.DeviceId == deviceId);
            if (freshDevice is not null)
            {
                freshDevice.Status = "Removed";
                freshDevice.DeviceEpoch++;
                freshDevice.LastSeenAt = DateTimeOffset.UtcNow.ToString("O");
            }
            fresh.Epoch++;
            _ctx.VaultManager.Save(fresh);
            _ctx.EventLogManager.Append(SyncEventType.DeviceRemoved, fresh.DeviceId, fresh.Epoch, deviceId, null);
        }

        return NativeResponse.Ok(request.RequestId, new
        {
            ok = true,
            epochRotated,
            recoveryKitInvalidated,
            rotatePasswordChecklist = rotateList,
            rotationCategories = new[]
            {
                "email", "banking", "Google", "Microsoft", "Apple",
                "crypto", "social media", "admin/business accounts",
            },
            warning = epochRotated
                ? "Device removed and vault re-keyed: the removed device cannot decrypt future data, but may still hold secrets it already accessed. Rotate high-risk passwords."
                : "Device removed administratively (vault re-key was unavailable). Rotate high-risk passwords; the removed device is not yet cryptographically denied current data.",
            recoveryNotice = recoveryKitInvalidated
                ? "Your recovery kit was invalidated by the key rotation. Create a new recovery kit now."
                : null,
        });
    }

    // ---- Helpers ----

    private static string GeneratePairingCode()
    {
        // 4 uppercase letters + hyphen + 4 digits
        const string letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // exclude I, O for clarity
        const string digits = "0123456789";

        var rng = new byte[8];
        RandomNumberGenerator.Fill(rng);

        char[] code = new char[9];
        for (int i = 0; i < 4; i++)
            code[i] = letters[rng[i] % letters.Length];
        code[4] = '-';
        for (int i = 0; i < 4; i++)
            code[5 + i] = digits[rng[4 + i] % digits.Length];

        return new string(code);
    }
}
