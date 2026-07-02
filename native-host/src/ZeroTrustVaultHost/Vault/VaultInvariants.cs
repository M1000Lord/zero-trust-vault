namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// One structural violation found by <see cref="VaultInvariants.Check"/>.
/// Never contains secret material — only ids, counts, and field names.
/// </summary>
public sealed record InvariantViolation(string Code, string Message);

/// <summary>
/// Structural invariant checker for a loaded <see cref="VaultFile"/> (Section
/// B). Pure and side-effect-free: it never decrypts anything, so it can run
/// on every load/unlock cheaply and catch corruption/tampering that parses as
/// valid JSON but is not a well-formed vault — duplicate ids, missing/invalid
/// wraps, orphaned epoch stamps, mismatched recovery-kit thresholds. This is
/// a structural check, not a cryptographic one: it cannot detect ciphertext
/// tampering (the AEAD tag on each item does that at decrypt time), only that
/// the on-disk shape itself is coherent.
/// </summary>
public static class VaultInvariants
{
    public static IReadOnlyList<InvariantViolation> Check(VaultFile vault)
    {
        var violations = new List<InvariantViolation>();
        if (vault is null)
        {
            violations.Add(new InvariantViolation("VAULT_NULL", "Vault is null."));
            return violations;
        }

        if (vault.Schema != 3)
            violations.Add(new InvariantViolation("SCHEMA_UNSUPPORTED", $"Unsupported schema version {vault.Schema}."));

        if (vault.Epoch < 1)
            violations.Add(new InvariantViolation("EPOCH_INVALID", "Vault epoch must be >= 1."));

        if (VaultIntegrity.ClassifyWrappedRootKey(vault.WrappedRootKey) != WrappedKeyStatus.Valid)
            violations.Add(new InvariantViolation("ROOT_KEY_INVALID", "wrappedRootKey is missing, empty, malformed, or too short."));

        CheckItems(vault, violations);
        CheckDevices(vault, violations);
        CheckRecoveryKit(vault, violations);

        return violations;
    }

    private static void CheckItems(VaultFile vault, List<InvariantViolation> violations)
    {
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in vault.Items)
        {
            if (string.IsNullOrEmpty(item.ItemId))
            {
                violations.Add(new InvariantViolation("ITEM_MISSING_ID", "An item has an empty itemId."));
                continue;
            }
            if (!seenIds.Add(item.ItemId))
                violations.Add(new InvariantViolation("ITEM_DUPLICATE_ID", $"Duplicate itemId: {item.ItemId}"));

            if (item.Deleted) continue; // tombstones do not need live ciphertext

            if (string.IsNullOrEmpty(item.OriginHash))
                violations.Add(new InvariantViolation("ITEM_MISSING_ORIGIN_HASH", $"Item {item.ItemId} has no originHash."));
            else if (!IsValidBase64(item.OriginHash))
                violations.Add(new InvariantViolation("ITEM_INVALID_ORIGIN_HASH", $"Item {item.ItemId} originHash is not valid base64."));

            if (!IsValidEncryptedBlob(item.EncryptedPayload))
                violations.Add(new InvariantViolation("ITEM_BROKEN_PAYLOAD", $"Item {item.ItemId} encryptedPayload is missing a field or has invalid base64."));
            if (!IsValidEncryptedBlob(item.EncryptedMetadata))
                violations.Add(new InvariantViolation("ITEM_BROKEN_METADATA", $"Item {item.ItemId} encryptedMetadata is missing a field or has invalid base64."));

            if (item.Epoch < 1)
                violations.Add(new InvariantViolation("ITEM_EPOCH_INVALID", $"Item {item.ItemId} has epoch < 1."));
            else if (item.Epoch > vault.Epoch)
                violations.Add(new InvariantViolation("ITEM_EPOCH_AHEAD_OF_VAULT", $"Item {item.ItemId} epoch ({item.Epoch}) exceeds vault epoch ({vault.Epoch})."));
        }
    }

    private static void CheckDevices(VaultFile vault, List<InvariantViolation> violations)
    {
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var device in vault.Devices)
        {
            if (string.IsNullOrEmpty(device.DeviceId))
            {
                violations.Add(new InvariantViolation("DEVICE_MISSING_ID", "A device entry has an empty deviceId."));
                continue;
            }
            if (!seenIds.Add(device.DeviceId))
                violations.Add(new InvariantViolation("DEVICE_DUPLICATE_ID", $"Duplicate deviceId: {device.DeviceId}"));

            if (!string.IsNullOrEmpty(device.WrappedEpochKey) && !IsValidBase64(device.WrappedEpochKey))
                violations.Add(new InvariantViolation("DEVICE_WRAP_INVALID", $"Device {device.DeviceId} wrappedEpochKey is not valid base64."));
        }
    }

    private static void CheckRecoveryKit(VaultFile vault, List<InvariantViolation> violations)
    {
        if (vault.RecoveryKit is null) return;
        var kit = vault.RecoveryKit;

        if (kit.Threshold < 2)
            violations.Add(new InvariantViolation("RECOVERY_THRESHOLD_TOO_LOW", "Recovery threshold must be at least 2."));
        if (kit.ShareCount < kit.Threshold)
            violations.Add(new InvariantViolation("RECOVERY_SHARE_COUNT_INVALID", "Recovery shareCount must be >= threshold."));
        if (string.IsNullOrEmpty(kit.VerificationHmac) || !IsValidBase64(kit.VerificationHmac))
            violations.Add(new InvariantViolation("RECOVERY_HMAC_INVALID", "Recovery verificationHmac is missing or not valid base64."));
    }

    private static bool IsValidEncryptedBlob(EncryptedBlob? blob)
    {
        if (blob is null) return false;
        if (string.IsNullOrEmpty(blob.Nonce) || string.IsNullOrEmpty(blob.Tag) || string.IsNullOrEmpty(blob.Ciphertext))
            return false;
        return IsValidBase64(blob.Nonce) && IsValidBase64(blob.Tag) && IsValidBase64(blob.Ciphertext);
    }

    private static bool IsValidBase64(string s)
    {
        try { Convert.FromBase64String(s); return true; }
        catch (FormatException) { return false; }
    }
}
