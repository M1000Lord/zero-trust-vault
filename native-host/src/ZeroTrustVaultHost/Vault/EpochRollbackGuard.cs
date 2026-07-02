using System.Text.Json;

namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// Anti-rollback guard (Section B / threat matrix "downgrade/rollback
/// attack"): detects a vault.json that has been swapped for an OLDER, valid
/// snapshot of the SAME vault (e.g. restored from a backup, or a copy saved
/// before a device revocation/rotation). Without this, an attacker who can
/// write to the vault directory could undo a revocation simply by restoring
/// the pre-revocation vault.json, since that file alone parses and decrypts
/// perfectly fine — nothing about the vault file itself proves it is stale.
///
/// Mechanism: a small sidecar marker file records the highest epoch this
/// device has ever seen for the current vault id. On every load we compare
/// the file's epoch against the marker; a lower epoch for the same vault id
/// is a rollback and must fail closed, never silently accepted.
///
/// Honest limitation (documented in KNOWN_LIMITATIONS.md): this sidecar sits
/// in the same directory as the vault and is not hardware-backed. An
/// attacker capable of overwriting vault.json can typically also delete or
/// roll back this marker file unless the folder ACLs specifically prevent
/// it (see Section R). This raises the bar — a copy-vault-only attack is now
/// detected — but it is not equivalent to a TPM monotonic counter, which
/// would be required for a rollback guarantee that survives a fully
/// compromised local filesystem.
/// </summary>
public static class EpochRollbackGuard
{
    private const string MarkerFileName = "vault.epoch.marker";

    public sealed record RollbackCheckResult(bool RollbackDetected, int? LastSeenEpoch, string? LastSeenVaultId);

    /// <summary>
    /// Compares <paramref name="vault"/>'s epoch against the last-seen marker
    /// for its vault id. If no rollback is detected, advances the marker
    /// forward (never backward) and returns RollbackDetected=false. If a
    /// rollback IS detected, the marker is left untouched (so the last-known-
    /// good epoch is preserved for the next check) and RollbackDetected=true
    /// is returned — callers must fail closed, not proceed with the load.
    /// </summary>
    public static RollbackCheckResult CheckAndAdvance(string vaultDirectory, VaultFile vault)
    {
        string markerPath = Path.Combine(vaultDirectory, MarkerFileName);
        var marker = TryReadMarker(markerPath);

        bool sameVault = marker is not null && string.Equals(marker.VaultId, vault.VaultId, StringComparison.Ordinal);
        bool rollback = sameVault && vault.Epoch < marker!.Epoch;

        if (rollback)
            return new RollbackCheckResult(true, marker!.Epoch, marker.VaultId);

        int newMarkerEpoch = sameVault ? Math.Max(marker!.Epoch, vault.Epoch) : vault.Epoch;
        WriteMarker(markerPath, new EpochMarker { VaultId = vault.VaultId, Epoch = newMarkerEpoch });
        return new RollbackCheckResult(false, marker?.Epoch, marker?.VaultId);
    }

    /// <summary>Resets tracking for a fresh vault (new vault id after reset/recovery).</summary>
    public static void Reset(string vaultDirectory, VaultFile vault)
    {
        string markerPath = Path.Combine(vaultDirectory, MarkerFileName);
        WriteMarker(markerPath, new EpochMarker { VaultId = vault.VaultId, Epoch = vault.Epoch });
    }

    private sealed class EpochMarker
    {
        public string VaultId { get; set; } = string.Empty;
        public int Epoch { get; set; }
    }

    private static EpochMarker? TryReadMarker(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<EpochMarker>(File.ReadAllText(path));
        }
        catch { return null; }
    }

    private static void WriteMarker(string path, EpochMarker marker)
    {
        try
        {
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(marker));
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            // Best-effort: a marker write failure must not block a legitimate
            // vault operation. Worst case, the next rollback check is less
            // precise, not that the vault becomes unusable.
        }
    }
}
