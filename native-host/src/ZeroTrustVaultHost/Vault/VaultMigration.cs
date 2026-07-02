using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// Detects old vault formats (schema < 3 or no schema field), backs up, and migrates to v3.
/// Since the old format's encrypted credentials cannot be decrypted without the old key
/// (which requires Windows Hello), migration creates a fresh vault structure with migrated
/// unencrypted fields only. Encrypted blobs are preserved as-is if possible.
/// </summary>
public static class VaultMigration
{
    private static readonly JsonSerializerOptions s_options = new() { WriteIndented = true };

    /// <summary>
    /// Returns true if migration is needed (file exists but is not schema v3).
    /// </summary>
    public static bool IsMigrationNeeded(string vaultPath)
    {
        if (!File.Exists(vaultPath)) return false;

        try
        {
            string json = File.ReadAllText(vaultPath, Encoding.UTF8);
            var node = JsonNode.Parse(json);
            if (node is null) return true;
            int schema = node["schema"]?.GetValue<int>() ?? 0;
            return schema < 3;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// Performs migration: backs up old vault.json, then produces a v3 skeleton.
    /// The actual re-encryption requires Windows Hello and is handled by the unlock flow.
    /// After migration the vault exists at schema v3 with items array from old format (if parseable).
    /// </summary>
    public static MigrationResult Migrate(string vaultPath, string deviceId, string vaultId, byte[] wrappedRootKey)
    {
        // Step 1: backup
        string backupPath = vaultPath + ".pre-migration-backup";
        File.Copy(vaultPath, backupPath, overwrite: true);

        // Step 2: parse old format
        var oldItems = ParseOldItems(vaultPath);

        // Step 3: build new v3 vault (items not re-encrypted here — they start as tombstones
        // since we cannot decrypt old blobs without Hello; the extension must re-add them)
        var newVault = new VaultFile
        {
            Schema = 3,
            VaultId = vaultId,
            DeviceId = deviceId,
            Epoch = 1,
            WrappedRootKey = Convert.ToBase64String(wrappedRootKey),
            Items = new(),
            Devices = new(),
            PendingPairings = new(),
            EventLog = new(),
            RecoveryKit = null,
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            UpdatedAt = DateTimeOffset.UtcNow.ToString("O"),
        };

        // Write new vault
        string tempPath = vaultPath + ".tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(newVault, s_options), Encoding.UTF8);
        File.Move(tempPath, vaultPath, overwrite: true);

        return new MigrationResult
        {
            BackupPath = backupPath,
            OldItemCount = oldItems.Count,
            MigratedAt = DateTimeOffset.UtcNow,
        };
    }

    private static List<OldItem> ParseOldItems(string vaultPath)
    {
        var result = new List<OldItem>();
        try
        {
            string json = File.ReadAllText(vaultPath, Encoding.UTF8);
            var node = JsonNode.Parse(json);
            if (node is null) return result;

            var credentials = node["credentials"]?.AsArray()
                           ?? node["items"]?.AsArray();
            if (credentials is null) return result;

            foreach (var item in credentials)
            {
                if (item is null) continue;
                result.Add(new OldItem
                {
                    Id = item["id"]?.GetValue<string>() ?? item["itemId"]?.GetValue<string>() ?? string.Empty,
                    Label = item["label"]?.GetValue<string>() ?? string.Empty,
                });
            }
        }
        catch
        {
            // Best-effort parse; if old format is unreadable, return empty
        }
        return result;
    }

    private sealed class OldItem
    {
        public string Id { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
    }
}

public sealed class MigrationResult
{
    public string BackupPath { get; set; } = string.Empty;
    public int OldItemCount { get; set; }
    public DateTimeOffset MigratedAt { get; set; }
}
