using System.Text.Json;
using ZeroTrustVaultHost.Diagnostics;

namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// Classification of the wrappedRootKey field in a vault file.
/// </summary>
public enum WrappedKeyStatus
{
    /// <summary>Present, valid base64, and long enough to be an RSA-OAEP wrap (>= 128 bytes).</summary>
    Valid,
    /// <summary>Field is null.</summary>
    Missing,
    /// <summary>Field is present but an empty/whitespace string.</summary>
    Empty,
    /// <summary>Decodes from base64 but is shorter than a plausible wrapped key.</summary>
    TooShort,
    /// <summary>Not valid base64.</summary>
    InvalidBase64,
}

/// <summary>
/// Machine-readable reason a vault was quarantined. Never contains secrets.
/// </summary>
public enum CorruptReason
{
    MissingWrappedRootKey,
    EmptyWrappedRootKey,
    WrappedRootKeyTooShort,
    WrappedRootKeyInvalidFormat,
    RootKeyUnwrapFailed,
    /// <summary>VaultInvariants.Check found a structural problem (duplicate id, broken wrap, epoch mismatch, etc.).</summary>
    InvariantViolation,
    /// <summary>EpochRollbackGuard detected a vault epoch older than one this device has already seen.</summary>
    RollbackDetected,
}

/// <summary>
/// User-facing corrupt-vault states. Surfaced as error codes so the popup can
/// render the correct recovery guidance instead of a generic internal error.
/// </summary>
public static class VaultCorruptCode
{
    /// <summary>Vault was empty/corrupt with no user data; quarantined and safe to reset.</summary>
    public const string EmptyResetAvailable = "VaultCorruptEmptyResetAvailable";
    /// <summary>Vault has user data and a recovery kit; recovery flow should be offered.</summary>
    public const string RecoveryRequired = "VaultCorruptRecoveryRequired";
    /// <summary>Vault has user data but NO recovery kit; user must preserve the quarantined copy.</summary>
    public const string NoRecovery = "VaultCorruptNoRecovery";
    /// <summary>Quarantine itself failed (e.g. permissions); the vault was NOT modified.</summary>
    public const string QuarantineFailed = "VaultCorruptQuarantineFailed";
}

/// <summary>
/// Result of attempting to quarantine a corrupt vault.
/// </summary>
public sealed record QuarantineResult(
    bool Success,
    string? QuarantinedVaultPath,
    string? DiagnosticPath,
    string? FailureMessage);

/// <summary>
/// Non-secret diagnostic snapshot written alongside a quarantined vault.
/// Deliberately contains ONLY counts and flags — never key material, usernames,
/// passwords, TOTP seeds, plaintext origins, or decrypted metadata.
/// </summary>
public sealed class CorruptVaultDiagnostic
{
    public string Reason { get; set; } = string.Empty;
    public string TimestampUtc { get; set; } = string.Empty;
    public int SchemaVersion { get; set; }
    public long FileSizeBytes { get; set; }
    public int ItemCount { get; set; }
    public int EventCount { get; set; }
    public int DeviceCount { get; set; }
    public bool HasRecoveryBundle { get; set; }
    public string CodeVersion { get; set; } = string.Empty;
}

/// <summary>
/// Pure, path-injectable helpers for detecting and safely handling a corrupt
/// vault. No dependency on the singleton VaultManager paths, so it is fully
/// unit-testable against temp directories.
///
/// Safety contract:
///  * Quarantine COPIES the corrupt file; it never deletes or truncates it.
///  * The caller decides whether a fresh vault may be created — VaultIntegrity
///    never overwrites a vault that still contains user data.
/// </summary>
public static class VaultIntegrity
{
    /// <summary>RSA-2048 OAEP-SHA256 wrap of a 32-byte key is 256 bytes; require &gt;= 128.</summary>
    public const int MinWrappedKeyBytes = 128;

    /// <summary>Classifies the wrappedRootKey string without throwing.</summary>
    public static WrappedKeyStatus ClassifyWrappedRootKey(string? wrappedRootKey)
    {
        if (wrappedRootKey is null) return WrappedKeyStatus.Missing;
        if (string.IsNullOrWhiteSpace(wrappedRootKey)) return WrappedKeyStatus.Empty;

        byte[] bytes;
        try { bytes = Convert.FromBase64String(wrappedRootKey); }
        catch (FormatException) { return WrappedKeyStatus.InvalidBase64; }

        return bytes.Length < MinWrappedKeyBytes
            ? WrappedKeyStatus.TooShort
            : WrappedKeyStatus.Valid;
    }

    /// <summary>Maps a wrapped-key status to its machine-readable corrupt reason.</summary>
    public static CorruptReason ToReason(WrappedKeyStatus status) => status switch
    {
        WrappedKeyStatus.Missing       => CorruptReason.MissingWrappedRootKey,
        WrappedKeyStatus.Empty         => CorruptReason.EmptyWrappedRootKey,
        WrappedKeyStatus.TooShort      => CorruptReason.WrappedRootKeyTooShort,
        WrappedKeyStatus.InvalidBase64 => CorruptReason.WrappedRootKeyInvalidFormat,
        _ => CorruptReason.WrappedRootKeyInvalidFormat,
    };

    /// <summary>
    /// True if the vault holds anything the user would not want silently lost:
    /// any item (even tombstoned), event, device, or recovery bundle.
    /// </summary>
    public static bool HasUserData(VaultFile? vault)
    {
        if (vault is null) return false;
        if (vault.Items.Count > 0) return true;
        if (vault.EventLog.Count > 0) return true;
        if (vault.Devices.Count > 0) return true;
        if (vault.RecoveryKit is not null) return true;
        if (vault.PendingPairings.Count > 0) return true;
        return false;
    }

    /// <summary>
    /// Attempts to parse a vault file for inspection. Returns null if it cannot
    /// be parsed at all (still treated as corrupt, just with unknown contents).
    /// </summary>
    public static VaultFile? TryParse(string vaultPath)
    {
        try
        {
            if (!File.Exists(vaultPath)) return null;
            string json = File.ReadAllText(vaultPath);
            return JsonSerializer.Deserialize<VaultFile>(json);
        }
        catch { return null; }
    }

    /// <summary>
    /// Copies the corrupt vault into the quarantine directory with a UTC-stamped
    /// name, and writes a non-secret diagnostic JSON next to it. Also copies any
    /// recognised sidecar files (.tmp, .sha256) if present. Never deletes the
    /// original. Returns success=false (without throwing) if the copy fails.
    /// </summary>
    public static QuarantineResult Quarantine(
        string vaultPath,
        string quarantineDir,
        CorruptReason reason,
        VaultFile? parsed,
        string codeVersion)
    {
        string stamp = DateTime.UtcNow.ToString("yyyyMMddTHHmmssfffZ");
        try
        {
            Directory.CreateDirectory(quarantineDir);

            string corruptCopy = Path.Combine(quarantineDir, $"vault.corrupt.{stamp}.json");
            if (File.Exists(vaultPath))
                File.Copy(vaultPath, corruptCopy, overwrite: false);

            // Copy recognised sidecars if they exist (non-fatal if absent).
            foreach (var suffix in new[] { ".tmp", ".sha256" })
            {
                string sidecar = vaultPath + suffix;
                if (File.Exists(sidecar))
                {
                    try { File.Copy(sidecar, Path.Combine(quarantineDir, $"vault.corrupt.{stamp}{suffix}"), overwrite: false); }
                    catch { /* sidecar copy is best-effort */ }
                }
            }

            long size = File.Exists(vaultPath) ? new FileInfo(vaultPath).Length : 0;
            var diag = new CorruptVaultDiagnostic
            {
                Reason            = reason.ToString(),
                TimestampUtc      = DateTimeOffset.UtcNow.ToString("O"),
                SchemaVersion     = parsed?.Schema ?? -1,
                FileSizeBytes     = size,
                ItemCount         = parsed?.Items.Count ?? -1,
                EventCount        = parsed?.EventLog.Count ?? -1,
                DeviceCount       = parsed?.Devices.Count ?? -1,
                HasRecoveryBundle = parsed?.RecoveryKit is not null,
                CodeVersion       = codeVersion,
            };

            string diagPath = Path.Combine(quarantineDir, $"vault.corrupt.{stamp}.diagnostic.json");
            File.WriteAllText(diagPath, JsonSerializer.Serialize(diag, new JsonSerializerOptions { WriteIndented = true }));

            DiagnosticLog.Write("QUARANTINE", $"Quarantined corrupt vault ({reason}); diagnostic written.");
            return new QuarantineResult(true, corruptCopy, diagPath, null);
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write("QUARANTINE", $"Quarantine FAILED: {ex.GetType().Name}");
            return new QuarantineResult(false, null, null, ex.Message);
        }
    }
}
