using System.Text.RegularExpressions;

namespace ZeroTrustVaultHost.Diagnostics;

/// <summary>
/// Centralized, release-safe diagnostic logger.
///
/// Logging is ENABLED only when one of these is true:
///   * the assembly was compiled with the DEBUG constant (dev builds), OR
///   * the environment variable ZTV_DEBUG_LOG=1 is set (explicit dev opt-in).
///
/// In a Release build with no opt-in, <see cref="Write"/> is a hard no-op:
/// no file is created, nothing is written to %TEMP%.
///
/// Even when enabled, every message passes through <see cref="Redact"/>, which
/// strips anything that looks like a secret (long base64/hex blobs, key=value
/// pairs naming sensitive fields). Callers must still never pass raw secrets,
/// but redaction is a defense-in-depth backstop.
///
/// The build configuration is surfaced to release verification via the
/// assembly metadata key "ZtvDiagLogging" (see the .csproj). verify-release.ps1
/// fails the release if that value is "enabled".
/// </summary>
public static class DiagnosticLog
{
    private static readonly bool s_enabled = ComputeEnabled();
    private static readonly string s_logPath =
        Path.Combine(Path.GetTempPath(), "ztv_diag.txt");
    private static readonly object s_lock = new();

    /// <summary>True if diagnostic logging will actually write output.</summary>
    public static bool Enabled => s_enabled;

    /// <summary>Absolute path of the diagnostic log file (whether or not it exists).</summary>
    public static string LogPath => s_logPath;

    private static bool ComputeEnabled()
    {
#if DEBUG
        return true;
#else
        // Release: only when explicitly opted in for field diagnosis.
        return string.Equals(
            Environment.GetEnvironmentVariable("ZTV_DEBUG_LOG"),
            "1",
            StringComparison.Ordinal);
#endif
    }

    /// <summary>
    /// Writes a redacted diagnostic line. No-op when logging is disabled.
    /// Never throws — diagnostics must never break the host.
    /// </summary>
    public static void Write(string category, string message)
    {
        if (!s_enabled) return;
        try
        {
            string line = $"[{DateTime.UtcNow:HH:mm:ss.fff}] {category}: {Redact(message)}\n";
            lock (s_lock)
                File.AppendAllText(s_logPath, line);
        }
        catch
        {
            // Swallow — a failed diagnostic write must never affect vault operations.
        }
    }

    /// <summary>
    /// Deletes the diagnostic log file if present. Used by the cleanup script's
    /// in-process equivalent and by tests. Never throws.
    /// </summary>
    public static void DeleteLog()
    {
        try { if (File.Exists(s_logPath)) File.Delete(s_logPath); }
        catch { /* ignore */ }
    }

    // ---- Redaction -----------------------------------------------------------

    // Field names whose values must never be logged in clear, even in dev mode.
    private static readonly string[] s_sensitiveKeys =
    {
        "password", "pass", "totp", "totpsecret", "secret", "seed",
        "rootkey", "wrappedrootkey", "privatekey", "share", "recoveryshare",
        "username", "usernameoremail", "email", "notes", "ciphertext",
        "sessionid", "token",
    };

    // key: value  /  key=value  (captures the value to mask)
    private static readonly Regex s_kvRegex = new(
        @"(?<key>[A-Za-z_][A-Za-z0-9_]*)\s*(?<sep>[:=])\s*(?<val>[^\s,;}]+)",
        RegexOptions.Compiled);

    // Long base64-ish or hex blobs that look like key material (>= 24 chars).
    private static readonly Regex s_blobRegex = new(
        @"\b[A-Za-z0-9+/=]{24,}\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Masks sensitive values. Replaces values of sensitive keys and any long
    /// base64/hex blob with "***REDACTED***". Returns a safe-to-log string.
    /// </summary>
    public static string Redact(string input)
    {
        if (string.IsNullOrEmpty(input)) return input ?? string.Empty;

        // 1) Mask values attached to sensitive key names.
        string result = s_kvRegex.Replace(input, m =>
        {
            string key = m.Groups["key"].Value.ToLowerInvariant();
            if (Array.IndexOf(s_sensitiveKeys, key) >= 0)
                return $"{m.Groups["key"].Value}{m.Groups["sep"].Value}***REDACTED***";
            return m.Value;
        });

        // 2) Mask any remaining long opaque blobs (likely key material/base64).
        result = s_blobRegex.Replace(result, "***REDACTED***");

        return result;
    }
}
