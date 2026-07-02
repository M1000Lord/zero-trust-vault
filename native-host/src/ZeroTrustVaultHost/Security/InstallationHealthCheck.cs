using System.Text.Json;
using Microsoft.Win32;

namespace ZeroTrustVaultHost.Security;

/// <summary>
/// Reports how this native host is actually registered with the browser, so
/// the extension's health dashboard can surface degraded-trust states
/// instead of silently trusting whatever native messaging happened to wire
/// up (Section R: installer/registry/native-host hijack hardening).
/// </summary>
public sealed record InstallationHealthStatus(
    string RegistrationMode,             // "HKLM", "HKCU", "None", "Unknown"
    bool HklmRegistered,
    bool HkcuRegistered,
    string? RegisteredManifestPath,
    bool ManifestPathMatchesExpected,
    bool ManifestFileExists,
    string? ManifestDeclaredExePath,
    bool ExePathMatchesRunningExe,
    bool Degraded,
    string? DegradedReason);

public static class InstallationHealthCheck
{
    private const string HostName = "com.zerotrust.vault";
    private static readonly string[] HklmKeyPaths =
    {
        @"SOFTWARE\Google\Chrome\NativeMessagingHosts\" + HostName,
        @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts\" + HostName,
    };
    private static readonly string[] HkcuKeyPaths =
    {
        @"Software\Google\Chrome\NativeMessagingHosts\" + HostName,
        @"Software\Microsoft\Edge\NativeMessagingHosts\" + HostName,
    };

    /// <summary>
    /// Performs the real registry/filesystem/process reads and classifies
    /// the result. Never throws — any read failure is folded into a
    /// degraded/unknown status rather than crashing the health check.
    /// </summary>
    public static InstallationHealthStatus Collect(string hostDirectory)
    {
        string? hklmValue = null;
        string? hkcuValue = null;

        try
        {
            foreach (var keyPath in HklmKeyPaths)
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                var v = key?.GetValue(null) as string;
                if (!string.IsNullOrWhiteSpace(v)) { hklmValue = v; break; }
            }
        }
        catch { /* best-effort */ }

        try
        {
            foreach (var keyPath in HkcuKeyPaths)
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                var v = key?.GetValue(null) as string;
                if (!string.IsNullOrWhiteSpace(v)) { hkcuValue = v; break; }
            }
        }
        catch { /* best-effort */ }

        string expectedManifestPath = Path.Combine(hostDirectory, HostName + ".json");

        string? registeredPath = hklmValue ?? hkcuValue;
        bool manifestExists = false;
        string? declaredExePath = null;

        if (registeredPath is not null)
        {
            try
            {
                manifestExists = File.Exists(registeredPath);
                if (manifestExists)
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(registeredPath));
                    if (doc.RootElement.TryGetProperty("path", out var pathProp))
                        declaredExePath = pathProp.GetString();
                }
            }
            catch { /* treated as manifest-invalid below */ }
        }

        string? runningExePath = null;
        try { runningExePath = Environment.ProcessPath; } catch { }

        return Classify(hklmValue, hkcuValue, expectedManifestPath, manifestExists, declaredExePath, runningExePath);
    }

    /// <summary>
    /// Pure classification over already-read values — fully unit-testable
    /// without touching the real registry.
    /// </summary>
    public static InstallationHealthStatus Classify(
        string? hklmRegisteredPath,
        string? hkcuRegisteredPath,
        string expectedManifestPath,
        bool manifestFileExists,
        string? manifestDeclaredExePath,
        string? runningExePath)
    {
        bool hklmRegistered = !string.IsNullOrWhiteSpace(hklmRegisteredPath);
        bool hkcuRegistered = !string.IsNullOrWhiteSpace(hkcuRegisteredPath);
        string? registeredPath = hklmRegisteredPath ?? hkcuRegisteredPath;

        bool manifestPathMatchesExpected = registeredPath is not null
            && string.Equals(
                Path.GetFullPath(registeredPath),
                Path.GetFullPath(expectedManifestPath),
                StringComparison.OrdinalIgnoreCase);

        bool exePathMatches = manifestDeclaredExePath is not null
            && runningExePath is not null
            && string.Equals(
                Path.GetFullPath(manifestDeclaredExePath),
                Path.GetFullPath(runningExePath),
                StringComparison.OrdinalIgnoreCase);

        string mode;
        bool degraded = false;
        string? reason = null;

        if (hklmRegistered)
        {
            mode = "HKLM";
        }
        else if (hkcuRegistered)
        {
            mode = "HKCU";
            degraded = true;
            reason = "Registered under HKCU only. HKLM registration failed or was declined during install " +
                     "(likely UAC elevation was skipped). HKCU registration is writable by the logged-in user " +
                     "alone, without administrator rights, which is a weaker trust boundary than HKLM.";
        }
        else
        {
            mode = "None";
            degraded = true;
            reason = "No native-messaging registration found under HKLM or HKCU for Chrome or Edge. " +
                     "The browser should not be able to launch this host at all; if it is running anyway, " +
                     "investigate how it was started.";
        }

        if (!degraded && registeredPath is not null && !manifestPathMatchesExpected)
        {
            degraded = true;
            reason = $"Registry points to an unexpected manifest path ('{registeredPath}' instead of " +
                      "the manifest co-located with this executable). This can indicate the registry " +
                      "entry was hijacked to redirect the browser to a different native host.";
        }
        else if (!degraded && registeredPath is not null && !manifestFileExists)
        {
            degraded = true;
            reason = "The manifest path the registry points to does not exist on disk.";
        }
        else if (!degraded && manifestDeclaredExePath is not null && runningExePath is not null && !exePathMatches)
        {
            degraded = true;
            reason = $"The installed manifest declares a different executable path ('{manifestDeclaredExePath}') " +
                      "than the one currently running. This can indicate the manifest was hijacked to point at " +
                      "a different (possibly malicious) executable.";
        }

        return new InstallationHealthStatus(
            mode, hklmRegistered, hkcuRegistered, registeredPath,
            manifestPathMatchesExpected, manifestFileExists, manifestDeclaredExePath, exePathMatches,
            degraded, reason);
    }
}
