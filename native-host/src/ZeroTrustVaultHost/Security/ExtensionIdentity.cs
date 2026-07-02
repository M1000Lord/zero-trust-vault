using System.Text.Json;
using System.Text.RegularExpressions;

namespace ZeroTrustVaultHost.Security;

/// <summary>
/// Loads the set of extension IDs this native host is actually installed to
/// trust, from the native-messaging manifest written by install.ps1
/// (co-located with the host executable as "com.zerotrust.vault.json",
/// containing "allowed_origins": ["chrome-extension://&lt;id&gt;/", ...]).
///
/// This is the fix for a real gap: the request envelope carries an
/// "extensionId" field that the extension fills in with chrome.runtime.id,
/// but nothing previously checked it against anything — a compromised
/// extension context, or any other local caller that can speak the native
/// messaging protocol, could claim to be any extension ID. Chrome's own
/// allowed_origins check (in the SAME manifest file) already restricts which
/// extension Chrome will launch this host FOR, but that is enforced by Chrome,
/// not by us — this class lets the host independently verify the caller
/// claims the same identity Chrome was supposed to restrict it to, which is
/// "necessary but not sufficient" defense in depth per the hardening brief.
/// </summary>
public sealed class ExtensionIdentity
{
    private static readonly Regex ChromeExtensionIdPattern = new("^[a-p]{32}$", RegexOptions.Compiled);

    public IReadOnlySet<string> AllowedExtensionIds { get; }

    /// <summary>True if a manifest was found and parsed successfully.</summary>
    public bool Loaded { get; }

    /// <summary>Non-secret diagnostic reason if <see cref="Loaded"/> is false.</summary>
    public string? LoadError { get; }

    private ExtensionIdentity(IReadOnlySet<string> allowedIds, bool loaded, string? loadError)
    {
        AllowedExtensionIds = allowedIds;
        Loaded = loaded;
        LoadError = loadError;
    }

    /// <summary>
    /// Loads from the native-messaging manifest co-located with the running
    /// executable. Never throws — returns an unloaded instance with a
    /// non-secret diagnostic reason on any failure.
    /// </summary>
    public static ExtensionIdentity LoadFromHostDirectory(string hostDirectory)
    {
        string manifestPath = Path.Combine(hostDirectory, "com.zerotrust.vault.json");
        return LoadFromManifestFile(manifestPath);
    }

    /// <summary>Loads from an explicit manifest file path (used directly by tests).</summary>
    public static ExtensionIdentity LoadFromManifestFile(string manifestPath)
    {
        try
        {
            if (!File.Exists(manifestPath))
                return new ExtensionIdentity(new HashSet<string>(), false, "NativeMessagingManifestNotFound");

            string json = File.ReadAllText(manifestPath);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("allowed_origins", out var originsEl) ||
                originsEl.ValueKind != JsonValueKind.Array)
                return new ExtensionIdentity(new HashSet<string>(), false, "AllowedOriginsFieldMissing");

            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var el in originsEl.EnumerateArray())
            {
                string? origin = el.GetString();
                if (string.IsNullOrEmpty(origin)) continue;

                // "chrome-extension://<32-char-id>/"
                const string prefix = "chrome-extension://";
                if (!origin.StartsWith(prefix, StringComparison.Ordinal)) continue;
                string rest = origin[prefix.Length..].TrimEnd('/');
                if (ChromeExtensionIdPattern.IsMatch(rest))
                    ids.Add(rest);
            }

            if (ids.Count == 0)
                return new ExtensionIdentity(new HashSet<string>(), false, "NoValidExtensionIdInManifest");

            return new ExtensionIdentity(ids, true, null);
        }
        catch (Exception ex)
        {
            // Never surface the exception message (could contain a path); the
            // type name alone is enough for diagnostics and is non-secret.
            return new ExtensionIdentity(new HashSet<string>(), false, $"ManifestLoadFailed:{ex.GetType().Name}");
        }
    }

    /// <summary>An identity that never trusts any caller — used when the host
    /// cannot determine its own expected caller and must fail closed.</summary>
    public static ExtensionIdentity Untrusted(string reason) =>
        new(new HashSet<string>(), false, reason);

    /// <summary>
    /// Validates a caller-supplied extension ID against the expected set.
    /// Returns a machine-readable rejection reason, or null if valid.
    /// </summary>
    public string? Validate(string? providedExtensionId)
    {
        if (string.IsNullOrEmpty(providedExtensionId))
            return "MISSING_EXTENSION_ID";

        if (!ChromeExtensionIdPattern.IsMatch(providedExtensionId))
            return "MALFORMED_EXTENSION_ID";

        if (!Loaded)
            return "EXTENSION_IDENTITY_UNVERIFIABLE";

        if (!AllowedExtensionIds.Contains(providedExtensionId))
            return "EXTENSION_ID_MISMATCH";

        return null;
    }
}
