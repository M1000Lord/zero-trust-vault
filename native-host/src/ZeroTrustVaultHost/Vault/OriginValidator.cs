namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// Validates and normalizes origin strings.
/// Rejects HTTP origins, IDN/punycode (xn--), and non-https schemes.
/// </summary>
public static class OriginValidator
{
    /// <summary>
    /// Returns a normalized origin string (scheme://host[:port]) or throws ArgumentException.
    /// </summary>
    public static string ValidateAndNormalize(string? origin)
    {
        if (string.IsNullOrWhiteSpace(origin))
            throw new ArgumentException("Origin is required.", nameof(origin));

        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
            throw new ArgumentException($"Origin '{origin}' is not a valid URI.", nameof(origin));

        // Must be HTTPS
        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Origin scheme '{uri.Scheme}' is not allowed. Only HTTPS origins are accepted.", nameof(origin));

        // Reject IDN / punycode labels
        string host = uri.IdnHost; // already decoded
        foreach (var label in host.Split('.'))
        {
            if (label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"IDN/punycode origin labels are not allowed: '{host}'.", nameof(origin));
        }

        // Reject if the raw origin itself contains xn-- (belt-and-suspenders)
        if (origin.Contains("xn--", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"IDN/punycode detected in origin: '{origin}'.", nameof(origin));

        // Normalize: scheme://host (omit default port 443)
        string normalized;
        if (uri.IsDefaultPort)
        {
            normalized = $"https://{host}";
        }
        else
        {
            normalized = $"https://{host}:{uri.Port}";
        }

        return normalized;
    }

    /// <summary>
    /// Returns true if the origin is valid HTTPS and not IDN.
    /// </summary>
    public static bool IsValid(string? origin)
    {
        try
        {
            ValidateAndNormalize(origin);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns true if two normalized origins match exactly.
    /// </summary>
    public static bool ExactMatch(string normalizedA, string normalizedB)
        => string.Equals(normalizedA, normalizedB, StringComparison.Ordinal);
}
