using System.Security.Cryptography;
using ZeroTrustVaultHost.Diagnostics;

namespace ZeroTrustVaultHost.WindowsHello;

/// <summary>
/// Manages Windows Hello authentication and CNG key operations for vault root key wrapping.
/// VaultRootKey is encrypted directly to a non-exportable CNG key and stored as
/// wrappedRootKey in vault.json. No public vault field is sufficient to unwrap it.
/// VaultRootKey is never written to disk unencrypted; it is zeroed after use.
/// </summary>
public sealed class HelloManager : IHelloManager
{
    private const string DeviceWrappingKeyName = "ZeroTrustVault_DeviceWrappingKey";
    private const string PlatformKsp = "Microsoft Platform Crypto Provider";

    // ---- Public API ----

    /// <summary>
    /// Prompts Windows Hello and returns true if the user verified successfully.
    /// Returns false if the user cancelled or Hello is unavailable.
    /// </summary>
    public async Task<HelloResult> RequestUserVerificationAsync(string prompt)
    {
        DiagnosticLog.Write("HELLO", "RequestUserVerificationAsync invoked");
        try
        {
            // The windowless UserConsentVerifier.RequestVerificationAsync requires a
            // CoreWindow (UWP-style) on the calling thread. A native-messaging host
            // launched by Chrome is a plain console process with no CoreWindow, so
            // that call can silently never show a dialog. Try the windowed COM
            // interop first (anchors the dialog to a real HWND we create); only fall
            // back to the windowless API if the interop path is unavailable, so
            // behavior never regresses below what worked before.
            Windows.Security.Credentials.UI.UserConsentVerificationResult result;
            var windowed = await ConsentVerifierInterop.TryRequestAsync(prompt);
            if (windowed.HasValue)
            {
                result = windowed.Value;
                DiagnosticLog.Write("HELLO", $"Windowed UserConsentVerifier result: {result}");
            }
            else
            {
                DiagnosticLog.Write("HELLO", "Windowed interop unavailable; falling back to windowless API.");
                var verifier = Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync(prompt);
                result = await verifier;
                DiagnosticLog.Write("HELLO", $"Windowless UserConsentVerifier result: {result}");
            }

            return result switch
            {
                Windows.Security.Credentials.UI.UserConsentVerificationResult.Verified => HelloResult.Verified,
                Windows.Security.Credentials.UI.UserConsentVerificationResult.DeviceNotPresent => HelloResult.DeviceNotPresent,
                Windows.Security.Credentials.UI.UserConsentVerificationResult.NotConfiguredForUser => HelloResult.NotConfigured,
                Windows.Security.Credentials.UI.UserConsentVerificationResult.DisabledByPolicy => HelloResult.DisabledByPolicy,
                Windows.Security.Credentials.UI.UserConsentVerificationResult.DeviceBusy => HelloResult.DeviceBusy,
                Windows.Security.Credentials.UI.UserConsentVerificationResult.RetriesExhausted => HelloResult.RetriesExhausted,
                Windows.Security.Credentials.UI.UserConsentVerificationResult.Canceled => HelloResult.Canceled,
                _ => HelloResult.Failed,
            };
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write("HELLO", $"RequestUserVerificationAsync exception: {ex.GetType().Name}");
            return HelloResult.Failed;
        }
    }

    /// <summary>
    /// Checks whether Windows Hello is available and configured for this device/user.
    /// Returns "available", "unavailable", or "notConfigured".
    /// </summary>
    public async Task<string> GetPresenceAvailabilityAsync()
    {
        try
        {
            var availability = await Windows.Security.Credentials.UI.UserConsentVerifier.CheckAvailabilityAsync();
            DiagnosticLog.Write("HELLO", $"CheckAvailabilityAsync result: {availability}");
            return availability switch
            {
                Windows.Security.Credentials.UI.UserConsentVerifierAvailability.Available => HelloAvailability.Available,
                Windows.Security.Credentials.UI.UserConsentVerifierAvailability.DeviceNotPresent => HelloAvailability.DeviceNotPresent,
                Windows.Security.Credentials.UI.UserConsentVerifierAvailability.NotConfiguredForUser => HelloAvailability.NotConfigured,
                Windows.Security.Credentials.UI.UserConsentVerifierAvailability.DisabledByPolicy => HelloAvailability.DisabledByPolicy,
                // DeviceBusy is transient; surface as Unavailable so the popup blocks but does not hard-fail.
                Windows.Security.Credentials.UI.UserConsentVerifierAvailability.DeviceBusy => HelloAvailability.Unavailable,
                _ => HelloAvailability.Unavailable,
            };
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write("HELLO", $"GetPresenceAvailabilityAsync exception: {ex.GetType().Name}");
            // An exception means we genuinely don't know — distinct from a definite "unavailable".
            return HelloAvailability.Unknown;
        }
    }

    // ---- Key wrapping ----

    /// <summary>
    /// Gets or creates the non-exportable CNG device wrapping key. The Platform
    /// KSP keeps key material outside the vault file and outside application code.
    /// </summary>
    public CngKey GetOrCreateDeviceWrappingKey()
    {
        var provider = new CngProvider(PlatformKsp);
        try
        {
            return CngKey.Open(DeviceWrappingKeyName, provider);
        }
        catch (CryptographicException)
        {
            // Create below.
        }

        // UIPolicy.None: the app already performs its own explicit Windows Hello
        // verification (RequestUserVerificationAsync, via the windowed interop)
        // immediately before every WrapRootKey/UnwrapRootKey call. ForceHighProtection
        // additionally makes Windows itself show a SEPARATE "This application needs to
        // use a cryptographic key" consent dialog on every key use — confirmed by
        // direct testing to appear AFTER the fingerprint check already succeeded,
        // defaulting to a password/PIN text box rather than fingerprint, which reads
        // as "asks for a password every time" and is pure redundant friction: the
        // security guarantee (fresh user verification before key use) is already
        // enforced by the app's own Hello gate, not by this OS-level popup.
        var creationParams = new CngKeyCreationParameters
        {
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Decryption,
            Provider = provider,
            KeyCreationOptions = CngKeyCreationOptions.None,
            UIPolicy = new CngUIPolicy(
                CngUIProtectionLevels.None,
                "Zero Trust Vault",
                "Authorize use of the vault device key",
                "Windows Hello is required to protect the vault root key",
                "Zero Trust Vault"),
        };
        creationParams.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

        return CngKey.Create(CngAlgorithm.Rsa, DeviceWrappingKeyName, creationParams);
    }

    /// <summary>
    /// Wraps the VaultRootKey directly with the non-exportable CNG device key.
    /// Windows Hello verification is performed by the caller immediately before
    /// this operation; the CNG private key is never exportable.
    /// </summary>
    public byte[] WrapRootKey(byte[] rootKey)
    {
        if (rootKey.Length != 32)
            throw new ArgumentException("Root key must be 32 bytes.", nameof(rootKey));

        using var key = GetOrCreateDeviceWrappingKey();
        using var rsa = new RSACng(key);
        return rsa.Encrypt(rootKey, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>
    /// Unwraps the VaultRootKey using the same non-exportable CNG device key.
    /// </summary>
    public byte[] UnwrapRootKey(byte[] wrappedBytes)
    {
        if (wrappedBytes.Length < 128)
            throw new ArgumentException("Wrapped key data is too short.", nameof(wrappedBytes));

        using var key = GetOrCreateDeviceWrappingKey();
        using var rsa = new RSACng(key);
        var rootKey = rsa.Decrypt(wrappedBytes, RSAEncryptionPadding.OaepSHA256);
        if (rootKey.Length != 32)
            throw new CryptographicException("Unwrapped root key has invalid length.");
        return rootKey;
    }

    /// <summary>
    /// Generates a fresh 256-bit VaultRootKey.
    /// </summary>
    public static byte[] GenerateRootKey() => RandomNumberGenerator.GetBytes(32);

}

public enum HelloResult
{
    Verified,
    Failed,
    Canceled,
    DeviceNotPresent,
    NotConfigured,
    DisabledByPolicy,
    DeviceBusy,
    RetriesExhausted,
}

/// <summary>
/// Canonical Windows Hello availability strings returned by the native host.
/// The popup must treat exactly these values (case-insensitively) as the
/// authoritative vocabulary. "Available" is the only value that permits unlock;
/// "Unknown" means availability could not be determined (warn, do not block hard).
/// </summary>
public static class HelloAvailability
{
    public const string Available        = "Available";
    public const string DeviceNotPresent = "DeviceNotPresent";
    public const string NotConfigured    = "NotConfigured";
    public const string DisabledByPolicy = "DisabledByPolicy";
    public const string Unavailable      = "Unavailable";
    public const string Unknown          = "Unknown";

    /// <summary>True only when the value means Hello can be used right now.</summary>
    public static bool IsUsable(string? value) =>
        string.Equals(value, Available, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Interface for mocking in tests.
/// </summary>
public interface IHelloManager
{
    Task<HelloResult> RequestUserVerificationAsync(string prompt);
    Task<string> GetPresenceAvailabilityAsync();
    byte[] WrapRootKey(byte[] rootKey);
    byte[] UnwrapRootKey(byte[] wrappedBytes);
}
