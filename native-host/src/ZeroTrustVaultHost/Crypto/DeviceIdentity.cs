using System.Security.Cryptography;
using System.Text;

namespace ZeroTrustVaultHost.Crypto;

/// <summary>
/// Device-graph identity primitives:
///   * DeviceId derived as a hash of the device's public signing key
///     (so a device id cannot be forged independently of its key), and
///   * a Short Authentication String (SAS) derived from a canonical pairing
///     transcript so both devices display the same code and the user can
///     detect a man-in-the-middle.
///
/// These are pure, deterministic, and fully unit-testable. They are the
/// building blocks for real device pairing; the cross-device transport and the
/// signed AddDevice verification on the joining device are tracked separately
/// (see AUDIT_PACKAGE/KNOWN_LIMITATIONS.md).
/// </summary>
public static class DeviceIdentity
{
    /// <summary>
    /// DeviceId = base64url( SHA-256( publicSigningKeyBlob ) ), no padding.
    /// Deterministic and collision-resistant; binds the id to the key.
    /// </summary>
    public static string ComputeDeviceId(byte[] publicSigningKeyBlob)
    {
        if (publicSigningKeyBlob is null || publicSigningKeyBlob.Length == 0)
            throw new ArgumentException("Public signing key blob is required.", nameof(publicSigningKeyBlob));

        byte[] hash = SHA256.HashData(publicSigningKeyBlob);
        return Base64Url(hash);
    }

    /// <summary>
    /// Derives a deterministic 6-digit SAS from a canonical pairing transcript.
    /// Both devices build the same transcript (sorted public keys so order does
    /// not matter) and therefore compute the same code. The user confirms the
    /// codes match before approving — this is what defeats a MITM relay.
    /// </summary>
    public static string ComputeSas(
        string pairingSessionId,
        byte[] publicKeyA,
        byte[] publicKeyB,
        byte[] pairingNonce,
        int digits = 6)
    {
        if (string.IsNullOrEmpty(pairingSessionId))
            throw new ArgumentException("pairingSessionId is required.", nameof(pairingSessionId));
        if (publicKeyA is null || publicKeyB is null)
            throw new ArgumentException("Both public keys are required.");
        if (pairingNonce is null || pairingNonce.Length < 16)
            throw new ArgumentException("pairingNonce must be at least 16 bytes.", nameof(pairingNonce));
        if (digits < 4 || digits > 9)
            throw new ArgumentOutOfRangeException(nameof(digits), "SAS digits must be 4..9.");

        // Order-independent: hash the two keys in a canonical (sorted) order.
        var (first, second) = CompareBytes(publicKeyA, publicKeyB) <= 0
            ? (publicKeyA, publicKeyB)
            : (publicKeyB, publicKeyA);

        using var sha = SHA256.Create();
        // transcript = "ZTV-SAS-v1" || sessionId || firstKey || secondKey || nonce
        var transcript = new List<byte>();
        transcript.AddRange(Encoding.UTF8.GetBytes("ZTV-SAS-v1"));
        transcript.AddRange(Encoding.UTF8.GetBytes(pairingSessionId));
        transcript.AddRange(first);
        transcript.AddRange(second);
        transcript.AddRange(pairingNonce);

        byte[] hash = sha.ComputeHash(transcript.ToArray());

        // Take the first 4 bytes as an unsigned int, mod 10^digits.
        uint value = (uint)((hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3]);
        long modulus = (long)Math.Pow(10, digits);
        long code = value % modulus;
        return code.ToString().PadLeft(digits, '0');
    }

    // ---- helpers ----

    private static int CompareBytes(byte[] a, byte[] b)
    {
        int len = Math.Min(a.Length, b.Length);
        for (int i = 0; i < len; i++)
        {
            int d = a[i].CompareTo(b[i]);
            if (d != 0) return d;
        }
        return a.Length.CompareTo(b.Length);
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
