using System.Security.Cryptography;

namespace ZeroTrustVaultHost.Crypto;

/// <summary>
/// RFC 6238 TOTP implementation using HMAC-SHA1.
/// Supports 6-digit codes with 30-second time steps.
/// </summary>
public static class TotpGenerator
{
    private const int Digits = 6;
    private const int Step = 30;

    /// <summary>
    /// Generates a 6-digit TOTP code for the given secret at the given time.
    /// </summary>
    /// <param name="secret">Raw TOTP secret bytes (not base32-encoded).</param>
    /// <param name="at">The time to generate the code for (defaults to now).</param>
    public static string GenerateCode(byte[] secret, DateTimeOffset? at = null)
    {
        long counter = (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / Step;
        byte[] counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);

        using var hmac = new HMACSHA1(secret);
        byte[] hash = hmac.ComputeHash(counterBytes);

        int offset = hash[19] & 0x0f;
        int code = ((hash[offset] & 0x7f) << 24)
                 | (hash[offset + 1] << 16)
                 | (hash[offset + 2] << 8)
                 |  hash[offset + 3];

        return (code % 1_000_000).ToString("D6");
    }

    /// <summary>
    /// Returns the number of seconds remaining in the current 30-second window.
    /// </summary>
    public static int SecondsRemaining(DateTimeOffset? at = null)
    {
        long unixSeconds = (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        return Step - (int)(unixSeconds % Step);
    }

    /// <summary>
    /// Decodes a base32 string (RFC 4648, no padding required) to bytes.
    /// Accepts both upper and lower case; ignores spaces and hyphens.
    /// </summary>
    public static byte[] Base32Decode(string base32)
    {
        if (string.IsNullOrEmpty(base32))
            return Array.Empty<byte>();

        // Strip whitespace, hyphens, equals padding, convert to uppercase
        base32 = base32.Replace(" ", "").Replace("-", "").Replace("=", "").ToUpperInvariant();

        if (base32.Length == 0)
            return Array.Empty<byte>();

        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int outputLength = base32.Length * 5 / 8;
        byte[] output = new byte[outputLength];

        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;

        foreach (char c in base32)
        {
            int val = alphabet.IndexOf(c);
            if (val < 0)
                throw new ArgumentException($"Invalid base32 character: '{c}'", nameof(base32));

            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output[index++] = (byte)((buffer >> bitsLeft) & 0xFF);
            }
        }

        return output;
    }

    /// <summary>
    /// Generates a TOTP code from a base32-encoded secret string.
    /// </summary>
    public static string GenerateCodeFromBase32(string base32Secret, DateTimeOffset? at = null)
    {
        byte[] secretBytes = Base32Decode(base32Secret);
        return GenerateCode(secretBytes, at);
    }
}
