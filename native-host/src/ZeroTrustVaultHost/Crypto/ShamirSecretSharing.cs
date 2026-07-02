using System.Security.Cryptography;

namespace ZeroTrustVaultHost.Crypto;

/// <summary>
/// Shamir's Secret Sharing over GF(256) with primitive polynomial 0x11B (x^8+x^4+x^3+x+1).
/// Operates byte-by-byte: one GF(256) polynomial per secret byte.
/// Uses Lagrange interpolation at x=0 for reconstruction.
/// </summary>
public static class ShamirSecretSharing
{
    // GF(256) with irreducible polynomial p(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
    // exp[i] = g^i where g=0x03 is a generator
    // log[x] = i such that g^i = x  (undefined for x=0)

    private static readonly byte[] s_exp = new byte[256];
    private static readonly byte[] s_log = new byte[256];

    static ShamirSecretSharing()
    {
        // Build exp/log tables via repeated multiplication by g=0x03
        int x = 1;
        for (int i = 0; i < 255; i++)
        {
            s_exp[i] = (byte)x;
            s_log[x] = (byte)i;
            // Multiply x by g=3 in GF(256): x*3 = x*2 XOR x = (x<<1) XOR x
            // (x<<1) reduces mod 0x11B if bit 7 is set
            int x2 = x << 1;
            if ((x2 & 0x100) != 0) x2 ^= 0x11B;
            x = x2 ^ x; // multiply by 3 = 2+1
        }
        s_exp[255] = s_exp[0]; // wrap-around convenience
        // s_log[0] intentionally left 0 (never used in valid GF arithmetic)
    }

    // Multiply two GF(256) elements
    private static byte GfMul(byte a, byte b)
    {
        if (a == 0 || b == 0) return 0;
        int sum = s_log[a] + s_log[b];
        if (sum >= 255) sum -= 255;
        return s_exp[sum];
    }

    // Divide a/b in GF(256)
    private static byte GfDiv(byte a, byte b)
    {
        if (b == 0) throw new DivideByZeroException("GF(256) division by zero.");
        if (a == 0) return 0;
        int diff = s_log[a] - s_log[b];
        if (diff < 0) diff += 255;
        return s_exp[diff];
    }

    /// <summary>
    /// Evaluates polynomial at x: p(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
    /// Uses Horner's method: p(x) = c0 + x*(c1 + x*(c2 + ...))
    /// Traversal: start from highest degree coefficient.
    /// </summary>
    private static byte EvalPoly(byte[] coeffs, byte x)
    {
        byte result = 0;
        for (int i = coeffs.Length - 1; i >= 0; i--)
        {
            result = (byte)(GfMul(result, x) ^ coeffs[i]);
        }
        return result;
    }

    /// <summary>
    /// Splits a secret into <paramref name="n"/> shares with reconstruction threshold <paramref name="k"/>.
    /// Returns array of (1-based shareIndex, shareBytes).
    /// </summary>
    public static (int Index, byte[] Value)[] Split(byte[] secret, int threshold, int shares)
    {
        if (secret is null || secret.Length == 0)
            throw new ArgumentException("Secret must not be empty.", nameof(secret));
        if (threshold < 2)
            throw new ArgumentException("Threshold must be at least 2.", nameof(threshold));
        if (shares < threshold)
            throw new ArgumentException("Number of shares must be >= threshold.", nameof(shares));
        if (shares > 255)
            throw new ArgumentException("Maximum 255 shares supported in GF(256).", nameof(shares));

        int len = secret.Length;
        var result = new (int Index, byte[] Value)[shares];
        for (int s = 0; s < shares; s++)
            result[s] = (s + 1, new byte[len]);

        for (int byteIdx = 0; byteIdx < len; byteIdx++)
        {
            // Build degree-(threshold-1) polynomial: coeffs[0]=secret[byteIdx], coeffs[1..] random
            byte[] coeffs = new byte[threshold];
            coeffs[0] = secret[byteIdx];
            RandomNumberGenerator.Fill(coeffs.AsSpan(1));

            // Evaluate polynomial at x = 1, 2, ..., shares
            for (int s = 0; s < shares; s++)
            {
                byte xVal = (byte)(s + 1);
                result[s].Value[byteIdx] = EvalPoly(coeffs, xVal);
            }
        }

        return result;
    }

    /// <summary>
    /// Reconstructs the secret from at least <c>threshold</c> shares using Lagrange interpolation at x=0.
    /// </summary>
    public static byte[] Combine((int Index, byte[] Value)[] shares)
    {
        if (shares is null || shares.Length < 2)
            throw new ArgumentException("At least 2 shares are required.", nameof(shares));

        int len = shares[0].Value.Length;
        foreach (var sh in shares)
        {
            if (sh.Value.Length != len)
                throw new ArgumentException("All shares must have the same length.", nameof(shares));
            if (sh.Index < 1 || sh.Index > 255)
                throw new ArgumentException($"Invalid share index {sh.Index}. Must be 1-255.", nameof(shares));
        }

        // Check for duplicate indices
        var indices = shares.Select(s => s.Index).ToHashSet();
        if (indices.Count != shares.Length)
            throw new ArgumentException("Duplicate share indices are not allowed.", nameof(shares));

        byte[] secret = new byte[len];

        for (int byteIdx = 0; byteIdx < len; byteIdx++)
        {
            // Lagrange interpolation at x=0 over GF(256)
            // L(0) = sum_i [ y_i * prod_{j!=i} (0 - x_j) / (x_i - x_j) ]
            // In GF(256): 0 - x_j = x_j (additive inverse = self), x_i - x_j = x_i XOR x_j
            byte result = 0;

            for (int i = 0; i < shares.Length; i++)
            {
                byte xi = (byte)shares[i].Index;
                byte yi = shares[i].Value[byteIdx];

                // Compute Lagrange basis polynomial L_i(0)
                byte num = 1;   // product of (-x_j) = product of x_j  (for j != i)
                byte den = 1;   // product of (x_i - x_j) = product of (x_i XOR x_j)

                for (int j = 0; j < shares.Length; j++)
                {
                    if (j == i) continue;
                    byte xj = (byte)shares[j].Index;
                    num = GfMul(num, xj);              // 0 - xj = xj in GF(2^8)
                    den = GfMul(den, (byte)(xi ^ xj)); // xi - xj = xi XOR xj
                }

                // Add y_i * L_i(0) = y_i * num / den
                result ^= GfMul(yi, GfDiv(num, den));
            }

            secret[byteIdx] = result;
        }

        return secret;
    }
}
