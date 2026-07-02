using System.Security.Cryptography;
using Xunit;
using ZeroTrustVaultHost.Crypto;

namespace ZeroTrustVaultHost.Tests.Crypto;

public sealed class ShamirSecretSharingTests
{
    // ---- 3-of-5: Sufficient shares succeed ----

    [Fact]
    public void Combine_3Of5Shares_RecoversSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);
        Assert.Equal(5, shares.Length);

        // Use exactly 3 shares
        var subset = shares[0..3];
        byte[] recovered = ShamirSecretSharing.Combine(subset);
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void Combine_4Of5Shares_RecoversSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);

        var subset = shares[1..5]; // 4 shares
        byte[] recovered = ShamirSecretSharing.Combine(subset);
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void Combine_AllFiveShares_RecoversSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);
        byte[] recovered = ShamirSecretSharing.Combine(shares);
        Assert.Equal(secret, recovered);
    }

    // ---- 2-of-5: Insufficient shares fail ----

    [Fact]
    public void Combine_2Of5Shares_DoesNotRecoverSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);

        // Only 2 shares — should NOT recover the correct secret
        var subset = shares[0..2];
        byte[] wrong = ShamirSecretSharing.Combine(subset);
        Assert.NotEqual(secret, wrong);
    }

    [Fact]
    public void Combine_1Share_ThrowsArgumentException()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(16);
        var shares = ShamirSecretSharing.Split(secret, threshold: 2, shares: 3);

        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Combine(shares[0..1]));
    }

    // ---- Threshold boundary ----

    [Fact]
    public void Split_ThresholdEqualsShares_Works()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(16);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 3);
        Assert.Equal(3, shares.Length);

        byte[] recovered = ShamirSecretSharing.Combine(shares);
        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void Split_Threshold2Of3_Works()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(16);
        var shares = ShamirSecretSharing.Split(secret, threshold: 2, shares: 3);

        var subset = shares[0..2];
        byte[] recovered = ShamirSecretSharing.Combine(subset);
        Assert.Equal(secret, recovered);
    }

    // ---- Validation ----

    [Fact]
    public void Split_ThresholdLessThan2_ThrowsArgumentException()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(16);
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Split(secret, threshold: 1, shares: 5));
    }

    [Fact]
    public void Split_SharesLessThanThreshold_ThrowsArgumentException()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(16);
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Split(secret, threshold: 5, shares: 3));
    }

    [Fact]
    public void Split_EmptySecret_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            ShamirSecretSharing.Split(Array.Empty<byte>(), threshold: 2, shares: 3));
    }

    // ---- Share properties ----

    [Fact]
    public void Split_SharesHaveCorrectIndices()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(16);
        var shares = ShamirSecretSharing.Split(secret, threshold: 2, shares: 5);

        for (int i = 0; i < shares.Length; i++)
        {
            Assert.Equal(i + 1, shares[i].Index); // 1-based indices
        }
    }

    [Fact]
    public void Split_SharesHaveCorrectLength()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);

        foreach (var share in shares)
        {
            Assert.Equal(secret.Length, share.Value.Length);
        }
    }

    [Fact]
    public void Split_SharesAreNotIdentical()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);

        // All shares should differ (with overwhelming probability)
        for (int i = 0; i < shares.Length; i++)
        {
            for (int j = i + 1; j < shares.Length; j++)
            {
                Assert.NotEqual(shares[i].Value, shares[j].Value);
            }
        }
    }

    [Fact]
    public void Split_SharesDoNotRevealSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);

        // No individual share should equal the secret
        foreach (var share in shares)
        {
            Assert.NotEqual(secret, share.Value);
        }
    }

    // ---- Different secret lengths ----

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void Split_VariousSecretLengths_RoundTrip(int length)
    {
        byte[] secret = RandomNumberGenerator.GetBytes(length);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);
        byte[] recovered = ShamirSecretSharing.Combine(shares[0..3]);
        Assert.Equal(secret, recovered);
    }

    // ---- Non-sequential share selection ----

    [Fact]
    public void Combine_NonSequentialShares_RecoversSecret()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);

        // Use shares 0, 2, 4 (indices 1, 3, 5)
        var subset = new[] { shares[0], shares[2], shares[4] };
        byte[] recovered = ShamirSecretSharing.Combine(subset);
        Assert.Equal(secret, recovered);
    }

    // ---- Known GF(256) properties ----

    [Fact]
    public void Split_DifferentRuns_ProduceDifferentShares()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        var shares1 = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);
        var shares2 = ShamirSecretSharing.Split(secret, threshold: 3, shares: 5);

        // Random polynomial coefficients mean different runs produce different shares
        bool anyDifferent = false;
        for (int i = 0; i < 5; i++)
        {
            if (!shares1[i].Value.SequenceEqual(shares2[i].Value))
            {
                anyDifferent = true;
                break;
            }
        }
        Assert.True(anyDifferent, "Two splits of the same secret produced identical shares (extremely unlikely).");
    }
}
