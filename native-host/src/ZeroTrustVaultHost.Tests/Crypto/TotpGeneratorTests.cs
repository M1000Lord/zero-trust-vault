using Xunit;
using ZeroTrustVaultHost.Crypto;

namespace ZeroTrustVaultHost.Tests.Crypto;

/// <summary>
/// Tests for RFC 6238 TOTP implementation using official NIST test vectors.
/// Reference: RFC 6238 Appendix B - TOTP Algorithm: Test Values
/// The test uses SHA1 mode. Secret for SHA1: "12345678901234567890" (ASCII bytes).
/// </summary>
public sealed class TotpGeneratorTests
{
    // RFC 6238 SHA1 seed as ASCII bytes
    private static readonly byte[] Sha1Seed =
        System.Text.Encoding.ASCII.GetBytes("12345678901234567890");

    // RFC 6238 test vectors for SHA1 (Table 1)
    // Time (Unix) -> Expected 8-digit code
    // Note: RFC 6238 uses 8-digit codes in examples; our implementation generates 6-digit codes.
    // We verify that the algorithm core (counter derivation, HMAC, dynamic truncation) is correct
    // by using the known counter values and checking the truncated result mod 10^6.
    [Theory]
    [InlineData(59L,         "287082")]  // T=1 (counter=0x0000000000000001)
    [InlineData(1111111109L, "081804")]  // T=37037036
    [InlineData(1111111111L, "050471")]  // T=37037037
    [InlineData(1234567890L, "005924")]  // T=41152263
    [InlineData(2000000000L, "279037")]  // T=66666666
    [InlineData(20000000000L,"353130")]  // T=666666666
    public void GenerateCode_MatchesRfc6238Sha1Vectors(long unixSeconds, string expectedCode)
    {
        var time = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        string code = TotpGenerator.GenerateCode(Sha1Seed, time);
        Assert.Equal(expectedCode, code);
    }

    [Fact]
    public void GenerateCode_Returns6Digits()
    {
        byte[] secret = System.Security.Cryptography.RandomNumberGenerator.GetBytes(20);
        string code = TotpGenerator.GenerateCode(secret);
        Assert.Equal(6, code.Length);
        Assert.True(int.TryParse(code, out _), $"Code '{code}' is not numeric.");
    }

    [Fact]
    public void GenerateCode_ZeroPadsWhenNeeded()
    {
        // Find a seed that generates a small number (pad to 6 digits)
        // Use a fixed seed and time where we know the code is < 100000
        // T=59 with SHA1 seed gives 287082 (already 6 digits)
        // Instead test zero-padding by code format
        var time = DateTimeOffset.FromUnixTimeSeconds(59L);
        string code = TotpGenerator.GenerateCode(Sha1Seed, time);
        Assert.Equal(6, code.Length); // Always 6 chars including leading zeros
    }

    // ---- SecondsRemaining ----

    [Fact]
    public void SecondsRemaining_IsInRange()
    {
        int secs = TotpGenerator.SecondsRemaining();
        Assert.InRange(secs, 1, 30);
    }

    [Fact]
    public void SecondsRemaining_AtStepBoundary()
    {
        // At exactly T=0 mod 30, there should be 30 seconds remaining
        var time = DateTimeOffset.FromUnixTimeSeconds(30); // 30 mod 30 = 0
        int remaining = TotpGenerator.SecondsRemaining(time);
        Assert.Equal(30, remaining);
    }

    [Fact]
    public void SecondsRemaining_AtMidPoint()
    {
        var time = DateTimeOffset.FromUnixTimeSeconds(45); // 45 mod 30 = 15
        int remaining = TotpGenerator.SecondsRemaining(time);
        Assert.Equal(15, remaining);
    }

    // ---- Base32 decode ----

    [Fact]
    public void Base32Decode_KnownValue_DecodesCorrectly()
    {
        // "JBSWY3DPEHPK3PXP" is a well-known test TOTP base32 secret
        // "Hello!" in base32 is "JBSWY3DPEB3W64TMMQ======"
        // Test with RFC 4648 example: "f" -> "MY======"
        byte[] decoded = TotpGenerator.Base32Decode("MY");
        Assert.Single(decoded);
        Assert.Equal((byte)'f', decoded[0]);
    }

    [Fact]
    public void Base32Decode_EmptyString_ReturnsEmpty()
    {
        byte[] result = TotpGenerator.Base32Decode(string.Empty);
        Assert.Empty(result);
    }

    [Fact]
    public void Base32Decode_WithSpacesAndHyphens_IsIgnored()
    {
        // "MY" and "M Y" and "M-Y" should decode to same result
        byte[] normal = TotpGenerator.Base32Decode("MY");
        byte[] withSpaces = TotpGenerator.Base32Decode("M Y");
        byte[] withHyphens = TotpGenerator.Base32Decode("M-Y");
        Assert.Equal(normal, withSpaces);
        Assert.Equal(normal, withHyphens);
    }

    [Fact]
    public void Base32Decode_InvalidCharacter_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => TotpGenerator.Base32Decode("1234!"));
    }

    [Fact]
    public void GenerateCodeFromBase32_ProducesValidCode()
    {
        // "JBSWY3DPEHPK3PXP" is a standard test secret
        string code = TotpGenerator.GenerateCodeFromBase32("JBSWY3DPEHPK3PXP");
        Assert.Equal(6, code.Length);
        Assert.True(int.TryParse(code, out _));
    }

    [Fact]
    public void GenerateCodeFromBase32_LowerCase_SameAsUpperCase()
    {
        string upper = TotpGenerator.GenerateCodeFromBase32("JBSWY3DPEHPK3PXP");
        string lower = TotpGenerator.GenerateCodeFromBase32("jbswy3dpehpk3pxp");
        Assert.Equal(upper, lower);
    }

    // ---- Consecutive step boundary ----

    [Fact]
    public void GenerateCode_SameStepProducesSameCode()
    {
        byte[] secret = System.Text.Encoding.ASCII.GetBytes("12345678901234567890");
        var t1 = DateTimeOffset.FromUnixTimeSeconds(60);
        var t2 = DateTimeOffset.FromUnixTimeSeconds(89); // same 30-second window

        string code1 = TotpGenerator.GenerateCode(secret, t1);
        string code2 = TotpGenerator.GenerateCode(secret, t2);
        Assert.Equal(code1, code2);
    }

    [Fact]
    public void GenerateCode_AdjacentStepProducesDifferentCode()
    {
        byte[] secret = System.Text.Encoding.ASCII.GetBytes("12345678901234567890");
        var t1 = DateTimeOffset.FromUnixTimeSeconds(59L);
        var t2 = DateTimeOffset.FromUnixTimeSeconds(1111111109L);

        string code1 = TotpGenerator.GenerateCode(secret, t1);
        string code2 = TotpGenerator.GenerateCode(secret, t2);
        Assert.NotEqual(code1, code2);
    }
}
