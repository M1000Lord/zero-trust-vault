using Xunit;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Vault;

public sealed class OriginValidatorTests
{
    // ---- HTTP must fail ----

    [Theory]
    [InlineData("http://example.com")]
    [InlineData("http://example.com:80")]
    [InlineData("http://192.168.1.1")]
    [InlineData("http://localhost")]
    public void ValidateAndNormalize_HttpOrigin_ThrowsArgumentException(string origin)
    {
        Assert.Throws<ArgumentException>(() =>
            OriginValidator.ValidateAndNormalize(origin));
    }

    // ---- IDN / punycode must fail ----

    [Theory]
    [InlineData("https://xn--nxasmq6b.com")]          // internationalized
    [InlineData("https://www.xn--nxasmq6b.com")]      // subdomain with xn--
    [InlineData("https://xn--p1acf.xn--p1acf.com")]   // multiple punycode labels
    public void ValidateAndNormalize_IdnOrigin_ThrowsArgumentException(string origin)
    {
        Assert.Throws<ArgumentException>(() =>
            OriginValidator.ValidateAndNormalize(origin));
    }

    // ---- Non-HTTPS schemes must fail ----

    [Theory]
    [InlineData("ftp://example.com")]
    [InlineData("ws://example.com")]
    [InlineData("wss://example.com")]
    [InlineData("chrome-extension://abcdefghijklmnopqrstuvwxyz123456")]
    [InlineData("file:///etc/passwd")]
    public void ValidateAndNormalize_NonHttpsScheme_ThrowsArgumentException(string origin)
    {
        Assert.Throws<ArgumentException>(() =>
            OriginValidator.ValidateAndNormalize(origin));
    }

    // ---- Null / empty must fail ----

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateAndNormalize_NullOrEmpty_ThrowsArgumentException(string? origin)
    {
        Assert.Throws<ArgumentException>(() =>
            OriginValidator.ValidateAndNormalize(origin));
    }

    // ---- Valid HTTPS origins ----

    [Theory]
    [InlineData("https://example.com",         "https://example.com")]
    [InlineData("https://example.com:443",     "https://example.com")]   // default port stripped
    [InlineData("https://example.com:8443",    "https://example.com:8443")]
    [InlineData("https://sub.example.com",     "https://sub.example.com")]
    [InlineData("https://a.b.c.example.com",   "https://a.b.c.example.com")]
    [InlineData("https://example.com:1234",    "https://example.com:1234")]
    public void ValidateAndNormalize_ValidHttps_ReturnsNormalizedOrigin(string input, string expected)
    {
        string result = OriginValidator.ValidateAndNormalize(input);
        Assert.Equal(expected, result);
    }

    // ---- Port normalization ----

    [Fact]
    public void ValidateAndNormalize_Port443_IsStripped()
    {
        string result = OriginValidator.ValidateAndNormalize("https://example.com:443");
        Assert.Equal("https://example.com", result);
        Assert.DoesNotContain(":443", result);
    }

    [Fact]
    public void ValidateAndNormalize_NonDefaultPort_IsPreserved()
    {
        string result = OriginValidator.ValidateAndNormalize("https://example.com:8443");
        Assert.Contains(":8443", result);
    }

    // ---- Exact match ----

    [Fact]
    public void ExactMatch_SameOrigins_ReturnsTrue()
    {
        string a = OriginValidator.ValidateAndNormalize("https://example.com");
        string b = OriginValidator.ValidateAndNormalize("https://example.com");
        Assert.True(OriginValidator.ExactMatch(a, b));
    }

    [Fact]
    public void ExactMatch_DifferentOrigins_ReturnsFalse()
    {
        string a = OriginValidator.ValidateAndNormalize("https://example.com");
        string b = OriginValidator.ValidateAndNormalize("https://other.com");
        Assert.False(OriginValidator.ExactMatch(a, b));
    }

    [Fact]
    public void ExactMatch_DifferentPorts_ReturnsFalse()
    {
        string a = OriginValidator.ValidateAndNormalize("https://example.com:8443");
        string b = OriginValidator.ValidateAndNormalize("https://example.com:9000");
        Assert.False(OriginValidator.ExactMatch(a, b));
    }

    [Fact]
    public void ExactMatch_WithAndWithoutDefaultPort_ReturnsTrue()
    {
        // Both should normalize to "https://example.com"
        string a = OriginValidator.ValidateAndNormalize("https://example.com");
        string b = OriginValidator.ValidateAndNormalize("https://example.com:443");
        Assert.True(OriginValidator.ExactMatch(a, b));
    }

    // ---- IsValid helper ----

    [Fact]
    public void IsValid_ValidHttpsOrigin_ReturnsTrue()
    {
        Assert.True(OriginValidator.IsValid("https://example.com"));
    }

    [Fact]
    public void IsValid_HttpOrigin_ReturnsFalse()
    {
        Assert.False(OriginValidator.IsValid("http://example.com"));
    }

    [Fact]
    public void IsValid_IdnOrigin_ReturnsFalse()
    {
        Assert.False(OriginValidator.IsValid("https://xn--nxasmq6b.com"));
    }

    [Fact]
    public void IsValid_Null_ReturnsFalse()
    {
        Assert.False(OriginValidator.IsValid(null));
    }
}
