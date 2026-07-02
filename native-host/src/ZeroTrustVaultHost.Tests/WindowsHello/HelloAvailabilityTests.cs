using Xunit;
using ZeroTrustVaultHost.WindowsHello;

namespace ZeroTrustVaultHost.Tests.WindowsHello;

/// <summary>
/// Tests for the canonical Hello availability vocabulary and the case-insensitive
/// "is usable" check. This is the native-host half of the casing-bug fix; the
/// popup half (helloAvailabilityState) is mirrored here in intent.
/// </summary>
public sealed class HelloAvailabilityTests
{
    [Theory]
    [InlineData("Available")]
    [InlineData("available")]   // the original bug: lowercase must still count as usable
    [InlineData("AVAILABLE")]
    public void IsUsable_AvailableAnyCase_True(string value) =>
        Assert.True(HelloAvailability.IsUsable(value));

    [Theory]
    [InlineData("DeviceNotPresent")]
    [InlineData("NotConfigured")]
    [InlineData("DisabledByPolicy")]
    [InlineData("Unavailable")]
    [InlineData("Unknown")]
    [InlineData("")]
    [InlineData(null)]
    public void IsUsable_NonAvailable_False(string? value) =>
        Assert.False(HelloAvailability.IsUsable(value));

    [Fact]
    public void CanonicalConstants_HaveExpectedValues()
    {
        Assert.Equal("Available",        HelloAvailability.Available);
        Assert.Equal("DeviceNotPresent", HelloAvailability.DeviceNotPresent);
        Assert.Equal("NotConfigured",    HelloAvailability.NotConfigured);
        Assert.Equal("DisabledByPolicy", HelloAvailability.DisabledByPolicy);
        Assert.Equal("Unavailable",      HelloAvailability.Unavailable);
        Assert.Equal("Unknown",          HelloAvailability.Unknown);
    }
}
