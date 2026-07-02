using Xunit;
using ZeroTrustVaultHost.Security;

namespace ZeroTrustVaultHost.Tests.Security;

/// <summary>
/// Section R regression tests: the health check must correctly classify
/// registration mode (HKLM vs HKCU vs none) and detect registry/manifest/exe
/// hijack indicators, using the pure Classify() function (no real registry
/// access needed to test the decision logic).
/// </summary>
public sealed class InstallationHealthCheckTests
{
    private const string ExpectedManifest = @"C:\Program Files\ZeroTrustVault\com.zerotrust.vault.json";
    private const string RunningExe = @"C:\Program Files\ZeroTrustVault\ZeroTrustVaultHost.exe";

    [Fact]
    public void HklmRegistered_MatchingManifestAndExe_IsHealthy()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: ExpectedManifest,
            hkcuRegisteredPath: null,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: true,
            manifestDeclaredExePath: RunningExe,
            runningExePath: RunningExe);

        Assert.Equal("HKLM", status.RegistrationMode);
        Assert.False(status.Degraded);
        Assert.Null(status.DegradedReason);
    }

    [Fact]
    public void HkcuOnly_IsDegraded()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: null,
            hkcuRegisteredPath: ExpectedManifest,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: true,
            manifestDeclaredExePath: RunningExe,
            runningExePath: RunningExe);

        Assert.Equal("HKCU", status.RegistrationMode);
        Assert.True(status.Degraded);
        Assert.Contains("HKCU", status.DegradedReason);
    }

    [Fact]
    public void NoRegistration_IsDegraded()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: null,
            hkcuRegisteredPath: null,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: false,
            manifestDeclaredExePath: null,
            runningExePath: RunningExe);

        Assert.Equal("None", status.RegistrationMode);
        Assert.True(status.Degraded);
    }

    [Fact]
    public void RegistryPointsToUnexpectedManifestPath_IsDegraded_RegistryHijackIndicator()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: @"C:\Users\attacker\evil\com.zerotrust.vault.json",
            hkcuRegisteredPath: null,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: true,
            manifestDeclaredExePath: RunningExe,
            runningExePath: RunningExe);

        Assert.True(status.Degraded);
        Assert.False(status.ManifestPathMatchesExpected);
        Assert.Contains("hijack", status.DegradedReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ManifestFileMissing_IsDegraded()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: ExpectedManifest,
            hkcuRegisteredPath: null,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: false,
            manifestDeclaredExePath: null,
            runningExePath: RunningExe);

        Assert.True(status.Degraded);
        Assert.False(status.ManifestFileExists);
    }

    [Fact]
    public void ManifestDeclaresDifferentExePath_IsDegraded_ExeHijackIndicator()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: ExpectedManifest,
            hkcuRegisteredPath: null,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: true,
            manifestDeclaredExePath: @"C:\Users\attacker\evil.exe",
            runningExePath: RunningExe);

        Assert.True(status.Degraded);
        Assert.False(status.ExePathMatchesRunningExe);
        Assert.Contains("hijack", status.DegradedReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HklmPreferredOverHkcu_WhenBothPresent()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: ExpectedManifest,
            hkcuRegisteredPath: ExpectedManifest,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: true,
            manifestDeclaredExePath: RunningExe,
            runningExePath: RunningExe);

        Assert.Equal("HKLM", status.RegistrationMode);
        Assert.True(status.HklmRegistered);
        Assert.True(status.HkcuRegistered);
        Assert.False(status.Degraded);
    }

    [Fact]
    public void ManifestPathComparison_IsCaseInsensitive_WindowsPaths()
    {
        var status = InstallationHealthCheck.Classify(
            hklmRegisteredPath: ExpectedManifest.ToUpperInvariant(),
            hkcuRegisteredPath: null,
            expectedManifestPath: ExpectedManifest,
            manifestFileExists: true,
            manifestDeclaredExePath: RunningExe,
            runningExePath: RunningExe);

        Assert.True(status.ManifestPathMatchesExpected);
        Assert.False(status.Degraded);
    }
}
