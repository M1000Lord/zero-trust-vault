using Xunit;
using ZeroTrustVaultHost.Diagnostics;

namespace ZeroTrustVaultHost.Tests.Diagnostics;

/// <summary>
/// Tests for the redaction backstop in DiagnosticLog. Even though callers must
/// never pass secrets, redaction guarantees that anything that slips through is
/// masked before it can land in a log line.
/// </summary>
public sealed class DiagnosticLogTests
{
    [Theory]
    [InlineData("password=hunter2longvalue")]
    [InlineData("Password: hunter2longvalue")]
    [InlineData("totpSecret=JBSWY3DPEHPK3PXP")]
    [InlineData("rootKey=00112233445566778899aabbccddeeff")]
    public void Redact_MasksSensitiveKeyValues(string input)
    {
        string output = DiagnosticLog.Redact(input);
        Assert.Contains("***REDACTED***", output);
        Assert.DoesNotContain("hunter2longvalue", output);
        Assert.DoesNotContain("JBSWY3DPEHPK3PXP", output);
    }

    [Fact]
    public void Redact_MasksLongBase64Blobs()
    {
        string secret = "QmFzZTY0RW5jb2RlZFNlY3JldEtleU1hdGVyaWFsMTIzNDU2Nzg5";
        string output = DiagnosticLog.Redact($"wrapped {secret} done");
        Assert.DoesNotContain(secret, output);
        Assert.Contains("***REDACTED***", output);
    }

    [Fact]
    public void Redact_LeavesShortNonSensitiveTextAlone()
    {
        string output = DiagnosticLog.Redact("status=ok count=3");
        Assert.Contains("status=ok", output);
        Assert.Contains("count=3", output);
    }

    [Fact]
    public void Redact_NullOrEmpty_DoesNotThrow()
    {
        Assert.Equal(string.Empty, DiagnosticLog.Redact(""));
        Assert.Equal(string.Empty, DiagnosticLog.Redact(null!));
    }

    [Fact]
    public void Write_NeverThrows()
    {
        // Should be safe regardless of enabled state.
        var ex = Record.Exception(() => DiagnosticLog.Write("TEST", "password=secretvalue123"));
        Assert.Null(ex);
    }
}
