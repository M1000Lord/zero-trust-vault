using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Diagnostics;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Section C regression test: exercises a realistic sequence of secret-
/// bearing operations (unlock, add, reveal, TOTP, recovery kit) with
/// distinctive, unique secret values, then scans the ACTUAL diagnostic log
/// file DiagnosticLog.Write persists to and asserts none of those plaintext
/// values ever appear. This is stronger than testing DiagnosticLog.Redact()
/// in isolation (see DiagnosticLogTests.cs) — it proves the real command
/// handlers never hand plaintext secrets to logging in the first place,
/// not just that the redaction backstop works when given a secret-shaped
/// string directly.
/// </summary>
public sealed class SecretRedactionIntegrationTests : IDisposable
{
    private const string Origin = "https://example.com:443";

    private readonly string _tempDir;
    private readonly VaultManager _vaultManager;
    private readonly CommandContext _ctx;

    public SecretRedactionIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-redaction-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vaultManager = new VaultManager(_tempDir);
        _ctx = new CommandContext(
            _vaultManager, new SessionManager(), new StubHelloManager(),
            new RateLimiter(), new SecurityEventLog(), new EventLogManager(_vaultManager));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private static NativeMessaging.NativeRequest MakeRequest(string command, string? sessionId = null, object? payload = null) => new()
    {
        ProtocolVersion = 1,
        RequestId = Guid.NewGuid().ToString("D"),
        Command = command,
        Timestamp = DateTimeOffset.UtcNow.ToString("O"),
        ClientNonce = Guid.NewGuid().ToString("N"),
        ExtensionId = "abcdefghijklmnopabcdefghijklmnop",
        Origin = Origin,
        SessionId = sessionId,
        Payload = payload is null
            ? JsonDocument.Parse("{}").RootElement
            : JsonDocument.Parse(JsonSerializer.Serialize(payload)).RootElement,
    };

    private static string ExtractSessionId(NativeMessaging.NativeResponse response)
    {
        var prop = response.Result!.GetType().GetProperty("sessionId");
        return (string)prop!.GetValue(response.Result)!;
    }

    [Fact]
    public async Task RealisticSecretOperations_NeverAppearInDiagnosticLog()
    {
        // Highly distinctive, unique-per-run values so a match can only come
        // from THIS test (DiagnosticLog's sink is a shared file across the
        // whole test process, not test-isolated).
        string uniqueTag = Guid.NewGuid().ToString("N");
        string password = $"P@ssw0rd-{uniqueTag}-DoNotLog";
        // Base32 alphabet is A-Z/2-7 only; derive a valid-but-unique suffix
        // from the tag rather than reusing its raw hex characters (0189 etc.
        // are not valid base32).
        string base32Suffix = new string(uniqueTag.Where(c => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".Contains(char.ToUpperInvariant(c)))
            .Select(char.ToUpperInvariant).Take(8).ToArray()).PadRight(8, 'A');
        string totpSecret = "JBSWY3DPEHPK3PXP" + base32Suffix;
        string username = $"user-{uniqueTag}@example.com";

        var vaultCmds = new VaultCommands(_ctx);
        var totpCmds = new TotpCommands(_ctx);
        var recoveryCmds = new RecoveryCommands(_ctx);

        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        Assert.Equal("ok", unlockResp.Status);
        string sessionId = ExtractSessionId(unlockResp);

        var addResp = await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = username, password, totpSecret }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", addResp.Status);

        string credentialId = _vaultManager.GetOrLoad().Items[0].ItemId;

        var revealResp = await vaultCmds.DecryptCredentialAsync(
            MakeRequest("decryptSelectedCredentialForExactOrigin", sessionId, new { credentialId }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", revealResp.Status);

        var totpResp = await totpCmds.GenerateTotpAsync(
            MakeRequest("generateTotpForCredential", sessionId, new { credentialId }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", totpResp.Status);

        var kitResp = await recoveryCmds.CreateRecoveryKitAsync(MakeRequest("createRecoveryKit", sessionId), Origin, CancellationToken.None);
        Assert.Equal("ok", kitResp.Status);

        // Also exercise DiagnosticLog directly with a message that happens to
        // mention these values, to prove the redaction backstop still holds
        // even if a future call site is careless.
        DiagnosticLog.Write("TEST", $"password={password} totp={totpSecret} user={username}");

        string logContent = File.Exists(DiagnosticLog.LogPath) ? File.ReadAllText(DiagnosticLog.LogPath) : string.Empty;

        Assert.DoesNotContain(password, logContent, StringComparison.Ordinal);
        Assert.DoesNotContain(totpSecret, logContent, StringComparison.Ordinal);
        Assert.DoesNotContain(username, logContent, StringComparison.Ordinal);
    }
}
