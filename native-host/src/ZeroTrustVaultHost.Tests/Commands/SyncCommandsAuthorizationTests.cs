using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Regression tests for Section A (centralized command authorization) as it
/// applies to sync commands specifically. Before this fix, syncPullEvents /
/// syncPushEvents / verifyEventLog validated a session ONLY when one was
/// supplied — a missing or empty sessionId fell through the check entirely
/// (see SyncCommands.cs history: `sessionEntry is null && !string.IsNullOrEmpty(...)`
/// is false when sessionId is null, so no error was ever returned). That let
/// any caller read the full mesh event log — device ids, item ids, timestamps
/// — with no authentication at all. These tests pin the fixed behavior:
/// session is required (any origin, since sync is device-wide not per-site),
/// and must be valid/unexpired.
/// </summary>
public sealed class SyncCommandsAuthorizationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly CommandRouter _router;
    private readonly SessionManager _sessionManager;

    public SyncCommandsAuthorizationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-sync-authz-" + Guid.NewGuid().ToString("N"));
        var vaultManager = new VaultManager(_tempDir);
        _sessionManager = new SessionManager();
        var helloManager = new StubHelloManager();
        var rateLimiter = new RateLimiter();
        var secEventLog = new SecurityEventLog();
        var eventLogManager = new EventLogManager(vaultManager);

        _router = new CommandRouter(
            vaultManager,
            _sessionManager,
            helloManager,
            rateLimiter,
            secEventLog,
            eventLogManager);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Theory]
    [InlineData("syncPullEvents")]
    [InlineData("syncPushEvents")]
    [InlineData("verifyEventLog")]
    public async Task MissingSession_IsRejected(string command)
    {
        var request = MakeRequest(command, sessionId: null);
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_REQUIRED", response.Error?.Code);
    }

    [Theory]
    [InlineData("syncPullEvents")]
    [InlineData("syncPushEvents")]
    [InlineData("verifyEventLog")]
    public async Task EmptySession_IsRejected(string command)
    {
        var request = MakeRequest(command, sessionId: "");
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_REQUIRED", response.Error?.Code);
    }

    [Theory]
    [InlineData("syncPullEvents")]
    [InlineData("syncPushEvents")]
    [InlineData("verifyEventLog")]
    public async Task UnknownSession_IsRejected(string command)
    {
        var request = MakeRequest(command, sessionId: Guid.NewGuid().ToString("D"));
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_INVALID", response.Error?.Code);
    }

    [Theory]
    [InlineData("syncPullEvents")]
    [InlineData("syncPushEvents")]
    [InlineData("verifyEventLog")]
    public async Task ValidSession_FromAnyOrigin_IsAccepted(string command)
    {
        // Sync is device-wide, not scoped to a single website — a session
        // created for one origin must still work for sync commands.
        string sessionId = _sessionManager.CreateSession("https://example.com");

        var request = MakeRequest(command, sessionId);
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.NotEqual("SESSION_REQUIRED", response.Error?.Code);
        Assert.NotEqual("SESSION_INVALID", response.Error?.Code);
    }

    [Theory]
    [InlineData("syncPullEvents")]
    [InlineData("syncPushEvents")]
    [InlineData("verifyEventLog")]
    public async Task ExpiredSession_IsRejected(string command)
    {
        var shortSessionManager = new SessionManager(TimeSpan.FromMilliseconds(1));
        var vaultManager = new VaultManager(_tempDir);
        var helloManager = new StubHelloManager();
        var router = new CommandRouter(
            vaultManager, shortSessionManager, helloManager,
            new RateLimiter(), new SecurityEventLog(), new EventLogManager(vaultManager));

        string sessionId = shortSessionManager.CreateSession("https://example.com");
        await Task.Delay(25);

        var request = MakeRequest(command, sessionId);
        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_EXPIRED", response.Error?.Code);
    }

    private static NativeMessaging.NativeRequest MakeRequest(string command, string? sessionId) =>
        new()
        {
            ProtocolVersion = 1,
            RequestId = Guid.NewGuid().ToString("D"),
            Command = command,
            Timestamp = DateTimeOffset.UtcNow.ToString("O"),
            ClientNonce = Guid.NewGuid().ToString("N"),
            ExtensionId = "abcdefghijklmnopabcdefghijklmnop",
            Origin = null,
            SessionId = sessionId,
            Payload = command == "syncPushEvents"
                ? JsonDocument.Parse("""{"events":[]}""").RootElement
                : JsonDocument.Parse("{}").RootElement,
        };
}
