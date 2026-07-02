using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Section A regression tests: every session-gated vault command must reject
/// a missing session, an unknown session, a session bound to a different
/// origin, and an expired session — consistently, via the centralized
/// CommandContext.ValidateSessionForOrigin gate. Before centralization these
/// checks were re-implemented per-handler with no test pinning the error
/// codes, so a future handler could easily drift or omit one.
/// </summary>
public sealed class VaultCommandsAuthorizationTests : IDisposable
{
    private const string OriginA = "https://a.example.com";
    private const string OriginB = "https://b.example.com";

    private readonly string _tempDir;
    private readonly VaultManager _vaultManager;
    private readonly SessionManager _sessionManager;
    private readonly CommandRouter _router;

    public VaultCommandsAuthorizationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-vault-authz-" + Guid.NewGuid().ToString("N"));
        _vaultManager = new VaultManager(_tempDir);
        _sessionManager = new SessionManager();
        var helloManager = new StubHelloManager();
        var rateLimiter = new RateLimiter();
        var secEventLog = new SecurityEventLog();
        var eventLogManager = new EventLogManager(_vaultManager);

        _router = new CommandRouter(
            _vaultManager, _sessionManager, helloManager,
            rateLimiter, secEventLog, eventLogManager);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private async Task BootstrapVaultAsync()
    {
        var unlock = MakeRequest("unlockOrigin", OriginA, sessionId: null);
        var response = await _router.RouteAsync(unlock, CancellationToken.None);
        Assert.Equal("ok", response.Status);
    }

    [Theory]
    [InlineData("listSummariesForOrigin")]
    [InlineData("countCredentialsForOrigin")]
    public async Task LowRiskCommand_MissingSession_ReturnsSessionRequired(string command)
    {
        await BootstrapVaultAsync();

        var request = MakeRequest(command, OriginA, sessionId: null);
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_REQUIRED", response.Error?.Code);
    }

    [Theory]
    [InlineData("listSummariesForOrigin")]
    [InlineData("countCredentialsForOrigin")]
    public async Task LowRiskCommand_UnknownSession_ReturnsSessionInvalid(string command)
    {
        await BootstrapVaultAsync();

        var request = MakeRequest(command, OriginA, sessionId: Guid.NewGuid().ToString("D"));
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_INVALID", response.Error?.Code);
    }

    [Theory]
    [InlineData("listSummariesForOrigin")]
    [InlineData("countCredentialsForOrigin")]
    public async Task LowRiskCommand_SessionForDifferentOrigin_ReturnsOriginMismatch(string command)
    {
        await BootstrapVaultAsync();
        string sessionForA = _sessionManager.CreateSession(OriginA);

        // Same session, but the request claims a different origin.
        var request = MakeRequest(command, OriginB, sessionId: sessionForA);
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_ORIGIN_MISMATCH", response.Error?.Code);
    }

    [Theory]
    [InlineData("listSummariesForOrigin")]
    [InlineData("countCredentialsForOrigin")]
    public async Task LowRiskCommand_ExpiredSession_ReturnsSessionExpired(string command)
    {
        var shortSessionManager = new SessionManager(TimeSpan.FromMilliseconds(1));
        var vaultManager = new VaultManager(_tempDir);
        var helloManager = new StubHelloManager();
        var router = new CommandRouter(
            vaultManager, shortSessionManager, helloManager,
            new RateLimiter(), new SecurityEventLog(), new EventLogManager(vaultManager));

        var unlock = MakeRequest("unlockOrigin", OriginA, sessionId: null);
        await router.RouteAsync(unlock, CancellationToken.None);

        string sessionId = shortSessionManager.CreateSession(OriginA);
        await Task.Delay(25);

        var request = MakeRequest(command, OriginA, sessionId);
        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_EXPIRED", response.Error?.Code);
    }

    [Fact]
    public async Task Reveal_MissingSession_ReturnsSessionRequired()
    {
        await BootstrapVaultAsync();

        var request = MakeRequest(
            "decryptSelectedCredentialForExactOrigin", OriginA, sessionId: null,
            payloadJson: """{"credentialId":"00000000-0000-0000-0000-000000000000"}""");
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_REQUIRED", response.Error?.Code);
    }

    [Fact]
    public async Task Reveal_SessionForDifferentOrigin_ReturnsOriginMismatch()
    {
        await BootstrapVaultAsync();
        string sessionForA = _sessionManager.CreateSession(OriginA);

        var request = MakeRequest(
            "decryptSelectedCredentialForExactOrigin", OriginB, sessionId: sessionForA,
            payloadJson: """{"credentialId":"00000000-0000-0000-0000-000000000000"}""");
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("SESSION_ORIGIN_MISMATCH", response.Error?.Code);
    }

    private static NativeRequest MakeRequest(string command, string? origin, string? sessionId, string payloadJson = "{}") =>
        new()
        {
            ProtocolVersion = 1,
            RequestId = Guid.NewGuid().ToString("D"),
            Command = command,
            Timestamp = DateTimeOffset.UtcNow.ToString("O"),
            ClientNonce = Guid.NewGuid().ToString("N"),
            ExtensionId = "abcdefghijklmnopabcdefghijklmnop",
            Origin = origin,
            SessionId = sessionId,
            Payload = JsonDocument.Parse(payloadJson).RootElement,
        };
}
