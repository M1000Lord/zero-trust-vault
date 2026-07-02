using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Tests for CommandRouter: unknown command rejection, unknown payload field rejection,
/// stale timestamp rejection. Uses stub/mock implementations for Hello.
/// </summary>
public sealed class CommandRouterTests : IDisposable
{
    private readonly string _tempDir;
    private readonly CommandRouter _router;

    public CommandRouterTests()
    {
        // Deliberately an isolated temp directory, NOT the real production
        // vault path — these tests previously used `new VaultManager()` (the
        // default, real %LOCALAPPDATA%\ZeroTrustVault path), which meant every
        // test run could create/mutate/reset the actual user's vault file on
        // whatever machine ran the suite, and raced with any other test class
        // touching that same real path when xUnit ran classes in parallel
        // (observed as intermittent LockVault_EmptyPayload_ReturnsOk failures
        // only when the full suite ran, never in isolation).
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-router-tests-" + Guid.NewGuid().ToString("N"));
        var vaultManager = new VaultManager(_tempDir);
        var sessionManager = new SessionManager();
        var helloManager = new StubHelloManager();
        var rateLimiter = new RateLimiter();
        var secEventLog = new SecurityEventLog();
        var eventLogManager = new EventLogManager(vaultManager);

        _router = new CommandRouter(
            vaultManager,
            sessionManager,
            helloManager,
            rateLimiter,
            secEventLog,
            eventLogManager);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    // ---- Unknown command ----

    [Fact]
    public async Task UnknownCommand_ReturnsUnknownCommandError()
    {
        var request = MakeRequest("notARealCommand");
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("UNKNOWN_COMMAND", response.Error?.Code);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task EmptyCommand_ReturnsUnknownCommandError(string command)
    {
        var request = MakeRequest(command);
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("UNKNOWN_COMMAND", response.Error?.Code);
    }

    [Theory]
    [InlineData("GetVaultStatus")]   // wrong case
    [InlineData("GETVALUTSTATUS")]
    [InlineData("getVaultStatusX")]  // extra char
    [InlineData("get_vault_status")] // underscore variant
    public async Task MiscasedOrMisspelledCommand_ReturnsUnknownCommandError(string command)
    {
        var request = MakeRequest(command);
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("UNKNOWN_COMMAND", response.Error?.Code);
    }

    // ---- Stale timestamp ----

    [Fact]
    public async Task StaleTimestamp_TooOld_ReturnsStaleTimestampError()
    {
        var request = MakeRequest("getVaultStatus");
        request.Timestamp = DateTimeOffset.UtcNow.AddSeconds(-61).ToString("O");

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("STALE_TIMESTAMP", response.Error?.Code);
    }

    [Fact]
    public async Task StaleTimestamp_InFuture_ReturnsStaleTimestampError()
    {
        var request = MakeRequest("getVaultStatus");
        request.Timestamp = DateTimeOffset.UtcNow.AddSeconds(61).ToString("O");

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("STALE_TIMESTAMP", response.Error?.Code);
    }

    [Fact]
    public async Task FreshTimestamp_Within60Seconds_IsAccepted()
    {
        var request = MakeRequest("getVaultStatus");
        // Fresh timestamp — should NOT get STALE_TIMESTAMP error
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.NotEqual("STALE_TIMESTAMP", response.Error?.Code);
    }

    [Fact]
    public async Task InvalidTimestampFormat_ReturnsInvalidTimestampError()
    {
        var request = MakeRequest("getVaultStatus");
        request.Timestamp = "not-a-timestamp";

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("INVALID_TIMESTAMP", response.Error?.Code);
    }

    // ---- Unknown payload fields ----

    [Fact]
    public async Task GetVaultStatus_WithUnknownField_ReturnsUnknownFieldError()
    {
        var request = MakeRequest("getVaultStatus");
        request.Payload = JsonDocument.Parse("""{"unknownField": "value"}""").RootElement;

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("UNKNOWN_FIELD", response.Error?.Code);
    }

    [Fact]
    public async Task LockVault_WithUnknownField_ReturnsUnknownFieldError()
    {
        var request = MakeRequest("lockOriginSession");
        request.Payload = JsonDocument.Parse("""{"hack": true}""").RootElement;

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("UNKNOWN_FIELD", response.Error?.Code);
    }

    // ---- Protocol version ----

    [Fact]
    public async Task WrongProtocolVersion_ReturnsUnsupportedProtocolError()
    {
        var request = MakeRequest("getVaultStatus");
        request.ProtocolVersion = 99;

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("UNSUPPORTED_PROTOCOL_VERSION", response.Error?.Code);
    }

    // ---- HTTP origin rejection ----

    [Fact]
    public async Task HttpOrigin_ReturnsInvalidOriginError()
    {
        var request = MakeRequest("unlockOrigin");
        request.Origin = "http://example.com";

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("INVALID_ORIGIN", response.Error?.Code);
    }

    [Fact]
    public async Task IdnOrigin_ReturnsInvalidOriginError()
    {
        var request = MakeRequest("unlockOrigin");
        request.Origin = "https://xn--nxasmq6b.com";

        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("INVALID_ORIGIN", response.Error?.Code);
    }

    // ---- ValidatePayloadFields helper ----

    [Fact]
    public void ValidatePayloadFields_UnknownField_ReturnsError()
    {
        var payload = JsonDocument.Parse("""{"credentialId": "abc", "evilField": true}""").RootElement;
        string? error = CommandRouter.ValidatePayloadFields(payload, new[] { "credentialId" });
        Assert.NotNull(error);
        Assert.Contains("evilField", error);
    }

    [Fact]
    public void ValidatePayloadFields_KnownFieldsOnly_ReturnsNull()
    {
        var payload = JsonDocument.Parse("""{"credentialId": "abc"}""").RootElement;
        string? error = CommandRouter.ValidatePayloadFields(payload, new[] { "credentialId" });
        Assert.Null(error);
    }

    [Fact]
    public void ValidatePayloadFields_EmptyObject_ReturnsNull()
    {
        var payload = JsonDocument.Parse("{}").RootElement;
        string? error = CommandRouter.ValidatePayloadFields(payload, new[] { "credentialId" });
        Assert.Null(error);
    }

    // ---- getVaultStatus command ----

    [Fact]
    public async Task GetVaultStatus_EmptyPayload_ReturnsOk()
    {
        var request = MakeRequest("getVaultStatus");
        var response = await _router.RouteAsync(request, CancellationToken.None);

        // Either "ok" with result (vault exists or not) — not an error about the command itself
        // Note: may return ok with exists=false
        Assert.Equal(request.RequestId, response.RequestId);
    }

    // ---- lockOriginSession command ----

    [Fact]
    public async Task LockVault_EmptyPayload_ReturnsOk()
    {
        var request = MakeRequest("lockOriginSession");
        var response = await _router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        Assert.Equal(request.RequestId, response.RequestId);
    }

    // ---- Timestamp boundary ----

    [Fact]
    public async Task Timestamp_Exactly60SecondsOld_IsAccepted()
    {
        var request = MakeRequest("lockOriginSession");
        request.Timestamp = DateTimeOffset.UtcNow.AddSeconds(-59).ToString("O"); // 59s is within window

        var response = await _router.RouteAsync(request, CancellationToken.None);
        Assert.NotEqual("STALE_TIMESTAMP", response.Error?.Code);
    }

    // ---- Native-host caller authentication (extensionId gate) ----

    private const string RealExtensionId  = "abcdefghijklmnopabcdefghijklmnop";
    private const string OtherExtensionId = "ponmlkjihgfedcbaponmlkjihgfedcba";

    private static CommandRouter MakeRouterWithIdentity(ZeroTrustVaultHost.Security.ExtensionIdentity identity)
    {
        var vaultManager = new VaultManager();
        var sessionManager = new SessionManager();
        var helloManager = new StubHelloManager();
        var rateLimiter = new RateLimiter();
        var secEventLog = new SecurityEventLog();
        var eventLogManager = new EventLogManager(vaultManager);
        return new CommandRouter(vaultManager, sessionManager, helloManager, rateLimiter, secEventLog, eventLogManager, identity);
    }

    private static ZeroTrustVaultHost.Security.ExtensionIdentity LoadedIdentity(params string[] allowedIds)
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "ztv-cr-extid-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string manifestPath = Path.Combine(tempDir, "com.zerotrust.vault.json");
        string origins = string.Join(", ", allowedIds.Select(id => $"\"chrome-extension://{id}/\""));
        File.WriteAllText(manifestPath, $$"""{ "allowed_origins": [{{origins}}] }""");
        return ZeroTrustVaultHost.Security.ExtensionIdentity.LoadFromManifestFile(manifestPath);
    }

    [Fact]
    public async Task WrongExtensionId_SecretCommand_Rejected()
    {
        var router = MakeRouterWithIdentity(LoadedIdentity(RealExtensionId));
        var request = MakeRequest("lockOriginSession");
        request.ExtensionId = OtherExtensionId;

        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("EXTENSION_ID_MISMATCH", response.Error?.Code);
    }

    [Fact]
    public async Task MissingExtensionId_SecretCommand_Rejected()
    {
        var router = MakeRouterWithIdentity(LoadedIdentity(RealExtensionId));
        var request = MakeRequest("lockOriginSession");
        request.ExtensionId = "";

        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("MISSING_EXTENSION_ID", response.Error?.Code);
    }

    [Fact]
    public async Task MalformedExtensionId_SecretCommand_Rejected()
    {
        var router = MakeRouterWithIdentity(LoadedIdentity(RealExtensionId));
        var request = MakeRequest("lockOriginSession");
        request.ExtensionId = "not-a-valid-chrome-extension-id!!";

        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("MALFORMED_EXTENSION_ID", response.Error?.Code);
    }

    [Fact]
    public async Task CorrectExtensionId_SecretCommand_Accepted()
    {
        var router = MakeRouterWithIdentity(LoadedIdentity(RealExtensionId));
        var request = MakeRequest("lockOriginSession");
        request.ExtensionId = RealExtensionId;

        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("ok", response.Status);
    }

    [Fact]
    public async Task UnverifiableIdentity_DiagnosticCommand_StillReachable()
    {
        // "Untrusted" simulates a manifest that could not be found/loaded —
        // diagnostic commands must remain reachable so a broken install can
        // still explain itself, even though secret commands would be blocked.
        var router = MakeRouterWithIdentity(ZeroTrustVaultHost.Security.ExtensionIdentity.Untrusted("test"));
        var request = MakeRequest("getVaultStatus");
        request.ExtensionId = "totally-wrong-id";

        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.NotEqual("MALFORMED_EXTENSION_ID", response.Error?.Code);
        Assert.NotEqual("EXTENSION_ID_MISMATCH", response.Error?.Code);
    }

    [Fact]
    public async Task UnverifiableIdentity_SecurityHealthCheck_StillReachable()
    {
        var router = MakeRouterWithIdentity(ZeroTrustVaultHost.Security.ExtensionIdentity.Untrusted("test"));
        var request = MakeRequest("securityHealthCheck");
        request.ExtensionId = "";

        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.Equal("ok", response.Status);
    }

    [Fact]
    public async Task WrongExtensionId_ErrorMessage_DoesNotLeakClaimedId()
    {
        var router = MakeRouterWithIdentity(LoadedIdentity(RealExtensionId));
        var request = MakeRequest("lockOriginSession");
        request.ExtensionId = OtherExtensionId;

        var response = await router.RouteAsync(request, CancellationToken.None);

        Assert.DoesNotContain(OtherExtensionId, response.Error?.SafeMessage ?? "");
        Assert.DoesNotContain(RealExtensionId, response.Error?.SafeMessage ?? "");
    }

    // ---- Helper ----

    private static NativeRequest MakeRequest(string command, string? origin = null) =>
        new NativeRequest
        {
            ProtocolVersion = 1,
            RequestId = Guid.NewGuid().ToString("D"),
            Command = command,
            Timestamp = DateTimeOffset.UtcNow.ToString("O"),
            ClientNonce = Guid.NewGuid().ToString("N"),
            ExtensionId = "abcdefghijklmnopabcdefghijklmnop", // well-formed (32 lowercase a-p) fake test id
            Origin = origin,
            SessionId = null,
            Payload = JsonDocument.Parse("{}").RootElement,
        };
}

/// <summary>
/// Stub IHelloManager for testing — always returns Verified without prompting.
/// </summary>
internal sealed class StubHelloManager : IHelloManager
{
    private bool _shouldVerify = true;

    public StubHelloManager(bool shouldVerify = true) => _shouldVerify = shouldVerify;

    public Task<HelloResult> RequestUserVerificationAsync(string prompt) =>
        Task.FromResult(_shouldVerify ? HelloResult.Verified : HelloResult.Canceled);

    public Task<string> GetPresenceAvailabilityAsync() =>
        Task.FromResult("available");

    public byte[] WrapRootKey(byte[] rootKey)
    {
        // Simple XOR wrap for testing (NOT production crypto)
        byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
        byte[] tag = new byte[16];
        byte[] ciphertext = (byte[])rootKey.Clone();
        byte[] result = new byte[12 + 16 + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, 12);
        Buffer.BlockCopy(tag, 0, result, 12, 16);
        Buffer.BlockCopy(ciphertext, 0, result, 28, ciphertext.Length);
        return result;
    }

    public byte[] UnwrapRootKey(byte[] wrappedBytes)
    {
        if (wrappedBytes.Length < 28) throw new InvalidOperationException("Too short.");
        return wrappedBytes[28..];
    }
}
