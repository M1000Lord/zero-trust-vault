using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Proves the root-key lifetime redesign: the plaintext root key is unwrapped
/// fresh for each operation and zeroized before the response is returned —
/// never cached across calls. Each test captures the ACTUAL byte[] instance
/// handed back by UnwrapRootKey (via <see cref="CapturingHelloManager"/>) and
/// asserts every byte is zero once the command handler has returned.
/// </summary>
public sealed class RootKeyLifetimeTests : IDisposable
{
    private readonly string _tempDir;
    private readonly VaultManager _vaultManager;
    private readonly CapturingHelloManager _hello;
    private readonly CommandContext _ctx;
    private const string Origin = "https://example.com:443";

    public RootKeyLifetimeTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-rootkey-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vaultManager = new VaultManager(_tempDir);
        _hello = new CapturingHelloManager();
        _ctx = new CommandContext(
            _vaultManager,
            new SessionManager(),
            _hello,
            new RateLimiter(),
            new SecurityEventLog(),
            new EventLogManager(_vaultManager));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private static void AssertAllZero(byte[]? key)
    {
        Assert.NotNull(key);
        Assert.All(key!, b => Assert.Equal(0, b));
    }

    private static NativeRequest MakeRequest(string command, string? sessionId = null, object? payload = null) => new()
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

    /// <summary>Bootstraps a vault directly (bypassing the capturing stub) so
    /// the "vault already exists" code path — the one that unwraps via the
    /// capturable interface method — is what subsequent calls exercise.</summary>
    private string Bootstrap()
    {
        byte[] root = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        byte[] wrapped = _hello.WrapRootKey(root);
        _vaultManager.CreateNew(wrapped);
        VaultCrypto.SecureClear(root);
        return Convert.ToBase64String(wrapped);
    }

    // ---- unlockOrigin ----

    [Fact]
    public async Task Unlock_ExistingVault_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var request = MakeRequest("unlockOrigin");

        var response = await vaultCmds.UnlockAsync(request, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        Assert.NotEmpty(_hello.UnwrappedKeys);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    // ---- listSummariesForOrigin ----

    [Fact]
    public async Task List_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        var request = MakeRequest("listSummariesForOrigin", sessionId);
        var response = await vaultCmds.ListCredentialSummariesAsync(request, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    // ---- addCredentialForExactOrigin ----

    [Fact]
    public async Task Add_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var addRequest = MakeRequest("addCredentialForExactOrigin", null, new { usernameOrEmail = "u", password = "p" });

        var response = await vaultCmds.AddCredentialAsync(addRequest, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    // ---- decryptSelectedCredentialForExactOrigin (reveal) + fill share the same path ----

    [Fact]
    public async Task Reveal_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        var addResp = await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", addResp.Status);

        var vault = _vaultManager.GetOrLoad();
        string credentialId = vault.Items[0].ItemId;

        var revealRequest = MakeRequest("decryptSelectedCredentialForExactOrigin", sessionId, new { credentialId });
        var response = await vaultCmds.DecryptCredentialAsync(revealRequest, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    // ---- fillCredentialForExactOrigin ----

    [Fact]
    public async Task Fill_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        var addResp = await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", addResp.Status);

        var vault = _vaultManager.GetOrLoad();
        string credentialId = vault.Items[0].ItemId;

        var fillRequest = MakeRequest("fillCredentialForExactOrigin", sessionId, new { credentialId });
        fillRequest.TabId = 1;
        fillRequest.WindowId = 1;
        var response = await vaultCmds.FillCredentialAsync(fillRequest, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    [Fact]
    public async Task Fill_MissingTabBinding_RejectedBeforeAnyRootKeyUnwrap()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        int unwrapsBefore = _hello.UnwrappedKeys.Count;

        var fillRequest = MakeRequest("fillCredentialForExactOrigin", sessionId, new { credentialId = "anything" });
        // TabId/WindowId deliberately left null.
        var response = await vaultCmds.FillCredentialAsync(fillRequest, Origin, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("FILL_CONTEXT_REQUIRED", response.Error?.Code);
        Assert.Equal(unwrapsBefore, _hello.UnwrappedKeys.Count); // no root-key unwrap attempted
    }

    [Fact]
    public async Task Reveal_DoesNotRequireTabBinding()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        var addResp = await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);
        var vault = _vaultManager.GetOrLoad();
        string credentialId = vault.Items[0].ItemId;

        // No TabId/WindowId set — reveal is not fill and must not require it.
        var revealRequest = MakeRequest("decryptSelectedCredentialForExactOrigin", sessionId, new { credentialId });
        var response = await vaultCmds.DecryptCredentialAsync(revealRequest, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
    }

    // ---- updateCredentialAtomic ----

    [Fact]
    public async Task Update_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);

        string credentialId = _vaultManager.GetOrLoad().Items[0].ItemId;

        var updateRequest = MakeRequest("updateCredentialAtomic", sessionId,
            new { credentialId, password = "newpass" });
        var response = await vaultCmds.UpdateCredentialAtomicAsync(updateRequest, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    // ---- deleteCredentialTombstone ----

    [Fact]
    public async Task Delete_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);
        string credentialId = _vaultManager.GetOrLoad().Items[0].ItemId;

        var deleteRequest = MakeRequest("deleteCredentialTombstone", sessionId, new { credentialId });
        var response = await vaultCmds.DeleteCredentialTombstoneAsync(deleteRequest, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    [Fact]
    public async Task Delete_RequiresFreshHello()
    {
        // This is also the regression test proving delete was hardened to
        // require fresh Hello (it previously did not).
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);
        string credentialId = _vaultManager.GetOrLoad().Items[0].ItemId;

        _hello.ShouldVerify = false; // simulate Hello failing/being cancelled
        var deleteRequest = MakeRequest("deleteCredentialTombstone", sessionId, new { credentialId });
        var response = await vaultCmds.DeleteCredentialTombstoneAsync(deleteRequest, Origin, CancellationToken.None);

        Assert.Equal("error", response.Status);
        Assert.Equal("HELLO_CANCELED", response.Error?.Code);
    }

    // ---- generateTotpForCredential ----

    [Fact]
    public async Task GenerateTotp_RootKeyZeroizedAfter()
    {
        Bootstrap();
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId,
                new { usernameOrEmail = "u", password = "p", totpSecret = "JBSWY3DPEHPK3PXP" }),
            Origin, CancellationToken.None);
        string credentialId = _vaultManager.GetOrLoad().Items[0].ItemId;

        var totpCmds = new TotpCommands(_ctx);
        var totpRequest = MakeRequest("generateTotpForCredential", sessionId, new { credentialId });
        var response = await totpCmds.GenerateTotpAsync(totpRequest, Origin, CancellationToken.None);

        Assert.Equal("ok", response.Status);
        AssertAllZero(_hello.UnwrappedKeys[^1]);
    }

    // ---- Helper ----

    private static string ExtractSessionId(NativeResponse response)
    {
        var prop = response.Result!.GetType().GetProperty("sessionId");
        return (string)prop!.GetValue(response.Result)!;
    }
}

/// <summary>
/// IHelloManager test double that captures every byte[] instance returned by
/// UnwrapRootKey, so tests can assert it was zeroized after use. Wrap format
/// matches the existing StubHelloManager convention used elsewhere in this
/// suite: 12-byte nonce + 16-byte tag (both unused, just placeholders) +
/// plaintext key — NOT production crypto, purely for test capture.
/// </summary>
public sealed class CapturingHelloManager : IHelloManager
{
    public readonly List<byte[]> UnwrappedKeys = new();
    public bool ShouldVerify { get; set; } = true;

    public Task<HelloResult> RequestUserVerificationAsync(string prompt) =>
        Task.FromResult(ShouldVerify ? HelloResult.Verified : HelloResult.Canceled);

    public Task<string> GetPresenceAvailabilityAsync() => Task.FromResult("Available");

    // Padded to comfortably exceed VaultIntegrity.MinWrappedKeyBytes (128) so
    // ClassifyWrappedRootKey treats this as a real (RSA-2048-OAEP-sized) wrap
    // rather than corrupt/too-short — otherwise these tests would silently hit
    // the corrupt-vault reset path instead of the normal unwrap path.
    private const int PaddingBytes = 150;

    public byte[] WrapRootKey(byte[] rootKey)
    {
        byte[] padding = new byte[PaddingBytes];
        byte[] result = new byte[PaddingBytes + rootKey.Length];
        Buffer.BlockCopy(padding, 0, result, 0, PaddingBytes);
        Buffer.BlockCopy(rootKey, 0, result, PaddingBytes, rootKey.Length);
        return result;
    }

    public byte[] UnwrapRootKey(byte[] wrappedBytes)
    {
        if (wrappedBytes.Length < PaddingBytes) throw new InvalidOperationException("Too short.");
        byte[] key = wrappedBytes[PaddingBytes..]; // fresh array each call — never a shared/cached reference
        UnwrappedKeys.Add(key);
        return key;
    }
}
