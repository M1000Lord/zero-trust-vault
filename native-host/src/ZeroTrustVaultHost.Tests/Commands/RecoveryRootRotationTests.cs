using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Section I regression tests: recovery must rotate the vault's root key
/// AGAIN after successfully reconstructing it from shares — not just re-wrap
/// the same old root to a new device. Before this fix, a successful recovery
/// reused the reconstructed root key directly, so (a) the very shares just
/// used remained valid forever afterward, and (b) any previously-removed
/// device that still held a wrap of that same root would regain access.
/// </summary>
public sealed class RecoveryRootRotationTests : IDisposable
{
    private const string Origin = "https://example.com:443";

    private readonly string _tempDir;
    private readonly VaultManager _vaultManager;
    private readonly CapturingHelloManager _hello;
    private readonly CommandContext _ctx;

    public RecoveryRootRotationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-recovery-rotation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vaultManager = new VaultManager(_tempDir);
        _hello = new CapturingHelloManager();
        _ctx = new CommandContext(
            _vaultManager, new SessionManager(), _hello,
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

    private static string[] ExtractShares(NativeMessaging.NativeResponse response)
    {
        var prop = response.Result!.GetType().GetProperty("shares");
        return (string[])prop!.GetValue(response.Result)!;
    }

    private async Task<(VaultCommands vaultCmds, RecoveryCommands recoveryCmds, string sessionId, string[] shares)> BootstrapWithRecoveryKitAsync()
    {
        var vaultCmds = new VaultCommands(_ctx);
        var recoveryCmds = new RecoveryCommands(_ctx);

        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);

        await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);

        var kitResp = await recoveryCmds.CreateRecoveryKitAsync(MakeRequest("createRecoveryKit", sessionId), Origin, CancellationToken.None);
        Assert.Equal("ok", kitResp.Status);
        string[] shares = ExtractShares(kitResp);

        return (vaultCmds, recoveryCmds, sessionId, shares);
    }

    [Fact]
    public async Task SuccessfulRecovery_RotatesRootAndInvalidatesOldRecoveryKit()
    {
        var (_, recoveryCmds, _, shares) = await BootstrapWithRecoveryKitAsync();
        int epochBefore = _vaultManager.GetOrLoad().Epoch;

        var recoverResp = await recoveryCmds.RecoverVaultAsync(
            MakeRequest("recoverVault", payload: new { shares = shares.Take(3).ToArray() }),
            Origin, CancellationToken.None);

        Assert.Equal("ok", recoverResp.Status);

        var vaultAfter = _vaultManager.GetOrLoad();
        Assert.True(vaultAfter.Epoch > epochBefore); // root was actually rotated, not reused
        Assert.Null(vaultAfter.RecoveryKit); // old kit invalidated — user must create a new one
    }

    [Fact]
    public async Task SuccessfulRecovery_ExistingItemsStillDecryptAfterRotation()
    {
        var (vaultCmds, recoveryCmds, _, shares) = await BootstrapWithRecoveryKitAsync();

        var recoverResp = await recoveryCmds.RecoverVaultAsync(
            MakeRequest("recoverVault", payload: new { shares = shares.Take(3).ToArray() }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", recoverResp.Status);

        // A fresh unlock after recovery must still be able to read the
        // existing credential — rotation re-encrypted it, it did not lose it.
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        Assert.Equal("ok", unlockResp.Status);
        string sessionId = ExtractSessionId(unlockResp);

        var listResp = await vaultCmds.ListCredentialSummariesAsync(MakeRequest("listSummariesForOrigin", sessionId), Origin, CancellationToken.None);
        Assert.Equal("ok", listResp.Status);
    }

    [Fact]
    public async Task ReusedSharesAfterRecovery_AreRejected_NotSilentlyAcceptedForever()
    {
        var (_, recoveryCmds, _, shares) = await BootstrapWithRecoveryKitAsync();

        var firstRecover = await recoveryCmds.RecoverVaultAsync(
            MakeRequest("recoverVault", payload: new { shares = shares.Take(3).ToArray() }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", firstRecover.Status);

        // Replay the SAME shares again — before this fix, this would succeed
        // forever since the root key never actually changed.
        var secondRecover = await recoveryCmds.RecoverVaultAsync(
            MakeRequest("recoverVault", payload: new { shares = shares.Take(3).ToArray() }),
            Origin, CancellationToken.None);

        Assert.Equal("error", secondRecover.Status);
        Assert.Equal("RECOVERY_FAILED", secondRecover.Error?.Code);
    }

    [Fact]
    public async Task SuccessfulRecovery_RemovesAllPreviouslyPairedDevices()
    {
        var (_, recoveryCmds, _, shares) = await BootstrapWithRecoveryKitAsync();

        // Simulate a previously-paired device still on record.
        var vault = _vaultManager.GetOrLoad();
        vault.Devices.Add(new VaultDevice { DeviceId = "old-device", Status = "Active", WrappedEpochKey = Convert.ToBase64String(new byte[32]) });
        _vaultManager.Save(vault);

        var recoverResp = await recoveryCmds.RecoverVaultAsync(
            MakeRequest("recoverVault", payload: new { shares = shares.Take(3).ToArray() }),
            Origin, CancellationToken.None);
        Assert.Equal("ok", recoverResp.Status);

        var vaultAfter = _vaultManager.GetOrLoad();
        var oldDevice = vaultAfter.Devices.First(d => d.DeviceId == "old-device");
        Assert.Equal("Removed", oldDevice.Status);
        Assert.Equal(string.Empty, oldDevice.WrappedEpochKey);
    }
}
