using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Section B end-to-end tests: a tampered-but-parseable vault.json (duplicate
/// item ids) and a rolled-back vault.json (an old, valid snapshot restored
/// over a newer one) must both be rejected by unlockOrigin — fail closed,
/// never silently accepted — rather than only being caught by the narrower
/// unit tests on VaultInvariants/EpochRollbackGuard directly.
/// </summary>
public sealed class VaultCorruptionAndRollbackTests : IDisposable
{
    private const string Origin = "https://example.com:443";

    private readonly string _tempDir;
    private readonly VaultManager _vaultManager;
    private readonly CapturingHelloManager _hello;
    private readonly CommandContext _ctx;
    private readonly string _vaultFilePath;

    public VaultCorruptionAndRollbackTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-corrupt-rollback-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vaultManager = new VaultManager(_tempDir);
        _vaultFilePath = Path.Combine(_tempDir, "vault.json");
        _hello = new CapturingHelloManager();
        _ctx = new CommandContext(
            _vaultManager, new SessionManager(), _hello,
            new RateLimiter(), new SecurityEventLog(), new EventLogManager(_vaultManager));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
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

    private static string ExtractSessionId(NativeResponse response)
    {
        var prop = response.Result!.GetType().GetProperty("sessionId");
        return (string)prop!.GetValue(response.Result)!;
    }

    [Fact]
    public async Task DuplicateItemIds_UnlockFailsClosed_NotSilentlyAccepted()
    {
        var vaultCmds = new VaultCommands(_ctx);

        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(unlockResp);
        await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);

        // Tamper: duplicate the one item's id directly in the persisted vault.
        var vault = _vaultManager.Load();
        var original = vault.Items[0];
        var duplicate = new VaultItemV3
        {
            ItemId = original.ItemId, // same id — this is the corruption
            OriginHash = original.OriginHash,
            EncryptedPayload = original.EncryptedPayload,
            EncryptedMetadata = original.EncryptedMetadata,
            CreatedByDeviceId = original.CreatedByDeviceId,
            CreatedAtLogical = original.CreatedAtLogical,
            UpdatedAtLogical = original.UpdatedAtLogical,
            Deleted = false,
            Version = 1,
            Epoch = original.Epoch,
        };
        vault.Items.Add(duplicate);
        _vaultManager.Save(vault);

        var secondUnlock = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);

        Assert.Equal("error", secondUnlock.Status);
        Assert.Equal(VaultCorruptCode.NoRecovery, secondUnlock.Error?.Code);
    }

    [Fact]
    public async Task RolledBackVaultSnapshot_UnlockFailsClosed()
    {
        var vaultCmds = new VaultCommands(_ctx);

        // Epoch 1: unlock once so the anti-rollback marker is seeded.
        var firstUnlock = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        Assert.Equal("ok", firstUnlock.Status);

        // Snapshot the epoch-1 vault bytes — this stands in for a backup or a
        // copy an attacker exfiltrated before a later rotation.
        string oldSnapshotJson = File.ReadAllText(_vaultFilePath);

        // Simulate a legitimate rotation bumping the epoch to 2, then unlock
        // again so the anti-rollback marker catches up to epoch 2.
        var vault = _vaultManager.Load();
        vault.Epoch = 2;
        _vaultManager.Save(vault);
        var secondUnlock = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        Assert.Equal("ok", secondUnlock.Status);

        // Attack: restore the epoch-1 snapshot over the current (epoch-2) file.
        File.WriteAllText(_vaultFilePath, oldSnapshotJson);

        var thirdUnlock = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);

        Assert.Equal("error", thirdUnlock.Status);
        // No items exist in this test, so HasUserData is false only if items/
        // devices/events/recoveryKit are all empty — the vault DOES have at
        // least the unlock-created shape, but zero items/devices/recovery, so
        // the empty-reset path could apply. Either fail-closed code is
        // acceptable here; what matters is it is NOT "ok".
        Assert.NotEqual("ok", thirdUnlock.Status);
    }

    [Fact]
    public async Task RolledBackVaultWithUserData_RequiresRecoveryOrRestoreRatherThanSilentAccept()
    {
        var vaultCmds = new VaultCommands(_ctx);

        var firstUnlock = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        string sessionId = ExtractSessionId(firstUnlock);
        await vaultCmds.AddCredentialAsync(
            MakeRequest("addCredentialForExactOrigin", sessionId, new { usernameOrEmail = "u", password = "p" }),
            Origin, CancellationToken.None);

        string oldSnapshotJson = File.ReadAllText(_vaultFilePath);

        var vault = _vaultManager.Load();
        vault.Epoch = 2;
        _vaultManager.Save(vault);
        var secondUnlock = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        Assert.Equal("ok", secondUnlock.Status);

        File.WriteAllText(_vaultFilePath, oldSnapshotJson);

        var thirdUnlock = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);

        Assert.Equal("error", thirdUnlock.Status);
        Assert.Equal(VaultCorruptCode.NoRecovery, thirdUnlock.Error?.Code);
    }
}
