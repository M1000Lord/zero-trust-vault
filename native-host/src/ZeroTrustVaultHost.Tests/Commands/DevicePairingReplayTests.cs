using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Section G regression tests: a pairing session must be single-use and
/// time-limited. Before this fix, a successfully-approved pairing stayed in
/// vault.PendingPairings with only an Approved=true flag (never removed), and
/// the approval lookup fell back to that same list — so replaying an old,
/// already-approved (or long-expired) pairingId+code+SAS could reach the SAS
/// check again. This tests the fix: approved pairings are removed outright,
/// and stale (never-approved) pairings expire.
/// </summary>
public sealed class DevicePairingReplayTests : IDisposable
{
    private const string Origin = "https://example.com:443";

    private readonly string _tempDir;
    private readonly VaultManager _vaultManager;
    private readonly CapturingHelloManager _hello;
    private readonly CommandContext _ctx;
    private readonly DeviceCommands _deviceCmds;

    public DevicePairingReplayTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-pairing-replay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vaultManager = new VaultManager(_tempDir);
        _hello = new CapturingHelloManager();
        _ctx = new CommandContext(
            _vaultManager, new SessionManager(), _hello,
            new RateLimiter(), new SecurityEventLog(), new EventLogManager(_vaultManager));
        _deviceCmds = new DeviceCommands(_ctx);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private static NativeMessaging.NativeRequest MakeRequest(string command, object? payload = null) => new()
    {
        ProtocolVersion = 1,
        RequestId = Guid.NewGuid().ToString("D"),
        Command = command,
        Timestamp = DateTimeOffset.UtcNow.ToString("O"),
        ClientNonce = Guid.NewGuid().ToString("N"),
        ExtensionId = "abcdefghijklmnopabcdefghijklmnop",
        Origin = Origin,
        SessionId = null,
        Payload = payload is null
            ? JsonDocument.Parse("{}").RootElement
            : JsonDocument.Parse(JsonSerializer.Serialize(payload)).RootElement,
    };

    private async Task BootstrapVaultAsync()
    {
        var vaultCmds = new VaultCommands(_ctx);
        var unlockResp = await vaultCmds.UnlockAsync(MakeRequest("unlockOrigin"), Origin, CancellationToken.None);
        Assert.Equal("ok", unlockResp.Status);
    }

    private sealed record ApprovalMaterial(string SigningKeyB64, string EncryptionKeyB64, string PairingSessionId, string NonceB64, string Sas);

    private static ApprovalMaterial BuildApprovalMaterial()
    {
        using var rsa = RSA.Create(2048);
        byte[] encryptionKey = rsa.ExportSubjectPublicKeyInfo();
        byte[] signingKey = RandomNumberGenerator.GetBytes(91); // opaque for SAS/DeviceId purposes in this test
        string pairingSessionId = Guid.NewGuid().ToString("N");
        byte[] nonce = RandomNumberGenerator.GetBytes(16);
        string sas = DeviceIdentity.ComputeSas(pairingSessionId, signingKey, encryptionKey, nonce);

        return new ApprovalMaterial(
            Convert.ToBase64String(signingKey),
            Convert.ToBase64String(encryptionKey),
            pairingSessionId,
            Convert.ToBase64String(nonce),
            sas);
    }

    private object BuildApprovalPayload(string pairingId, string pairingCode, ApprovalMaterial m) => new
    {
        pairingId,
        pairingCode,
        deviceName = "Test Device",
        newDevicePublicSigningKey = m.SigningKeyB64,
        newDevicePublicEncryptionKey = m.EncryptionKeyB64,
        pairingSessionId = m.PairingSessionId,
        pairingNonce = m.NonceB64,
        sas = m.Sas,
    };

    [Fact]
    public async Task FullPairingFlow_Succeeds()
    {
        await BootstrapVaultAsync();

        var beginResp = await _deviceCmds.BeginDevicePairingAsync(MakeRequest("beginDevicePairing"), Origin, CancellationToken.None);
        Assert.Equal("ok", beginResp.Status);
        string pairingId = (string)beginResp.Result!.GetType().GetProperty("pairingId")!.GetValue(beginResp.Result)!;
        string pairingCode = (string)beginResp.Result!.GetType().GetProperty("pairingCode")!.GetValue(beginResp.Result)!;

        var material = BuildApprovalMaterial();
        var approveResp = await _deviceCmds.ApproveDevicePairingAsync(
            MakeRequest("approveDevicePairing", BuildApprovalPayload(pairingId, pairingCode, material)),
            Origin, CancellationToken.None);

        Assert.Equal("ok", approveResp.Status);
        Assert.Single(_vaultManager.GetOrLoad().Devices);
    }

    [Fact]
    public async Task ReplayedApproval_SamePairingId_IsRejected()
    {
        await BootstrapVaultAsync();

        var beginResp = await _deviceCmds.BeginDevicePairingAsync(MakeRequest("beginDevicePairing"), Origin, CancellationToken.None);
        string pairingId = (string)beginResp.Result!.GetType().GetProperty("pairingId")!.GetValue(beginResp.Result)!;
        string pairingCode = (string)beginResp.Result!.GetType().GetProperty("pairingCode")!.GetValue(beginResp.Result)!;

        var material = BuildApprovalMaterial();
        var payload = BuildApprovalPayload(pairingId, pairingCode, material);

        var firstApprove = await _deviceCmds.ApproveDevicePairingAsync(MakeRequest("approveDevicePairing", payload), Origin, CancellationToken.None);
        Assert.Equal("ok", firstApprove.Status);

        // Replay the exact same approval a second time.
        var secondApprove = await _deviceCmds.ApproveDevicePairingAsync(MakeRequest("approveDevicePairing", payload), Origin, CancellationToken.None);

        Assert.Equal("error", secondApprove.Status);
        Assert.Equal("PAIRING_NOT_FOUND", secondApprove.Error?.Code);
        Assert.Single(_vaultManager.GetOrLoad().Devices); // no second device was added
    }

    [Fact]
    public async Task ExpiredPairing_IsRejected()
    {
        await BootstrapVaultAsync();

        var beginResp = await _deviceCmds.BeginDevicePairingAsync(MakeRequest("beginDevicePairing"), Origin, CancellationToken.None);
        string pairingId = (string)beginResp.Result!.GetType().GetProperty("pairingId")!.GetValue(beginResp.Result)!;
        string pairingCode = (string)beginResp.Result!.GetType().GetProperty("pairingCode")!.GetValue(beginResp.Result)!;

        // Backdate the pairing beyond the expiry window.
        var vault = _vaultManager.GetOrLoad();
        var pending = vault.PendingPairings.First(p => p.PairingId == pairingId);
        pending.InitiatedAt = DateTimeOffset.UtcNow.AddMinutes(-11).ToString("O");
        _vaultManager.Save(vault);

        var material = BuildApprovalMaterial();
        var approveResp = await _deviceCmds.ApproveDevicePairingAsync(
            MakeRequest("approveDevicePairing", BuildApprovalPayload(pairingId, pairingCode, material)),
            Origin, CancellationToken.None);

        Assert.Equal("error", approveResp.Status);
        Assert.Equal("PAIRING_EXPIRED", approveResp.Error?.Code);
    }

    [Fact]
    public async Task WrongPairingCode_IsRejected()
    {
        await BootstrapVaultAsync();

        var beginResp = await _deviceCmds.BeginDevicePairingAsync(MakeRequest("beginDevicePairing"), Origin, CancellationToken.None);
        string pairingId = (string)beginResp.Result!.GetType().GetProperty("pairingId")!.GetValue(beginResp.Result)!;

        var material = BuildApprovalMaterial();
        var approveResp = await _deviceCmds.ApproveDevicePairingAsync(
            MakeRequest("approveDevicePairing", BuildApprovalPayload(pairingId, "WRONG-0000", material)),
            Origin, CancellationToken.None);

        Assert.Equal("error", approveResp.Status);
        Assert.Equal("PAIRING_CODE_MISMATCH", approveResp.Error?.Code);
    }

    [Fact]
    public async Task MismatchedSas_IsRejected_MitmDefense()
    {
        await BootstrapVaultAsync();

        var beginResp = await _deviceCmds.BeginDevicePairingAsync(MakeRequest("beginDevicePairing"), Origin, CancellationToken.None);
        string pairingId = (string)beginResp.Result!.GetType().GetProperty("pairingId")!.GetValue(beginResp.Result)!;
        string pairingCode = (string)beginResp.Result!.GetType().GetProperty("pairingCode")!.GetValue(beginResp.Result)!;

        var material = BuildApprovalMaterial() with { Sas = "000000" }; // wrong SAS
        var approveResp = await _deviceCmds.ApproveDevicePairingAsync(
            MakeRequest("approveDevicePairing", BuildApprovalPayload(pairingId, pairingCode, material)),
            Origin, CancellationToken.None);

        Assert.Equal("error", approveResp.Status);
        Assert.Equal("SAS_MISMATCH", approveResp.Error?.Code);
    }
}
