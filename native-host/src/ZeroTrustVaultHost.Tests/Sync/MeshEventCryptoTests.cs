using System.Security.Cryptography;
using Xunit;
using ZeroTrustVaultHost.Sync;

namespace ZeroTrustVaultHost.Tests.Sync;

/// <summary>
/// Tests for signed, hash-chained MeshSync events. These prove the core
/// integrity properties the sync design depends on: tampering, wrong keys,
/// unknown/removed devices, and broken chains are all rejected.
/// </summary>
public sealed class MeshEventCryptoTests
{
    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static MeshEvent NewEvent(string deviceId, string prevHash, string id = "e1") => new()
    {
        SchemaVersion = 1,
        VaultId = "vault-1",
        SpaceId = "space-1",
        EventId = id,
        EventType = "CredentialAdded",
        DeviceId = deviceId,
        DeviceEpoch = 1,
        SpaceEpoch = 1,
        HybridLogicalClock = "1-0-" + deviceId,
        CreatedAtUtc = "2026-06-30T00:00:00Z",
        PreviousEventHash = prevHash,
        PayloadNonce = "bm9uY2U=",
        EncryptedPayload = "Y2lwaGVy",
        Aad = "YWFk",
    };

    [Fact]
    public void SignThenVerify_Succeeds()
    {
        using var key = NewKey();
        var evt = MeshEventCrypto.SignEvent(NewEvent("devA", ""), key);

        Assert.NotEmpty(evt.Signature);
        Assert.NotEmpty(evt.EventHash);
        Assert.True(MeshEventCrypto.VerifyEvent(evt, key));
    }

    [Fact]
    public void TamperedPayload_FailsVerification()
    {
        using var key = NewKey();
        var evt = MeshEventCrypto.SignEvent(NewEvent("devA", ""), key);

        evt.EncryptedPayload = "dGFtcGVyZWQ="; // changed after signing
        Assert.False(MeshEventCrypto.VerifyEvent(evt, key));
    }

    [Fact]
    public void TamperedPreviousHash_FailsVerification()
    {
        using var key = NewKey();
        var evt = MeshEventCrypto.SignEvent(NewEvent("devA", ""), key);

        evt.PreviousEventHash = "deadbeef";
        Assert.False(MeshEventCrypto.VerifyEvent(evt, key));
    }

    [Fact]
    public void TamperedEventType_FailsVerification()
    {
        using var key = NewKey();
        var evt = MeshEventCrypto.SignEvent(NewEvent("devA", ""), key);

        evt.EventType = "CredentialDeleted";
        Assert.False(MeshEventCrypto.VerifyEvent(evt, key));
    }

    [Fact]
    public void WrongKey_FailsVerification()
    {
        using var signer = NewKey();
        using var attacker = NewKey();
        var evt = MeshEventCrypto.SignEvent(NewEvent("devA", ""), signer);

        Assert.False(MeshEventCrypto.VerifyEvent(evt, attacker));
    }

    [Fact]
    public void MissingSignature_FailsVerification()
    {
        using var key = NewKey();
        var evt = MeshEventCrypto.SignEvent(NewEvent("devA", ""), key);
        evt.Signature = "";
        Assert.False(MeshEventCrypto.VerifyEvent(evt, key));
    }

    [Fact]
    public void ForgedSignatureBytes_FailVerification()
    {
        using var key = NewKey();
        var evt = MeshEventCrypto.SignEvent(NewEvent("devA", ""), key);
        evt.Signature = Convert.ToBase64String(new byte[64]); // all zeros
        Assert.False(MeshEventCrypto.VerifyEvent(evt, key));
    }

    [Fact]
    public void ValidChain_Verifies()
    {
        using var keyA = NewKey();
        var e1 = MeshEventCrypto.SignEvent(NewEvent("devA", "", "e1"), keyA);
        var e2 = MeshEventCrypto.SignEvent(NewEvent("devA", e1.EventHash, "e2"), keyA);

        var result = MeshEventCrypto.VerifyChain(new[] { e1, e2 }, _ => keyA);
        Assert.True(result.Valid);
    }

    [Fact]
    public void BrokenChain_IsDetected()
    {
        using var keyA = NewKey();
        var e1 = MeshEventCrypto.SignEvent(NewEvent("devA", "", "e1"), keyA);
        var e2 = MeshEventCrypto.SignEvent(NewEvent("devA", "wrong-prev", "e2"), keyA);

        var result = MeshEventCrypto.VerifyChain(new[] { e1, e2 }, _ => keyA);
        Assert.False(result.Valid);
        Assert.Equal(1, result.FailedIndex);
    }

    [Fact]
    public void RemovedOrUnknownDevice_IsRejected()
    {
        using var keyA = NewKey();
        var e1 = MeshEventCrypto.SignEvent(NewEvent("devA", "", "e1"), keyA);

        // resolveKey returns null → device unknown/removed.
        var result = MeshEventCrypto.VerifyChain(new[] { e1 }, _ => null);
        Assert.False(result.Valid);
        Assert.Contains("removed", result.Reason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CanonicalJson_IsKeyOrderIndependent()
    {
        // Two objects with the same content in different declaration order must
        // canonicalize to identical bytes.
        var a = CanonicalJson.SerializeToString(new { b = 1, a = 2, c = new { y = 1, x = 2 } });
        var b = CanonicalJson.SerializeToString(new { c = new { x = 2, y = 1 }, a = 2, b = 1 });
        Assert.Equal(a, b);
    }
}
