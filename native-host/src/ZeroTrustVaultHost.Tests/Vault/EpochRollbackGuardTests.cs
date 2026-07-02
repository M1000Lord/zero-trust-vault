using Xunit;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Vault;

/// <summary>
/// Section B anti-rollback tests. A vault.json swapped for an older, still
/// perfectly valid snapshot of the SAME vault must be detected — this is the
/// "downgrade/rollback attack" threat scenario (e.g. undoing a device
/// revocation by restoring the pre-revocation file).
/// </summary>
public sealed class EpochRollbackGuardTests : IDisposable
{
    private readonly string _tempDir;

    public EpochRollbackGuardTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-rollback-guard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private static VaultFile MakeVault(string vaultId, int epoch) => new()
    {
        Schema = 3,
        VaultId = vaultId,
        Epoch = epoch,
    };

    [Fact]
    public void FirstEverCheck_NoMarker_NoRollback()
    {
        var vault = MakeVault("vault-a", epoch: 1);

        var result = EpochRollbackGuard.CheckAndAdvance(_tempDir, vault);

        Assert.False(result.RollbackDetected);
    }

    [Fact]
    public void SameEpoch_NoRollback()
    {
        var vault = MakeVault("vault-a", epoch: 3);
        EpochRollbackGuard.CheckAndAdvance(_tempDir, vault); // seed marker at epoch 3

        var result = EpochRollbackGuard.CheckAndAdvance(_tempDir, vault); // same epoch again

        Assert.False(result.RollbackDetected);
    }

    [Fact]
    public void HigherEpoch_NoRollback_MarkerAdvances()
    {
        var v1 = MakeVault("vault-a", epoch: 1);
        EpochRollbackGuard.CheckAndAdvance(_tempDir, v1);

        var v2 = MakeVault("vault-a", epoch: 2);
        var result = EpochRollbackGuard.CheckAndAdvance(_tempDir, v2);

        Assert.False(result.RollbackDetected);
    }

    [Fact]
    public void LowerEpoch_SameVaultId_RollbackDetected()
    {
        var v3 = MakeVault("vault-a", epoch: 3);
        EpochRollbackGuard.CheckAndAdvance(_tempDir, v3); // marker now at epoch 3

        var vOld = MakeVault("vault-a", epoch: 1); // attacker restores an old snapshot
        var result = EpochRollbackGuard.CheckAndAdvance(_tempDir, vOld);

        Assert.True(result.RollbackDetected);
        Assert.Equal(3, result.LastSeenEpoch);
    }

    [Fact]
    public void RollbackDetected_MarkerIsNotRegressed()
    {
        var v5 = MakeVault("vault-a", epoch: 5);
        EpochRollbackGuard.CheckAndAdvance(_tempDir, v5);

        var vOld = MakeVault("vault-a", epoch: 2);
        EpochRollbackGuard.CheckAndAdvance(_tempDir, vOld); // rollback attempt, marker must stay at 5

        // A legitimate vault back at epoch 5 should still be accepted (no
        // false rollback caused by the attempted rollback having corrupted tracking).
        var result = EpochRollbackGuard.CheckAndAdvance(_tempDir, v5);
        Assert.False(result.RollbackDetected);

        // But epoch 3 or 4 (still below the real high-water mark) must still be rejected.
        var stillRollback = EpochRollbackGuard.CheckAndAdvance(_tempDir, MakeVault("vault-a", epoch: 4));
        Assert.True(stillRollback.RollbackDetected);
    }

    [Fact]
    public void DifferentVaultId_TreatedAsFreshVault_NoRollback()
    {
        var vA = MakeVault("vault-a", epoch: 5);
        EpochRollbackGuard.CheckAndAdvance(_tempDir, vA);

        // A genuinely different vault (new vault id) starting at epoch 1 is
        // not a rollback of vault-a — it's an unrelated vault.
        var vB = MakeVault("vault-b", epoch: 1);
        var result = EpochRollbackGuard.CheckAndAdvance(_tempDir, vB);

        Assert.False(result.RollbackDetected);
    }

    [Fact]
    public void Reset_InitializesTrackingForNewVaultId()
    {
        var vA = MakeVault("vault-a", epoch: 5);
        EpochRollbackGuard.CheckAndAdvance(_tempDir, vA);

        var vB = MakeVault("vault-b", epoch: 1);
        EpochRollbackGuard.Reset(_tempDir, vB);

        // A rollback attempt against the NEW vault id is now correctly tracked.
        var rollback = EpochRollbackGuard.CheckAndAdvance(_tempDir, MakeVault("vault-b", epoch: 0));
        Assert.True(rollback.RollbackDetected);
    }
}
