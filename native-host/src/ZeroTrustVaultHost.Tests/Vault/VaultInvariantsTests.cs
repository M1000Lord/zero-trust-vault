using Xunit;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Vault;

/// <summary>
/// Section B: structural invariant checker. Proves each listed invariant is
/// actually enforced (duplicate ids, missing/invalid wraps, broken ciphertext
/// blobs, epoch inconsistency, recovery-kit shape) and that a well-formed
/// vault produces zero violations (no false positives blocking normal use).
/// </summary>
public sealed class VaultInvariantsTests
{
    private static VaultFile MakeCleanVault()
    {
        // 150 zero bytes padded + 32-byte key, base64 — comfortably over
        // VaultIntegrity.MinWrappedKeyBytes (128), same convention used by
        // RootKeyLifetimeTests' CapturingHelloManager.
        byte[] wrapped = new byte[182];
        return new VaultFile
        {
            Schema = 3,
            VaultId = Convert.ToBase64String(new byte[16]),
            DeviceId = Convert.ToBase64String(new byte[32]),
            Epoch = 1,
            WrappedRootKey = Convert.ToBase64String(wrapped),
            Items = new(),
            Devices = new(),
            PendingPairings = new(),
            EventLog = new(),
            RecoveryKit = null,
        };
    }

    private static VaultItemV3 MakeValidItem(string id, int epoch = 1) => new()
    {
        ItemId = id,
        OriginHash = Convert.ToBase64String(new byte[32]),
        EncryptedPayload = new EncryptedBlob
        {
            Nonce = Convert.ToBase64String(new byte[12]),
            Tag = Convert.ToBase64String(new byte[16]),
            Ciphertext = Convert.ToBase64String(new byte[8]),
        },
        EncryptedMetadata = new EncryptedBlob
        {
            Nonce = Convert.ToBase64String(new byte[12]),
            Tag = Convert.ToBase64String(new byte[16]),
            Ciphertext = Convert.ToBase64String(new byte[8]),
        },
        Deleted = false,
        Epoch = epoch,
    };

    [Fact]
    public void CleanVault_NoViolations()
    {
        var vault = MakeCleanVault();
        vault.Items.Add(MakeValidItem("item-1"));

        var violations = VaultInvariants.Check(vault);

        Assert.Empty(violations);
    }

    [Fact]
    public void DuplicateItemIds_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.Items.Add(MakeValidItem("dup"));
        vault.Items.Add(MakeValidItem("dup"));

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "ITEM_DUPLICATE_ID");
    }

    [Fact]
    public void DuplicateDeviceIds_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.Devices.Add(new VaultDevice { DeviceId = "dup-device", Status = "Active" });
        vault.Devices.Add(new VaultDevice { DeviceId = "dup-device", Status = "Active" });

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "DEVICE_DUPLICATE_ID");
    }

    [Fact]
    public void MissingWrappedRootKey_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.WrappedRootKey = "";

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "ROOT_KEY_INVALID");
    }

    [Fact]
    public void InvalidBase64WrappedRootKey_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.WrappedRootKey = "not-valid-base64!!!";

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "ROOT_KEY_INVALID");
    }

    [Fact]
    public void ItemWithInvalidOriginHashBase64_IsViolation()
    {
        var vault = MakeCleanVault();
        var item = MakeValidItem("item-1");
        item.OriginHash = "!!!not-base64!!!";
        vault.Items.Add(item);

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "ITEM_INVALID_ORIGIN_HASH");
    }

    [Fact]
    public void ItemWithMissingCiphertextField_IsViolation()
    {
        var vault = MakeCleanVault();
        var item = MakeValidItem("item-1");
        item.EncryptedPayload.Ciphertext = "";
        vault.Items.Add(item);

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "ITEM_BROKEN_PAYLOAD");
    }

    [Fact]
    public void ItemWithInvalidBase64Ciphertext_IsViolation()
    {
        var vault = MakeCleanVault();
        var item = MakeValidItem("item-1");
        item.EncryptedPayload.Ciphertext = "not valid base64 !!!";
        vault.Items.Add(item);

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "ITEM_BROKEN_PAYLOAD");
    }

    [Fact]
    public void TombstonedItem_SkipsCiphertextChecks()
    {
        var vault = MakeCleanVault();
        vault.Items.Add(new VaultItemV3 { ItemId = "tombstone-1", Deleted = true });

        var violations = VaultInvariants.Check(vault);

        Assert.Empty(violations);
    }

    [Fact]
    public void ItemEpochAheadOfVaultEpoch_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.Epoch = 1;
        vault.Items.Add(MakeValidItem("item-1", epoch: 5));

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "ITEM_EPOCH_AHEAD_OF_VAULT");
    }

    [Fact]
    public void VaultEpochBelowOne_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.Epoch = 0;

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "EPOCH_INVALID");
    }

    [Fact]
    public void UnsupportedSchema_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.Schema = 2;

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "SCHEMA_UNSUPPORTED");
    }

    [Fact]
    public void RecoveryKit_ThresholdBelowTwo_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.RecoveryKit = new RecoveryKitEntry { ShareCount = 5, Threshold = 1, VerificationHmac = Convert.ToBase64String(new byte[32]) };

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "RECOVERY_THRESHOLD_TOO_LOW");
    }

    [Fact]
    public void RecoveryKit_ShareCountBelowThreshold_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.RecoveryKit = new RecoveryKitEntry { ShareCount = 2, Threshold = 3, VerificationHmac = Convert.ToBase64String(new byte[32]) };

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "RECOVERY_SHARE_COUNT_INVALID");
    }

    [Fact]
    public void RecoveryKit_MissingHmac_IsViolation()
    {
        var vault = MakeCleanVault();
        vault.RecoveryKit = new RecoveryKitEntry { ShareCount = 5, Threshold = 3, VerificationHmac = "" };

        var violations = VaultInvariants.Check(vault);

        Assert.Contains(violations, v => v.Code == "RECOVERY_HMAC_INVALID");
    }

    [Fact]
    public void RecoveryKit_ValidShape_NoViolation()
    {
        var vault = MakeCleanVault();
        vault.RecoveryKit = new RecoveryKitEntry { ShareCount = 5, Threshold = 3, VerificationHmac = Convert.ToBase64String(new byte[32]) };

        var violations = VaultInvariants.Check(vault);

        Assert.DoesNotContain(violations, v => v.Code.StartsWith("RECOVERY_"));
    }
}
