using System.Security.Cryptography;
using Xunit;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Crypto;

/// <summary>
/// End-to-end recovery drill (acceptance-gate "Recovery"): 2 shares fail, 3
/// shares succeed, and the reconstructed root actually decrypts credentials that
/// were saved before the disaster. Mirrors the host's recovery model where the
/// VaultRootKey itself is the Shamir secret.
/// </summary>
public sealed class RecoveryDrillTests
{
    private const string Origin = "https://bank.example.com:443";

    private static (VaultFile vault, VaultItemV3 item) MakeVaultWithItem(byte[] root, string pass)
    {
        var vault = new VaultFile
        {
            Schema = 3,
            VaultId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            DeviceId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            Epoch = 1,
        };
        string itemId = Guid.NewGuid().ToString("D");
        byte[] originHash = VaultManager.ComputeOriginHash(root, Origin);
        byte[] vaultId = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(itemId);
        byte[] itemKey = SubkeyDerivation.DeriveItemEncryptionKey(root);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultId, itemIdBytes, originHash, vault.Epoch, "ItemEncryptionKey");

        var item = new VaultItemV3
        {
            ItemId = itemId,
            OriginHash = Convert.ToBase64String(originHash),
            EncryptedPayload = VaultCrypto.EncryptJson(itemKey, new VaultPayload { Password = pass }, aad),
            Epoch = vault.Epoch,
        };
        vault.Items.Add(item);
        return (vault, item);
    }

    private static string DecryptPassword(VaultFile vault, byte[] root, VaultItemV3 item)
    {
        byte[] itemKey = SubkeyDerivation.DeriveItemEncryptionKey(root);
        byte[] vaultId = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(item.ItemId);
        byte[] originHash = Convert.FromBase64String(item.OriginHash);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultId, itemIdBytes, originHash, item.Epoch, "ItemEncryptionKey");
        return VaultCrypto.DecryptJson<VaultPayload>(itemKey, item.EncryptedPayload, aad).Password;
    }

    [Fact]
    public void Drill_TwoSharesFail_ThreeSucceed_AndDecryptOldCredentials()
    {
        byte[] root = RandomNumberGenerator.GetBytes(32);
        var (vault, item) = MakeVaultWithItem(root, "vaultPass!");

        // Disaster recovery factor: split the root key into 5 shares (3-of-5).
        var shares = ShamirSecretSharing.Split(root, threshold: 3, shares: 5);

        // 2 shares must NOT reconstruct the usable root.
        byte[] twoShareGuess = ShamirSecretSharing.Combine(shares[0..2]);
        Assert.NotEqual(root, twoShareGuess);
        Assert.ThrowsAny<CryptographicException>(() => DecryptPassword(vault, twoShareGuess, item));

        // 3 shares reconstruct the exact root...
        byte[] recovered = ShamirSecretSharing.Combine(shares[0..3]);
        Assert.Equal(root, recovered);

        // ...and the recovered key decrypts the pre-disaster credential.
        Assert.Equal("vaultPass!", DecryptPassword(vault, recovered, item));
    }

    [Fact]
    public void Drill_RecoveryRotatesEpoch_AndDataStillReadable()
    {
        byte[] root = RandomNumberGenerator.GetBytes(32);
        var (vault, item) = MakeVaultWithItem(root, "pw");

        var shares = ShamirSecretSharing.Split(root, threshold: 3, shares: 5);
        byte[] recovered = ShamirSecretSharing.Combine(shares[2..5]);

        int epochBefore = vault.Epoch;
        // Recovery rebinds to a new device key (simulated) and rotates the epoch
        // counter, but the root is unchanged so existing items remain readable.
        vault.DeviceId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        vault.Epoch++;

        Assert.Equal(epochBefore + 1, vault.Epoch);
        Assert.Equal("pw", DecryptPassword(vault, recovered, item));
    }
}
