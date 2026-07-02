using System.Security.Cryptography;
using Xunit;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Vault;

/// <summary>
/// Proves the core property of cryptographic device revocation: after a root-key
/// rotation, a holder of the OLD root (i.e. a removed device) can no longer
/// decrypt the vault, while the NEW root decrypts everything and origin lookups
/// still resolve. Pure crypto — no Hello/CNG required.
/// </summary>
public sealed class VaultRekeyTests
{
    private const string Origin = "https://example.com:443";

    private static VaultFile NewVault() => new()
    {
        Schema = 3,
        VaultId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
        DeviceId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        Epoch = 1,
    };

    /// <summary>Encrypts an item exactly as the host does, at the vault's current epoch.</summary>
    private static VaultItemV3 AddItem(VaultFile vault, byte[] root, string origin, string user, string pass)
    {
        string itemId = Guid.NewGuid().ToString("D");
        byte[] originHash = VaultManager.ComputeOriginHash(root, origin);
        byte[] vaultId = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(itemId);

        var payload = new VaultPayload { UsernameOrEmail = user, Password = pass, Label = "acct" };
        var metadata = new VaultMetadata { Origin = origin, CreatedAt = "t", UpdatedAt = "t" };

        byte[] itemKey = SubkeyDerivation.DeriveItemEncryptionKey(root);
        byte[] metaKey = SubkeyDerivation.DeriveMetadataEncryptionKey(root);
        byte[] payAad = VaultCrypto.BuildAad(vault.Schema, vaultId, itemIdBytes, originHash, vault.Epoch, "ItemEncryptionKey");
        byte[] metAad = VaultCrypto.BuildAad(vault.Schema, vaultId, itemIdBytes, originHash, vault.Epoch, "MetadataEncryptionKey");

        var item = new VaultItemV3
        {
            ItemId = itemId,
            OriginHash = Convert.ToBase64String(originHash),
            EncryptedPayload = VaultCrypto.EncryptJson(itemKey, payload, payAad),
            EncryptedMetadata = VaultCrypto.EncryptJson(metaKey, metadata, metAad),
            CreatedByDeviceId = vault.DeviceId,
            Epoch = vault.Epoch,
            Version = 1,
        };
        vault.Items.Add(item);
        return item;
    }

    /// <summary>Decrypts an item's payload under a given root at the item's stored epoch/origin hash.</summary>
    private static VaultPayload Decrypt(VaultFile vault, byte[] root, VaultItemV3 item)
    {
        byte[] itemKey = SubkeyDerivation.DeriveItemEncryptionKey(root);
        byte[] vaultId = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(item.ItemId);
        byte[] originHash = Convert.FromBase64String(item.OriginHash);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultId, itemIdBytes, originHash, item.Epoch, "ItemEncryptionKey");
        return VaultCrypto.DecryptJson<VaultPayload>(itemKey, item.EncryptedPayload, aad);
    }

    [Fact]
    public void RotateRoot_NewRootDecrypts_OldRootCannot()
    {
        var vault = NewVault();
        byte[] oldRoot = HelloManagerGenerate();
        var item = AddItem(vault, oldRoot, Origin, "alice", "s3cret");

        // Sanity: old root decrypts before rotation.
        Assert.Equal("s3cret", Decrypt(vault, oldRoot, item).Password);

        byte[] newRoot = HelloManagerGenerate();
        int newEpoch = VaultRekey.RotateRoot(vault, oldRoot, newRoot);

        // New root (held by remaining devices) decrypts the re-encrypted item.
        Assert.Equal("s3cret", Decrypt(vault, newRoot, item).Password);

        // The removed device, holding only the OLD root, can no longer decrypt.
        Assert.ThrowsAny<CryptographicException>(() => Decrypt(vault, oldRoot, item));

        Assert.Equal(2, newEpoch);
        Assert.Equal(2, vault.Epoch);
        Assert.Equal(2, item.Epoch);
    }

    [Fact]
    public void RotateRoot_RecomputesOriginHash_UnderNewRoot()
    {
        var vault = NewVault();
        byte[] oldRoot = HelloManagerGenerate();
        var item = AddItem(vault, oldRoot, Origin, "bob", "pw");

        byte[] newRoot = HelloManagerGenerate();
        VaultRekey.RotateRoot(vault, oldRoot, newRoot);

        // Origin lookups under the new root resolve the item; under the old root they do not.
        byte[] newHash = VaultManager.ComputeOriginHash(newRoot, Origin);
        byte[] oldHash = VaultManager.ComputeOriginHash(oldRoot, Origin);
        Assert.Equal(Convert.ToBase64String(newHash), item.OriginHash);
        Assert.NotEqual(Convert.ToBase64String(oldHash), item.OriginHash);
        Assert.Single(VaultManager.GetItemsForOrigin(vault, newHash));
        Assert.Empty(VaultManager.GetItemsForOrigin(vault, oldHash));
    }

    [Fact]
    public void RotateRoot_AllItemsSurvive_AcrossManyItems()
    {
        var vault = NewVault();
        byte[] oldRoot = HelloManagerGenerate();
        var items = new List<(VaultItemV3 item, string pw)>();
        for (int i = 0; i < 10; i++)
            items.Add((AddItem(vault, oldRoot, $"https://site{i}.com:443", $"user{i}", $"pw{i}"), $"pw{i}"));

        byte[] newRoot = HelloManagerGenerate();
        VaultRekey.RotateRoot(vault, oldRoot, newRoot);

        foreach (var (item, pw) in items)
            Assert.Equal(pw, Decrypt(vault, newRoot, item).Password);
    }

    [Fact]
    public void RotateRoot_RejectsWrongSizedKeys()
    {
        var vault = NewVault();
        Assert.Throws<ArgumentException>(() => VaultRekey.RotateRoot(vault, new byte[16], new byte[32]));
        Assert.Throws<ArgumentException>(() => VaultRekey.RotateRoot(vault, new byte[32], new byte[16]));
    }

    private static byte[] HelloManagerGenerate() => RandomNumberGenerator.GetBytes(32);
}
