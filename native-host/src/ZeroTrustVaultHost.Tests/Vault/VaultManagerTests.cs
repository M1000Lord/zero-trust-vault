using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Vault;

/// <summary>
/// Tests for vault file operations: add/read/delete/tombstone.
/// Uses a TestVaultHelper backed by a temp directory to avoid touching the real vault.
/// </summary>
public sealed class VaultManagerTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _vaultPath;
    private readonly TestVaultHelper _vault;

    public VaultManagerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _vaultPath = Path.Combine(_tempDir, "vault.json");
        _vault = new TestVaultHelper(_vaultPath);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    // ---- VaultExists ----

    [Fact]
    public void VaultExists_WhenNoFile_ReturnsFalse()
    {
        Assert.False(_vault.Exists());
    }

    [Fact]
    public void VaultExists_AfterCreateNew_ReturnsTrue()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        _vault.CreateNew(wrapped);
        Assert.True(_vault.Exists());
    }

    // ---- CreateNew ----

    [Fact]
    public void CreateNew_ProducesSchemaV3Vault()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var vault = _vault.CreateNew(wrapped);

        Assert.Equal(3, vault.Schema);
        Assert.NotEmpty(vault.VaultId);
        Assert.NotEmpty(vault.DeviceId);
        Assert.Equal(1, vault.Epoch);
        Assert.Empty(vault.Items);
    }

    [Fact]
    public void CreateNew_StoredWrappedKeyMatchesInput()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var vault = _vault.CreateNew(wrapped);
        byte[] stored = Convert.FromBase64String(vault.WrappedRootKey);
        Assert.Equal(wrapped, stored);
    }

    // ---- Load ----

    [Fact]
    public void Load_AfterCreate_ReturnsConsistentVault()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var created = _vault.CreateNew(wrapped);
        var loaded = _vault.Load();

        Assert.Equal(created.VaultId, loaded.VaultId);
        Assert.Equal(created.DeviceId, loaded.DeviceId);
        Assert.Equal(3, loaded.Schema);
    }

    [Fact]
    public void Load_WhenFileNotExists_ThrowsFileNotFoundException()
    {
        Assert.Throws<FileNotFoundException>(() => _vault.Load());
    }

    // ---- UpsertItem ----

    [Fact]
    public void UpsertItem_AddsItemToVault()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var vaultFile = _vault.CreateNew(wrapped);

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] originHash = RandomNumberGenerator.GetBytes(32);
        string itemId = Guid.NewGuid().ToString("D");

        var item = CreateTestItem(vaultFile, key, itemId, originHash);
        _vault.UpsertItem(item);

        var loaded = _vault.GetOrLoad();
        Assert.Single(loaded.Items);
        Assert.Equal(itemId, loaded.Items[0].ItemId);
    }

    [Fact]
    public void UpsertItem_UpdatesExistingItem()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var vaultFile = _vault.CreateNew(wrapped);

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] originHash = RandomNumberGenerator.GetBytes(32);
        string itemId = Guid.NewGuid().ToString("D");

        var item = CreateTestItem(vaultFile, key, itemId, originHash);
        _vault.UpsertItem(item);

        // Update version
        item.Version = 2;
        _vault.UpsertItem(item);

        var loaded = _vault.GetOrLoad();
        Assert.Single(loaded.Items);
        Assert.Equal(2, loaded.Items[0].Version);
    }

    // ---- TombstoneItem ----

    [Fact]
    public void TombstoneItem_MarksItemAsDeleted()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var vaultFile = _vault.CreateNew(wrapped);

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] originHash = RandomNumberGenerator.GetBytes(32);
        string itemId = Guid.NewGuid().ToString("D");

        var item = CreateTestItem(vaultFile, key, itemId, originHash);
        _vault.UpsertItem(item);

        bool result = _vault.TombstoneItem(itemId);
        Assert.True(result);

        var loaded = _vault.GetOrLoad();
        Assert.True(loaded.Items[0].Deleted);
    }

    [Fact]
    public void TombstoneItem_NonExistentItem_ReturnsFalse()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        _vault.CreateNew(wrapped);

        bool result = _vault.TombstoneItem(Guid.NewGuid().ToString());
        Assert.False(result);
    }

    // ---- GetItemsForOrigin ----

    [Fact]
    public void GetItemsForOrigin_ReturnsOnlyMatchingNonDeleted()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var vaultFile = _vault.CreateNew(wrapped);

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] originHash1 = RandomNumberGenerator.GetBytes(32);
        byte[] originHash2 = RandomNumberGenerator.GetBytes(32);

        _vault.UpsertItem(CreateTestItem(vaultFile, key, Guid.NewGuid().ToString("D"), originHash1));
        _vault.UpsertItem(CreateTestItem(vaultFile, key, Guid.NewGuid().ToString("D"), originHash1));
        _vault.UpsertItem(CreateTestItem(vaultFile, key, Guid.NewGuid().ToString("D"), originHash2));

        var loaded = _vault.GetOrLoad();
        var forOrigin1 = VaultManager.GetItemsForOrigin(loaded, originHash1).ToList();
        var forOrigin2 = VaultManager.GetItemsForOrigin(loaded, originHash2).ToList();

        Assert.Equal(2, forOrigin1.Count);
        Assert.Single(forOrigin2);
    }

    [Fact]
    public void GetItemsForOrigin_ExcludesDeletedItems()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        var vaultFile = _vault.CreateNew(wrapped);

        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] originHash = RandomNumberGenerator.GetBytes(32);
        string itemId = Guid.NewGuid().ToString("D");

        var item = CreateTestItem(vaultFile, key, itemId, originHash);
        _vault.UpsertItem(item);
        _vault.TombstoneItem(itemId);

        var loaded = _vault.GetOrLoad();
        var items = VaultManager.GetItemsForOrigin(loaded, originHash).ToList();
        Assert.Empty(items);
    }

    // ---- Atomic write ----

    [Fact]
    public void Save_IsAtomic_NoTempFileLeft()
    {
        byte[] wrapped = RandomNumberGenerator.GetBytes(60);
        _vault.CreateNew(wrapped);

        string tempPath = _vaultPath + ".tmp";
        Assert.False(File.Exists(tempPath), ".tmp file should not remain after atomic save.");
    }

    // ---- ComputeOriginHash ----

    [Fact]
    public void ComputeOriginHash_SameInputs_ProduceSameHash()
    {
        byte[] rootKey = RandomNumberGenerator.GetBytes(32);
        string origin = "https://example.com";

        byte[] hash1 = VaultManager.ComputeOriginHash(rootKey, origin);
        byte[] hash2 = VaultManager.ComputeOriginHash(rootKey, origin);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeOriginHash_DifferentOrigins_ProduceDifferentHashes()
    {
        byte[] rootKey = RandomNumberGenerator.GetBytes(32);
        byte[] hash1 = VaultManager.ComputeOriginHash(rootKey, "https://example.com");
        byte[] hash2 = VaultManager.ComputeOriginHash(rootKey, "https://other.com");
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeOriginHash_DifferentKeys_ProduceDifferentHashes()
    {
        byte[] key1 = RandomNumberGenerator.GetBytes(32);
        byte[] key2 = RandomNumberGenerator.GetBytes(32);
        string origin = "https://example.com";

        byte[] hash1 = VaultManager.ComputeOriginHash(key1, origin);
        byte[] hash2 = VaultManager.ComputeOriginHash(key2, origin);
        Assert.NotEqual(hash1, hash2);
    }

    // ---- Helpers ----

    private static VaultItemV3 CreateTestItem(VaultFile vault, byte[] key, string itemId, byte[] originHash)
    {
        var payload = new VaultPayload
        {
            UsernameOrEmail = "user@test.com",
            Password = "password123",
            Label = "Test",
        };
        var metadata = new VaultMetadata
        {
            Origin = "https://test.example.com",
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            UpdatedAt = DateTimeOffset.UtcNow.ToString("O"),
        };

        byte[] payloadKey = SubkeyDerivation.DeriveItemEncryptionKey(key);
        byte[] vaultIdBytes = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(itemId);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultIdBytes, itemIdBytes, originHash, vault.Epoch, "ItemEncryptionKey");
        var encPayload = VaultCrypto.EncryptJson(payloadKey, payload, aad);

        byte[] metaKey = SubkeyDerivation.DeriveMetadataEncryptionKey(key);
        byte[] metaAad = VaultCrypto.BuildAad(vault.Schema, vaultIdBytes, itemIdBytes, originHash, vault.Epoch, "MetadataEncryptionKey");
        var encMeta = VaultCrypto.EncryptJson(metaKey, metadata, metaAad);

        return new VaultItemV3
        {
            ItemId = itemId,
            OriginHash = Convert.ToBase64String(originHash),
            EncryptedPayload = encPayload,
            EncryptedMetadata = encMeta,
            CreatedByDeviceId = vault.DeviceId,
            CreatedAtLogical = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            UpdatedAtLogical = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Deleted = false,
            Version = 1,
            Epoch = vault.Epoch,
        };
    }
}

/// <summary>
/// Standalone vault helper for tests — uses a custom path, not the real LOCALAPPDATA path.
/// </summary>
internal sealed class TestVaultHelper
{
    private readonly string _vaultPath;
    private VaultFile? _cached;

    private static readonly JsonSerializerOptions s_options = new() { WriteIndented = true };

    public TestVaultHelper(string vaultPath) => _vaultPath = vaultPath;

    public bool Exists() => File.Exists(_vaultPath);

    public VaultFile CreateNew(byte[] wrappedRootKey)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_vaultPath)!);
        var vault = new VaultFile
        {
            Schema = 3,
            VaultId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            DeviceId = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            Epoch = 1,
            WrappedRootKey = Convert.ToBase64String(wrappedRootKey),
            Items = new(),
            Devices = new(),
            PendingPairings = new(),
            EventLog = new(),
            RecoveryKit = null,
            CreatedAt = DateTimeOffset.UtcNow.ToString("O"),
            UpdatedAt = DateTimeOffset.UtcNow.ToString("O"),
        };
        SaveVault(vault);
        _cached = vault;
        return vault;
    }

    public VaultFile Load()
    {
        if (!File.Exists(_vaultPath))
            throw new FileNotFoundException("Vault file not found.", _vaultPath);
        string json = File.ReadAllText(_vaultPath);
        var vault = JsonSerializer.Deserialize<VaultFile>(json, s_options)
            ?? throw new InvalidDataException("Vault is null.");
        _cached = vault;
        return vault;
    }

    public VaultFile GetOrLoad() => _cached ?? Load();

    public void UpsertItem(VaultItemV3 item)
    {
        var vault = GetOrLoad();
        int idx = vault.Items.FindIndex(i => i.ItemId == item.ItemId);
        if (idx >= 0) vault.Items[idx] = item;
        else vault.Items.Add(item);
        SaveVault(vault);
        _cached = vault;
    }

    public bool TombstoneItem(string itemId)
    {
        var vault = GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == itemId);
        if (item is null) return false;
        item.Deleted = true;
        item.UpdatedAtLogical = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        SaveVault(vault);
        _cached = vault;
        return true;
    }

    private void SaveVault(VaultFile vault)
    {
        vault.UpdatedAt = DateTimeOffset.UtcNow.ToString("O");
        string tempPath = _vaultPath + ".tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(vault, s_options));
        File.Move(tempPath, _vaultPath, overwrite: true);
    }
}
