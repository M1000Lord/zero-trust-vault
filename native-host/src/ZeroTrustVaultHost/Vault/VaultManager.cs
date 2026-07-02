using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ZeroTrustVaultHost.Crypto;

namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// Loads and saves vault.json v3 with atomic write (write-to-temp then rename).
/// </summary>
public sealed class VaultManager
{
    private static readonly string DefaultVaultDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ZeroTrustVault");

    /// <summary>Default production vault path — unchanged for all existing callers.</summary>
    public static readonly string VaultFilePath = Path.Combine(DefaultVaultDirectory, "vault.json");

    /// <summary>Default production quarantine directory.</summary>
    public static readonly string QuarantineDirectory = Path.Combine(DefaultVaultDirectory, "quarantine");

    /// <summary>Code version stamped into quarantine diagnostics. Non-secret.</summary>
    public const string CodeVersion = "2.0.0";

    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = null, // use explicit [JsonPropertyName] attributes
    };

    // Instance-level path, defaulting to the static production path so every
    // existing call site (`new VaultManager()`) is unaffected. Tests can pass
    // a temp directory instead of ever touching the real user vault.
    private readonly string _vaultDirectory;
    private readonly string _vaultFilePath;
    private VaultFile? _cachedVault;

    /// <summary>Directory this instance's vault (and sidecars like the epoch-rollback marker) live in.</summary>
    public string VaultDirectory => _vaultDirectory;

    public VaultManager() : this(DefaultVaultDirectory) { }

    /// <summary>Constructs a VaultManager rooted at a custom directory (tests only).</summary>
    public VaultManager(string vaultDirectory)
    {
        _vaultDirectory = vaultDirectory;
        _vaultFilePath = Path.Combine(vaultDirectory, "vault.json");
    }

    public bool VaultExists() => File.Exists(_vaultFilePath);

    /// <summary>
    /// Loads the vault from disk. Throws if not found or corrupt.
    /// </summary>
    public VaultFile Load()
    {
        if (!File.Exists(_vaultFilePath))
            throw new FileNotFoundException("Vault file not found.", _vaultFilePath);

        string json = File.ReadAllText(_vaultFilePath, Encoding.UTF8);
        var vault = JsonSerializer.Deserialize<VaultFile>(json, s_jsonOptions)
            ?? throw new InvalidDataException("Vault file is empty or null.");

        if (vault.Schema != 3)
            throw new InvalidDataException($"Unexpected vault schema version {vault.Schema}. Run migration first.");

        _cachedVault = vault;
        return vault;
    }

    /// <summary>
    /// Saves the vault atomically: write to .tmp file, then rename over the original.
    /// </summary>
    public void Save(VaultFile vault)
    {
        Directory.CreateDirectory(_vaultDirectory);
        vault.UpdatedAt = DateTimeOffset.UtcNow.ToString("O");

        string tempPath = _vaultFilePath + ".tmp";
        string json = JsonSerializer.Serialize(vault, s_jsonOptions);
        File.WriteAllText(tempPath, json, Encoding.UTF8);
        File.Move(tempPath, _vaultFilePath, overwrite: true);

        _cachedVault = vault;
    }

    /// <summary>
    /// Creates a brand-new vault file on disk. Requires the wrapped root key bytes.
    /// </summary>
    public VaultFile CreateNew(byte[] wrappedRootKey)
    {
        Directory.CreateDirectory(_vaultDirectory);

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

        Save(vault);
        return vault;
    }

    /// <summary>
    /// Returns the last loaded vault or loads from disk.
    /// </summary>
    public VaultFile GetOrLoad() => _cachedVault ?? Load();

    /// <summary>
    /// Invalidates the in-memory cache (e.g., after lock).
    /// </summary>
    public void Invalidate() => _cachedVault = null;

    // ---- Item helpers ----

    /// <summary>
    /// Computes the HMAC-SHA256 origin hash using the OriginHashKey subkey.
    /// </summary>
    public static byte[] ComputeOriginHash(byte[] rootKey, string normalizedOrigin)
    {
        byte[] subkey = SubkeyDerivation.DeriveOriginHashKey(rootKey);
        using var hmac = new HMACSHA256(subkey);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(normalizedOrigin));
    }

    /// <summary>
    /// Returns all non-deleted items whose origin hash matches.
    /// </summary>
    public static IEnumerable<VaultItemV3> GetItemsForOrigin(VaultFile vault, byte[] originHash)
    {
        string originHashB64 = Convert.ToBase64String(originHash);
        return vault.Items.Where(i => !i.Deleted && i.OriginHash == originHashB64);
    }

    /// <summary>
    /// Adds or replaces an item in the vault and saves.
    /// </summary>
    public void UpsertItem(VaultItemV3 item)
    {
        var vault = GetOrLoad();
        int idx = vault.Items.FindIndex(i => i.ItemId == item.ItemId);
        if (idx >= 0)
            vault.Items[idx] = item;
        else
            vault.Items.Add(item);
        Save(vault);
    }

    /// <summary>
    /// Marks an item as deleted (tombstone) and saves.
    /// </summary>
    public bool TombstoneItem(string itemId)
    {
        var vault = GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == itemId);
        if (item is null) return false;
        item.Deleted = true;
        item.UpdatedAtLogical = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Save(vault);
        return true;
    }
}
