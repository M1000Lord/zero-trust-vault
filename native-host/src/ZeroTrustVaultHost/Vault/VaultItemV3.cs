using System.Text.Json.Serialization;

namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// Represents a single vault item in schema v3.
/// </summary>
public sealed class VaultItemV3
{
    [JsonPropertyName("itemId")]
    public string ItemId { get; set; } = string.Empty;

    /// <summary>HMAC-SHA256 of the normalized origin, base64-encoded (32 bytes).</summary>
    [JsonPropertyName("originHash")]
    public string OriginHash { get; set; } = string.Empty;

    [JsonPropertyName("encryptedPayload")]
    public EncryptedBlob EncryptedPayload { get; set; } = new();

    [JsonPropertyName("encryptedMetadata")]
    public EncryptedBlob EncryptedMetadata { get; set; } = new();

    [JsonPropertyName("createdByDeviceId")]
    public string CreatedByDeviceId { get; set; } = string.Empty;

    [JsonPropertyName("createdAtLogical")]
    public long CreatedAtLogical { get; set; }

    [JsonPropertyName("updatedAtLogical")]
    public long UpdatedAtLogical { get; set; }

    [JsonPropertyName("deleted")]
    public bool Deleted { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("epoch")]
    public int Epoch { get; set; } = 1;
}

/// <summary>
/// AES-256-GCM encrypted blob stored as base64 fields.
/// </summary>
public sealed class EncryptedBlob
{
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;   // base64, 12 bytes

    [JsonPropertyName("tag")]
    public string Tag { get; set; } = string.Empty;     // base64, 16 bytes

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty; // base64
}

/// <summary>
/// Decrypted payload for a vault item (encrypted at rest).
/// </summary>
public sealed class VaultPayload
{
    [JsonPropertyName("usernameOrEmail")]
    public string UsernameOrEmail { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("totpSecret")]
    public string TotpSecret { get; set; } = string.Empty;

    [JsonPropertyName("label")]
    public string Label { get; set; } = string.Empty;

    [JsonPropertyName("notes")]
    public string Notes { get; set; } = string.Empty;
}

/// <summary>
/// Decrypted metadata for a vault item (encrypted at rest).
/// </summary>
public sealed class VaultMetadata
{
    [JsonPropertyName("origin")]
    public string Origin { get; set; } = string.Empty;

    [JsonPropertyName("createdAt")]
    public string CreatedAt { get; set; } = string.Empty;

    [JsonPropertyName("updatedAt")]
    public string UpdatedAt { get; set; } = string.Empty;
}

/// <summary>
/// Device entry in the vault.
/// </summary>
public sealed class VaultDevice
{
    [JsonPropertyName("deviceId")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("createdAt")]
    public string CreatedAt { get; set; } = string.Empty;

    [JsonPropertyName("addedAt")]
    public string AddedAt { get; set; } = string.Empty;

    [JsonPropertyName("lastSeenAt")]
    public string LastSeenAt { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "Active";

    [JsonPropertyName("deviceEpoch")]
    public int DeviceEpoch { get; set; } = 1;

    [JsonPropertyName("permissions")]
    public List<string> Permissions { get; set; } = new();

    [JsonPropertyName("deviceSigningPublicKey")]
    public string DeviceSigningPublicKey { get; set; } = string.Empty;

    [JsonPropertyName("deviceEncryptionPublicKey")]
    public string DeviceEncryptionPublicKey { get; set; } = string.Empty;

    [JsonPropertyName("wrappedEpochKey")]
    public string WrappedEpochKey { get; set; } = string.Empty;

    [JsonPropertyName("publicKeyBlob")]
    public string PublicKeyBlob { get; set; } = string.Empty;
}

/// <summary>
/// Pending device pairing entry.
/// </summary>
public sealed class PendingPairing
{
    [JsonPropertyName("pairingId")]
    public string PairingId { get; set; } = string.Empty;

    [JsonPropertyName("pairingCode")]
    public string PairingCode { get; set; } = string.Empty;

    [JsonPropertyName("initiatedAt")]
    public string InitiatedAt { get; set; } = string.Empty;

    [JsonPropertyName("approved")]
    public bool Approved { get; set; }
}

/// <summary>
/// Top-level vault file structure (schema v3).
/// </summary>
public sealed class VaultFile
{
    [JsonPropertyName("schema")]
    public int Schema { get; set; } = 3;

    [JsonPropertyName("vaultId")]
    public string VaultId { get; set; } = string.Empty;   // base64, 16 bytes

    [JsonPropertyName("deviceId")]
    public string DeviceId { get; set; } = string.Empty;  // base64, 32 bytes

    [JsonPropertyName("epoch")]
    public int Epoch { get; set; } = 1;

    [JsonPropertyName("wrappedRootKey")]
    public string WrappedRootKey { get; set; } = string.Empty; // base64

    [JsonPropertyName("items")]
    public List<VaultItemV3> Items { get; set; } = new();

    [JsonPropertyName("devices")]
    public List<VaultDevice> Devices { get; set; } = new();

    [JsonPropertyName("pendingPairings")]
    public List<PendingPairing> PendingPairings { get; set; } = new();

    [JsonPropertyName("eventLog")]
    public List<object> EventLog { get; set; } = new();

    [JsonPropertyName("recoveryKit")]
    public RecoveryKitEntry? RecoveryKit { get; set; }

    [JsonPropertyName("createdAt")]
    public string CreatedAt { get; set; } = string.Empty;

    [JsonPropertyName("updatedAt")]
    public string UpdatedAt { get; set; } = string.Empty;
}

/// <summary>
/// Stored recovery kit metadata (the actual shares are given to the user, not stored).
/// </summary>
public sealed class RecoveryKitEntry
{
    [JsonPropertyName("createdAt")]
    public string CreatedAt { get; set; } = string.Empty;

    [JsonPropertyName("shareCount")]
    public int ShareCount { get; set; }

    [JsonPropertyName("threshold")]
    public int Threshold { get; set; }

    /// <summary>HMAC of the RecoveryRootSecret for verification during recovery.</summary>
    [JsonPropertyName("verificationHmac")]
    public string VerificationHmac { get; set; } = string.Empty;
}
