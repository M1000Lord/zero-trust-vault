using System.Text.Json.Serialization;

namespace ZeroTrustVaultHost.Sync;

/// <summary>
/// All 13 event types for the append-only sync event log.
/// Events are encrypted before storage.
/// </summary>
public enum SyncEventType
{
    CredentialAdded,
    CredentialUpdated,
    CredentialDeleted,
    CredentialTombstoned,
    VaultUnlocked,
    VaultLocked,
    DeviceAdded,
    DeviceRemoved,
    RecoveryKitCreated,
    VaultRecovered,
    EpochRotated,
    SyncPull,
    SyncPush,
}

/// <summary>
/// A single entry in the append-only event log.
/// The log forms a hash chain: each entry includes the hash of the previous entry.
/// </summary>
public sealed class SyncEvent
{
    [JsonPropertyName("eventId")]
    public string EventId { get; set; } = string.Empty;

    [JsonPropertyName("eventType")]
    public string EventType { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = string.Empty;

    [JsonPropertyName("deviceId")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("epoch")]
    public int Epoch { get; set; }

    [JsonPropertyName("resourceId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResourceId { get; set; }

    [JsonPropertyName("previousHash")]
    public string PreviousHash { get; set; } = string.Empty;

    [JsonPropertyName("entryHash")]
    public string EntryHash { get; set; } = string.Empty;

    /// <summary>
    /// Encrypted event payload (AES-256-GCM, using EventLogEncryptionKey subkey).
    /// </summary>
    [JsonPropertyName("encryptedPayload")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public EncryptedEventPayload? EncryptedPayload { get; set; }
}

public sealed class EncryptedEventPayload
{
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("tag")]
    public string Tag { get; set; } = string.Empty;

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;
}
