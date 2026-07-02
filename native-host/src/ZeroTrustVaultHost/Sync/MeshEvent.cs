using System.Text.Json.Serialization;

namespace ZeroTrustVaultHost.Sync;

/// <summary>
/// A MeshSync event in the append-only, signed, hash-chained log. Field set
/// matches the target sync event format. The payload is encrypted; the relay
/// can never read it. Every event is signed by the originating device key.
///
/// Signed content = every field EXCEPT <see cref="EventHash"/> and
/// <see cref="Signature"/>. The hash chain binds each event to its predecessor
/// via <see cref="PreviousEventHash"/>.
/// </summary>
public sealed class MeshEvent
{
    [JsonPropertyName("schemaVersion")]   public int SchemaVersion { get; set; } = 1;
    [JsonPropertyName("vaultId")]         public string VaultId { get; set; } = string.Empty;
    [JsonPropertyName("spaceId")]         public string SpaceId { get; set; } = string.Empty;
    [JsonPropertyName("eventId")]         public string EventId { get; set; } = string.Empty;
    [JsonPropertyName("eventType")]       public string EventType { get; set; } = string.Empty;
    [JsonPropertyName("deviceId")]        public string DeviceId { get; set; } = string.Empty;
    [JsonPropertyName("deviceEpoch")]     public int DeviceEpoch { get; set; }
    [JsonPropertyName("spaceEpoch")]      public int SpaceEpoch { get; set; }
    [JsonPropertyName("hybridLogicalClock")] public string HybridLogicalClock { get; set; } = string.Empty;
    [JsonPropertyName("createdAtUtc")]    public string CreatedAtUtc { get; set; } = string.Empty;
    [JsonPropertyName("previousEventHash")] public string PreviousEventHash { get; set; } = string.Empty;

    // Encrypted payload (AES-256-GCM); relay cannot decrypt.
    [JsonPropertyName("payloadNonce")]    public string PayloadNonce { get; set; } = string.Empty;
    [JsonPropertyName("encryptedPayload")] public string EncryptedPayload { get; set; } = string.Empty;
    [JsonPropertyName("aad")]             public string Aad { get; set; } = string.Empty;

    // Integrity + authenticity (excluded from signed content).
    [JsonPropertyName("eventHash")]       public string EventHash { get; set; } = string.Empty;
    [JsonPropertyName("signatureAlgorithm")] public string SignatureAlgorithm { get; set; } = "ECDSA_P256_SHA256";
    [JsonPropertyName("signature")]       public string Signature { get; set; } = string.Empty;

    /// <summary>Returns the subset of fields that are covered by the signature/hash.</summary>
    public object SignedContent() => new
    {
        schemaVersion = SchemaVersion,
        vaultId = VaultId,
        spaceId = SpaceId,
        eventId = EventId,
        eventType = EventType,
        deviceId = DeviceId,
        deviceEpoch = DeviceEpoch,
        spaceEpoch = SpaceEpoch,
        hybridLogicalClock = HybridLogicalClock,
        createdAtUtc = CreatedAtUtc,
        previousEventHash = PreviousEventHash,
        payloadNonce = PayloadNonce,
        encryptedPayload = EncryptedPayload,
        aad = Aad,
        signatureAlgorithm = SignatureAlgorithm,
    };
}
