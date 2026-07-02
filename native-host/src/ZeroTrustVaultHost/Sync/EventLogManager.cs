using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Sync;

/// <summary>
/// Manages the append-only event log with hash chain verification.
/// Events are stored as JSON objects in vault.eventLog.
/// Each event's entryHash = HMAC-SHA256(previousHash || eventType || timestamp || resourceId).
/// </summary>
public sealed class EventLogManager
{
    private static readonly JsonSerializerOptions s_options = new() { WriteIndented = false };
    private static readonly HashSet<string> s_allowedMeshEventTypes = new(StringComparer.Ordinal)
    {
        "CreateCredential",
        "UpdateCredential",
        "DeleteCredential",
        "CreateRecoveryKit",
        "RecoveryCompleted",
        "AddDevice",
        "RemoveDevice",
        "RotateDeviceEpoch",
        "CreateSharedSpace",
        "AddMemberToSharedSpace",
        "RemoveMemberFromSharedSpace",
        "RotateSharedSpaceEpoch",
        "UpdatePolicy",
        "SecurityAlert",
        "BackupCreated",
        "SyncCheckpoint",
    };
    private readonly VaultManager _vaultManager;

    public EventLogManager(VaultManager vaultManager)
    {
        _vaultManager = vaultManager;
    }

    /// <summary>
    /// Appends a new event to the log and saves the vault.
    /// </summary>
    public SyncEvent Append(
        SyncEventType eventType,
        string deviceId,
        int epoch,
        string? resourceId,
        byte[]? auditMacKey)
    {
        VaultFile vault;
        try { vault = _vaultManager.GetOrLoad(); }
        catch { return CreateGenesisEvent(eventType, deviceId, epoch, resourceId, auditMacKey); }

        // Parse existing events to get the last hash
        string previousHash = GetLastHash(vault);

        var evt = new SyncEvent
        {
            EventId = Guid.NewGuid().ToString("D"),
            EventType = eventType.ToString(),
            Timestamp = DateTimeOffset.UtcNow.ToString("O"),
            DeviceId = deviceId,
            Epoch = epoch,
            ResourceId = resourceId,
            PreviousHash = previousHash,
            EntryHash = string.Empty,
        };

        evt.EntryHash = ComputeEntryHash(evt, auditMacKey);

        // Append to vault event log
        vault.EventLog.Add(evt);
        _vaultManager.Save(vault);

        return evt;
    }

    /// <summary>
    /// Verifies the entire hash chain in the vault event log.
    /// </summary>
    public ChainVerificationResult VerifyChain(byte[]? auditMacKey)
    {
        VaultFile vault;
        try { vault = _vaultManager.GetOrLoad(); }
        catch { return new ChainVerificationResult(true, true, string.Empty); }

        if (vault.EventLog.Count == 0)
            return new ChainVerificationResult(true, true, string.Empty);

        string expectedPrevious = string.Empty;
        string lastHash = string.Empty;

        foreach (var rawEvent in vault.EventLog)
        {
            SyncEvent? evt = null;
            try
            {
                string json = JsonSerializer.Serialize(rawEvent, s_options);
                evt = JsonSerializer.Deserialize<SyncEvent>(json, s_options);
            }
            catch
            {
                return new ChainVerificationResult(false, false, lastHash);
            }

            if (evt is null)
                return new ChainVerificationResult(false, false, lastHash);

            if (!string.Equals(evt.PreviousHash, expectedPrevious, StringComparison.Ordinal))
                return new ChainVerificationResult(false, false, lastHash);

            string expectedHash = ComputeEntryHash(evt, auditMacKey);
            if (!string.Equals(evt.EntryHash, expectedHash, StringComparison.Ordinal))
                return new ChainVerificationResult(false, false, lastHash);

            expectedPrevious = evt.EntryHash;
            lastHash = evt.EntryHash;
        }

        return new ChainVerificationResult(true, true, lastHash);
    }

    /// <summary>
    /// Returns all event log entries for sync pull.
    /// </summary>
    public IReadOnlyList<object> GetAllEvents()
    {
        try
        {
            var vault = _vaultManager.GetOrLoad();
            return vault.EventLog.AsReadOnly();
        }
        catch
        {
            return Array.Empty<object>();
        }
    }

    /// <summary>
    /// Accepts remote MeshEvents only after device, signature, epoch, replay, and
    /// hash-chain validation. Old SyncEvent pushes are intentionally unsupported.
    /// </summary>
    public MeshAcceptResult AcceptMeshEvents(IEnumerable<MeshEvent> events)
    {
        var vault = _vaultManager.GetOrLoad();
        var incoming = events.ToList();
        var existingMesh = ReadMeshEvents(vault).ToList();
        var seenIds = new HashSet<string>(
            existingMesh.Select(e => e.EventId).Where(id => !string.IsNullOrEmpty(id)),
            StringComparer.Ordinal);
        string expectedPrevious = existingMesh.Count == 0 ? string.Empty : existingMesh[^1].EventHash;

        foreach (var evt in incoming)
        {
            string? error = ValidateIncomingMeshEvent(vault, evt, seenIds, expectedPrevious);
            if (error is not null)
                return new MeshAcceptResult(0, "INVALID_MESH_EVENT", error);

            seenIds.Add(evt.EventId);
            expectedPrevious = evt.EventHash;
        }

        foreach (var evt in incoming)
            vault.EventLog.Add(evt);

        if (incoming.Count > 0)
            _vaultManager.Save(vault);
        return new MeshAcceptResult(incoming.Count, null, null);
    }

    // ---- Helpers ----

    private static string? ValidateIncomingMeshEvent(
        VaultFile vault,
        MeshEvent evt,
        HashSet<string> seenIds,
        string expectedPreviousHash)
    {
        if (evt.SchemaVersion != 1) return "Unsupported MeshEvent schemaVersion.";
        if (string.IsNullOrWhiteSpace(evt.EventId)) return "Missing eventId.";
        if (seenIds.Contains(evt.EventId)) return "Duplicate or replayed eventId.";
        if (!s_allowedMeshEventTypes.Contains(evt.EventType)) return "Unknown eventType.";
        if (!string.Equals(evt.VaultId, vault.VaultId, StringComparison.Ordinal)) return "Wrong vaultId.";
        if (string.IsNullOrWhiteSpace(evt.SpaceId)) return "Missing spaceId.";
        if (string.IsNullOrWhiteSpace(evt.DeviceId)) return "Missing deviceId.";
        if (string.IsNullOrWhiteSpace(evt.PayloadNonce)) return "Missing payloadNonce.";
        if (string.IsNullOrWhiteSpace(evt.EncryptedPayload)) return "Missing encryptedPayload.";
        if (string.IsNullOrWhiteSpace(evt.Aad)) return "Missing aad.";
        if (string.IsNullOrWhiteSpace(evt.EventHash)) return "Missing eventHash.";
        if (string.IsNullOrWhiteSpace(evt.Signature)) return "Missing signature.";
        if (!string.Equals(evt.PreviousEventHash, expectedPreviousHash, StringComparison.Ordinal))
            return "previousEventHash does not extend local history; possible fork.";
        if (evt.SpaceEpoch != vault.Epoch) return "Wrong spaceEpoch.";

        var device = vault.Devices.FirstOrDefault(d => string.Equals(d.DeviceId, evt.DeviceId, StringComparison.Ordinal));
        if (device is null) return "Event signed by unknown device.";
        if (!string.Equals(device.Status, "Active", StringComparison.Ordinal)) return "Event signed by non-active or removed device.";
        if (evt.DeviceEpoch != device.DeviceEpoch) return "Wrong deviceEpoch.";

        // Authority: membership events require owner/admin permission; credential
        // events require at least read/write. The vault's own device is the owner.
        if (!MeshAuthorization.IsAuthorized(evt.EventType, device, vault))
            return "Device not authorized for this event type.";

        string keyB64 = !string.IsNullOrWhiteSpace(device.DeviceSigningPublicKey)
            ? device.DeviceSigningPublicKey
            : device.PublicKeyBlob;
        if (string.IsNullOrWhiteSpace(keyB64)) return "Device has no signing public key.";

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(keyB64), out _);
            if (!MeshEventCrypto.VerifyEvent(evt, ecdsa))
                return "Invalid event signature or eventHash.";
        }
        catch
        {
            return "Malformed device signing public key or signature.";
        }

        return null;
    }

    private static IEnumerable<MeshEvent> ReadMeshEvents(VaultFile vault)
    {
        foreach (var raw in vault.EventLog)
        {
            MeshEvent? evt = null;
            try
            {
                string json = JsonSerializer.Serialize(raw, s_options);
                evt = JsonSerializer.Deserialize<MeshEvent>(json, s_options);
            }
            catch { }

            if (evt is not null && !string.IsNullOrEmpty(evt.EventHash))
                yield return evt;
        }
    }

    private string GetLastHash(VaultFile vault)
    {
        if (vault.EventLog.Count == 0) return string.Empty;
        try
        {
            var lastRaw = vault.EventLog[^1];
            string json = JsonSerializer.Serialize(lastRaw, s_options);
            var last = JsonSerializer.Deserialize<SyncEvent>(json, s_options);
            return last?.EntryHash ?? string.Empty;
        }
        catch { return string.Empty; }
    }

    private string ComputeEntryHash(SyncEvent evt, byte[]? auditMacKey)
    {
        // Hash input: previousHash || eventType || timestamp || eventId || resourceId
        string input = $"{evt.PreviousHash}|{evt.EventType}|{evt.Timestamp}|{evt.EventId}|{evt.ResourceId ?? ""}";
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);

        byte[] hash;
        if (auditMacKey is not null)
        {
            using var hmac = new HMACSHA256(auditMacKey);
            hash = hmac.ComputeHash(inputBytes);
        }
        else
        {
            hash = SHA256.HashData(inputBytes);
        }

        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private SyncEvent CreateGenesisEvent(
        SyncEventType eventType, string deviceId, int epoch,
        string? resourceId, byte[]? auditMacKey)
    {
        var evt = new SyncEvent
        {
            EventId = Guid.NewGuid().ToString("D"),
            EventType = eventType.ToString(),
            Timestamp = DateTimeOffset.UtcNow.ToString("O"),
            DeviceId = deviceId,
            Epoch = epoch,
            ResourceId = resourceId,
            PreviousHash = string.Empty,
            EntryHash = string.Empty,
        };
        evt.EntryHash = ComputeEntryHash(evt, auditMacKey);
        return evt;
    }
}

public sealed record ChainVerificationResult(bool Ok, bool ChainValid, string LastHash);
public sealed record MeshAcceptResult(int Accepted, string? ErrorCode, string? ErrorMessage);
