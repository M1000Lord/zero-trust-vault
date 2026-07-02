using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Sync;

/// <summary>
/// Authority check for incoming MeshEvents (acceptance-gate "Authority":
/// membership events require owner/admin permission). Pure and unit-testable.
///
/// The vault's own device (vault.DeviceId) is the implicit owner. Remote devices
/// must carry the appropriate permission in the device graph to author a given
/// class of event. Credential edits require at least read/write; membership
/// changes (adding/removing devices, rotating epochs, policy) require owner or
/// admin. A device with no relevant permission is rejected even if its signature
/// and epoch are otherwise valid.
/// </summary>
public static class MeshAuthorization
{
    public const string Owner     = "VaultOwner";
    public const string Admin     = "DeviceAdmin";
    public const string ReadWrite = "CredentialReadWrite";

    private static readonly HashSet<string> s_membershipEvents = new(StringComparer.Ordinal)
    {
        "AddDevice", "RemoveDevice", "RotateDeviceEpoch",
        "DeviceAdded", "DeviceRemoved", "EpochRotated",
        "AddMemberToSharedSpace", "RemoveMemberFromSharedSpace",
        "RotateSharedSpaceEpoch", "UpdatePolicy",
    };

    private static readonly HashSet<string> s_credentialEvents = new(StringComparer.Ordinal)
    {
        "CreateCredential", "UpdateCredential", "DeleteCredential",
        "CredentialAdded", "CredentialUpdated", "CredentialDeleted", "CredentialTombstoned",
    };

    /// <summary>True if <paramref name="device"/> may author an event of this type.</summary>
    public static bool IsAuthorized(string eventType, VaultDevice device, bool isLocalOwnerDevice)
    {
        if (isLocalOwnerDevice) return true;

        var perms = device.Permissions ?? new List<string>();
        bool isOwnerOrAdmin = perms.Contains(Owner) || perms.Contains(Admin);

        if (s_membershipEvents.Contains(eventType))
            return isOwnerOrAdmin;

        if (s_credentialEvents.Contains(eventType))
            return isOwnerOrAdmin || perms.Contains(ReadWrite);

        // Maintenance / unknown events: require at least read/write membership.
        return isOwnerOrAdmin || perms.Contains(ReadWrite);
    }

    /// <summary>Convenience overload resolving the local-owner flag from the vault.</summary>
    public static bool IsAuthorized(string eventType, VaultDevice device, VaultFile vault) =>
        IsAuthorized(eventType, device,
            string.Equals(device.DeviceId, vault.DeviceId, StringComparison.Ordinal));
}
