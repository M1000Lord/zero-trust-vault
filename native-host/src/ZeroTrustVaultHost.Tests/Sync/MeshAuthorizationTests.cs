using Xunit;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Sync;

/// <summary>
/// Acceptance-gate "Authority": membership events require owner/admin; credential
/// events require at least read/write; the vault's own device is the owner.
/// </summary>
public sealed class MeshAuthorizationTests
{
    private static VaultDevice Device(params string[] perms) => new()
    {
        DeviceId = "dev-remote",
        Status = "Active",
        Permissions = perms.ToList(),
    };

    [Theory]
    [InlineData("AddDevice")]
    [InlineData("RemoveDevice")]
    [InlineData("RotateDeviceEpoch")]
    [InlineData("UpdatePolicy")]
    public void MembershipEvents_RequireOwnerOrAdmin(string eventType)
    {
        Assert.False(MeshAuthorization.IsAuthorized(eventType, Device(MeshAuthorization.ReadWrite), isLocalOwnerDevice: false));
        Assert.True(MeshAuthorization.IsAuthorized(eventType, Device(MeshAuthorization.Admin), isLocalOwnerDevice: false));
        Assert.True(MeshAuthorization.IsAuthorized(eventType, Device(MeshAuthorization.Owner), isLocalOwnerDevice: false));
    }

    [Theory]
    [InlineData("CreateCredential")]
    [InlineData("UpdateCredential")]
    [InlineData("DeleteCredential")]
    public void CredentialEvents_RequireReadWrite(string eventType)
    {
        Assert.True(MeshAuthorization.IsAuthorized(eventType, Device(MeshAuthorization.ReadWrite), isLocalOwnerDevice: false));
        Assert.True(MeshAuthorization.IsAuthorized(eventType, Device(MeshAuthorization.Admin), isLocalOwnerDevice: false));
        Assert.False(MeshAuthorization.IsAuthorized(eventType, Device(), isLocalOwnerDevice: false));
    }

    [Fact]
    public void LocalOwnerDevice_IsAlwaysAuthorized()
    {
        Assert.True(MeshAuthorization.IsAuthorized("RemoveDevice", Device(), isLocalOwnerDevice: true));
        Assert.True(MeshAuthorization.IsAuthorized("UpdateCredential", Device(), isLocalOwnerDevice: true));
    }

    [Fact]
    public void NoPermissions_RejectsMembership()
    {
        Assert.False(MeshAuthorization.IsAuthorized("AddDevice", Device(), isLocalOwnerDevice: false));
    }

    [Fact]
    public void VaultOverload_ResolvesLocalOwnerFromVaultDeviceId()
    {
        var vault = new VaultFile { DeviceId = "dev-owner" };
        var owner = new VaultDevice { DeviceId = "dev-owner", Permissions = new() };
        var remote = new VaultDevice { DeviceId = "dev-remote", Permissions = new() };

        Assert.True(MeshAuthorization.IsAuthorized("RemoveDevice", owner, vault));
        Assert.False(MeshAuthorization.IsAuthorized("RemoveDevice", remote, vault));
    }
}
