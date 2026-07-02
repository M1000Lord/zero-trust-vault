using Xunit;
using ZeroTrustVaultHost.Sync;

namespace ZeroTrustVaultHost.Tests.Sync;

/// <summary>
/// Acceptance-gate "Conflict": concurrent update/update and delete/update preserve
/// data; a password conflict keeps both by default; ZTV never silently destroys a
/// secret on conflict.
/// </summary>
public sealed class MeshConflictResolverTests
{
    [Fact]
    public void IncomingBasedOnCurrentVersion_FastForwards()
    {
        var r = MeshConflictResolver.Resolve(
            existingDeleted: false, existingVersion: 3, existingDigest: "A",
            incomingDeleted: false, incomingBaseVersion: 3, incomingDigest: "B");
        Assert.Equal(ConflictResolution.ApplyIncoming, r);
    }

    [Fact]
    public void ConcurrentDifferentPasswords_KeepBoth()
    {
        // Existing advanced to v3; incoming was based on v2 and has different content.
        var r = MeshConflictResolver.Resolve(
            existingDeleted: false, existingVersion: 3, existingDigest: "newPwA",
            incomingDeleted: false, incomingBaseVersion: 2, incomingDigest: "newPwB");
        Assert.Equal(ConflictResolution.KeepBoth, r);
    }

    [Fact]
    public void ConcurrentDeleteVsLiveEdit_Resurrects()
    {
        // Incoming deletes based on an older version while the item was edited.
        var r = MeshConflictResolver.Resolve(
            existingDeleted: false, existingVersion: 4, existingDigest: "edited",
            incomingDeleted: true, incomingBaseVersion: 2, incomingDigest: "");
        Assert.Equal(ConflictResolution.Resurrect, r);
    }

    [Fact]
    public void ConcurrentLiveEditVsExistingDelete_Resurrects()
    {
        var r = MeshConflictResolver.Resolve(
            existingDeleted: true, existingVersion: 4, existingDigest: "",
            incomingDeleted: false, incomingBaseVersion: 2, incomingDigest: "edited");
        Assert.Equal(ConflictResolution.Resurrect, r);
    }

    [Fact]
    public void ConcurrentSameContent_KeepsExisting()
    {
        var r = MeshConflictResolver.Resolve(
            existingDeleted: false, existingVersion: 3, existingDigest: "same",
            incomingDeleted: false, incomingBaseVersion: 1, incomingDigest: "same");
        Assert.Equal(ConflictResolution.KeepExisting, r);
    }

    [Fact]
    public void ConcurrentDeleteVsDelete_IsIdempotent()
    {
        var r = MeshConflictResolver.Resolve(
            existingDeleted: true, existingVersion: 3, existingDigest: "",
            incomingDeleted: true, incomingBaseVersion: 1, incomingDigest: "");
        Assert.Equal(ConflictResolution.KeepExisting, r);
    }
}
