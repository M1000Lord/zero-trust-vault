namespace ZeroTrustVaultHost.Sync;

/// <summary>
/// Conflict-resolution policy for concurrent credential edits (acceptance-gate
/// "Conflict": concurrent update/update and delete/update preserve data; a
/// password conflict keeps both by default). Pure and unit-testable.
///
/// Causality is approximated by the base version each edit was made against: an
/// incoming edit whose base version is the current version saw the latest state
/// and fast-forwards; an incoming edit based on an older version is concurrent.
/// Concurrent edits never silently overwrite — a differing password keeps both
/// copies, and a delete racing a live edit resurrects the edit. ZTV biases
/// toward never destroying a secret on conflict.
/// </summary>
public enum ConflictResolution
{
    /// <summary>Incoming saw the latest state (or matches it) — apply it.</summary>
    ApplyIncoming,
    /// <summary>Incoming is stale and adds nothing — keep what we have.</summary>
    KeepExisting,
    /// <summary>Concurrent, differing edits — keep both (conflict copy).</summary>
    KeepBoth,
    /// <summary>A delete raced a concurrent live edit — keep the edit, not the delete.</summary>
    Resurrect,
}

public static class MeshConflictResolver
{
    /// <summary>
    /// Decides how to merge an incoming edit against the current item state.
    /// </summary>
    /// <param name="existingDeleted">Is the current item a tombstone?</param>
    /// <param name="existingVersion">Current item version.</param>
    /// <param name="existingDigest">Content digest of the current item.</param>
    /// <param name="incomingDeleted">Does the incoming edit delete the item?</param>
    /// <param name="incomingBaseVersion">Version the incoming edit was based on.</param>
    /// <param name="incomingDigest">Content digest the incoming edit produces.</param>
    public static ConflictResolution Resolve(
        bool existingDeleted, int existingVersion, string existingDigest,
        bool incomingDeleted, int incomingBaseVersion, string incomingDigest)
    {
        // Fast-forward: the incoming edit was made against the current (or a
        // newer) version, so it causally dominates — apply it.
        if (incomingBaseVersion >= existingVersion)
            return ConflictResolution.ApplyIncoming;

        // Concurrent from here down (incoming based on an older version).

        // Identical outcome (same content + same deleted flag) — no real conflict.
        if (existingDeleted == incomingDeleted &&
            string.Equals(existingDigest, incomingDigest, StringComparison.Ordinal))
            return ConflictResolution.KeepExisting;

        // Delete vs live edit (in either direction) — never let a delete erase a
        // concurrent edit; resurrect the surviving content.
        if (existingDeleted != incomingDeleted)
            return ConflictResolution.Resurrect;

        // Two concurrent content edits (e.g. a password changed on both devices)
        // — keep both so neither secret is lost.
        return ConflictResolution.KeepBoth;
    }
}
