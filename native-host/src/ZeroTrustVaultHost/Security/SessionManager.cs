using System.Collections.Concurrent;

namespace ZeroTrustVaultHost.Security;

/// <summary>
/// Tracks active sessions. Each session is bound to a specific origin.
/// Sessions cannot be reused across origins. Default timeout: 15 minutes.
/// </summary>
public sealed class SessionManager
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(15);

    private readonly ConcurrentDictionary<string, SessionEntry> _sessions = new();
    private readonly TimeSpan _timeout;

    public SessionManager(TimeSpan? timeout = null)
    {
        _timeout = timeout ?? DefaultTimeout;
    }

    /// <summary>
    /// Creates a new session bound to the given origin.
    /// </summary>
    public string CreateSession(string normalizedOrigin)
    {
        string sessionId = Guid.NewGuid().ToString("D");
        var entry = new SessionEntry(sessionId, normalizedOrigin, DateTimeOffset.UtcNow);
        _sessions[sessionId] = entry;
        return sessionId;
    }

    /// <summary>
    /// Validates a session: checks it exists, origin matches, and it hasn't timed out.
    /// Updates LastUsedAt on success.
    /// </summary>
    public SessionValidationResult Validate(string? sessionId, string normalizedOrigin)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return SessionValidationResult.Missing;

        if (!_sessions.TryGetValue(sessionId, out var entry))
            return SessionValidationResult.NotFound;

        if (!string.Equals(entry.Origin, normalizedOrigin, StringComparison.Ordinal))
            return SessionValidationResult.OriginMismatch;

        if (DateTimeOffset.UtcNow - entry.LastUsedAt > _timeout)
        {
            _sessions.TryRemove(sessionId, out _);
            return SessionValidationResult.Expired;
        }

        // Update last used
        var updated = entry with { LastUsedAt = DateTimeOffset.UtcNow };
        _sessions[sessionId] = updated;

        return SessionValidationResult.Valid;
    }

    /// <summary>
    /// Validates a session for device-wide operations that are not scoped to
    /// a single website origin (e.g. sync). Checks existence and expiry only
    /// — deliberately skips the origin-binding check that <see cref="Validate"/>
    /// performs, since sync is not per-origin. Updates LastUsedAt on success.
    /// </summary>
    public SessionValidationResult ValidateAnyOrigin(string? sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return SessionValidationResult.Missing;

        if (!_sessions.TryGetValue(sessionId, out var entry))
            return SessionValidationResult.NotFound;

        if (DateTimeOffset.UtcNow - entry.LastUsedAt > _timeout)
        {
            _sessions.TryRemove(sessionId, out _);
            return SessionValidationResult.Expired;
        }

        var updated = entry with { LastUsedAt = DateTimeOffset.UtcNow };
        _sessions[sessionId] = updated;

        return SessionValidationResult.Valid;
    }

    /// <summary>
    /// Returns the session entry, or null if invalid.
    /// </summary>
    public SessionEntry? Get(string? sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return null;
        _sessions.TryGetValue(sessionId, out var entry);
        return entry;
    }

    /// <summary>
    /// Removes a specific session (e.g., after lock).
    /// </summary>
    public void Remove(string sessionId) => _sessions.TryRemove(sessionId, out _);

    /// <summary>
    /// Clears ALL sessions immediately (e.g., lockVault).
    /// </summary>
    public void ClearAll() => _sessions.Clear();

    /// <summary>
    /// Removes all expired sessions.
    /// </summary>
    public void PurgeExpired()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kv in _sessions)
        {
            if (now - kv.Value.LastUsedAt > _timeout)
                _sessions.TryRemove(kv.Key, out _);
        }
    }

    public int ActiveCount => _sessions.Count;
}

public sealed record SessionEntry(
    string SessionId,
    string Origin,
    DateTimeOffset CreatedAt)
{
    public DateTimeOffset LastUsedAt { get; init; } = CreatedAt;
}

public enum SessionValidationResult
{
    Valid,
    Missing,
    NotFound,
    OriginMismatch,
    Expired,
}
