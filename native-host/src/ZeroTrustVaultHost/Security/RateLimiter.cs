using System.Collections.Concurrent;

namespace ZeroTrustVaultHost.Security;

/// <summary>
/// Per-command rate limiting with sliding windows.
/// Rules:
///   - Max 5 secret reveals per minute per session
///   - Max 10 Windows Hello prompts per 5 minutes (global)
///   - Max 3 failed Hello attempts before 30-second cooldown (global)
/// </summary>
public sealed class RateLimiter
{
    // Timestamps of recent events, keyed by bucket string
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _windows = new();
    private readonly object _lock = new();

    // Track consecutive Hello failures for cooldown
    private int _consecutiveHelloFailures = 0;
    private DateTimeOffset? _helloCooldownUntil = null;

    private static readonly TimeSpan SecretRevealWindow = TimeSpan.FromMinutes(1);
    private const int MaxSecretRevealsPerWindow = 5;

    private static readonly TimeSpan HelloWindow = TimeSpan.FromMinutes(5);
    private const int MaxHelloPromptsPerWindow = 10;

    private const int MaxConsecutiveHelloFailures = 3;
    private static readonly TimeSpan HelloCooldown = TimeSpan.FromSeconds(30);

    // ---- Secret reveal rate limiting ----

    /// <summary>
    /// Returns null if allowed, or a RateLimitInfo with retry delay if rate-limited.
    /// </summary>
    public RateLimitInfo? CheckSecretReveal(string sessionId)
    {
        string bucket = $"secret:{sessionId}";
        return CheckWindow(bucket, SecretRevealWindow, MaxSecretRevealsPerWindow);
    }

    public void RecordSecretReveal(string sessionId)
    {
        string bucket = $"secret:{sessionId}";
        Record(bucket);
    }

    // ---- Windows Hello rate limiting ----

    public RateLimitInfo? CheckHelloPrompt()
    {
        lock (_lock)
        {
            // Check cooldown from repeated failures
            if (_helloCooldownUntil.HasValue && DateTimeOffset.UtcNow < _helloCooldownUntil.Value)
            {
                int retryAfter = (int)(_helloCooldownUntil.Value - DateTimeOffset.UtcNow).TotalSeconds + 1;
                return new RateLimitInfo("RATE_LIMITED", "Too many failed Hello attempts. Please wait.", retryAfter);
            }
        }

        return CheckWindow("hello:global", HelloWindow, MaxHelloPromptsPerWindow);
    }

    public void RecordHelloSuccess()
    {
        Record("hello:global");
        lock (_lock)
        {
            _consecutiveHelloFailures = 0;
            _helloCooldownUntil = null;
        }
    }

    public void RecordHelloFailure()
    {
        Record("hello:global");
        lock (_lock)
        {
            _consecutiveHelloFailures++;
            if (_consecutiveHelloFailures >= MaxConsecutiveHelloFailures)
            {
                _helloCooldownUntil = DateTimeOffset.UtcNow + HelloCooldown;
                _consecutiveHelloFailures = 0;
            }
        }
    }

    // ---- Helpers ----

    private RateLimitInfo? CheckWindow(string bucket, TimeSpan window, int maxCount)
    {
        var now = DateTimeOffset.UtcNow;

        lock (_lock)
        {
            if (!_windows.TryGetValue(bucket, out var queue))
                return null; // No events yet — allowed

            // Purge old events
            while (queue.Count > 0 && now - queue.Peek() > window)
                queue.Dequeue();

            if (queue.Count >= maxCount)
            {
                // Rate limited — compute when oldest event falls outside window
                var oldest = queue.Peek();
                int retryAfter = (int)((oldest + window) - now).TotalSeconds + 1;
                return new RateLimitInfo("RATE_LIMITED", "Rate limit exceeded. Please wait.", retryAfter);
            }

            return null;
        }
    }

    private void Record(string bucket)
    {
        var now = DateTimeOffset.UtcNow;
        lock (_lock)
        {
            var queue = _windows.GetOrAdd(bucket, _ => new Queue<DateTimeOffset>());
            queue.Enqueue(now);
        }
    }
}

public sealed record RateLimitInfo(string Code, string SafeMessage, int RetryAfterSeconds);
