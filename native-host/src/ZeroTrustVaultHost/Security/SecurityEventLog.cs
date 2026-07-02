using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroTrustVaultHost.Security;

/// <summary>
/// Append-only local security event log. Never stores plaintext secrets.
/// Events are written as newline-delimited JSON to a local file.
/// </summary>
public sealed class SecurityEventLog
{
    private static readonly string LogDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ZeroTrustVault");

    private static readonly string LogFilePath = Path.Combine(LogDirectory, "security-events.log");

    private static readonly JsonSerializerOptions s_options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly object _writeLock = new();

    public void LogEvent(SecurityEvent evt)
    {
        try
        {
            Directory.CreateDirectory(LogDirectory);
            string line = JsonSerializer.Serialize(evt, s_options);
            lock (_writeLock)
            {
                File.AppendAllText(LogFilePath, line + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch
        {
            // Best-effort; never throw from logging
        }
    }

    public void LogHelloSuccess(string sessionId, string origin) =>
        LogEvent(new SecurityEvent("HELLO_SUCCESS", sessionId, origin));

    public void LogHelloFailure(string? sessionId, string? origin, string reason) =>
        LogEvent(new SecurityEvent("HELLO_FAILURE", sessionId, origin) { Details = reason });

    public void LogUnlock(string sessionId, string origin) =>
        LogEvent(new SecurityEvent("VAULT_UNLOCK", sessionId, origin));

    public void LogLock(string? sessionId) =>
        LogEvent(new SecurityEvent("VAULT_LOCK", sessionId, null));

    public void LogCredentialAdded(string sessionId, string origin, string credentialId) =>
        LogEvent(new SecurityEvent("CREDENTIAL_ADDED", sessionId, origin) { ResourceId = credentialId });

    public void LogCredentialDeleted(string sessionId, string origin, string credentialId) =>
        LogEvent(new SecurityEvent("CREDENTIAL_DELETED", sessionId, origin) { ResourceId = credentialId });

    public void LogCredentialRevealed(string sessionId, string origin, string credentialId) =>
        LogEvent(new SecurityEvent("CREDENTIAL_REVEALED", sessionId, origin) { ResourceId = credentialId });

    public void LogRateLimited(string? sessionId, string command) =>
        LogEvent(new SecurityEvent("RATE_LIMITED", sessionId, null) { Details = command });

    public void LogValidationError(string command, string reason) =>
        LogEvent(new SecurityEvent("VALIDATION_ERROR", null, null) { Details = $"{command}: {reason}" });

    public void LogMigration(string details) =>
        LogEvent(new SecurityEvent("VAULT_MIGRATION", null, null) { Details = details });

    /// <summary>Records that a corrupt vault was quarantined. Reason is non-secret.</summary>
    public void LogVaultQuarantined(string reason) =>
        LogEvent(new SecurityEvent("VAULT_QUARANTINED", null, null) { Details = reason });

    /// <summary>Records that a corrupt empty vault was reinitialized after quarantine.</summary>
    public void LogVaultReset(string details) =>
        LogEvent(new SecurityEvent("VAULT_RESET", null, null) { Details = details });
}

public sealed class SecurityEvent
{
    public SecurityEvent(string eventType, string? sessionId, string? origin)
    {
        EventType = eventType;
        SessionId = sessionId;
        Origin = origin;
        Timestamp = DateTimeOffset.UtcNow.ToString("O");
    }

    [JsonPropertyName("eventType")]
    public string EventType { get; set; }

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; }

    [JsonPropertyName("sessionId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SessionId { get; set; }

    [JsonPropertyName("origin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Origin { get; set; }

    [JsonPropertyName("resourceId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResourceId { get; set; }

    [JsonPropertyName("details")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Details { get; set; }
}
