using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroTrustVaultHost.NativeMessaging;

/// <summary>
/// Incoming request from the Chrome extension via native messaging.
/// </summary>
public sealed class NativeRequest
{
    [JsonPropertyName("protocolVersion")]
    public int ProtocolVersion { get; set; }

    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = string.Empty;

    [JsonPropertyName("command")]
    public string Command { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = string.Empty;

    [JsonPropertyName("clientNonce")]
    public string ClientNonce { get; set; } = string.Empty;

    [JsonPropertyName("extensionId")]
    public string ExtensionId { get; set; } = string.Empty;

    [JsonPropertyName("origin")]
    public string? Origin { get; set; }

    [JsonPropertyName("tabId")]
    public int? TabId { get; set; }

    [JsonPropertyName("windowId")]
    public int? WindowId { get; set; }

    [JsonPropertyName("frameId")]
    public int? FrameId { get; set; }

    [JsonPropertyName("sessionId")]
    public string? SessionId { get; set; }

    [JsonPropertyName("payload")]
    public JsonElement Payload { get; set; }
}

/// <summary>
/// Outgoing response sent back to the Chrome extension.
/// </summary>
public sealed class NativeResponse
{
    [JsonPropertyName("requestId")]
    public string RequestId { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "ok";

    [JsonPropertyName("result")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Result { get; set; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public NativeError? Error { get; set; }

    public static NativeResponse Ok(string requestId, object result) => new()
    {
        RequestId = requestId,
        Status = "ok",
        Result = result
    };

    public static NativeResponse Err(string requestId, string code, string safeMessage) => new()
    {
        RequestId = requestId,
        Status = "error",
        Error = new NativeError { Code = code, SafeMessage = safeMessage }
    };
}

public sealed class NativeError
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;

    [JsonPropertyName("safeMessage")]
    public string SafeMessage { get; set; } = string.Empty;

    [JsonPropertyName("retryAfterSeconds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? RetryAfterSeconds { get; set; }
}
