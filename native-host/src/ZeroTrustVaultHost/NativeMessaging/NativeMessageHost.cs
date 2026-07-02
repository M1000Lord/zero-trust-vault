using System.Text;
using System.Text.Json;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Diagnostics;

namespace ZeroTrustVaultHost.NativeMessaging;

/// <summary>
/// Implements the Chrome native messaging protocol:
/// each message is prefixed with a 4-byte little-endian length, followed by UTF-8 JSON.
/// </summary>
public sealed class NativeMessageHost
{
    private static readonly JsonSerializerOptions s_readOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
    };

    private static readonly JsonSerializerOptions s_writeOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly CommandRouter _router;

    public NativeMessageHost(CommandRouter router)
    {
        _router = router;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();

        var lengthBuffer = new byte[4];

        while (!ct.IsCancellationRequested)
        {
            // Read exactly 4 bytes for the message length
            int bytesRead = await ReadExactAsync(stdin, lengthBuffer, 0, 4, ct);
            if (bytesRead == 0)
                break; // stdin closed — extension disconnected

            int messageLength = BitConverter.ToInt32(lengthBuffer, 0);
            if (messageLength <= 0 || messageLength > 1_048_576) // 1 MB max
            {
                // Malformed framing; terminate (length value is non-secret).
                DiagnosticLog.Write("HOST", $"Invalid message length {messageLength} — terminating");
                break;
            }

            var messageBuffer = new byte[messageLength];
            bytesRead = await ReadExactAsync(stdin, messageBuffer, 0, messageLength, ct);
            if (bytesRead < messageLength)
                break;

            NativeResponse response;
            string requestId = string.Empty;

            try
            {
                using var document = JsonDocument.Parse(messageBuffer);
                requestId = TryReadRequestId(document.RootElement);

                string? fieldError = CommandRouter.ValidateRequestFields(document.RootElement);
                if (fieldError is not null)
                {
                    response = NativeResponse.Err(requestId, "UNKNOWN_FIELD", fieldError);
                    await WriteResponseAsync(stdout, response, ct);
                    continue;
                }

                var request = document.RootElement.Deserialize<NativeRequest>(s_readOptions);
                if (request is null)
                {
                    response = NativeResponse.Err(requestId, "INVALID_MESSAGE", "Could not parse message.");
                }
                else
                {
                    requestId = request.RequestId ?? string.Empty;
                    response = await _router.RouteAsync(request, ct);
                }
            }
            catch (JsonException)
            {
                response = NativeResponse.Err(requestId, "INVALID_JSON", "Message is not valid JSON.");
            }
            catch (Exception ex)
            {
#if DEBUG
                response = NativeResponse.Err(requestId, "INTERNAL_ERROR", $"Internal error: {ex.Message}");
#else
                response = NativeResponse.Err(requestId, "INTERNAL_ERROR", "An internal error occurred.");
                _ = ex; // suppress unused variable warning in release
#endif
            }

            // Command + status are non-secret; useful for tracing the flow.
            DiagnosticLog.Write("HOST", $"Handled '{requestId}' -> status={response.Status}");
            await WriteResponseAsync(stdout, response, ct);
        }
    }

    private static string TryReadRequestId(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            return string.Empty;
        if (!root.TryGetProperty("requestId", out var requestIdProp))
            return string.Empty;
        return requestIdProp.ValueKind == JsonValueKind.String
            ? requestIdProp.GetString() ?? string.Empty
            : string.Empty;
    }

    private static async Task WriteResponseAsync(Stream stdout, NativeResponse response, CancellationToken ct)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(response, s_writeOptions);
        byte[] lengthPrefix = BitConverter.GetBytes(json.Length);
        await stdout.WriteAsync(lengthPrefix, ct);
        await stdout.WriteAsync(json, ct);
        await stdout.FlushAsync(ct);
    }

    private static async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, ct);
            if (read == 0)
                return totalRead; // EOF
            totalRead += read;
        }
        return totalRead;
    }
}
