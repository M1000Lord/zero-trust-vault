using System.Buffers;
using System.Text;
using System.Text.Json;

namespace ZeroTrustVaultHost.Sync;

/// <summary>
/// Deterministic ("canonical") JSON serialization for signing and hashing.
///
/// Two semantically-equal objects must produce byte-identical output so that a
/// signature computed on one machine verifies on another. We achieve this by
/// recursively re-emitting a parsed JSON document with object keys sorted by
/// ordinal code point and no insignificant whitespace.
///
/// This is the serialization that event signatures and the hash chain are
/// computed over.
/// </summary>
public static class CanonicalJson
{
    /// <summary>Serializes any object to canonical UTF-8 JSON bytes.</summary>
    public static byte[] SerializeToBytes<T>(T value)
    {
        // Round-trip through JsonDocument so we can canonicalize key order.
        byte[] raw = JsonSerializer.SerializeToUtf8Bytes(value);
        using var doc = JsonDocument.Parse(raw);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
        {
            WriteCanonical(doc.RootElement, writer);
        }
        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>Canonical JSON as a string (UTF-8 decoded).</summary>
    public static string SerializeToString<T>(T value) =>
        Encoding.UTF8.GetString(SerializeToBytes(value));

    private static void WriteCanonical(JsonElement element, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                // Sort properties by ordinal name for determinism.
                foreach (var prop in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(prop.Name);
                    WriteCanonical(prop.Value, writer);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                    WriteCanonical(item, writer);
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.Number:
                writer.WriteRawValue(element.GetRawText());
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
                writer.WriteBooleanValue(element.GetBoolean());
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
        }
    }
}
