using System.Text.Json;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;
using ZeroTrustVaultHost.Sync;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Central command dispatcher. Validates all envelope-level fields before routing.
/// Rejects: unknown commands, unknown payload fields, stale timestamps, HTTP origins, IDN origins.
/// </summary>
public sealed class CommandRouter
{
    private static readonly TimeSpan MaxTimestampSkew = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan NonceRetention = TimeSpan.FromMinutes(2);

    private readonly VaultCommands _vault;
    private readonly TotpCommands _totp;
    private readonly RecoveryCommands _recovery;
    private readonly DeviceCommands _device;
    private readonly SyncCommands _sync;
    private readonly HealthCommands _health;
    private readonly SecurityEventLog _secEventLog;
    private readonly ExtensionIdentity _extensionIdentity;
    private readonly Dictionary<string, DateTimeOffset> _recentNonces = new(StringComparer.Ordinal);
    private readonly object _nonceLock = new();

    // Allowed top-level request fields (strict schema)
    private static readonly HashSet<string> s_knownRequestFields = new(StringComparer.Ordinal)
    {
        "protocolVersion", "requestId", "command", "timestamp",
        "clientNonce", "extensionId", "origin", "tabId", "windowId", "frameId",
        "sessionId", "payload"
    };

    // Commands that never touch vault contents or secrets and must remain
    // reachable even when caller identity cannot be established — otherwise a
    // broken install (e.g. a stale/missing native-messaging manifest) would
    // also hide the diagnostics a user needs to see WHY everything is blocked.
    private static readonly HashSet<string> s_diagnosticCommands = new(StringComparer.Ordinal)
    {
        "getVaultStatus", "securityHealthCheck",
    };

    public CommandRouter(
        VaultManager vaultManager,
        SessionManager sessionManager,
        IHelloManager helloManager,
        RateLimiter rateLimiter,
        SecurityEventLog securityEventLog,
        EventLogManager eventLogManager,
        ExtensionIdentity? extensionIdentity = null)
    {
        _secEventLog = securityEventLog;
        _extensionIdentity = extensionIdentity ?? ExtensionIdentity.Untrusted("NotProvided");

        var ctx = new CommandContext(vaultManager, sessionManager, helloManager, rateLimiter, securityEventLog, eventLogManager);

        _vault    = new VaultCommands(ctx);
        _totp     = new TotpCommands(ctx);
        _recovery = new RecoveryCommands(ctx);
        _device   = new DeviceCommands(ctx);
        _sync     = new SyncCommands(ctx);
        _health   = new HealthCommands(ctx);
    }

    public async Task<NativeResponse> RouteAsync(NativeRequest request, CancellationToken ct)
    {
        string reqId = request.RequestId ?? string.Empty;

        // 1. Protocol version check
        if (request.ProtocolVersion != 1)
        {
            _secEventLog.LogValidationError(request.Command, $"Unsupported protocol version {request.ProtocolVersion}");
            return NativeResponse.Err(reqId, "UNSUPPORTED_PROTOCOL_VERSION", "Protocol version 1 required.");
        }

        var nonceError = ValidateAndRecordNonce(request, reqId);
        if (nonceError is not null)
            return nonceError;

        // 2. Timestamp validation: reject if |now - timestamp| > 60 seconds
        if (!DateTimeOffset.TryParse(request.Timestamp, out var reqTime))
        {
            _secEventLog.LogValidationError(request.Command, "Invalid timestamp format");
            return NativeResponse.Err(reqId, "INVALID_TIMESTAMP", "Timestamp is missing or invalid.");
        }

        var skew = DateTimeOffset.UtcNow - reqTime;
        if (Math.Abs(skew.TotalSeconds) > MaxTimestampSkew.TotalSeconds)
        {
            _secEventLog.LogValidationError(request.Command, $"Stale timestamp: {skew.TotalSeconds:F0}s skew");
            return NativeResponse.Err(reqId, "STALE_TIMESTAMP", "Request timestamp is too old or in the future.");
        }

        // 3. Validate and normalize origin if present (commands that need it will require it explicitly)
        string? normalizedOrigin = null;
        if (!string.IsNullOrEmpty(request.Origin))
        {
            try
            {
                normalizedOrigin = OriginValidator.ValidateAndNormalize(request.Origin);
            }
            catch (ArgumentException ex)
            {
                _secEventLog.LogValidationError(request.Command, $"Invalid origin: {ex.Message}");
                return NativeResponse.Err(reqId, "INVALID_ORIGIN", "Origin is invalid. Only HTTPS origins are accepted.");
            }
        }

        // 4. Unknown command check
        if (string.IsNullOrWhiteSpace(request.Command))
            return NativeResponse.Err(reqId, "UNKNOWN_COMMAND", "Command is required.");

        // 4b. Native-host caller authentication: the extensionId field is
        // supplied by the caller and must NOT be trusted merely because it is
        // present (Chrome's own allowed_origins check restricts who Chrome
        // launches this host for, but that is enforced by Chrome, not by us —
        // this is the host's own independent check). Diagnostic commands stay
        // reachable regardless, so a broken install can still explain itself.
        if (!s_diagnosticCommands.Contains(request.Command))
        {
            string? idError = _extensionIdentity.Validate(request.ExtensionId);

            bool allowUnverifiableInDevBuild = false;
#if DEBUG
            // Only the "we could not determine our own expected caller"
            // case (e.g. running the exe directly from a build output
            // directory rather than an installed location) is relaxed, and
            // ONLY in Debug builds — this whole branch does not exist in
            // Release. A wrong, malformed, or missing ID is ALWAYS rejected,
            // in both configurations.
            allowUnverifiableInDevBuild = idError == "EXTENSION_IDENTITY_UNVERIFIABLE";
#endif
            if (idError is not null && !allowUnverifiableInDevBuild)
            {
                // Log only the classification code — never the raw claimed ID
                // alongside anything else — as safe, non-secret metadata.
                _secEventLog.LogValidationError(request.Command, $"Extension identity rejected: {idError}");
                return NativeResponse.Err(reqId, idError, "Caller identity could not be verified.");
            }
            if (allowUnverifiableInDevBuild)
            {
                _secEventLog.LogValidationError(request.Command,
                    "DEV BUILD: extension identity unverifiable (no installed manifest found) — allowing for local testing only.");
            }
        }

        // 5. Route to the appropriate handler
        try
        {
            return request.Command switch
            {
                // Health / vault status
                "getVaultStatus"         => await _health.GetVaultStatusAsync(request, normalizedOrigin, ct),
                "securityHealthCheck"    => await _health.SecurityHealthCheckAsync(request, normalizedOrigin, ct),

                // Vault operations
                "unlockOrigin"                          => await _vault.UnlockAsync(request, normalizedOrigin, ct),
                "listSummariesForOrigin"                => await _vault.ListCredentialSummariesAsync(request, normalizedOrigin, ct),
                "decryptSelectedCredentialForExactOrigin"=> await _vault.DecryptCredentialAsync(request, normalizedOrigin, ct),
                "fillCredentialForExactOrigin"           => await _vault.FillCredentialAsync(request, normalizedOrigin, ct),
                "addCredentialForExactOrigin"           => await _vault.AddCredentialAsync(request, normalizedOrigin, ct),
                "lockOriginSession"                     => await _vault.LockVaultAsync(request, normalizedOrigin, ct),
                "countCredentialsForOrigin"             => await _vault.CountCredentialsAsync(request, normalizedOrigin, ct),
                "updateCredentialAtomic"                => await _vault.UpdateCredentialAtomicAsync(request, normalizedOrigin, ct),
                "deleteCredentialTombstone"             => await _vault.DeleteCredentialTombstoneAsync(request, normalizedOrigin, ct),

                // TOTP / clipboard
                "generateTotpForCredential"  => await _totp.GenerateTotpAsync(request, normalizedOrigin, ct),
                "copySecretWithTimedClear"   => await _totp.CopySecretWithTimedClearAsync(request, normalizedOrigin, ct),

                // Recovery
                "createRecoveryKit" => await _recovery.CreateRecoveryKitAsync(request, normalizedOrigin, ct),
                "recoverVault"      => await _recovery.RecoverVaultAsync(request, normalizedOrigin, ct),

                // Device pairing
                "beginDevicePairing"   => await _device.BeginDevicePairingAsync(request, normalizedOrigin, ct),
                "approveDevicePairing" => await _device.ApproveDevicePairingAsync(request, normalizedOrigin, ct),
                "removeDevice"         => await _device.RemoveDeviceAsync(request, normalizedOrigin, ct),

                // Sync
                "syncPullEvents"  => await _sync.SyncPullAsync(request, normalizedOrigin, ct),
                "syncPushEvents"  => await _sync.SyncPushAsync(request, normalizedOrigin, ct),
                "verifyEventLog"  => await _sync.VerifyEventLogAsync(request, normalizedOrigin, ct),

                _ => UnknownCommand(reqId, request.Command),
            };
        }
        catch (OperationCanceledException)
        {
            return NativeResponse.Err(reqId, "CANCELLED", "Operation was cancelled.");
        }
        catch (Exception ex)
        {
#if DEBUG
            return NativeResponse.Err(reqId, "INTERNAL_ERROR", $"Internal error: {ex.GetType().Name}: {ex.Message}");
#else
            _ = ex;
            return NativeResponse.Err(reqId, "INTERNAL_ERROR", "An internal error occurred.");
#endif
        }
    }

    private NativeResponse UnknownCommand(string reqId, string command)
    {
        _secEventLog.LogValidationError(command, "Unknown command");
        return NativeResponse.Err(reqId, "UNKNOWN_COMMAND", $"Unknown command: '{command}'.");
    }

    private NativeResponse? ValidateAndRecordNonce(NativeRequest request, string reqId)
    {
        string nonce = request.ClientNonce ?? string.Empty;
        if (nonce.Length < 16 || nonce.Length > 128)
        {
            _secEventLog.LogValidationError(request.Command, "Missing or invalid client nonce");
            return NativeResponse.Err(reqId, "INVALID_CLIENT_NONCE", "Request nonce is missing or invalid.");
        }

        var now = DateTimeOffset.UtcNow;
        lock (_nonceLock)
        {
            foreach (var old in _recentNonces.Where(kv => now - kv.Value > NonceRetention).Select(kv => kv.Key).ToArray())
                _recentNonces.Remove(old);

            if (_recentNonces.ContainsKey(nonce))
            {
                _secEventLog.LogValidationError(request.Command, "Replay nonce rejected");
                return NativeResponse.Err(reqId, "REPLAYED_NONCE", "Request was already used.");
            }

            _recentNonces[nonce] = now;
        }

        return null;
    }

    // ---- Static helpers used by command handlers ----

    public static string? ValidateRequestFields(JsonElement requestEnvelope)
    {
        if (requestEnvelope.ValueKind != JsonValueKind.Object)
            return "Request must be a JSON object.";

        foreach (var prop in requestEnvelope.EnumerateObject())
        {
            if (!s_knownRequestFields.Contains(prop.Name))
                return $"Unknown request field: '{prop.Name}'.";
        }

        return null;
    }

    /// <summary>
    /// Validates that a JsonElement payload contains ONLY the allowed field names.
    /// Returns an error description if unknown fields are found, null otherwise.
    /// </summary>
    public static string? ValidatePayloadFields(JsonElement payload, IEnumerable<string> allowedFields)
    {
        if (payload.ValueKind != JsonValueKind.Object)
            return null; // empty/null payload has no fields to check

        var allowed = new HashSet<string>(allowedFields, StringComparer.Ordinal);
        foreach (var prop in payload.EnumerateObject())
        {
            if (!allowed.Contains(prop.Name))
                return $"Unknown payload field: '{prop.Name}'.";
        }
        return null;
    }

    /// <summary>
    /// Tries to get a required string field from a JsonElement payload.
    /// </summary>
    public static bool TryGetString(JsonElement payload, string fieldName, out string value)
    {
        value = string.Empty;
        if (payload.ValueKind != JsonValueKind.Object) return false;
        if (!payload.TryGetProperty(fieldName, out var prop)) return false;
        if (prop.ValueKind != JsonValueKind.String) return false;
        value = prop.GetString() ?? string.Empty;
        return !string.IsNullOrEmpty(value);
    }
}
