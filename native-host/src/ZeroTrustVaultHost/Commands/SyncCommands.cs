using System.Text.Json;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Handles sync commands: syncPullEvents, syncPushEvents, verifyEventLog.
/// </summary>
public sealed class SyncCommands
{
    private readonly CommandContext _ctx;

    public SyncCommands(CommandContext ctx) => _ctx = ctx;

    // ---- syncPullEvents ----

    public async Task<NativeResponse> SyncPullAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string[] allowed = { "since" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // Sync is device-wide, not scoped to one website origin, but it still
        // requires a valid, unexpired session — previously a missing/empty
        // sessionId fell through this check unchecked, letting any caller
        // read the full event log (device ids, item ids, timestamps).
        var sessionErr = _ctx.ValidateAnySession(request.SessionId, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        var events = _ctx.EventLogManager.GetAllEvents();

        // Optional filter by 'since' ISO8601 timestamp
        if (CommandRouter.TryGetString(request.Payload, "since", out string sinceStr)
            && DateTimeOffset.TryParse(sinceStr, out var since))
        {
            var filtered = new List<object>();
            foreach (var raw in events)
            {
                try
                {
                    string json = JsonSerializer.Serialize(raw);
                    var evt = JsonSerializer.Deserialize<SyncEvent>(json);
                    if (evt is not null && DateTimeOffset.TryParse(evt.Timestamp, out var ts) && ts > since)
                        filtered.Add(raw);
                }
                catch { }
            }
            await Task.CompletedTask;
            return NativeResponse.Ok(request.RequestId, new { events = filtered });
        }

        await Task.CompletedTask;
        return NativeResponse.Ok(request.RequestId, new { events });
    }

    // ---- syncPushEvents ----

    public async Task<NativeResponse> SyncPushAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string[] allowed = { "events" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        // Validate session (see SyncPullAsync remarks — a missing session
        // must be rejected, not silently allowed through).
        var sessionErr = _ctx.ValidateAnySession(request.SessionId, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        if (!request.Payload.TryGetProperty("events", out var eventsElement))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "events array is required.");

        if (eventsElement.ValueKind != JsonValueKind.Array)
            return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "events must be an array.");

        var incoming = new List<MeshEvent>();
        foreach (var el in eventsElement.EnumerateArray())
        {
            try
            {
                var evt = JsonSerializer.Deserialize<MeshEvent>(el.GetRawText());
                if (evt is not null) incoming.Add(evt);
            }
            catch
            {
                return NativeResponse.Err(request.RequestId, "MALFORMED_EVENT", "One or more sync events are malformed.");
            }
        }

        var acceptResult = _ctx.EventLogManager.AcceptMeshEvents(incoming);
        if (acceptResult.ErrorCode is not null)
            return NativeResponse.Err(request.RequestId, acceptResult.ErrorCode, acceptResult.ErrorMessage ?? "Sync event rejected.");

        await Task.CompletedTask;
        return NativeResponse.Ok(request.RequestId, new
        {
            ok = true,
            accepted = acceptResult.Accepted,
        });
    }

    // ---- verifyEventLog ----

    public async Task<NativeResponse> VerifyEventLogAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        var sessionErr = _ctx.ValidateAnySession(request.SessionId, request.RequestId, out var sessionProof);
        if (sessionErr is not null) return sessionErr;

        // Try to get audit MAC key from vault root key (best-effort)
        byte[]? auditMacKey = null;
        if (_ctx.VaultManager.VaultExists())
        {
            try
            {
                var vault = _ctx.VaultManager.GetOrLoad();
                byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, sessionProof!);
                auditMacKey = Crypto.SubkeyDerivation.DeriveAuditLogMacKey(rootKey);
                Crypto.VaultCrypto.SecureClear(rootKey);
            }
            catch { }
        }

        var result = _ctx.EventLogManager.VerifyChain(auditMacKey);
        if (auditMacKey is not null) Crypto.VaultCrypto.SecureClear(auditMacKey);

        await Task.CompletedTask;
        return NativeResponse.Ok(request.RequestId, new
        {
            ok = result.Ok,
            chainValid = result.ChainValid,
            lastHash = result.LastHash,
        });
    }

}
