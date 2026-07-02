using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;
using ZeroTrustVaultHost.Sync;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Opaque proof that a specific command-authorization check has already
/// passed for the current request. Handlers cannot construct one directly —
/// only <see cref="CommandContext"/>'s gate methods can — so it is a compile
/// error to reach <see cref="CommandContext.UnwrapCurrentRootKey"/> without
/// having gone through one of those checks first. This is the "impossible to
/// call accidentally" property Section A of the hardening brief asks for: a
/// future command handler that forgets to validate session/Hello simply
/// cannot obtain a token to pass in, and therefore cannot compile a call to
/// unwrap the root key.
/// </summary>
public abstract class OperationAuthorization
{
    private protected OperationAuthorization() { }
}

/// <summary>Proof that a session was validated (bound to a specific origin, or origin-agnostic for device-wide operations like sync). Low-risk tier only — does NOT imply a fresh Hello prompt.</summary>
public sealed class SessionAuthorization : OperationAuthorization
{
    internal SessionAuthorization() { }
}

/// <summary>Proof that a FRESH Windows Hello verification just succeeded for this call. High-risk tier (reveal/add/update/delete/TOTP/recovery/pairing).</summary>
public sealed class FreshHelloAuthorization : OperationAuthorization
{
    internal FreshHelloAuthorization() { }
}

/// <summary>
/// Shared dependencies injected into all command handlers, plus the
/// centralized authorization gate every secret-bearing command must pass
/// through (Section A: origin, session, session-origin binding, and fresh
/// Hello where required, enforced in one place instead of re-implemented
/// per-handler).
/// </summary>
public sealed class CommandContext
{
    public VaultManager VaultManager { get; }
    public SessionManager SessionManager { get; }
    public IHelloManager HelloManager { get; }
    public RateLimiter RateLimiter { get; }
    public SecurityEventLog SecurityEventLog { get; }
    public EventLogManager EventLogManager { get; }

    public CommandContext(
        VaultManager vaultManager,
        SessionManager sessionManager,
        IHelloManager helloManager,
        RateLimiter rateLimiter,
        SecurityEventLog securityEventLog,
        EventLogManager eventLogManager)
    {
        VaultManager = vaultManager;
        SessionManager = sessionManager;
        HelloManager = helloManager;
        RateLimiter = rateLimiter;
        SecurityEventLog = securityEventLog;
        EventLogManager = eventLogManager;
    }

    /// <summary>
    /// Unwraps the vault's root key fresh, for use within the narrow scope of
    /// a single operation only. This is the ONLY sanctioned way to obtain the
    /// root key — there is deliberately no session-level cache of it anywhere
    /// in the codebase (see AUDIT_PACKAGE/KNOWN_LIMITATIONS.md "root-key
    /// lifetime"). Callers MUST wrap the returned array in a try/finally and
    /// call VaultCrypto.SecureClear on it as soon as the operation using it
    /// completes — never store it in a field, dictionary, closure, or
    /// response object. Requires an <see cref="OperationAuthorization"/> token
    /// obtained from <see cref="ValidateSessionForOrigin"/>,
    /// <see cref="ValidateAnySession"/>, or <see cref="RequireFreshHelloAsync"/> —
    /// there is no overload that skips this.
    /// </summary>
    public byte[] UnwrapCurrentRootKey(Vault.VaultFile vault, OperationAuthorization proof)
    {
        _ = proof; // possession of the token is the check; nothing further to inspect
        return HelloManager.UnwrapRootKey(Convert.FromBase64String(vault.WrappedRootKey));
    }

    /// <summary>
    /// Low-risk tier gate: validates that a session exists, is bound to
    /// <paramref name="normalizedOrigin"/>, and has not expired. Returns an
    /// error response on failure (null on success), and hands back a proof
    /// token on success.
    /// </summary>
    public NativeResponse? ValidateSessionForOrigin(
        string? sessionId, string normalizedOrigin, string requestId, out SessionAuthorization? proof)
    {
        var validation = SessionManager.Validate(sessionId, normalizedOrigin);
        if (validation != SessionValidationResult.Valid)
        {
            proof = null;
            return NativeResponse.Err(requestId, SessionErrorCode(validation), $"Session {validation}.");
        }
        proof = new SessionAuthorization();
        return null;
    }

    /// <summary>
    /// Low-risk tier gate for device-wide operations that are not scoped to a
    /// single website origin (e.g. sync). Requires the session to exist and
    /// not be expired, regardless of which origin it was created for.
    /// </summary>
    public NativeResponse? ValidateAnySession(
        string? sessionId, string requestId, out SessionAuthorization? proof)
    {
        var validation = SessionManager.ValidateAnyOrigin(sessionId);
        if (validation != SessionValidationResult.Valid)
        {
            proof = null;
            return NativeResponse.Err(requestId, SessionErrorCode(validation), $"Session {validation}.");
        }
        proof = new SessionAuthorization();
        return null;
    }

    /// <summary>
    /// High-risk tier gate: enforces the Hello rate limit, requests a FRESH
    /// Windows Hello verification (never a cached one), and records the
    /// outcome. Returns an error response on failure (null on success), and a
    /// proof token on success.
    /// </summary>
    public async Task<(NativeResponse? Error, FreshHelloAuthorization? Proof)> RequireFreshHelloAsync(
        string promptMessage, string? sessionId, string? normalizedOrigin, string requestId)
    {
        var rateLimit = RateLimiter.CheckHelloPrompt();
        if (rateLimit is not null)
        {
            SecurityEventLog.LogRateLimited(sessionId, promptMessage);
            return (new NativeResponse
            {
                RequestId = requestId,
                Status = "error",
                Error = new NativeError
                {
                    Code = rateLimit.Code,
                    SafeMessage = rateLimit.SafeMessage,
                    RetryAfterSeconds = rateLimit.RetryAfterSeconds,
                }
            }, null);
        }

        var helloResult = await HelloManager.RequestUserVerificationAsync(promptMessage);
        if (helloResult != HelloResult.Verified)
        {
            RateLimiter.RecordHelloFailure();
            SecurityEventLog.LogHelloFailure(sessionId, normalizedOrigin, helloResult.ToString());
            return (HelloErrorResponse(requestId, helloResult), null);
        }
        RateLimiter.RecordHelloSuccess();
        return (null, new FreshHelloAuthorization());
    }

    private static string SessionErrorCode(SessionValidationResult validation) => validation switch
    {
        SessionValidationResult.Missing => "SESSION_REQUIRED",
        SessionValidationResult.NotFound => "SESSION_INVALID",
        SessionValidationResult.OriginMismatch => "SESSION_ORIGIN_MISMATCH",
        SessionValidationResult.Expired => "SESSION_EXPIRED",
        _ => "SESSION_INVALID",
    };

    /// <summary>
    /// Single canonical mapping from every <see cref="HelloResult"/> failure
    /// case to its wire error code/message. Previously duplicated (with
    /// drifting coverage — some handlers didn't map DisabledByPolicy or
    /// RetriesExhausted) across VaultCommands/TotpCommands/RecoveryCommands/
    /// DeviceCommands; now defined once.
    /// </summary>
    public static NativeResponse HelloErrorResponse(string requestId, HelloResult result)
    {
        (string code, string msg) = result switch
        {
            HelloResult.Canceled => ("HELLO_CANCELED", "Windows Hello verification was cancelled."),
            HelloResult.DeviceNotPresent => ("HELLO_DEVICE_NOT_PRESENT", "No Windows Hello device found."),
            HelloResult.NotConfigured => ("HELLO_NOT_CONFIGURED", "Windows Hello is not configured for this user."),
            HelloResult.DisabledByPolicy => ("HELLO_DISABLED_BY_POLICY", "Windows Hello is disabled by policy."),
            HelloResult.RetriesExhausted => ("HELLO_RETRIES_EXHAUSTED", "Windows Hello verification failed: too many retries."),
            _ => ("HELLO_FAILED", "Windows Hello verification failed."),
        };
        return NativeResponse.Err(requestId, code, msg);
    }
}
