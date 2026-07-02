using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.WindowsHello;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Handles generateTotpForCredential and copySecretWithTimedClear commands.
/// </summary>
public sealed class TotpCommands
{
    private readonly CommandContext _ctx;
    private const int ClipboardClearSeconds = 15;

    public TotpCommands(CommandContext ctx) => _ctx = ctx;

    // ---- generateTotpForCredential ----

    public async Task<NativeResponse> GenerateTotpAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string[] allowed = { "credentialId" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        if (!CommandRouter.TryGetString(request.Payload, "credentialId", out string credentialId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "credentialId is required.");

        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        // Rate limit secret reveals
        var rateLimit = _ctx.RateLimiter.CheckSecretReveal(request.SessionId!);
        if (rateLimit is not null)
        {
            _ctx.SecurityEventLog.LogRateLimited(request.SessionId, "generateTotpForCredential");
            return RateLimitedResponse(request.RequestId, rateLimit);
        }

        // Fresh Hello required
        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Generate TOTP", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == credentialId && !i.Deleted);
        if (item is null)
            return NativeResponse.Err(request.RequestId, "NOT_FOUND", "Credential not found.");

        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            if (Convert.ToBase64String(originHash) != item.OriginHash)
                return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", "Credential does not belong to this origin.");

            var payload = DecryptPayload(rootKey, vault, item);

            if (string.IsNullOrEmpty(payload.TotpSecret))
                return NativeResponse.Err(request.RequestId, "NO_TOTP_SECRET", "This credential does not have a TOTP secret.");

            var now = DateTimeOffset.UtcNow;
            string code = TotpGenerator.GenerateCodeFromBase32(payload.TotpSecret, now);
            int secondsRemaining = TotpGenerator.SecondsRemaining(now);

            _ctx.RateLimiter.RecordSecretReveal(request.SessionId!);

            return NativeResponse.Ok(request.RequestId, new
            {
                code,
                secondsRemaining,
            });
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }
    }

    // ---- copySecretWithTimedClear ----

    public async Task<NativeResponse> CopySecretWithTimedClearAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        if (normalizedOrigin is null)
            return NativeResponse.Err(request.RequestId, "ORIGIN_REQUIRED", "Origin is required.");

        string[] allowed = { "credentialId", "secretType" };
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, allowed);
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        if (!CommandRouter.TryGetString(request.Payload, "credentialId", out string credentialId))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "credentialId is required.");

        if (!CommandRouter.TryGetString(request.Payload, "secretType", out string secretType))
            return NativeResponse.Err(request.RequestId, "MISSING_FIELD", "secretType is required.");

        if (secretType != "password" && secretType != "totp")
            return NativeResponse.Err(request.RequestId, "INVALID_FIELD", "secretType must be 'password' or 'totp'.");

        var sessionErr = _ctx.ValidateSessionForOrigin(request.SessionId, normalizedOrigin, request.RequestId, out _);
        if (sessionErr is not null) return sessionErr;

        // Rate limit
        var rateLimit = _ctx.RateLimiter.CheckSecretReveal(request.SessionId!);
        if (rateLimit is not null) return RateLimitedResponse(request.RequestId, rateLimit);

        var (helloErr, helloProof) = await _ctx.RequireFreshHelloAsync(
            "Zero Trust Vault: Copy to clipboard", request.SessionId, normalizedOrigin, request.RequestId);
        if (helloErr is not null) return helloErr;

        var vault = _ctx.VaultManager.GetOrLoad();
        var item = vault.Items.FirstOrDefault(i => i.ItemId == credentialId && !i.Deleted);
        if (item is null)
            return NativeResponse.Err(request.RequestId, "NOT_FOUND", "Credential not found.");

        byte[] rootKey = _ctx.UnwrapCurrentRootKey(vault, helloProof!);
        string secret;
        try
        {
            byte[] originHash = VaultManager.ComputeOriginHash(rootKey, normalizedOrigin);
            if (Convert.ToBase64String(originHash) != item.OriginHash)
                return NativeResponse.Err(request.RequestId, "ORIGIN_MISMATCH", "Credential does not belong to this origin.");

            var payload = DecryptPayload(rootKey, vault, item);

            if (secretType == "password")
            {
                secret = payload.Password;
            }
            else // totp
            {
                if (string.IsNullOrEmpty(payload.TotpSecret))
                    return NativeResponse.Err(request.RequestId, "NO_TOTP_SECRET", "This credential does not have a TOTP secret.");
                secret = TotpGenerator.GenerateCodeFromBase32(payload.TotpSecret);
            }
        }
        finally
        {
            VaultCrypto.SecureClear(rootKey);
        }

        // Write to Windows clipboard
        WriteToClipboard(secret);

        // Schedule clipboard clear after 15 seconds (fire-and-forget)
        _ = ScheduleClipboardClearAsync(secret, ClipboardClearSeconds, ct);

        _ctx.RateLimiter.RecordSecretReveal(request.SessionId!);

        return NativeResponse.Ok(request.RequestId, new
        {
            ok = true,
            clearsInSeconds = ClipboardClearSeconds,
        });
    }

    // ---- Clipboard helpers ----

    private static void WriteToClipboard(string text)
    {
        // Use Windows API via interop for clipboard access
        // This is a WinForms-free implementation using kernel32/user32
        SetClipboardText(text);
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(nint hWndNewOwner);

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern nint SetClipboardData(uint uFormat, nint hMem);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GlobalAlloc(uint uFlags, nuint dwBytes);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GlobalLock(nint hMem);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(nint hMem);

    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;

    private static void SetClipboardText(string text)
    {
        try
        {
            if (!OpenClipboard(nint.Zero)) return;
            if (!EmptyClipboard()) { CloseClipboard(); return; }

            // Allocate global memory for the Unicode text (+1 for null terminator)
            int byteCount = (text.Length + 1) * 2;
            nint hGlobal = GlobalAlloc(GMEM_MOVEABLE, (nuint)byteCount);
            if (hGlobal == nint.Zero) { CloseClipboard(); return; }

            nint pGlobal = GlobalLock(hGlobal);
            if (pGlobal == nint.Zero) { CloseClipboard(); return; }

            // Copy string chars as UTF-16LE bytes using Marshal (no unsafe blocks needed)
            byte[] bytes = System.Text.Encoding.Unicode.GetBytes(text);
            System.Runtime.InteropServices.Marshal.Copy(bytes, 0, pGlobal, bytes.Length);
            // Null terminator (2 bytes for wchar_t)
            System.Runtime.InteropServices.Marshal.WriteInt16(pGlobal + bytes.Length, 0);

            GlobalUnlock(hGlobal);
            SetClipboardData(CF_UNICODETEXT, hGlobal);
            CloseClipboard();
        }
        catch
        {
            try { CloseClipboard(); } catch { }
        }
    }

    private static async Task ScheduleClipboardClearAsync(string writtenText, int delaySeconds, CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds), ct);

            // Only clear if the clipboard still contains what we wrote
            string? current = ReadFromClipboard();
            if (current == writtenText)
            {
                ClearClipboard();
            }
        }
        catch (OperationCanceledException) { }
        catch { }
    }

    private static string? ReadFromClipboard()
    {
        try
        {
            if (!OpenClipboard(nint.Zero)) return null;
            nint hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == nint.Zero) { CloseClipboard(); return null; }
            nint pData = GlobalLock(hData);
            if (pData == nint.Zero) { CloseClipboard(); return null; }
            string text = System.Runtime.InteropServices.Marshal.PtrToStringUni(pData) ?? string.Empty;
            GlobalUnlock(hData);
            CloseClipboard();
            return text;
        }
        catch
        {
            try { CloseClipboard(); } catch { }
            return null;
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern nint GetClipboardData(uint uFormat);

    private static void ClearClipboard()
    {
        try
        {
            if (!OpenClipboard(nint.Zero)) return;
            EmptyClipboard();
            CloseClipboard();
        }
        catch
        {
            try { CloseClipboard(); } catch { }
        }
    }

    // ---- Shared helpers ----

    private static VaultPayload DecryptPayload(byte[] rootKey, VaultFile vault, VaultItemV3 item)
    {
        byte[] payloadKey = SubkeyDerivation.DeriveItemEncryptionKey(rootKey);
        byte[] vaultIdBytes = Convert.FromBase64String(vault.VaultId);
        byte[] itemIdBytes = VaultCrypto.GuidToBytes(item.ItemId);
        byte[] originHashBytes = Convert.FromBase64String(item.OriginHash);
        byte[] aad = VaultCrypto.BuildAad(vault.Schema, vaultIdBytes, itemIdBytes, originHashBytes, item.Epoch, "ItemEncryptionKey");
        var result = VaultCrypto.DecryptJson<VaultPayload>(payloadKey, item.EncryptedPayload, aad);
        VaultCrypto.SecureClear(payloadKey);
        return result;
    }

    private static NativeResponse RateLimitedResponse(string requestId, RateLimitInfo info) =>
        new NativeResponse
        {
            RequestId = requestId,
            Status = "error",
            Error = new NativeMessaging.NativeError
            {
                Code = info.Code,
                SafeMessage = info.SafeMessage,
                RetryAfterSeconds = info.RetryAfterSeconds,
            }
        };
}
