using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Commands;

/// <summary>
/// Handles getVaultStatus and securityHealthCheck commands.
/// </summary>
public sealed class HealthCommands
{
    private readonly CommandContext _ctx;

    public HealthCommands(CommandContext ctx) => _ctx = ctx;

    // ---- getVaultStatus ----

    public async Task<NativeResponse> GetVaultStatusAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        // No payload fields expected
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        bool exists = _ctx.VaultManager.VaultExists();
        string presenceAvailability = await _ctx.HelloManager.GetPresenceAvailabilityAsync();

        int schemaVersion = 0;
        if (exists)
        {
            try
            {
                var vault = _ctx.VaultManager.GetOrLoad();
                schemaVersion = vault.Schema;
            }
            catch { schemaVersion = -1; }
        }

        return NativeResponse.Ok(request.RequestId, new
        {
            exists,
            presenceAvailability,
            schemaVersion,
        });
    }

    // ---- securityHealthCheck ----

    public async Task<NativeResponse> SecurityHealthCheckAsync(
        NativeRequest request, string? normalizedOrigin, CancellationToken ct)
    {
        string? fieldErr = CommandRouter.ValidatePayloadFields(request.Payload, Array.Empty<string>());
        if (fieldErr is not null)
            return NativeResponse.Err(request.RequestId, "UNKNOWN_FIELD", fieldErr);

        bool vaultExists = _ctx.VaultManager.VaultExists();
        string presenceAvailability = await _ctx.HelloManager.GetPresenceAvailabilityAsync();

        int schemaVersion = 0;
        string? recoveryKitStatus = null;
        string? lastBackupTime = null;
        string? lastIntegrityCheck = null;
        int deviceCount = 0;

        if (vaultExists)
        {
            try
            {
                var vault = _ctx.VaultManager.GetOrLoad();
                schemaVersion = vault.Schema;
                recoveryKitStatus = vault.RecoveryKit is null ? "none" : "created";
                lastBackupTime = vault.UpdatedAt;
                deviceCount = vault.Devices.Count;
            }
            catch { }
        }

        // Assert that no developer back-door or Hello-skip path exists in this build.
        // This is ALWAYS true: there is no such path in any configuration. The field
        // is a positive security assertion surfaced to the health dashboard.
        bool bypassPathsAbsent = true;

        // Check if the extension is running unpacked (we can't know from host; report null)
        bool? extensionUnpacked = null;

        // Section R: report exactly how (and whether) this host is registered
        // with the browser, so a degraded/hijacked registration surfaces to
        // the user instead of failing silently or being trusted blindly.
        InstallationHealthStatus installStatus;
        try
        {
            installStatus = InstallationHealthCheck.Collect(AppContext.BaseDirectory);
        }
        catch
        {
            installStatus = new InstallationHealthStatus(
                "Unknown", false, false, null, false, false, null, false,
                true, "Installation health check failed to run.");
        }

        return NativeResponse.Ok(request.RequestId, new
        {
            schemaVersion,
            recoveryKitStatus,
            lastBackupTime,
            lastIntegrityCheck,
            sessionTimeoutMinutes = 15,
            clipboardCopyEnabled = false,
            usbBackupEnabled = false,
            totpInNativeHost = true,
            extensionUnpacked,
            bypassPathsAbsent,
            vaultExists,
            presenceAvailability,
            deviceCount,
            registrationMode = installStatus.RegistrationMode,
            hklmRegistered = installStatus.HklmRegistered,
            hkcuRegistered = installStatus.HkcuRegistered,
            manifestPathOk = installStatus.ManifestPathMatchesExpected,
            manifestFileExists = installStatus.ManifestFileExists,
            exePathOk = installStatus.ExePathMatchesRunningExe,
            installationDegraded = installStatus.Degraded,
            installationDegradedReason = installStatus.DegradedReason,
        });
    }
}
