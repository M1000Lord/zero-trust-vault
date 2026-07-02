using ZeroTrustVaultHost.NativeMessaging;
using ZeroTrustVaultHost.Commands;
using ZeroTrustVaultHost.Vault;
using ZeroTrustVaultHost.Security;
using ZeroTrustVaultHost.WindowsHello;
using ZeroTrustVaultHost.Sync;
using ZeroTrustVaultHost.Diagnostics;

// Configure stdin/stdout for binary native messaging
Console.InputEncoding = System.Text.Encoding.UTF8;
Console.OutputEncoding = System.Text.Encoding.UTF8;

DiagnosticLog.Write("BOOT", "=== Native host starting ===");

// Wire up all services
try
{
    var vaultManager = new VaultManager();
    var sessionManager = new SessionManager();
    var helloManager = new HelloManager();
    var rateLimiter = new RateLimiter();
    var securityEventLog = new SecurityEventLog();
    var eventLogManager = new EventLogManager(vaultManager);

    // Load the expected caller identity from the native-messaging manifest
    // installed alongside this executable (never trust the extensionId field
    // the caller sends without checking it against something the host itself
    // controls). See ExtensionIdentity for details.
    var extensionIdentity = ExtensionIdentity.LoadFromHostDirectory(AppContext.BaseDirectory);
    DiagnosticLog.Write("BOOT", extensionIdentity.Loaded
        ? $"Extension identity loaded ({extensionIdentity.AllowedExtensionIds.Count} allowed id(s))."
        : $"Extension identity NOT loaded: {extensionIdentity.LoadError}");

    var router = new CommandRouter(
        vaultManager,
        sessionManager,
        helloManager,
        rateLimiter,
        securityEventLog,
        eventLogManager,
        extensionIdentity);

    var host = new NativeMessageHost(router);

    // Pre-activate the Windows Hello windowed-interop COM class in the
    // background so the first real Unlock click doesn't pay a WinRT class
    // activation cold-start cost on the user's critical path. Fire-and-forget:
    // failures here are non-fatal, the real request just activates it itself.
    _ = Task.Run(ConsentVerifierInterop.WarmUp);

    DiagnosticLog.Write("BOOT", "Services initialized; entering message loop.");
    await host.RunAsync(CancellationToken.None);
    DiagnosticLog.Write("BOOT", "Message loop exited normally.");
}
catch (Exception ex)
{
    // Type + message only — never log secrets or full payloads.
    DiagnosticLog.Write("FATAL", $"{ex.GetType().Name}: {ex.Message}");
    throw;
}
