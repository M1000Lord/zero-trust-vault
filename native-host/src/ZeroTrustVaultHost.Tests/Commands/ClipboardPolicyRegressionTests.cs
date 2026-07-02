using Xunit;

namespace ZeroTrustVaultHost.Tests.Commands;

public sealed class ClipboardPolicyRegressionTests
{
    [Fact]
    public void ServiceWorker_ClipboardCopyDefaultsDisabled()
    {
        string source = File.ReadAllText(ProjectFile("extension", "service_worker.js"));

        Assert.Contains("clipboardCopyEnabled:  false", source, StringComparison.Ordinal);
        Assert.Contains("settings.clipboardCopyEnabled !== true", source, StringComparison.Ordinal);
    }

    [Fact]
    public void NativeHealth_ReportsClipboardCopyDisabledByDefault()
    {
        string source = File.ReadAllText(ProjectFile("native-host", "src", "ZeroTrustVaultHost",
            "Commands", "HealthCommands.cs"));

        Assert.Contains("clipboardCopyEnabled = false", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Popup_ExposesAdvancedClipboardToggle()
    {
        string html = File.ReadAllText(ProjectFile("extension", "popup.html"));
        string js = File.ReadAllText(ProjectFile("extension", "popup.js"));

        Assert.Contains("clipboardToggle", html, StringComparison.Ordinal);
        Assert.Contains("clipboardCopyEnabled", js, StringComparison.Ordinal);
    }

    private static string ProjectFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(new[] { dir.FullName }.Concat(parts).ToArray());
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }

        throw new FileNotFoundException("Could not locate project file.", Path.Combine(parts));
    }
}
