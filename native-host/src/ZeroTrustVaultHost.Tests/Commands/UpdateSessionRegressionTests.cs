using Xunit;

namespace ZeroTrustVaultHost.Tests.Commands;

public sealed class UpdateSessionRegressionTests
{
    [Fact]
    public void AtomicUpdate_ResponseIncludesCurrentSessionId()
    {
        string source = File.ReadAllText(ProjectFile("native-host", "src", "ZeroTrustVaultHost",
            "Commands", "VaultCommands.cs"));

        Assert.Contains("sessionId = request.SessionId", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ServiceWorker_AtomicUpdatePreservesSessionIdFallback()
    {
        string source = File.ReadAllText(ProjectFile("extension", "service_worker.js"));

        Assert.Contains("atomicR.result?.sessionId || session.sessionId", source, StringComparison.Ordinal);
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
