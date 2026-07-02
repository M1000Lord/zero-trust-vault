using Xunit;

namespace ZeroTrustVaultHost.Tests.Sync;

public sealed class LiveSyncSafetyRegressionTests
{
    [Fact]
    public void EventLogManager_DoesNotContainOldAcceptAnythingLoop()
    {
        string source = File.ReadAllText(ProjectFile("native-host", "src", "ZeroTrustVaultHost",
            "Sync", "EventLogManager.cs"));

        Assert.DoesNotContain("if (string.IsNullOrEmpty(evt.EventId)) continue;", source, StringComparison.Ordinal);
        Assert.DoesNotContain("vault.EventLog.Add(evt);\r\n            accepted++;", source, StringComparison.Ordinal);
        Assert.Contains("AcceptMeshEvents", source, StringComparison.Ordinal);
        Assert.Contains("MeshEventCrypto.VerifyEvent", source, StringComparison.Ordinal);
    }

    [Fact]
    public void SyncCommands_ParsesMeshEventsForPush()
    {
        string source = File.ReadAllText(ProjectFile("native-host", "src", "ZeroTrustVaultHost",
            "Commands", "SyncCommands.cs"));

        Assert.Contains("JsonSerializer.Deserialize<MeshEvent>", source, StringComparison.Ordinal);
        Assert.Contains("AcceptMeshEvents", source, StringComparison.Ordinal);
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
