using Xunit;

namespace ZeroTrustVaultHost.Tests.Commands;

/// <summary>
/// Section P regression tests: fill (autofill into a web page) and reveal
/// (a generic decrypt) must stay separate, distinctly-named native commands.
/// Guards against silently merging them back together, which would remove
/// the native-host-side tab/window binding check that only applies to fill.
/// </summary>
public sealed class FillRevealSeparationTests
{
    [Fact]
    public void ServiceWorker_Fill_UsesDedicatedFillCommand()
    {
        string source = File.ReadAllText(ProjectFile("extension", "service_worker.js"));

        Assert.Contains("nativeCall(\"fillCredentialForExactOrigin\"", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ServiceWorker_Fill_DoesNotUseGenericRevealCommand()
    {
        string source = File.ReadAllText(ProjectFile("extension", "service_worker.js"));

        // The reveal command must not appear anywhere in service_worker.js —
        // if it's reintroduced, it means fill silently started reusing the
        // generic decrypt path again (the bug Section P fixes).
        Assert.DoesNotContain("decryptSelectedCredentialForExactOrigin", source, StringComparison.Ordinal);
    }

    [Fact]
    public void CommandRouter_RegistersFillAndRevealAsDistinctCommands()
    {
        string source = File.ReadAllText(ProjectFile("native-host", "src", "ZeroTrustVaultHost",
            "Commands", "CommandRouter.cs"));

        Assert.Contains("\"decryptSelectedCredentialForExactOrigin\"", source, StringComparison.Ordinal);
        Assert.Contains("\"fillCredentialForExactOrigin\"", source, StringComparison.Ordinal);
    }

    [Fact]
    public void VaultCommands_FillRequiresTabAndWindowBinding()
    {
        string source = File.ReadAllText(ProjectFile("native-host", "src", "ZeroTrustVaultHost",
            "Commands", "VaultCommands.cs"));

        Assert.Contains("requireFillContext && (request.TabId is null || request.WindowId is null)", source, StringComparison.Ordinal);
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
