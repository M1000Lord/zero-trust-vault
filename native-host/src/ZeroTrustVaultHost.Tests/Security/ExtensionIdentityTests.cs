using Xunit;
using ZeroTrustVaultHost.Security;

namespace ZeroTrustVaultHost.Tests.Security;

/// <summary>
/// Tests for ExtensionIdentity: the caller-authentication gate that loads the
/// expected extension ID from the installed native-messaging manifest rather
/// than trusting whatever the request claims.
/// </summary>
public sealed class ExtensionIdentityTests : IDisposable
{
    private readonly string _tempDir;

    public ExtensionIdentityTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv-extid-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private const string ValidId = "abcdefghijklmnopabcdefghijklmnop"; // 32 chars, a-p only
    private const string OtherValidId = "ponmlkjihgfedcbaponmlkjihgfedcba";

    private string WriteManifest(string json)
    {
        string path = Path.Combine(_tempDir, "com.zerotrust.vault.json");
        File.WriteAllText(path, json);
        return path;
    }

    [Fact]
    public void LoadFromManifestFile_ValidManifest_LoadsExpectedId()
    {
        string path = WriteManifest($$"""
            { "name": "com.zerotrust.vault", "allowed_origins": ["chrome-extension://{{ValidId}}/"] }
            """);

        var identity = ExtensionIdentity.LoadFromManifestFile(path);

        Assert.True(identity.Loaded);
        Assert.Contains(ValidId, identity.AllowedExtensionIds);
    }

    [Fact]
    public void LoadFromManifestFile_MissingFile_NotLoaded()
    {
        var identity = ExtensionIdentity.LoadFromManifestFile(Path.Combine(_tempDir, "does-not-exist.json"));
        Assert.False(identity.Loaded);
        Assert.Equal("NativeMessagingManifestNotFound", identity.LoadError);
    }

    [Fact]
    public void LoadFromManifestFile_MalformedJson_NotLoaded()
    {
        string path = WriteManifest("{ not valid json");
        var identity = ExtensionIdentity.LoadFromManifestFile(path);
        Assert.False(identity.Loaded);
    }

    [Fact]
    public void LoadFromManifestFile_NoAllowedOrigins_NotLoaded()
    {
        string path = WriteManifest("""{ "name": "com.zerotrust.vault" }""");
        var identity = ExtensionIdentity.LoadFromManifestFile(path);
        Assert.False(identity.Loaded);
        Assert.Equal("AllowedOriginsFieldMissing", identity.LoadError);
    }

    [Fact]
    public void LoadFromManifestFile_NoValidIdInOrigins_NotLoaded()
    {
        string path = WriteManifest("""{ "allowed_origins": ["https://not-a-chrome-extension.example/"] }""");
        var identity = ExtensionIdentity.LoadFromManifestFile(path);
        Assert.False(identity.Loaded);
        Assert.Equal("NoValidExtensionIdInManifest", identity.LoadError);
    }

    [Fact]
    public void LoadFromManifestFile_MultipleOrigins_LoadsAllValidIds()
    {
        string path = WriteManifest($$"""
            { "allowed_origins": ["chrome-extension://{{ValidId}}/", "chrome-extension://{{OtherValidId}}/"] }
            """);
        var identity = ExtensionIdentity.LoadFromManifestFile(path);
        Assert.True(identity.Loaded);
        Assert.Equal(2, identity.AllowedExtensionIds.Count);
    }

    // ---- Validate() ----

    [Fact]
    public void Validate_MissingId_ReturnsMissing()
    {
        var identity = ExtensionIdentity.Untrusted("test");
        Assert.Equal("MISSING_EXTENSION_ID", identity.Validate(null));
        Assert.Equal("MISSING_EXTENSION_ID", identity.Validate(""));
    }

    [Theory]
    [InlineData("tooshort")]
    [InlineData("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP")] // uppercase not allowed
    [InlineData("abcdefghijklmnopqrstuvwxyzabcdef")]  // contains q-z, outside a-p
    [InlineData("abcdefghijklmnopabcdefghijklmno1")]  // digit
    public void Validate_MalformedId_ReturnsMalformed(string badId)
    {
        var identity = ExtensionIdentity.Untrusted("test");
        Assert.Equal("MALFORMED_EXTENSION_ID", identity.Validate(badId));
    }

    [Fact]
    public void Validate_WellFormedButUnverifiable_ReturnsUnverifiable()
    {
        // Simulates a manual/direct launch where no manifest could be found —
        // in a Release build the router must reject this for secret commands.
        var identity = ExtensionIdentity.Untrusted("NativeMessagingManifestNotFound");
        Assert.Equal("EXTENSION_IDENTITY_UNVERIFIABLE", identity.Validate(ValidId));
    }

    [Fact]
    public void Validate_MatchingId_ReturnsNull()
    {
        string path = WriteManifest($$"""{ "allowed_origins": ["chrome-extension://{{ValidId}}/"] }""");
        var identity = ExtensionIdentity.LoadFromManifestFile(path);
        Assert.Null(identity.Validate(ValidId));
    }

    [Fact]
    public void Validate_WrongId_ReturnsMismatch()
    {
        string path = WriteManifest($$"""{ "allowed_origins": ["chrome-extension://{{ValidId}}/"] }""");
        var identity = ExtensionIdentity.LoadFromManifestFile(path);
        Assert.Equal("EXTENSION_ID_MISMATCH", identity.Validate(OtherValidId));
    }
}
