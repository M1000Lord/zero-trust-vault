using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Vault;

/// <summary>
/// Regression tests for the corrupt-vault detection + quarantine logic.
/// These directly cover the bug where an empty wrappedRootKey caused an
/// unhandled "Wrapped key data is too short" crash, and prove that a vault
/// containing user data is NEVER overwritten.
/// </summary>
public sealed class VaultIntegrityTests : IDisposable
{
    private readonly string _tempDir;

    public VaultIntegrityTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "ztv_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    // ---- Classification ----

    [Fact]
    public void ClassifyWrappedRootKey_Null_IsMissing() =>
        Assert.Equal(WrappedKeyStatus.Missing, VaultIntegrity.ClassifyWrappedRootKey(null));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ClassifyWrappedRootKey_Empty_IsEmpty(string value) =>
        Assert.Equal(WrappedKeyStatus.Empty, VaultIntegrity.ClassifyWrappedRootKey(value));

    [Fact]
    public void ClassifyWrappedRootKey_ShortBase64_IsTooShort()
    {
        // 32 bytes < 128-byte minimum
        string shortKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Assert.Equal(WrappedKeyStatus.TooShort, VaultIntegrity.ClassifyWrappedRootKey(shortKey));
    }

    [Fact]
    public void ClassifyWrappedRootKey_NotBase64_IsInvalidBase64() =>
        Assert.Equal(WrappedKeyStatus.InvalidBase64, VaultIntegrity.ClassifyWrappedRootKey("!!!not base64!!!"));

    [Fact]
    public void ClassifyWrappedRootKey_ValidRsaWrap_IsValid()
    {
        // 256 bytes = RSA-2048 OAEP wrap
        string validKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(256));
        Assert.Equal(WrappedKeyStatus.Valid, VaultIntegrity.ClassifyWrappedRootKey(validKey));
    }

    [Fact]
    public void ToReason_MapsEachStatus()
    {
        Assert.Equal(CorruptReason.MissingWrappedRootKey,       VaultIntegrity.ToReason(WrappedKeyStatus.Missing));
        Assert.Equal(CorruptReason.EmptyWrappedRootKey,         VaultIntegrity.ToReason(WrappedKeyStatus.Empty));
        Assert.Equal(CorruptReason.WrappedRootKeyTooShort,      VaultIntegrity.ToReason(WrappedKeyStatus.TooShort));
        Assert.Equal(CorruptReason.WrappedRootKeyInvalidFormat, VaultIntegrity.ToReason(WrappedKeyStatus.InvalidBase64));
    }

    // ---- User-data detection ----

    [Fact]
    public void HasUserData_EmptyVault_False()
    {
        var vault = new VaultFile { Schema = 3 };
        Assert.False(VaultIntegrity.HasUserData(vault));
    }

    [Fact]
    public void HasUserData_WithItem_True()
    {
        var vault = new VaultFile { Schema = 3 };
        vault.Items.Add(new VaultItemV3 { ItemId = "x" });
        Assert.True(VaultIntegrity.HasUserData(vault));
    }

    [Fact]
    public void HasUserData_WithTombstonedItemOnly_StillTrue()
    {
        var vault = new VaultFile { Schema = 3 };
        vault.Items.Add(new VaultItemV3 { ItemId = "x", Deleted = true });
        Assert.True(VaultIntegrity.HasUserData(vault)); // tombstones are still user data worth preserving
    }

    [Fact]
    public void HasUserData_WithEvent_True()
    {
        var vault = new VaultFile { Schema = 3 };
        vault.EventLog.Add(new { eventId = "e1" });
        Assert.True(VaultIntegrity.HasUserData(vault));
    }

    [Fact]
    public void HasUserData_WithRecoveryKit_True()
    {
        var vault = new VaultFile { Schema = 3, RecoveryKit = new RecoveryKitEntry { ShareCount = 5 } };
        Assert.True(VaultIntegrity.HasUserData(vault));
    }

    [Fact]
    public void HasUserData_Null_False() => Assert.False(VaultIntegrity.HasUserData(null));

    // ---- Quarantine ----

    [Fact]
    public void Quarantine_CopiesOriginal_AndWritesDiagnostic_WithoutDeleting()
    {
        string vaultPath = Path.Combine(_tempDir, "vault.json");
        var vault = new VaultFile { Schema = 3, WrappedRootKey = "" };
        vault.Items.Add(new VaultItemV3 { ItemId = "secret-item" });
        File.WriteAllText(vaultPath, JsonSerializer.Serialize(vault));
        string quarantineDir = Path.Combine(_tempDir, "quarantine");

        var result = VaultIntegrity.Quarantine(
            vaultPath, quarantineDir, CorruptReason.EmptyWrappedRootKey, vault, "test-1.0");

        Assert.True(result.Success);
        Assert.True(File.Exists(vaultPath), "original must NOT be deleted");
        Assert.True(File.Exists(result.QuarantinedVaultPath!), "corrupt copy must exist");
        Assert.True(File.Exists(result.DiagnosticPath!), "diagnostic must exist");
    }

    [Fact]
    public void Quarantine_Diagnostic_ContainsNoSecrets()
    {
        string vaultPath = Path.Combine(_tempDir, "vault.json");
        var vault = new VaultFile { Schema = 3, WrappedRootKey = "SUPERSECRETKEYMATERIAL" };
        // Put a recognizable "secret" into an item payload.
        vault.Items.Add(new VaultItemV3
        {
            ItemId = "i1",
            EncryptedPayload = new EncryptedBlob { Ciphertext = "PLAINTEXTPASSWORD123" },
        });
        File.WriteAllText(vaultPath, JsonSerializer.Serialize(vault));
        string quarantineDir = Path.Combine(_tempDir, "quarantine");

        var result = VaultIntegrity.Quarantine(
            vaultPath, quarantineDir, CorruptReason.EmptyWrappedRootKey, vault, "test-1.0");

        string diagJson = File.ReadAllText(result.DiagnosticPath!);
        Assert.DoesNotContain("SUPERSECRETKEYMATERIAL", diagJson);
        Assert.DoesNotContain("PLAINTEXTPASSWORD123", diagJson);
        // But it SHOULD contain non-secret counts and the reason.
        Assert.Contains("EmptyWrappedRootKey", diagJson);
        Assert.Contains("itemCount", diagJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Quarantine_DiagnosticReportsCounts()
    {
        string vaultPath = Path.Combine(_tempDir, "vault.json");
        var vault = new VaultFile { Schema = 3, WrappedRootKey = "" };
        vault.Items.Add(new VaultItemV3 { ItemId = "i1" });
        vault.Items.Add(new VaultItemV3 { ItemId = "i2" });
        vault.RecoveryKit = new RecoveryKitEntry { ShareCount = 5, Threshold = 3 };
        File.WriteAllText(vaultPath, JsonSerializer.Serialize(vault));

        var result = VaultIntegrity.Quarantine(
            vaultPath, Path.Combine(_tempDir, "q"), CorruptReason.EmptyWrappedRootKey, vault, "test-1.0");

        var diag = JsonSerializer.Deserialize<CorruptVaultDiagnostic>(File.ReadAllText(result.DiagnosticPath!))!;
        Assert.Equal(2, diag.ItemCount);
        Assert.True(diag.HasRecoveryBundle);
        Assert.Equal(3, diag.SchemaVersion);
    }

    [Fact]
    public void Quarantine_FailsGracefully_WhenCopySourceMissing()
    {
        // No vault file written → File.Copy is skipped but diagnostic still writes; success true.
        // Now simulate a hard failure: quarantine into a path that cannot be created.
        string vaultPath = Path.Combine(_tempDir, "vault.json");
        File.WriteAllText(vaultPath, "{}");

        // Use a file (not dir) as the quarantine directory parent to force failure.
        string blocker = Path.Combine(_tempDir, "blocker");
        File.WriteAllText(blocker, "x");
        string badQuarantineDir = Path.Combine(blocker, "sub"); // can't create dir under a file

        var result = VaultIntegrity.Quarantine(
            vaultPath, badQuarantineDir, CorruptReason.EmptyWrappedRootKey, null, "test-1.0");

        Assert.False(result.Success);
        Assert.True(File.Exists(vaultPath), "vault must remain untouched on quarantine failure");
    }

    [Fact]
    public void TryParse_ValidVault_ReturnsObject()
    {
        string vaultPath = Path.Combine(_tempDir, "vault.json");
        var vault = new VaultFile { Schema = 3 };
        vault.Items.Add(new VaultItemV3 { ItemId = "i1" });
        File.WriteAllText(vaultPath, JsonSerializer.Serialize(vault));

        var parsed = VaultIntegrity.TryParse(vaultPath);
        Assert.NotNull(parsed);
        Assert.Single(parsed!.Items);
    }

    [Fact]
    public void TryParse_Garbage_ReturnsNull()
    {
        string vaultPath = Path.Combine(_tempDir, "vault.json");
        File.WriteAllText(vaultPath, "this is not json {{{");
        Assert.Null(VaultIntegrity.TryParse(vaultPath));
    }
}
