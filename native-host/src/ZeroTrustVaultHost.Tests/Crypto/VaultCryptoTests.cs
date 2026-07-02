using System.Security.Cryptography;
using System.Text;
using Xunit;
using ZeroTrustVaultHost.Crypto;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Tests.Crypto;

public sealed class VaultCryptoTests
{
    // ---- Roundtrip tests ----

    [Fact]
    public void EncryptDecrypt_Roundtrip_ReturnsOriginalPlaintext()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = Encoding.UTF8.GetBytes("Hello, Zero Trust Vault!");
        byte[] aad = Encoding.UTF8.GetBytes("test-aad");

        var blob = VaultCrypto.Encrypt(key, plaintext, aad);
        byte[] decrypted = VaultCrypto.Decrypt(key, blob, aad);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_Json_Roundtrip()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] aad = Encoding.UTF8.GetBytes("json-aad");

        var payload = new VaultPayload
        {
            UsernameOrEmail = "user@example.com",
            Password = "SuperSecret123!",
            Label = "Example",
            TotpSecret = "JBSWY3DPEHPK3PXP",
            Notes = "test notes",
        };

        var blob = VaultCrypto.EncryptJson(key, payload, aad);
        var decrypted = VaultCrypto.DecryptJson<VaultPayload>(key, blob, aad);

        Assert.Equal(payload.UsernameOrEmail, decrypted.UsernameOrEmail);
        Assert.Equal(payload.Password, decrypted.Password);
        Assert.Equal(payload.Label, decrypted.Label);
        Assert.Equal(payload.TotpSecret, decrypted.TotpSecret);
    }

    // ---- Nonce uniqueness ----

    [Fact]
    public void Encrypt_ProducesUniqueNonces()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = Encoding.UTF8.GetBytes("same plaintext");
        byte[] aad = Encoding.UTF8.GetBytes("aad");

        var nonces = new HashSet<string>();
        for (int i = 0; i < 20; i++)
        {
            var blob = VaultCrypto.Encrypt(key, plaintext, aad);
            Assert.True(nonces.Add(blob.Nonce), $"Duplicate nonce detected on iteration {i}");
        }
    }

    // ---- AAD mismatch fails ----

    [Fact]
    public void Decrypt_WithWrongAad_ThrowsCryptographicException()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = Encoding.UTF8.GetBytes("secret data");
        byte[] correctAad = Encoding.UTF8.GetBytes("correct-aad");
        byte[] wrongAad = Encoding.UTF8.GetBytes("wrong-aad");

        var blob = VaultCrypto.Encrypt(key, plaintext, correctAad);

        // AesGcm throws AuthenticationTagMismatchException (subclass of CryptographicException)
        Assert.ThrowsAny<CryptographicException>(() =>
            VaultCrypto.Decrypt(key, blob, wrongAad));
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsCryptographicException()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = Encoding.UTF8.GetBytes("secret data");
        byte[] aad = Encoding.UTF8.GetBytes("aad");

        var blob = VaultCrypto.Encrypt(key, plaintext, aad);

        Assert.ThrowsAny<CryptographicException>(() =>
            VaultCrypto.Decrypt(wrongKey, blob, aad));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = Encoding.UTF8.GetBytes("tamper me");
        byte[] aad = Encoding.UTF8.GetBytes("aad");

        var blob = VaultCrypto.Encrypt(key, plaintext, aad);

        // Flip a byte in ciphertext
        byte[] ct = Convert.FromBase64String(blob.Ciphertext);
        ct[0] ^= 0xFF;
        blob.Ciphertext = Convert.ToBase64String(ct);

        Assert.ThrowsAny<CryptographicException>(() =>
            VaultCrypto.Decrypt(key, blob, aad));
    }

    // ---- AAD structure ----

    [Fact]
    public void BuildAad_ProducesCorrectLength()
    {
        byte[] vaultId = new byte[16];
        byte[] itemId = new byte[16];
        byte[] originHash = new byte[32];
        string purpose = "ItemEncryptionKey";

        byte[] aad = VaultCrypto.BuildAad(3, vaultId, itemId, originHash, 1L, purpose);

        int expectedLen = 4 + 16 + 16 + 32 + 8 + Encoding.UTF8.GetByteCount(purpose);
        Assert.Equal(expectedLen, aad.Length);
    }

    [Fact]
    public void BuildAad_DifferentPurposes_ProduceDifferentAads()
    {
        byte[] vaultId = new byte[16];
        byte[] itemId = new byte[16];
        byte[] originHash = new byte[32];

        byte[] aad1 = VaultCrypto.BuildAad(3, vaultId, itemId, originHash, 1L, "ItemEncryptionKey");
        byte[] aad2 = VaultCrypto.BuildAad(3, vaultId, itemId, originHash, 1L, "MetadataEncryptionKey");

        Assert.NotEqual(aad1, aad2);
    }

    // ---- Key requirements ----

    [Fact]
    public void Encrypt_WrongKeySize_ThrowsArgumentException()
    {
        byte[] badKey = new byte[16]; // AES-128, but we require AES-256
        byte[] plaintext = Encoding.UTF8.GetBytes("test");
        byte[] aad = Encoding.UTF8.GetBytes("aad");

        Assert.Throws<ArgumentException>(() =>
            VaultCrypto.Encrypt(badKey, plaintext, aad));
    }

    // ---- SecureClear ----

    [Fact]
    public void SecureClear_ZeroesKeyBytes()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        VaultCrypto.SecureClear(key);
        Assert.All(key, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SecureClear_NullDoesNotThrow()
    {
        byte[]? nullKey = null;
        var ex = Record.Exception(() => VaultCrypto.SecureClear(nullKey));
        Assert.Null(ex);
    }
}
