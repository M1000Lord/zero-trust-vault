using System.Security.Cryptography;
using System.Text;
using ZeroTrustVaultHost.Vault;

namespace ZeroTrustVaultHost.Crypto;

/// <summary>
/// AES-256-GCM encryption/decryption for vault items.
/// Uses System.Security.Cryptography only — no third-party crypto libraries.
/// Nonce: 12 bytes (random per operation).
/// Tag: 16 bytes.
/// AAD: schemaVersion(4 LE) || vaultId(16) || itemId(16) || originHash(32) || epoch(8 LE) || purposeTag(UTF8)
/// </summary>
public static class VaultCrypto
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    // ---- AAD construction ----

    /// <summary>
    /// Builds the AAD byte array for AEAD.
    /// </summary>
    public static byte[] BuildAad(
        int schemaVersion,
        byte[] vaultId,       // 16 bytes
        byte[] itemId,        // 16 bytes (parsed from GUID)
        byte[] originHash,    // 32 bytes
        long epoch,
        string purposeTag)
    {
        // schemaVersion(4) || vaultId(16) || itemId(16) || originHash(32) || epoch(8) || purposeTag(var)
        byte[] purposeBytes = Encoding.UTF8.GetBytes(purposeTag);
        byte[] aad = new byte[4 + 16 + 16 + 32 + 8 + purposeBytes.Length];
        int offset = 0;

        WriteLE32(aad, offset, (uint)schemaVersion); offset += 4;

        // vaultId: pad or truncate to 16 bytes
        int vaultIdLen = Math.Min(vaultId.Length, 16);
        Buffer.BlockCopy(vaultId, 0, aad, offset, vaultIdLen);
        offset += 16;

        // itemId: pad or truncate to 16 bytes
        int itemIdLen = Math.Min(itemId.Length, 16);
        Buffer.BlockCopy(itemId, 0, aad, offset, itemIdLen);
        offset += 16;

        // originHash: pad or truncate to 32 bytes
        int ohLen = Math.Min(originHash.Length, 32);
        Buffer.BlockCopy(originHash, 0, aad, offset, ohLen);
        offset += 32;

        WriteLE64(aad, offset, (ulong)epoch); offset += 8;

        Buffer.BlockCopy(purposeBytes, 0, aad, offset, purposeBytes.Length);

        return aad;
    }

    // ---- Encrypt ----

    /// <summary>
    /// Encrypts plaintext with AES-256-GCM. Returns an EncryptedBlob.
    /// </summary>
    public static EncryptedBlob Encrypt(byte[] key, byte[] plaintext, byte[] aad)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes for AES-256-GCM.", nameof(key));

        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        return new EncryptedBlob
        {
            Nonce = Convert.ToBase64String(nonce),
            Tag = Convert.ToBase64String(tag),
            Ciphertext = Convert.ToBase64String(ciphertext),
        };
    }

    // ---- Decrypt ----

    /// <summary>
    /// Decrypts an EncryptedBlob with AES-256-GCM. Throws CryptographicException on auth failure.
    /// </summary>
    public static byte[] Decrypt(byte[] key, EncryptedBlob blob, byte[] aad)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes for AES-256-GCM.", nameof(key));

        byte[] nonce = Convert.FromBase64String(blob.Nonce);
        byte[] tag = Convert.FromBase64String(blob.Tag);
        byte[] ciphertext = Convert.FromBase64String(blob.Ciphertext);

        if (nonce.Length != NonceSize)
            throw new CryptographicException($"Nonce must be {NonceSize} bytes.");
        if (tag.Length != TagSize)
            throw new CryptographicException($"Tag must be {TagSize} bytes.");

        byte[] plaintext = new byte[ciphertext.Length];
        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    // ---- Convenience: encrypt/decrypt JSON payloads ----

    public static EncryptedBlob EncryptJson<T>(byte[] key, T value, byte[] aad)
    {
        byte[] json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(value);
        return Encrypt(key, json, aad);
    }

    public static T DecryptJson<T>(byte[] key, EncryptedBlob blob, byte[] aad)
    {
        byte[] json = Decrypt(key, blob, aad);
        return System.Text.Json.JsonSerializer.Deserialize<T>(json)
            ?? throw new InvalidDataException($"Decrypted JSON is null for type {typeof(T).Name}.");
    }

    // ---- GUID ↔ bytes ----

    public static byte[] GuidToBytes(string guidStr)
    {
        if (!Guid.TryParse(guidStr, out var guid))
            throw new ArgumentException($"'{guidStr}' is not a valid GUID.", nameof(guidStr));
        return guid.ToByteArray();
    }

    // ---- Helpers ----

    private static void WriteLE32(byte[] buf, int offset, uint value)
    {
        buf[offset + 0] = (byte)(value);
        buf[offset + 1] = (byte)(value >> 8);
        buf[offset + 2] = (byte)(value >> 16);
        buf[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteLE64(byte[] buf, int offset, ulong value)
    {
        buf[offset + 0] = (byte)(value);
        buf[offset + 1] = (byte)(value >> 8);
        buf[offset + 2] = (byte)(value >> 16);
        buf[offset + 3] = (byte)(value >> 24);
        buf[offset + 4] = (byte)(value >> 32);
        buf[offset + 5] = (byte)(value >> 40);
        buf[offset + 6] = (byte)(value >> 48);
        buf[offset + 7] = (byte)(value >> 56);
    }

    /// <summary>
    /// Securely zeroes a byte array in memory.
    /// </summary>
    public static void SecureClear(byte[]? key)
    {
        if (key is null) return;
        CryptographicOperations.ZeroMemory(key);
    }
}
