using System.Security.Cryptography;
using System.Text;

namespace ZeroTrustVaultHost.Crypto;

/// <summary>
/// Derives all 8 named subkeys from VaultRootKey using HKDF-SHA256.
/// All subkeys are 256 bits (32 bytes).
/// Salt is always the UTF-8 bytes of "ZTV-v2".
/// </summary>
public static class SubkeyDerivation
{
    private static readonly byte[] s_salt = Encoding.UTF8.GetBytes("ZTV-v2");

    private static byte[] Derive(byte[] rootKey, string purpose) =>
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            rootKey,
            outputLength: 32,
            salt: s_salt,
            info: Encoding.UTF8.GetBytes(purpose));

    public static byte[] DeriveItemEncryptionKey(byte[] rootKey)           => Derive(rootKey, "ItemEncryptionKey");
    public static byte[] DeriveMetadataEncryptionKey(byte[] rootKey)       => Derive(rootKey, "MetadataEncryptionKey");
    public static byte[] DeriveOriginHashKey(byte[] rootKey)               => Derive(rootKey, "OriginHashKey");
    public static byte[] DeriveEventLogEncryptionKey(byte[] rootKey)       => Derive(rootKey, "EventLogEncryptionKey");
    public static byte[] DeriveRecoveryKeyEncryptionKey(byte[] rootKey)    => Derive(rootKey, "RecoveryKeyEncryptionKey");
    public static byte[] DeriveDeviceWrappingKeyContext(byte[] rootKey)    => Derive(rootKey, "DeviceWrappingKeyContext");
    public static byte[] DeriveAuditLogMacKey(byte[] rootKey)              => Derive(rootKey, "AuditLogMacKey");
    public static byte[] DeriveSharedSpaceKeyDerivationKey(byte[] rootKey) => Derive(rootKey, "SharedSpaceKeyDerivationKey");
}
