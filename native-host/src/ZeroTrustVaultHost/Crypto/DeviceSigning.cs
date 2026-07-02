using System.Security.Cryptography;
using System.Text;

namespace ZeroTrustVaultHost.Crypto;

/// <summary>
/// ECDSA P-256 device signing using CNG with non-exportable keys.
/// Used for device pairing attestation and event log signing.
/// </summary>
public static class DeviceSigning
{
    private const string KeyNamePrefix = "ZeroTrustVault_DeviceKey_";

    /// <summary>
    /// Creates or opens a non-exportable P-256 device signing key in the CNG key store.
    /// The key is bound to the local machine user key store.
    /// </summary>
    public static CngKey GetOrCreateDeviceKey(string deviceId)
    {
        string keyName = KeyNamePrefix + deviceId;

        try
        {
            return CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        }
        catch (CryptographicException)
        {
            // Key doesn't exist — create it
        }

        var creationParameters = new CngKeyCreationParameters
        {
            ExportPolicy = CngExportPolicies.None, // non-exportable
            KeyUsage = CngKeyUsages.Signing,
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
        };

        return CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParameters);
    }

    /// <summary>
    /// Signs data with the device key. Returns DER-encoded signature.
    /// </summary>
    public static byte[] Sign(CngKey key, byte[] data)
    {
        using var ecdsa = new ECDsaCng(key);
        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Verifies a signature against a public key blob.
    /// </summary>
    public static bool Verify(byte[] publicKeyBlob, byte[] data, byte[] signature)
    {
        try
        {
            using var key = CngKey.Import(publicKeyBlob, CngKeyBlobFormat.EccPublicBlob);
            using var ecdsa = new ECDsaCng(key);
            return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Exports the public key blob (ECC Public Blob format) for sharing with other devices.
    /// </summary>
    public static byte[] ExportPublicKeyBlob(CngKey key)
    {
        return key.Export(CngKeyBlobFormat.EccPublicBlob);
    }

    /// <summary>
    /// Deletes the device signing key from the CNG key store.
    /// </summary>
    public static void DeleteDeviceKey(string deviceId)
    {
        string keyName = KeyNamePrefix + deviceId;
        try
        {
            using var key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
            key.Delete();
        }
        catch (CryptographicException)
        {
            // Key not found — nothing to delete
        }
    }
}
