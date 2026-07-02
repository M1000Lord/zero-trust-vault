using ZeroTrustVaultHost.Crypto;

namespace ZeroTrustVaultHost.Vault;

/// <summary>
/// Cryptographic root-key rotation. Re-encrypts every item from an old
/// VaultRootKey to a new one and recomputes each origin hash under the new
/// origin-hash subkey, bumping the vault epoch and re-stamping every item to it.
///
/// This is the operation that makes device revocation real: after a removed
/// device is excluded from the graph, the host generates a fresh random
/// VaultRootKey, calls <see cref="RotateRoot"/>, and re-wraps the new root only
/// to the remaining active devices (and the local CNG/TPM key). The removed
/// device — which only ever held a wrap of the OLD root — can no longer decrypt
/// the re-encrypted vault. It can still possess secrets it exfiltrated before
/// removal (an accepted residual risk), but it gains no future access.
///
/// The method is pure (no Hello/CNG/IO) so it is fully unit-testable with
/// ephemeral keys. The caller is responsible for unwrapping the old root,
/// generating the new root, re-wrapping it, and persisting the vault.
/// </summary>
public static class VaultRekey
{
    /// <summary>
    /// Re-encrypts all items under <paramref name="newRoot"/> and advances the
    /// epoch. Throws <see cref="System.Security.Cryptography.CryptographicException"/>
    /// if any item fails to authenticate under <paramref name="oldRoot"/> — a
    /// rotation must never silently drop or corrupt an item.
    /// </summary>
    /// <returns>The new epoch value.</returns>
    public static int RotateRoot(VaultFile vault, byte[] oldRoot, byte[] newRoot)
    {
        if (vault is null) throw new ArgumentNullException(nameof(vault));
        if (oldRoot is null || oldRoot.Length != 32) throw new ArgumentException("oldRoot must be 32 bytes.", nameof(oldRoot));
        if (newRoot is null || newRoot.Length != 32) throw new ArgumentException("newRoot must be 32 bytes.", nameof(newRoot));

        int newEpoch = vault.Epoch + 1;

        byte[] oldItemKey = SubkeyDerivation.DeriveItemEncryptionKey(oldRoot);
        byte[] oldMetaKey = SubkeyDerivation.DeriveMetadataEncryptionKey(oldRoot);
        byte[] newItemKey = SubkeyDerivation.DeriveItemEncryptionKey(newRoot);
        byte[] newMetaKey = SubkeyDerivation.DeriveMetadataEncryptionKey(newRoot);
        byte[] vaultIdBytes = Convert.FromBase64String(vault.VaultId);

        try
        {
            foreach (var item in vault.Items)
            {
                byte[] itemIdBytes = VaultCrypto.GuidToBytes(item.ItemId);
                byte[] oldOriginHash = Convert.FromBase64String(item.OriginHash);

                // Decrypt under the OLD root using the item's currently-stored
                // epoch and origin hash (which reflect its last encryption).
                byte[] oldPayloadAad = VaultCrypto.BuildAad(
                    vault.Schema, vaultIdBytes, itemIdBytes, oldOriginHash, item.Epoch, "ItemEncryptionKey");
                var payload = VaultCrypto.DecryptJson<VaultPayload>(oldItemKey, item.EncryptedPayload, oldPayloadAad);

                byte[] oldMetaAad = VaultCrypto.BuildAad(
                    vault.Schema, vaultIdBytes, itemIdBytes, oldOriginHash, item.Epoch, "MetadataEncryptionKey");
                var metadata = VaultCrypto.DecryptJson<VaultMetadata>(oldMetaKey, item.EncryptedMetadata, oldMetaAad);

                // Recompute the origin hash under the NEW root from the plaintext
                // origin held in the (now decrypted) metadata.
                byte[] newOriginHash = VaultManager.ComputeOriginHash(newRoot, metadata.Origin);

                // Re-encrypt under the NEW root, new epoch, and new origin hash.
                byte[] newPayloadAad = VaultCrypto.BuildAad(
                    vault.Schema, vaultIdBytes, itemIdBytes, newOriginHash, newEpoch, "ItemEncryptionKey");
                item.EncryptedPayload = VaultCrypto.EncryptJson(newItemKey, payload, newPayloadAad);

                byte[] newMetaAad = VaultCrypto.BuildAad(
                    vault.Schema, vaultIdBytes, itemIdBytes, newOriginHash, newEpoch, "MetadataEncryptionKey");
                item.EncryptedMetadata = VaultCrypto.EncryptJson(newMetaKey, metadata, newMetaAad);

                item.OriginHash = Convert.ToBase64String(newOriginHash);
                item.Epoch = newEpoch;

                // Best-effort scrub of the recovered secret.
                VaultCrypto.SecureClear(System.Text.Encoding.UTF8.GetBytes(payload.Password));
            }

            vault.Epoch = newEpoch;
            vault.UpdatedAt = DateTimeOffset.UtcNow.ToString("O");
            return newEpoch;
        }
        finally
        {
            VaultCrypto.SecureClear(oldItemKey);
            VaultCrypto.SecureClear(oldMetaKey);
            VaultCrypto.SecureClear(newItemKey);
            VaultCrypto.SecureClear(newMetaKey);
        }
    }
}
