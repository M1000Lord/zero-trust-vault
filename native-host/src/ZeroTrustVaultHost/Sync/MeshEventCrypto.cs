using System.Security.Cryptography;
using ZeroTrustVaultHost.Crypto;

namespace ZeroTrustVaultHost.Sync;

/// <summary>
/// Signs, hashes, and verifies <see cref="MeshEvent"/>s, and verifies the
/// hash chain across a sequence. Uses portable ECDSA P-256 keys (SPKI public
/// keys) so signatures created on one device verify on another, and so the
/// logic is fully unit-testable with ephemeral keys.
///
/// Encryption of payloads reuses <see cref="VaultCrypto"/> (AES-256-GCM); the
/// relay only ever sees ciphertext.
///
/// What this class proves (covered by tests):
///   * a tampered field, payload, or previousEventHash fails verification
///   * an unsigned / wrong-key / wrong-signature event is rejected
///   * a broken hash chain is detected
/// What is NOT yet wired into the live host (see KNOWN_LIMITATIONS.md):
///   * device-authorization / removed-device rejection against a device graph
///   * epoch rotation, fork/split-view detection across a relay, conflict merge
/// </summary>
public static class MeshEventCrypto
{
    public const string SignatureAlgorithm = "ECDSA_P256_SHA256";

    /// <summary>
    /// Computes the event hash over the canonical signed content and signs it.
    /// Mutates and returns the event with EventHash + Signature populated.
    /// </summary>
    public static MeshEvent SignEvent(MeshEvent evt, ECDsa signingKey)
    {
        evt.SignatureAlgorithm = SignatureAlgorithm;
        evt.EventHash = ComputeEventHash(evt);
        byte[] hashBytes = Convert.FromHexString(evt.EventHash);
        byte[] sig = signingKey.SignHash(hashBytes);
        evt.Signature = Convert.ToBase64String(sig);
        return evt;
    }

    /// <summary>
    /// Verifies a single event: recomputes the hash and checks the signature
    /// with the supplied public key. Returns false on any mismatch.
    /// </summary>
    public static bool VerifyEvent(MeshEvent evt, ECDsa publicKey)
    {
        if (string.IsNullOrEmpty(evt.Signature) || string.IsNullOrEmpty(evt.EventHash))
            return false;
        if (!string.Equals(evt.SignatureAlgorithm, SignatureAlgorithm, StringComparison.Ordinal))
            return false;

        string recomputed = ComputeEventHash(evt);
        if (!FixedEquals(recomputed, evt.EventHash))
            return false;

        try
        {
            byte[] hashBytes = Convert.FromHexString(evt.EventHash);
            byte[] sig = Convert.FromBase64String(evt.Signature);
            return publicKey.VerifyHash(hashBytes, sig);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Verifies an ordered chain. Each event must (a) verify individually with
    /// the public key resolved for its deviceId, and (b) reference the prior
    /// event's hash. <paramref name="resolveKey"/> returns the verifying key for
    /// a deviceId, or null if the device is unknown/removed (→ rejected).
    /// </summary>
    public static ChainResult VerifyChain(
        IReadOnlyList<MeshEvent> events,
        Func<string, ECDsa?> resolveKey)
    {
        string expectedPrev = string.Empty;
        for (int i = 0; i < events.Count; i++)
        {
            var evt = events[i];

            if (!string.Equals(evt.PreviousEventHash, expectedPrev, StringComparison.Ordinal))
                return new ChainResult(false, i, "previousEventHash mismatch (broken chain or fork)");

            ECDsa? key = resolveKey(evt.DeviceId);
            if (key is null)
                return new ChainResult(false, i, $"unknown or removed device: {evt.DeviceId}");

            if (!VerifyEvent(evt, key))
                return new ChainResult(false, i, "signature or hash verification failed");

            expectedPrev = evt.EventHash;
        }
        return new ChainResult(true, -1, null);
    }

    /// <summary>SHA-256 (hex) over canonical signed content. Public for testing.</summary>
    public static string ComputeEventHash(MeshEvent evt)
    {
        byte[] canonical = CanonicalJson.SerializeToBytes(evt.SignedContent());
        byte[] hash = SHA256.HashData(canonical);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool FixedEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(a),
            System.Text.Encoding.ASCII.GetBytes(b));
}

/// <summary>Result of verifying an event chain.</summary>
public sealed record ChainResult(bool Valid, int FailedIndex, string? Reason);
