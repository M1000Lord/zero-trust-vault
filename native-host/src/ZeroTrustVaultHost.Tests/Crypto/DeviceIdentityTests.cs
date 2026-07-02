using System.Security.Cryptography;
using System.Text;
using Xunit;
using ZeroTrustVaultHost.Crypto;

namespace ZeroTrustVaultHost.Tests.Crypto;

/// <summary>
/// Tests for DeviceId derivation (hash of public key) and SAS derivation
/// (man-in-the-middle defense for pairing).
/// </summary>
public sealed class DeviceIdentityTests
{
    [Fact]
    public void ComputeDeviceId_IsDeterministic()
    {
        byte[] pub = RandomNumberGenerator.GetBytes(91); // ~P-256 SPKI size
        Assert.Equal(DeviceIdentity.ComputeDeviceId(pub), DeviceIdentity.ComputeDeviceId(pub));
    }

    [Fact]
    public void ComputeDeviceId_DiffersPerKey()
    {
        byte[] a = RandomNumberGenerator.GetBytes(91);
        byte[] b = RandomNumberGenerator.GetBytes(91);
        Assert.NotEqual(DeviceIdentity.ComputeDeviceId(a), DeviceIdentity.ComputeDeviceId(b));
    }

    [Fact]
    public void ComputeDeviceId_IsBase64Url_NoPadding()
    {
        string id = DeviceIdentity.ComputeDeviceId(RandomNumberGenerator.GetBytes(91));
        Assert.DoesNotContain("=", id);
        Assert.DoesNotContain("+", id);
        Assert.DoesNotContain("/", id);
    }

    [Fact]
    public void ComputeDeviceId_EmptyKey_Throws() =>
        Assert.Throws<ArgumentException>(() => DeviceIdentity.ComputeDeviceId(Array.Empty<byte>()));

    [Fact]
    public void ComputeSas_IsOrderIndependent()
    {
        byte[] keyA = RandomNumberGenerator.GetBytes(91);
        byte[] keyB = RandomNumberGenerator.GetBytes(91);
        byte[] nonce = RandomNumberGenerator.GetBytes(16);

        // Both devices compute the SAS; the joiner/initiator pass keys in opposite order.
        string sas1 = DeviceIdentity.ComputeSas("session-1", keyA, keyB, nonce);
        string sas2 = DeviceIdentity.ComputeSas("session-1", keyB, keyA, nonce);
        Assert.Equal(sas1, sas2);
    }

    [Fact]
    public void ComputeSas_DiffersWithDifferentKeys_MitmDefense()
    {
        byte[] keyA = RandomNumberGenerator.GetBytes(91);
        byte[] keyB = RandomNumberGenerator.GetBytes(91);
        byte[] mitm = RandomNumberGenerator.GetBytes(91); // attacker substitutes its key
        byte[] nonce = RandomNumberGenerator.GetBytes(16);

        string honest = DeviceIdentity.ComputeSas("session-1", keyA, keyB, nonce);
        string attacked = DeviceIdentity.ComputeSas("session-1", keyA, mitm, nonce);
        Assert.NotEqual(honest, attacked); // user sees mismatching codes and aborts
    }

    [Fact]
    public void ComputeSas_HasRequestedDigitCount()
    {
        byte[] keyA = RandomNumberGenerator.GetBytes(91);
        byte[] keyB = RandomNumberGenerator.GetBytes(91);
        byte[] nonce = RandomNumberGenerator.GetBytes(16);

        string sas = DeviceIdentity.ComputeSas("s", keyA, keyB, nonce, digits: 6);
        Assert.Equal(6, sas.Length);
        Assert.Matches(@"^\d{6}$", sas);
    }

    [Fact]
    public void ComputeSas_ShortNonce_Throws()
    {
        byte[] keyA = RandomNumberGenerator.GetBytes(91);
        byte[] keyB = RandomNumberGenerator.GetBytes(91);
        Assert.Throws<ArgumentException>(() =>
            DeviceIdentity.ComputeSas("s", keyA, keyB, new byte[4]));
    }
}
