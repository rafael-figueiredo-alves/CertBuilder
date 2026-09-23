using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertClientBuilder.Core;
using Xunit;

namespace CertClientBuilder.Tests;

public class ServerCertGeneratorTests
{
    private const string ServerAuthEkuValue = "1.3.6.1.5.5.7.3.1";

    [Fact]
    public void Create_SemDnsOuIp_DeveLancarArgumentException()
    {
        var ca = TestFixtures.CreateTestCa();
        var options = TestFixtures.DefaultLeafOptions();

        Assert.Throws<ArgumentException>(() => ServerCertGenerator.Create(ca, options));
    }

    [Fact]
    public void Create_ComDnsName_DeveIncluirNoSubjectAlternativeName()
    {
        var ca = TestFixtures.CreateTestCa();
        var options = TestFixtures.DefaultLeafOptions("api.local");
        options.DnsNames.Add("api.local");

        var server = ServerCertGenerator.Create(ca, options);
        var sanExtension = server.Certificate.Extensions
            .Cast<X509Extension>()
            .Single(e => e.Oid?.Value == "2.5.29.17"); // OID fixo do Subject Alternative Name (independe de idioma/SO)

        Assert.Contains("api.local", sanExtension.Format(false));
    }

    [Fact]
    public void Create_ComIpAddress_DeveIncluirNoSubjectAlternativeName()
    {
        var ca = TestFixtures.CreateTestCa();
        var options = TestFixtures.DefaultLeafOptions();
        options.IpAddresses.Add("127.0.0.1");

        var server = ServerCertGenerator.Create(ca, options);
        var sanExtension = server.Certificate.Extensions
            .Cast<X509Extension>()
            .Single(e => e.Oid?.Value == "2.5.29.17");

        Assert.Contains("127.0.0.1", sanExtension.Format(false));
    }

    [Fact]
    public void Create_DeveConterExtendedKeyUsageDeServerAuthentication()
    {
        var ca = TestFixtures.CreateTestCa();
        var options = TestFixtures.DefaultLeafOptions();
        options.DnsNames.Add("localhost");

        var server = ServerCertGenerator.Create(ca, options);
        var eku = server.Certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Single();

        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), oid => oid.Value == ServerAuthEkuValue);
    }

    [Fact]
    public void Create_DeveSerAssinadoPelaCaInformada()
    {
        var ca = TestFixtures.CreateTestCa();
        var options = TestFixtures.DefaultLeafOptions();
        options.DnsNames.Add("localhost");

        var server = ServerCertGenerator.Create(ca, options);

        Assert.Equal(ca.Certificate.Subject, server.Certificate.Issuer);
    }
}
