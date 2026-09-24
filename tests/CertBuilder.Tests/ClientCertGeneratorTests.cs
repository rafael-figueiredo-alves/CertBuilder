using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertBuilder.Core;
using CertBuilder.Core.Models;
using Xunit;

namespace CertBuilder.Tests;

public class ClientCertGeneratorTests
{
    private const string ClientAuthEkuValue = "1.3.6.1.5.5.7.3.2";

    [Fact]
    public void Create_DeveSerAssinadoPelaCaInformada()
    {
        var ca = TestFixtures.CreateTestCa();
        var client = ClientCertGenerator.Create(ca, TestFixtures.DefaultLeafOptions());

        Assert.Equal(ca.Certificate.Subject, client.Certificate.Issuer);
    }

    [Fact]
    public void Create_DeveConterExtendedKeyUsageDeClientAuthentication()
    {
        var ca = TestFixtures.CreateTestCa();
        var client = ClientCertGenerator.Create(ca, TestFixtures.DefaultLeafOptions());

        var eku = client.Certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Single();

        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(), oid => oid.Value == ClientAuthEkuValue);
    }

    [Fact]
    public void Create_NaoDeveSerMarcadoComoCa()
    {
        var ca = TestFixtures.CreateTestCa();
        var client = ClientCertGenerator.Create(ca, TestFixtures.DefaultLeafOptions());

        var basicConstraints = client.Certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Single();

        Assert.False(basicConstraints.CertificateAuthority);
    }

    [Fact]
    public void Create_DeveConterChavePrivadaParaUsoImediato()
    {
        var ca = TestFixtures.CreateTestCa();
        var client = ClientCertGenerator.Create(ca, TestFixtures.DefaultLeafOptions());

        Assert.True(client.Certificate.HasPrivateKey);
    }

    [Fact]
    public void Create_ComEmails_DeveIncluirNoSubjectAlternativeName()
    {
        var ca = TestFixtures.CreateTestCa();
        var options = TestFixtures.DefaultLeafOptions();
        options.Emails.Add("dev@example.com");

        var client = ClientCertGenerator.Create(ca, options);
        var sanExtension = client.Certificate.Extensions
            .Cast<X509Extension>()
            .Single(e => e.Oid?.Value == "2.5.29.17"); // OID fixo do Subject Alternative Name (independe de idioma/SO)

        Assert.Contains("dev@example.com", sanExtension.Format(false));
    }

    [Fact]
    public void Create_ComValidadeMaiorQueDaCa_DeveLimitarAoVencimentoDaCa()
    {
        var ca = TestFixtures.CreateTestCa(); // CA de teste tem 1 ano de validade

        // Pede uma validade bem maior que a da CA — não pode resultar em erro,
        // e o certificado gerado não pode vencer depois da CA que o assina.
        var client = ClientCertGenerator.Create(ca, new LeafCertOptions
        {
            CommonName = "cliente-validade-longa",
            KeyAlgorithm = KeyAlgorithm.EcdsaP256,
            ValidityYears = 50,
            PfxPassword = TestFixtures.LeafPassword
        });

        Assert.True(client.Certificate.NotAfter <= ca.Certificate.NotAfter);
    }
}
