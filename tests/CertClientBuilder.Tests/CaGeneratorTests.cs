using System.Security.Cryptography.X509Certificates;
using CertClientBuilder.Core;
using Xunit;

namespace CertClientBuilder.Tests;

public class CaGeneratorTests
{
    [Fact]
    public void CreateRootCa_DeveMarcarCertificateAuthorityComoVerdadeiro()
    {
        var ca = TestFixtures.CreateTestCa();

        var basicConstraints = ca.Certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Single();

        Assert.True(basicConstraints.CertificateAuthority);
    }

    [Fact]
    public void CreateRootCa_DeveConterChavePrivada()
    {
        var ca = TestFixtures.CreateTestCa();

        Assert.True(ca.Certificate.HasPrivateKey);
    }

    [Fact]
    public void CreateRootCa_SubjectDeveConterCommonNameInformado()
    {
        var ca = TestFixtures.CreateTestCa("Minha CA de Teste");

        Assert.Contains("CN=Minha CA de Teste", ca.Certificate.Subject);
    }

    [Fact]
    public void CreateRootCa_DeveSerAutoAssinado()
    {
        var ca = TestFixtures.CreateTestCa();

        // Numa CA raiz autoassinada, Subject e Issuer são iguais.
        Assert.Equal(ca.Certificate.Subject, ca.Certificate.Issuer);
    }
}
