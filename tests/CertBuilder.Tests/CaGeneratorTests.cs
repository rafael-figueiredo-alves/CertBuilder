using System.Security.Cryptography.X509Certificates;
using CertBuilder.Core;
using CertBuilder.Core.Models;
using Xunit;

namespace CertBuilder.Tests;

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

    [Fact]
    public void CreateRootCa_SemOpcoesDeIdentificacao_DeveUsarDefaultsBrasileiros()
    {
        var ca = CaGenerator.CreateRootCa(new CaOptions { PfxPassword = TestFixtures.CaPassword });

        Assert.Contains("CN=CertBuilder Root CA", ca.Certificate.Subject);
        Assert.Contains("C=BR", ca.Certificate.Subject);
        Assert.Contains("O=CertBuilder", ca.Certificate.Subject);
    }
}
