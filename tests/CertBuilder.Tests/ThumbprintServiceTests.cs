using CertBuilder.Core;
using Xunit;

namespace CertBuilder.Tests;

public class ThumbprintServiceTests
{
    [Fact]
    public void GetThumbprintSha256_DeveRetornar64CaracteresHexadecimais()
    {
        var ca = TestFixtures.CreateTestCa();

        var thumbprint = ThumbprintService.GetThumbprintSha256(ca.Certificate);

        Assert.Equal(64, thumbprint.Length);
        Assert.Matches("^[0-9A-Fa-f]+$", thumbprint);
    }

    [Fact]
    public void Summarize_ParaCa_DeveMarcarIsCaComoVerdadeiro()
    {
        var ca = TestFixtures.CreateTestCa();

        var summary = ThumbprintService.Summarize(ca.Certificate);

        Assert.True(summary.IsCa);
    }

    [Fact]
    public void Summarize_ParaCertificadoDeCliente_DeveMarcarIsCaComoFalso()
    {
        var ca = TestFixtures.CreateTestCa();
        var client = ClientCertGenerator.Create(ca, TestFixtures.DefaultLeafOptions());

        var summary = ThumbprintService.Summarize(client.Certificate);

        Assert.False(summary.IsCa);
    }

    [Fact]
    public void Summarize_DeveRefletirSubjectEIssuerDoCertificado()
    {
        var ca = TestFixtures.CreateTestCa();
        var client = ClientCertGenerator.Create(ca, TestFixtures.DefaultLeafOptions("cliente-01"));

        var summary = ThumbprintService.Summarize(client.Certificate);

        Assert.Contains("CN=cliente-01", summary.Subject);
        Assert.Equal(ca.Certificate.Subject, summary.Issuer);
    }
}
