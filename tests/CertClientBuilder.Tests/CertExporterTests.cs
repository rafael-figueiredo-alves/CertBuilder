using CertClientBuilder.Core;
using Xunit;

namespace CertClientBuilder.Tests;

public class CertExporterTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("ccb-tests-").FullName;

    [Fact]
    public void ExportPfx_DeveGerarArquivoCarregavelComMesmoThumbprint()
    {
        var ca = TestFixtures.CreateTestCa();
        var path = Path.Combine(_tempDir, "ca.pfx");

        CertExporter.ExportPfx(ca.Certificate, path, TestFixtures.CaPassword);
        var reloaded = ThumbprintService.LoadFromPfx(path, TestFixtures.CaPassword);

        Assert.Equal(
            ThumbprintService.GetThumbprintSha256(ca.Certificate),
            ThumbprintService.GetThumbprintSha256(reloaded));
    }

    [Fact]
    public void ExportPublicCer_NaoDeveConterChavePrivada()
    {
        var ca = TestFixtures.CreateTestCa();
        var path = Path.Combine(_tempDir, "ca.cer");

        CertExporter.ExportPublicCer(ca.Certificate, path);
        var reloaded = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificateFromFile(path);

        Assert.False(reloaded.HasPrivateKey);
    }

    [Fact]
    public void ExportPem_DeveGerarArquivosDeCertificadoEChave()
    {
        var ca = TestFixtures.CreateTestCa();
        var certPath = Path.Combine(_tempDir, "ca.crt");
        var keyPath = Path.Combine(_tempDir, "ca.key");

        CertExporter.ExportPem(ca.Certificate, ca.PrivateKey, certPath, keyPath);

        Assert.Contains("BEGIN CERTIFICATE", File.ReadAllText(certPath));
        Assert.Contains("BEGIN PRIVATE KEY", File.ReadAllText(keyPath));
    }

    public void Dispose()
    {
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }
}
