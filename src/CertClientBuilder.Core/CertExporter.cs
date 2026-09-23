using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertClientBuilder.Core;

/// <summary>
/// Exporta certificados (com ou sem chave privada) em formatos comuns:
/// PFX (Windows/.NET) e PEM separado (comum em Linux/nginx/OpenSSL).
/// </summary>
public static class CertExporter
{
    /// <summary>Exporta certificado + chave privada em um único arquivo PFX protegido por senha.</summary>
    public static void ExportPfx(X509Certificate2 certificate, string filePath, string password)
    {
        var bytes = certificate.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(filePath, bytes);
    }

    /// <summary>Exporta apenas o certificado público, sem chave privada (para distribuir a CA, por exemplo).</summary>
    public static void ExportPublicCer(X509Certificate2 certificate, string filePath)
    {
        var bytes = certificate.Export(X509ContentType.Cert);
        File.WriteAllBytes(filePath, bytes);
    }

    /// <summary>Exporta certificado (.crt) e chave privada (.key) em PEM separados — formato usado por nginx/Apache.</summary>
    public static void ExportPem(X509Certificate2 certificate, AsymmetricAlgorithm privateKey, string certPath, string keyPath)
    {
        File.WriteAllText(certPath, certificate.ExportCertificatePem());

        var keyPem = privateKey switch
        {
            RSA rsa => rsa.ExportPkcs8PrivateKeyPem(),
            ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKeyPem(),
            _ => throw new NotSupportedException($"Tipo de chave não suportado: {privateKey.GetType().Name}")
        };

        File.WriteAllText(keyPath, keyPem);
    }
}
