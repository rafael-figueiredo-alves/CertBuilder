using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertBuilder.Core;

/// <summary>Resumo de um certificado, útil para exibir em tabela no terminal.</summary>
public sealed record CertificateSummary(
    string Subject,
    string Issuer,
    string ThumbprintSha256,
    DateTime NotBefore,
    DateTime NotAfter,
    bool IsCa);

public static class ThumbprintService
{
    public static string GetThumbprintSha256(X509Certificate2 certificate) =>
        certificate.GetCertHashString(HashAlgorithmName.SHA256);

    public static CertificateSummary Summarize(X509Certificate2 certificate)
    {
        var isCa = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .Any(ext => ext.CertificateAuthority);

        return new CertificateSummary(
            certificate.Subject,
            certificate.Issuer,
            GetThumbprintSha256(certificate),
            certificate.NotBefore,
            certificate.NotAfter,
            isCa);
    }

    /// <summary>Carrega um certificado (com chave privada, se houver senha) a partir de um arquivo PFX.</summary>
    public static X509Certificate2 LoadFromPfx(string filePath, string password) =>
        X509CertificateLoader.LoadPkcs12FromFile(filePath, password);
}
