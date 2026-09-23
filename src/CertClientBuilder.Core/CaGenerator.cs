using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertClientBuilder.Core.Models;

namespace CertClientBuilder.Core;

/// <summary>
/// Resultado de uma geração de certificado: o certificado com a chave privada anexada
/// (necessário para depois assinar certificados-filho ou exportar em PFX).
/// </summary>
public sealed record GeneratedCertificate(X509Certificate2 Certificate, AsymmetricAlgorithm PrivateKey);

/// <summary>
/// Gera uma CA (Certificate Authority) raiz autoassinada.
/// A CA é o ponto de confiança: certificados de cliente e servidor emitidos por ela
/// só serão aceitos por quem instalar o certificado público da CA como raiz confiável.
/// </summary>
public static class CaGenerator
{
    public static GeneratedCertificate CreateRootCa(CaOptions options)
    {
        var (key, hash) = KeyFactory.Create(options.KeyAlgorithm);

        var subject = BuildDistinguishedName(options.CommonName, options.Organization, options.Country);
        var request = CertificateRequestFactory.Create(subject, key, hash);

        // CA=true habilita esse certificado a assinar outros certificados.
        // pathLengthConstraint=0 impede que essa CA assine outras CAs intermediárias
        // (mantém a cadeia simples: raiz -> folha).
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = notBefore.AddYears(options.ValidityYears);

        var cert = request.CreateSelfSigned(notBefore, notAfter);
        return new GeneratedCertificate(cert, key);
    }

    private static string BuildDistinguishedName(string commonName, string? organization, string? country)
    {
        var parts = new List<string> { $"CN={commonName}" };
        if (!string.IsNullOrWhiteSpace(organization)) parts.Add($"O={organization}");
        if (!string.IsNullOrWhiteSpace(country)) parts.Add($"C={country}");
        return string.Join(", ", parts);
    }
}
