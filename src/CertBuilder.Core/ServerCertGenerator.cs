using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertBuilder.Core.Models;

namespace CertBuilder.Core;

/// <summary>
/// Gera certificados de SERVIDOR, usados por um Kestrel/nginx/IIS para apresentar
/// identidade TLS ao cliente (Extended Key Usage = Server Authentication).
///
/// Importante: um certificado assinado por uma CA própria só é confiável em
/// máquinas onde o certificado público dessa CA for instalado manualmente como
/// raiz confiável. Não substitui uma CA pública (Let's Encrypt, etc.) para
/// servidores expostos à internet e acessados por navegadores de terceiros.
/// </summary>
public static class ServerCertGenerator
{
    private static readonly Oid ServerAuthEku = new("1.3.6.1.5.5.7.3.1");

    public static GeneratedCertificate Create(GeneratedCertificate ca, LeafCertOptions options)
    {
        if (options.DnsNames.Count == 0 && options.IpAddresses.Count == 0)
            throw new ArgumentException("Informe ao menos um DNS name ou IP para o SAN do certificado de servidor.");

        var (key, hash) = KeyFactory.Create(options.KeyAlgorithm);

        var subject = CertificateSubjectBuilder.Build(options.CommonName, options.Organization,
            options.OrganizationalUnit, options.Country, options.State, options.Locality);

        var request = CertificateRequestFactory.Create(subject, key, hash);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([ServerAuthEku], critical: true));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dns in options.DnsNames) sanBuilder.AddDnsName(dns);
        foreach (var ip in options.IpAddresses) sanBuilder.AddIpAddress(IPAddress.Parse(ip));
        request.CertificateExtensions.Add(sanBuilder.Build());

        var serial = RandomNumberGenerator.GetBytes(16);
        var (notBefore, notAfter) = ValidityCalculator.CalculateForLeaf(ca.Certificate, options.ValidityYears);

        using var signedWithoutKey = request.Create(ca.Certificate, notBefore, notAfter, serial);
        var certWithKey = CertificateRequestFactory.AttachPrivateKey(signedWithoutKey, key);

        return new GeneratedCertificate(certWithKey, key);
    }
}
