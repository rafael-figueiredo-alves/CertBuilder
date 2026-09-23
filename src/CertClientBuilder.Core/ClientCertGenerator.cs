using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertClientBuilder.Core.Models;

namespace CertClientBuilder.Core;

/// <summary>
/// Gera certificados de CLIENTE, usados pela aplicação cliente para se autenticar
/// junto a uma API que exige mTLS (Extended Key Usage = Client Authentication).
/// </summary>
public static class ClientCertGenerator
{
    private static readonly Oid ClientAuthEku = new("1.3.6.1.5.5.7.3.2");

    public static GeneratedCertificate Create(GeneratedCertificate ca, LeafCertOptions options)
    {
        var (key, hash) = KeyFactory.Create(options.KeyAlgorithm);

        var subject = string.IsNullOrWhiteSpace(options.Organization)
            ? $"CN={options.CommonName}"
            : $"CN={options.CommonName}, O={options.Organization}";

        var request = CertificateRequestFactory.Create(subject, key, hash);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([ClientAuthEku], critical: true));

        if (options.Emails.Count > 0)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var email in options.Emails) sanBuilder.AddEmailAddress(email);
            request.CertificateExtensions.Add(sanBuilder.Build());
        }

        var serial = RandomNumberGenerator.GetBytes(16);
        var (notBefore, notAfter) = ValidityCalculator.CalculateForLeaf(ca.Certificate, options.ValidityYears);

        using var signedWithoutKey = request.Create(ca.Certificate, notBefore, notAfter, serial);
        var certWithKey = CertificateRequestFactory.AttachPrivateKey(signedWithoutKey, key);

        return new GeneratedCertificate(certWithKey, key);
    }
}
