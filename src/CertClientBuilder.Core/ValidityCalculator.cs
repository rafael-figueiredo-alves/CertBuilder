using System.Security.Cryptography.X509Certificates;

namespace CertClientBuilder.Core;

/// <summary>
/// Um certificado assinado por uma CA nunca pode ter validade além da própria CA —
/// CAs (e navegadores/bibliotecas TLS) rejeitam essa cadeia. Este helper calcula a
/// janela de validade do certificado-folha já limitada ao "NotAfter" da CA emissora.
/// </summary>
internal static class ValidityCalculator
{
    public static (DateTimeOffset NotBefore, DateTimeOffset NotAfter) CalculateForLeaf(
        X509Certificate2 issuerCertificate, int requestedValidityYears)
    {
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var requestedNotAfter = notBefore.AddYears(requestedValidityYears);

        // NotAfter do certificado da CA vem como DateTime local; convertemos para
        // DateTimeOffset em UTC para comparar com segurança.
        var issuerNotAfter = new DateTimeOffset(issuerCertificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);

        var notAfter = requestedNotAfter < issuerNotAfter ? requestedNotAfter : issuerNotAfter;

        return (notBefore, notAfter);
    }
}
