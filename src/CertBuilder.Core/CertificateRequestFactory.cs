using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertBuilder.Core;

internal static class CertificateSubjectBuilder
{
    public static string Build(string commonName, string? organization, string? organizationalUnit,
        string? country, string? state, string? locality)
    {
        var parts = new List<string> { $"CN={commonName}" };
        Add(parts, "O", organization);
        Add(parts, "OU", organizationalUnit);
        Add(parts, "C", country);
        Add(parts, "ST", state);
        Add(parts, "L", locality);
        return string.Join(", ", parts);
    }

    private static void Add(List<string> parts, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) parts.Add($"{name}={value}");
    }
}

/// <summary>
/// CertificateRequest tem construtores diferentes para RSA e ECDSA — esta fábrica
/// esconde essa diferença dos geradores de CA e de certificados-folha.
/// </summary>
internal static class CertificateRequestFactory
{
    public static CertificateRequest Create(string distinguishedName, AsymmetricAlgorithm key, HashAlgorithmName hash) => key switch
    {
        RSA rsa => new CertificateRequest(distinguishedName, rsa, hash, RSASignaturePadding.Pkcs1),
        ECDsa ecdsa => new CertificateRequest(distinguishedName, ecdsa, hash),
        _ => throw new NotSupportedException($"Tipo de chave não suportado: {key.GetType().Name}")
    };

    /// <summary>
    /// X509Certificate2.CopyWithPrivateKey não tem overload genérico para AsymmetricAlgorithm —
    /// cada tipo de chave (RSA/ECDsa) tem seu próprio método de extensão. Este helper unifica isso.
    /// </summary>
    public static X509Certificate2 AttachPrivateKey(X509Certificate2 certificate, AsymmetricAlgorithm key) => key switch
    {
        RSA rsa => certificate.CopyWithPrivateKey(rsa),
        ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
        _ => throw new NotSupportedException($"Tipo de chave não suportado: {key.GetType().Name}")
    };
}
