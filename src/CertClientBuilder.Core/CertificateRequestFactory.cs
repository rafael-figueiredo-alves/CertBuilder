using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertClientBuilder.Core;

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
