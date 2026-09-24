using System.Security.Cryptography;
using CertBuilder.Core.Models;

namespace CertBuilder.Core;

/// <summary>
/// Cria a chave assimétrica e a assinatura (algoritmo de hash + padding, quando aplicável)
/// correspondentes à opção escolhida pelo usuário.
/// </summary>
internal static class KeyFactory
{
    public static (AsymmetricAlgorithm Key, HashAlgorithmName Hash) Create(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.Rsa2048 => (RSA.Create(2048), HashAlgorithmName.SHA256),
        KeyAlgorithm.Rsa4096 => (RSA.Create(4096), HashAlgorithmName.SHA256),
        KeyAlgorithm.EcdsaP256 => (ECDsa.Create(ECCurve.NamedCurves.nistP256), HashAlgorithmName.SHA256),
        KeyAlgorithm.EcdsaP384 => (ECDsa.Create(ECCurve.NamedCurves.nistP384), HashAlgorithmName.SHA384),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };
}
