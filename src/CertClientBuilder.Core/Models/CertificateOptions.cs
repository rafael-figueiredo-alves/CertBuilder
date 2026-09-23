namespace CertClientBuilder.Core.Models;

/// <summary>
/// Algoritmo de chave usado na geração do certificado.
/// ECDSA é recomendado: chaves menores e mais rápidas que RSA com segurança equivalente.
/// </summary>
public enum KeyAlgorithm
{
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384
}

/// <summary>
/// Dados coletados na "seção de perguntas" para gerar uma CA raiz.
/// </summary>
public sealed class CaOptions
{
    public required string CommonName { get; init; }
    public string? Organization { get; init; }
    public string? Country { get; init; }
    public KeyAlgorithm KeyAlgorithm { get; init; } = KeyAlgorithm.EcdsaP384;
    public int ValidityYears { get; init; } = 10;
    public required string PfxPassword { get; init; }
}

/// <summary>
/// Dados coletados para gerar um certificado folha (cliente ou servidor),
/// sempre assinado por uma CA previamente gerada/carregada.
/// </summary>
public sealed class LeafCertOptions
{
    public required string CommonName { get; init; }
    public string? Organization { get; init; }
    public KeyAlgorithm KeyAlgorithm { get; init; } = KeyAlgorithm.EcdsaP256;
    public int ValidityYears { get; init; } = 2;
    public required string PfxPassword { get; init; }

    /// <summary>Nomes DNS (SAN) — usado em certificados de servidor.</summary>
    public List<string> DnsNames { get; init; } = [];

    /// <summary>Endereços IP (SAN) — usado em certificados de servidor.</summary>
    public List<string> IpAddresses { get; init; } = [];

    /// <summary>E-mails (SAN) — comumente usado em certificados de cliente/mTLS.</summary>
    public List<string> Emails { get; init; } = [];
}
