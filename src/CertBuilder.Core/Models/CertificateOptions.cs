namespace CertBuilder.Core.Models;

/// <summary>Valores usados quando o usuário não informa dados da identificação.</summary>
public static class CertificateDefaults
{
    public const string CaCommonName = "CertBuilder Root CA";
    public const string LeafCommonName = "localhost";
    public const string Country = "BR";
    public const string Organization = "CertBuilder";
    public const string OrganizationalUnit = "Security";
    public const string State = "SP";
    public const string Locality = "Sao Paulo";
}

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
    public string CommonName { get; init; } = CertificateDefaults.CaCommonName;
    public string? Organization { get; init; } = CertificateDefaults.Organization;
    public string? OrganizationalUnit { get; init; } = CertificateDefaults.OrganizationalUnit;
    public string? Country { get; init; } = CertificateDefaults.Country;
    public string? State { get; init; } = CertificateDefaults.State;
    public string? Locality { get; init; } = CertificateDefaults.Locality;
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
    public string CommonName { get; init; } = CertificateDefaults.LeafCommonName;
    public string? Organization { get; init; } = CertificateDefaults.Organization;
    public string? OrganizationalUnit { get; init; } = CertificateDefaults.OrganizationalUnit;
    public string? Country { get; init; } = CertificateDefaults.Country;
    public string? State { get; init; } = CertificateDefaults.State;
    public string? Locality { get; init; } = CertificateDefaults.Locality;
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
