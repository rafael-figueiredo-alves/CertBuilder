using CertBuilder.Core;
using CertBuilder.Core.Models;

namespace CertBuilder.Tests;

/// <summary>
/// Fábricas pequenas para não repetir setup (CA de teste, opções padrão)
/// em cada classe de teste.
/// </summary>
internal static class TestFixtures
{
    public const string CaPassword = "senha-teste-ca";
    public const string LeafPassword = "senha-teste-leaf";

    public static GeneratedCertificate CreateTestCa(string commonName = "Teste CA Raiz") =>
        CaGenerator.CreateRootCa(new CaOptions
        {
            CommonName = commonName,
            KeyAlgorithm = KeyAlgorithm.EcdsaP256, // mais rápido para rodar nos testes
            ValidityYears = 1,
            PfxPassword = CaPassword
        });

    public static LeafCertOptions DefaultLeafOptions(string commonName = "teste.local") => new()
    {
        CommonName = commonName,
        KeyAlgorithm = KeyAlgorithm.EcdsaP256,
        ValidityYears = 1,
        PfxPassword = LeafPassword
    };
}
