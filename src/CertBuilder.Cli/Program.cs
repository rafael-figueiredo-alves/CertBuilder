using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertBuilder.Core;
using CertBuilder.Core.Models;
using Spectre.Console;

namespace CertBuilder.Cli;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Contains("--version") || args.Contains("-v"))
        {
            VersionInfo.PrintVersion();
            return 0;
        }

        if (args.Contains("--about"))
        {
            VersionInfo.PrintAbout();
            return 0;
        }

        AnsiConsole.Write(new FigletText("CertBuilder").Color(Color.Green));
        AnsiConsole.MarkupLine($"[grey]v{VersionInfo.Version} — {VersionInfo.Copyright}[/]\n");

        while (true)
        {
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("O que você quer fazer?")
                    .AddChoices(
                        "Gerar CA raiz",
                        "Gerar certificado de cliente (mTLS)",
                        "Gerar certificado de servidor (SSL)",
                        "Ver thumbprint de um certificado (.pfx)",
                        "Sobre",
                        "Sair"));

            try
            {
                switch (choice)
                {
                    case "Gerar CA raiz": RunGenerateCa(); break;
                    case "Gerar certificado de cliente (mTLS)": RunGenerateLeaf(isServer: false); break;
                    case "Gerar certificado de servidor (SSL)": RunGenerateLeaf(isServer: true); break;
                    case "Ver thumbprint de um certificado (.pfx)": RunShowThumbprint(); break;
                    case "Sobre": VersionInfo.PrintAbout(); break;
                    case "Sair": return 0;
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Erro:[/] {ex.Message}");
            }

            AnsiConsole.WriteLine();
        }
    }

    private static void RunGenerateCa()
    {
        var commonName = AnsiConsole.Ask("Nome comum da CA:", CertificateDefaults.CaCommonName);
        var organization = AnsiConsole.Ask("Organização:", CertificateDefaults.Organization);
        var organizationalUnit = AnsiConsole.Ask("Unidade organizacional:", CertificateDefaults.OrganizationalUnit);
        var country = AnsiConsole.Ask("País, 2 letras:", CertificateDefaults.Country);
        var state = AnsiConsole.Ask("Estado:", CertificateDefaults.State);
        var locality = AnsiConsole.Ask("Localidade:", CertificateDefaults.Locality);
        var years = AnsiConsole.Ask("Validade em anos:", 10);
        var algorithm = AskKeyAlgorithm();
        var password = AnsiConsole.Prompt(new TextPrompt<string>("Senha do arquivo .pfx da CA:").Secret());
        var outputDir = AnsiConsole.Ask("Pasta de saída:", "./output");

        Directory.CreateDirectory(outputDir);

        var ca = CaGenerator.CreateRootCa(new CaOptions
        {
            CommonName = commonName,
            Organization = string.IsNullOrWhiteSpace(organization) ? null : organization,
            OrganizationalUnit = string.IsNullOrWhiteSpace(organizationalUnit) ? null : organizationalUnit,
            Country = string.IsNullOrWhiteSpace(country) ? CertificateDefaults.Country : country,
            State = string.IsNullOrWhiteSpace(state) ? null : state,
            Locality = string.IsNullOrWhiteSpace(locality) ? null : locality,
            ValidityYears = years,
            KeyAlgorithm = algorithm,
            PfxPassword = password
        });

        var pfxPath = Path.Combine(outputDir, "ca.pfx");
        var cerPath = Path.Combine(outputDir, "ca.cer");
        var crtPath = Path.Combine(outputDir, "ca.crt");
        CertExporter.ExportPfx(ca.Certificate, pfxPath, password);
        CertExporter.ExportPublicCer(ca.Certificate, cerPath);
        CertExporter.ExportCrtAndKey(ca.Certificate, ca.PrivateKey, crtPath, Path.Combine(outputDir, "ca.key"));

        PrintSummary(ca.Certificate);
        AnsiConsole.MarkupLine($"[green]CA gerada com sucesso![/]");
        AnsiConsole.MarkupLine($"  Arquivo com chave privada: [blue]{pfxPath}[/] (guarde com segurança)");
        AnsiConsole.MarkupLine($"  Certificado público (distribuir): [blue]{cerPath}[/]");
        AnsiConsole.MarkupLine($"  Certificado PEM: [blue]{crtPath}[/]");
    }

    private static void RunGenerateLeaf(bool isServer)
    {
        var caPfxPath = AnsiConsole.Ask<string>("Caminho do .pfx da CA que vai assinar:");
        var caPassword = AnsiConsole.Prompt(new TextPrompt<string>("Senha do .pfx da CA:").Secret());
        var caCert = ThumbprintService.LoadFromPfx(caPfxPath, caPassword);
        var ca = new GeneratedCertificate(caCert, caCert.GetECDsaPrivateKey() as AsymmetricAlgorithm
                                                   ?? caCert.GetRSAPrivateKey()!);

        var commonName = AnsiConsole.Ask("Nome comum (CN):", CertificateDefaults.LeafCommonName);
        var organization = AnsiConsole.Ask("Organização:", CertificateDefaults.Organization);
        var organizationalUnit = AnsiConsole.Ask("Unidade organizacional:", CertificateDefaults.OrganizationalUnit);
        var country = AnsiConsole.Ask("País, 2 letras:", CertificateDefaults.Country);
        var state = AnsiConsole.Ask("Estado:", CertificateDefaults.State);
        var locality = AnsiConsole.Ask("Localidade:", CertificateDefaults.Locality);
        var years = AnsiConsole.Ask("Validade em anos:", 2);
        var algorithm = AskKeyAlgorithm();
        var password = AnsiConsole.Prompt(new TextPrompt<string>("Senha do arquivo .pfx gerado:").Secret());
        var outputDir = AnsiConsole.Ask("Pasta de saída:", "./output");
        Directory.CreateDirectory(outputDir);

        var options = new LeafCertOptions
        {
            CommonName = commonName,
            Organization = string.IsNullOrWhiteSpace(organization) ? null : organization,
            OrganizationalUnit = string.IsNullOrWhiteSpace(organizationalUnit) ? null : organizationalUnit,
            Country = string.IsNullOrWhiteSpace(country) ? CertificateDefaults.Country : country,
            State = string.IsNullOrWhiteSpace(state) ? null : state,
            Locality = string.IsNullOrWhiteSpace(locality) ? null : locality,
            ValidityYears = years,
            KeyAlgorithm = algorithm,
            PfxPassword = password
        };

        GeneratedCertificate leaf;
        string fileBaseName;

        if (isServer)
        {
            var dnsInput = AnsiConsole.Ask("Nomes DNS, separados por vírgula (ex.: localhost,api.local, *.api.com.br):", "localhost");
            var ipInput = AnsiConsole.Ask("IPs, separados por vírgula (opcional, ex.: 127.0.0.1):", string.Empty);

            options.DnsNames.AddRange(Split(dnsInput));
            options.IpAddresses.AddRange(Split(ipInput));

            leaf = ServerCertGenerator.Create(ca, options);
            fileBaseName = "server";
        }
        else
        {
            var emailInput = AnsiConsole.Ask("E-mails para o SAN, separados por vírgula (opcional):", string.Empty);
            options.Emails.AddRange(Split(emailInput));

            leaf = ClientCertGenerator.Create(ca, options);
            fileBaseName = "client";
        }

        var pfxPath = Path.Combine(outputDir, $"{fileBaseName}.pfx");
        var crtPath = Path.Combine(outputDir, $"{fileBaseName}.crt");
        var keyPath = Path.Combine(outputDir, $"{fileBaseName}.key");
        CertExporter.ExportPfx(leaf.Certificate, pfxPath, password);
        CertExporter.ExportCrtAndKey(leaf.Certificate, leaf.PrivateKey, crtPath, keyPath);

        if (Math.Abs((leaf.Certificate.NotAfter - caCert.NotAfter).TotalSeconds) < 2)
        {
            AnsiConsole.MarkupLine("[yellow]Aviso:[/] a validade pedida ia além do vencimento da CA — foi limitada para não ultrapassá-lo.");
        }

        PrintSummary(leaf.Certificate);
        AnsiConsole.MarkupLine($"[green]Certificado de {(isServer ? "servidor" : "cliente")} gerado![/]");
        AnsiConsole.MarkupLine($"  PFX: [blue]{pfxPath}[/]");
        AnsiConsole.MarkupLine($"  CRT: [blue]{crtPath}[/]");
        AnsiConsole.MarkupLine($"  KEY: [blue]{keyPath}[/]");
    }

    private static void RunShowThumbprint()
    {
        var path = AnsiConsole.Ask<string>("Caminho do .pfx:");
        var password = AnsiConsole.Prompt(new TextPrompt<string>("Senha:").Secret());
        var cert = ThumbprintService.LoadFromPfx(path, password);
        PrintSummary(cert);
    }

    private static void PrintSummary(X509Certificate2 cert)
    {
        var summary = ThumbprintService.Summarize(cert);
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Campo");
        table.AddColumn("Valor");
        table.AddRow("Subject", summary.Subject);
        table.AddRow("Issuer", summary.Issuer);
        table.AddRow("Thumbprint (SHA-256)", summary.ThumbprintSha256);
        table.AddRow("Válido de", summary.NotBefore.ToString("u"));
        table.AddRow("Válido até", summary.NotAfter.ToString("u"));
        table.AddRow("É CA?", summary.IsCa ? "Sim" : "Não");
        AnsiConsole.Write(table);
    }

    private static KeyAlgorithm AskKeyAlgorithm() =>
        AnsiConsole.Prompt(
            new SelectionPrompt<KeyAlgorithm>()
                .Title("Algoritmo de chave:")
                .AddChoices(KeyAlgorithm.EcdsaP384, KeyAlgorithm.EcdsaP256, KeyAlgorithm.Rsa4096, KeyAlgorithm.Rsa2048));

    private static string[] Split(string input) =>
        input.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
