using System.Reflection;
using Spectre.Console;

namespace CertClientBuilder.Cli;

/// <summary>
/// Lê os metadados definidos no .csproj (Version, Product, Copyright) para
/// exibir nas opções --version e --about, sem precisar hardcodar em dois lugares.
/// </summary>
internal static class VersionInfo
{
    private static readonly Assembly Assembly = typeof(VersionInfo).Assembly;

    public static string Product =>
        Assembly.GetCustomAttribute<AssemblyProductAttribute>()?.Product ?? "CertClientBuilder";

    public static string Version =>
        Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? Assembly.GetName().Version?.ToString()
        ?? "0.0.0";

    public static string Copyright =>
        Assembly.GetCustomAttribute<AssemblyCopyrightAttribute>()?.Copyright ?? string.Empty;

    public static void PrintVersion() =>
        AnsiConsole.MarkupLine($"[bold]{Product}[/] v{Version}");

    public static void PrintAbout()
    {
        var panel = new Panel(
            $"[bold]{Product}[/] v{Version}\n" +
            $"{Copyright}\n\n" +
            "Ferramenta de aprendizado para gerar CA raiz e certificados de\n" +
            "cliente/servidor (mTLS e SSL interno) usando System.Security.Cryptography.\n\n" +
            "[link]https://github.com/rafael-figueiredo-alves/CertClientBuilder[/]")
            .Header("Sobre")
            .Border(BoxBorder.Rounded);

        AnsiConsole.Write(panel);
    }
}
