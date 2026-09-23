# CertClientBuilder

> Ferramenta de linha de comando em C#/.NET para gerar, na prática, uma Autoridade Certificadora (CA) raiz e certificados de cliente/servidor — pensada para habilitar **mTLS** entre uma API ASP.NET Core e suas aplicações clientes, e para emitir certificados TLS internos sem depender de uma CA pública.

![.NET](https://img.shields.io/badge/.NET-10-512BD4)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-aprendizado-blue)

## Por que este projeto existe

A maior parte dos tutoriais sobre mTLS trata a geração de certificados como uma caixa-preta resolvida com dois comandos `openssl`. Este projeto existe para abrir essa caixa: entender, na prática e em C#, o que é uma CA, o que significa assinar um certificado, por que `Basic Constraints` e `Enhanced Key Usage` existem, e como tudo isso se conecta ao `ClientCertificateValidation` do Kestrel.

**Objetivo:** aprendizado aplicado, com uma ferramenta pequena, funcional e reutilizável em projetos pessoais e profissionais.

## O que ele faz

- Gera uma **CA raiz** autoassinada (RSA ou ECDSA), com senha protegendo a chave privada.
- Gera **certificados de cliente**, assinados pela CA, com `Extended Key Usage = Client Authentication` — o que a API espera ao validar mTLS.
- Gera **certificados de servidor**, assinados pela CA, com `Extended Key Usage = Server Authentication` e SAN (`DNS`/`IP`) — substitui um certificado autoassinado avulso em ambientes internos, sem os avisos de "certificado inválido" causados por certs sem cadeia.
- Calcula e exibe o **thumbprint (SHA-256)** e outros metadados de qualquer certificado `.pfx`.
- Exporta em **PFX** (Windows/.NET) e o certificado público da CA em **CER** (para distribuir aos clientes que vão confiar nela).
- Interface interativa no terminal (Spectre.Console) — sem precisar decorar flags.

## O que ele **não** faz (por design)

- Não substitui o Let's Encrypt para certificados de servidores **públicos**, acessados por navegadores de terceiros. Um certificado emitido por uma CA privada só é confiável em máquinas onde o certificado público dessa CA for instalado manualmente como raiz confiável. É a ferramenta certa para mTLS interno, ambientes de homologação e redes controladas — não para expor um site ao público geral.
- Não gerencia revogação (CRL/OCSP) — fica como possível evolução futura.

## Como o mTLS se encaixa

```
        ┌───────────────┐        apresenta client.pfx        ┌──────────────────┐
        │  App Cliente  │ ───────────────────────────────────▶│  API ASP.NET Core │
        └───────────────┘                                      └──────────────────┘
                ▲                                                        │
                │            client.pfx e server.pfx assinados           │ valida contra
                │            pela mesma CA raiz (ca.cer)                 ▼ ca.cer confiável
                └────────────────────── CA raiz ──────────────────────────┘
```

A API confia em qualquer certificado de cliente assinado pela CA (`ca.cer` instalado como raiz confiável no servidor). O cliente confia no certificado de servidor pela mesma razão. É essa cadeia de confiança que este projeto ajuda a construir passo a passo.

## Estrutura do projeto

```
CertClientBuilder/
├── src/
│   ├── CertClientBuilder.Core/       # Lógica de geração — sem dependência de UI
│   │   ├── Models/CertificateOptions.cs
│   │   ├── KeyFactory.cs
│   │   ├── CertificateRequestFactory.cs
│   │   ├── CaGenerator.cs
│   │   ├── ClientCertGenerator.cs
│   │   ├── ServerCertGenerator.cs
│   │   ├── CertExporter.cs
│   │   └── ThumbprintService.cs
│   └── CertClientBuilder.Cli/        # Menu interativo (Spectre.Console)
│       ├── Program.cs
│       └── VersionInfo.cs
├── tests/
│   └── CertClientBuilder.Tests/      # Testes de unidade (xUnit) do Core
│       ├── TestFixtures.cs
│       ├── CaGeneratorTests.cs
│       ├── ClientCertGeneratorTests.cs
│       ├── ServerCertGeneratorTests.cs
│       ├── CertExporterTests.cs
│       └── ThumbprintServiceTests.cs
├── CertClientBuilder.sln
└── LICENSE
```

## Como usar

### Pré-requisitos
- [.NET 10 SDK](https://dotnet.microsoft.com/download)

### Rodando

```bash
git clone https://github.com/rafael-figueiredo-alves/CertClientBuilder.git
cd CertClientBuilder
dotnet run --project src/CertClientBuilder.Cli
```

### Opções de linha de comando

```bash
dotnet run --project src/CertClientBuilder.Cli -- --version   # mostra versão
dotnet run --project src/CertClientBuilder.Cli -- --about     # mostra sobre + copyright
```

### Rodando os testes

```bash
dotnet test
```

Os testes cobrem apenas o `CertClientBuilder.Core` (geração de CA, certificados de cliente/servidor, exportação e thumbprint) — o projeto `Cli` fica de fora de propósito, por ser só interface.

### Fluxo típico

1. **Gerar CA raiz** → gera `ca.pfx` (guarde com segurança) e `ca.cer` (distribua para quem precisa confiar).
2. **Gerar certificado de cliente (mTLS)**, informando o `ca.pfx` gerado → gera `client.pfx`, usado pela aplicação cliente.
3. **Gerar certificado de servidor (SSL)**, informando o mesmo `ca.pfx` e os DNS names do servidor → gera `server.pfx`, configurado no Kestrel.
4. Instale `ca.cer` como raiz confiável nas máquinas que precisam validar essa cadeia.

### Usando o certificado de servidor no Kestrel (ASP.NET Core)

```csharp
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(https =>
    {
        https.ServerCertificate = X509CertificateLoader.LoadPkcs12FromFile("server.pfx", "senha");
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
    });
});
```

## Decisões técnicas

| Escolha | Motivo |
|---|---|
| ECDSA P-384 como padrão | Chaves menores e mais rápidas que RSA, com nível de segurança equivalente ou superior |
| `System.Security.Cryptography.X509Certificates` nativo | Sem dependências externas de criptografia — controle total sobre cada extensão do certificado |
| `pathLengthConstraint = 0` na CA | Impede que a CA emita outras CAs intermediárias, mantendo a cadeia simples (raiz → folha) |
| Spectre.Console | Interface de terminal legível, com prompts validados, sem sacrificar a natureza CLI da ferramenta |

## Roadmap (possíveis próximos passos)

- [ ] CA intermediária (separar CA offline de CA operacional)
- [ ] Lista de revogação (CRL) simplificada
- [ ] Exportação PEM completa via menu (já suportada no Core)

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).
