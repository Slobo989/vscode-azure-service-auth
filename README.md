# Azure Service Authentication for VS Code

A VS Code extension that mirrors Visual Studio's **Tools → Options → Azure Service Authentication → Account Selection**: pick a Microsoft account that's already signed into VS Code, and your .NET code can use it to call Azure resources — without per-test sign-in prompts, and **without adding any NuGet package to your project**.

The extension does three things:

1. Adds a **status bar dropdown** to choose a Microsoft account from the ones VS Code already has sessions for.
2. Runs a **local loopback token broker** that issues access tokens for the selected account on demand.
3. Registers a **PowerShell token-provider script** in the Visual Studio IdentityService (`%LOCALAPPDATA%\.IdentityService\AzureServiceAuth\tokenprovider.json`) so that `DefaultAzureCredential` / `VisualStudioCredential` in any .NET project automatically picks up the selected account — no code changes required.

> Why a broker? Modern `Azure.Identity` no longer ships a working `VisualStudioCodeCredential`. The broker bridges VS Code's authentication API and `TokenCredential` without requiring Azure CLI, MSAL caches, or browser prompts at test time.

## Install

### From VSIX (recommended)

```pwsh
# 1. Install the packaging tool (one-time)
npm install -g @vscode/vsce

# 2. Build and package
npm run compile
vsce package --allow-missing-repository

# 3. Install into VS Code
& "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd" --install-extension .\vscode-azure-service-auth-0.1.0.vsix --force
```

Then reload the VS Code window (`Ctrl+Shift+P` → **Developer: Reload Window**).

### From source (development)

```pwsh
cd vscode-azure-service-auth
npm install
npm run compile
# Press F5 in VS Code to launch the Extension Development Host.
```

## Usage

1. Click the **`$(azure) Sign in to Azure`** item on the status bar (or run **Azure Service Authentication: Select Account** from the Command Palette).
2. Pick an account, or choose **Sign in to another account…**.
3. The status bar shows the selected account. The extension writes discovery files and registers the token provider automatically.

### Verify the selected account

```pwsh
# From inside a workspace folder:
Get-Content .\.vscode\azure-service-auth.json | ConvertFrom-Json | Select-Object account, endpoint, pid

# Or from anywhere (user-scope fallback):
Get-ChildItem "$env:USERPROFILE\.vscode-azure-service-auth\*.json" |
    ForEach-Object { Get-Content $_ | ConvertFrom-Json } |
    Select-Object account, endpoint, pid
```

### Test the broker directly

```pwsh
$d = Get-Content "$env:USERPROFILE\.vscode-azure-service-auth\*.json" | ConvertFrom-Json | Select-Object -First 1
Invoke-RestMethod -Uri "$($d.endpoint)/token" `
    -Method Post `
    -Headers @{ Authorization = "Bearer $($d.token)" } `
    -ContentType application/json `
    -Body '{"scopes":["https://management.azure.com/.default"]}'
```

## Use from .NET

### Windows — no NuGet package required

On Windows, the extension registers itself as a Visual Studio IdentityService token provider. Any project using `Azure.Identity` works out of the box:

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

// DefaultAzureCredential includes VisualStudioCredential, which calls our
// token provider automatically while VS Code is running with an account selected.
var credential = new DefaultAzureCredential();

var client = new SecretClient(new Uri("https://my-vault.vault.azure.net/"), credential);
var secret = await client.GetSecretAsync("connection-string");
```

No `dotnet add package`, no `using VSCodeAzureCredential`, no code changes at all. When VS Code is not running (CI, production), `VisualStudioCredential` fails gracefully and `DefaultAzureCredential` falls through to the next credential in its chain (managed identity, environment variables, etc.).

### macOS / Linux — companion NuGet package

`Azure.Identity` only activates `VisualStudioCredential` on Windows — on macOS and Linux it silently skips it, so `DefaultAzureCredential` alone will never reach our broker. The companion NuGet package provides `VSCodeCredential`, which talks directly to the HTTP broker and works on all platforms:

```pwsh
dotnet add package VSCodeAzureCredential
```

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using VSCodeAzureCredential;

var credential = new ChainedTokenCredential(
    new VSCodeCredential(),       // selected VS Code account (local dev / tests)
    new DefaultAzureCredential()  // CI, managed identity, etc.
);

var client = new SecretClient(new Uri("https://my-vault.vault.azure.net/"), credential);
var secret = await client.GetSecretAsync("connection-string");
```

The HTTP broker and `VSCodeCredential` are fully cross-platform.

### Windows: explicit credential (optional)

If you prefer an explicit credential over the automatic `VisualStudioCredential` path:

```pwsh
dotnet add package VSCodeAzureCredential
```

```csharp
using Azure.Identity;
using VSCodeAzureCredential;

var credential = new ChainedTokenCredential(
    new VSCodeCredential(),       // selected VS Code account (local dev / tests)
    new DefaultAzureCredential()  // CI, managed identity, etc.
);
```

## How it works

When the extension activates it:

1. Starts a local HTTP token broker on a random loopback port.
2. Writes a discovery file (`<workspace>/.vscode/azure-service-auth.json` and `~/.vscode-azure-service-auth/<machineId>.json`) containing the endpoint URL and a per-session bearer secret.
3. **(Windows only)** Injects an entry into `%LOCALAPPDATA%\.IdentityService\AzureServiceAuth\tokenprovider.json` pointing to `bin/tokenProvider.ps1` inside the extension folder. `Azure.Identity`'s `VisualStudioCredential` reads this file and invokes the script when it needs a token. This step is skipped on macOS and Linux because `VisualStudioCredential` itself is Windows-only in `Azure.Identity`.
4. On extension deactivation (Windows), removes its entry from `tokenprovider.json` (leaving any Visual Studio entries intact).

The PowerShell token-provider script (`bin/tokenProvider.ps1`) receives `--resource` and `--tenant` arguments from `Azure.Identity`, translates the resource URL to an OAuth scope, finds the broker via the discovery file, and returns `{ "access_token": "...", "expires_on": "..." }` on stdout.

## Discovery file format

```json
{
  "endpoint": "http://127.0.0.1:54123",
  "token": "<random hex>",
  "account": "user@contoso.com",
  "pid": 12345
}
```

The discovery file is searched in this order:

1. Path in env var `VSCODE_AZURE_AUTH_BROKER`.
2. `.vscode/azure-service-auth.json` walking up from the current directory.
3. Any `*.json` in `%USERPROFILE%\.vscode-azure-service-auth\`.

Add `**/.vscode/azure-service-auth.json` to your repo's `.gitignore`. The file is per-session and not portable.

## Broker HTTP protocol

`POST /token` on the discovered endpoint.

Headers: `Authorization: Bearer <token from discovery file>`
Body:
```json
{ "scopes": ["https://vault.azure.net/.default"], "tenantId": "optional" }
```

Responses:

| Status | Meaning |
| --- | --- |
| 200 | `{ "token": "...", "expiresOn": "...", "account": "..." }` |
| 400 | `scopes` missing |
| 401 | Bad / missing bearer |
| 409 | No account selected in VS Code |
| 410 | Selected account has been removed from VS Code |

## Limitations

- VS Code does not expose the JWT `exp`. The broker reports a conservative 55-minute lifetime; `Azure.Identity` will retry on 401.
- The zero-code-change `VisualStudioCredential` integration is Windows-only (IdentityService path + `Azure.Identity` limitation). On macOS/Linux use the companion NuGet package. The HTTP broker itself is cross-platform.
- The broker is bound to `127.0.0.1` only and protected by a per-session bearer secret, but it inherits the trust boundary of your local machine. Don't expose it.
