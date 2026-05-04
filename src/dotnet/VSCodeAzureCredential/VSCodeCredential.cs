using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;

namespace VSCodeAzureCredential
{
    /// <summary>
    /// A <see cref="TokenCredential"/> that obtains Azure access tokens from the
    /// VS Code "Azure Service Authentication" extension via its local loopback
    /// token broker.
    /// </summary>
    /// <remarks>
    /// Place this credential first in a <c>ChainedTokenCredential</c> so it is
    /// used when running tests inside VS Code, and falls through to other
    /// credentials in CI or when the extension isn't running.
    /// </remarks>
    public sealed class VSCodeCredential : TokenCredential
    {
        private const string DiscoveryDirName = ".vscode";
        private const string DiscoveryFileName = "azure-service-auth.json";
        private const string EnvOverride = "VSCODE_AZURE_AUTH_BROKER";
        private const string UserDirName = ".vscode-azure-service-auth";

        private static readonly HttpClient s_http = new HttpClient
        {
            // Short timeout: the broker is always on localhost, so a slow response
            // means it is not running rather than a legitimate slow operation.
            Timeout = TimeSpan.FromSeconds(10),
        };

        private readonly string? _tenantId;

        public VSCodeCredential() : this(null) { }

        public VSCodeCredential(string? tenantId)
        {
            _tenantId = tenantId;
        }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
            => GetTokenAsync(requestContext, cancellationToken).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            DiscoveryFile discovery = LoadDiscoveryFile()
                ?? throw new CredentialUnavailableException(
                    "VS Code Azure Service Authentication broker is not running. " +
                    "Install and enable the extension, then select an account.");

            var request = new TokenRequest
            {
                Scopes = requestContext.Scopes,
                TenantId = _tenantId ?? requestContext.TenantId,
            };
            string body = JsonSerializer.Serialize(request, JsonOpts);

            using var msg = new HttpRequestMessage(HttpMethod.Post, discovery.Endpoint + "/token")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };
            msg.Headers.TryAddWithoutValidation("Authorization", "Bearer " + discovery.Token);

            HttpResponseMessage resp;
            try
            {
                resp = await s_http.SendAsync(msg, HttpCompletionOption.ResponseContentRead, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new CredentialUnavailableException(
                    $"Could not reach VS Code token broker at {discovery.Endpoint}: {ex.Message}", ex);
            }

            using (resp)
            {
                string text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                {
                    // 409 / 410 / 401 from the broker indicate user action is needed,
                    // not that the credential is unusable in principle.
                    throw new AuthenticationFailedException(
                        $"VS Code token broker returned {(int)resp.StatusCode}: {text}");
                }

                TokenResponse? parsed;
                try
                {
                    parsed = JsonSerializer.Deserialize<TokenResponse>(text, JsonOpts);
                }
                catch (Exception ex)
                {
                    throw new AuthenticationFailedException("Malformed broker response: " + ex.Message, ex);
                }

                if (parsed is null || string.IsNullOrEmpty(parsed.Token))
                {
                    throw new AuthenticationFailedException("Broker response did not include a token.");
                }

                DateTimeOffset expiresOn = DateTimeOffset.TryParse(parsed.ExpiresOn, out var exp)
                    ? exp
                    : DateTimeOffset.UtcNow.AddMinutes(50);

                return new AccessToken(parsed.Token!, expiresOn);
            }
        }

        private static DiscoveryFile? LoadDiscoveryFile()
        {
            // 1. Explicit override wins.
            string? overridePath = Environment.GetEnvironmentVariable(EnvOverride);
            if (!string.IsNullOrEmpty(overridePath) && File.Exists(overridePath))
            {
                return ReadFile(overridePath!);
            }

            // 2. Walk up from current directory looking for .vscode/azure-service-auth.json.
            DirectoryInfo? dir = new DirectoryInfo(Directory.GetCurrentDirectory());
            while (dir != null)
            {
                string candidate = Path.Combine(dir.FullName, DiscoveryDirName, DiscoveryFileName);
                if (File.Exists(candidate))
                {
                    return ReadFile(candidate);
                }
                dir = dir.Parent;
            }

            // 3. User-scope fallback (any file in ~/.vscode-azure-service-auth/).
            string userDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                UserDirName);
            if (Directory.Exists(userDir))
            {
                foreach (string file in Directory.GetFiles(userDir, "*.json"))
                {
                    DiscoveryFile? f = ReadFile(file);
                    if (f != null) { return f; }
                }
            }

            return null;
        }

        private static DiscoveryFile? ReadFile(string path)
        {
            try
            {
                string json = File.ReadAllText(path);
                DiscoveryFile? f = JsonSerializer.Deserialize<DiscoveryFile>(json, JsonOpts);
                if (f is null || string.IsNullOrEmpty(f.Endpoint) || string.IsNullOrEmpty(f.Token))
                {
                    return null;
                }

                // Security: only allow loopback endpoints to prevent SSRF if the
                // discovery file is written by a malicious process or committed to git.
                if (!f.Endpoint.StartsWith("http://127.0.0.1:", StringComparison.Ordinal))
                {
                    return null;
                }

                return f;
            }
            catch
            {
                return null;
            }
        }

        private static readonly JsonSerializerOptions JsonOpts = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
        };

        private sealed class DiscoveryFile
        {
            public string Endpoint { get; set; } = "";
            public string Token { get; set; } = "";
            public string? Account { get; set; }
        }

        private sealed class TokenRequest
        {
            public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();
            public string? TenantId { get; set; }
        }

        private sealed class TokenResponse
        {
            public string? Token { get; set; }
            public string? ExpiresOn { get; set; }
            public string? Account { get; set; }
        }
    }

}
