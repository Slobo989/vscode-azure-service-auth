# Token provider for the "Azure Service Authentication" VS Code extension.
#
# Azure.Identity's VisualStudioCredential calls this script with:
#   --resource <resource_url>  --tenant <tenant_id>
# and expects JSON output:  { "access_token": "...", "expires_on": "<ISO 8601>" }
#
# On success the script exits with code 0.
# On failure it writes an error message to stderr and exits non-zero.

$ErrorActionPreference = 'Stop'

# -- Parse arguments --------------------------------------------------------------
# AzureServiceTokenProvider (Microsoft.Azure.Services.AppAuthentication) appends
# resource and tenantId as positional args after the Arguments array in tokenprovider.json:
#   powershell.exe ... -File script.ps1 "<resource>" "<tenantId>"
#
# Some callers (e.g. Azure.Identity VisualStudioCredential) use named flags instead:
#   --resource <resource> --tenant <tenantId>
#
# We accept both styles.
$resource = ''
$tenant   = ''
$positional = [System.Collections.Generic.List[string]]::new()
$i = 0
while ($i -lt $args.Count) {
    switch ($args[$i]) {
        '--resource' {
            if (($i + 1) -lt $args.Count) { $resource = $args[$i + 1]; $i += 2 }
            else { $i++ }
        }
        '--tenant' {
            if (($i + 1) -lt $args.Count) { $tenant = $args[$i + 1]; $i += 2 }
            else { $i++ }
        }
        default {
            $positional.Add($args[$i])
            $i++
        }
    }
}

# Fall back to positional arguments when named flags were not supplied
if (-not $resource -and $positional.Count -ge 1) { $resource = $positional[0] }
if (-not $tenant   -and $positional.Count -ge 2) { $tenant   = $positional[1] }

if (-not $resource) {
    [Console]::Error.WriteLine('VSCodeTokenProvider: resource argument is required')
    exit 1
}

# -- Convert resource URL to OAuth scope ----------------------------------------
# Azure.Identity passes e.g. "https://management.azure.com/"
# The broker expects a scope like "https://management.azure.com/.default"
if ($resource -match '/\.default$') {
    $scope = $resource
} elseif ($resource.EndsWith('/')) {
    $scope = $resource + '.default'
} else {
    $scope = $resource + '/.default'
}

# -- Locate the broker discovery file -------------------------------------------
function Find-BrokerDiscovery {
    # 1. Walk up the directory tree from the current working directory
    $dir = [System.IO.Directory]::GetCurrentDirectory()
    while ($dir) {
        $candidate = [System.IO.Path]::Combine($dir, '.vscode', 'azure-service-auth.json')
        if ([System.IO.File]::Exists($candidate)) {
            try {
                $d = Get-Content $candidate -Raw | ConvertFrom-Json
                if ($d.endpoint -and $d.token) { return $d }
            } catch {}
        }
        $parent = [System.IO.Path]::GetDirectoryName($dir)
        if (-not $parent -or $parent -eq $dir) { break }
        $dir = $parent
    }

    # 2. User-scope fallback: ~/.vscode-azure-service-auth/*.json
    $userDir = [System.IO.Path]::Combine($env:USERPROFILE, '.vscode-azure-service-auth')
    if ([System.IO.Directory]::Exists($userDir)) {
        foreach ($f in [System.IO.Directory]::GetFiles($userDir, '*.json')) {
            try {
                $d = Get-Content $f -Raw | ConvertFrom-Json
                if ($d.endpoint -and $d.token) { return $d }
            } catch {}
        }
    }

    return $null
}

$discovery = Find-BrokerDiscovery
if (-not $discovery) {
    [Console]::Error.WriteLine('VSCodeTokenProvider: broker is not running (no discovery file found). Start VS Code and select an account via "Azure Service Authentication: Select Account".')
    exit 1
}

# Security: only allow loopback endpoints to prevent SSRF if the discovery file
# is tampered with or committed to a repository.
if (-not $discovery.endpoint -or -not ($discovery.endpoint -match '^http://127\.0\.0\.1:\d+$')) {
    [Console]::Error.WriteLine('VSCodeTokenProvider: discovery file contains a non-loopback endpoint, rejecting.')
    exit 1
}

# -- Call the broker -------------------------------------------------------------
$requestBody = [ordered]@{ scopes = @($scope) }
if ($tenant -and $tenant -ne '') {
    $requestBody['tenantId'] = $tenant
}

try {
    $response = Invoke-RestMethod `
        -Uri         ($discovery.endpoint + '/token') `
        -Method      Post `
        -Headers     @{ Authorization = "Bearer $($discovery.token)" } `
        -ContentType 'application/json' `
        -Body        ($requestBody | ConvertTo-Json -Compress) `
        -ErrorAction Stop
} catch {
    [Console]::Error.WriteLine("VSCodeTokenProvider: broker request failed - $_")
    exit 1
}

if (-not $response.token) {
    [Console]::Error.WriteLine('VSCodeTokenProvider: broker returned no token')
    exit 1
}

# -- Emit result -----------------------------------------------------------------
# Azure.Identity reads 'access_token' and 'expires_on' (ISO 8601 string).
[ordered]@{
    access_token = $response.token
    expires_on   = $response.expiresOn
} | ConvertTo-Json -Compress | Write-Output

exit 0
