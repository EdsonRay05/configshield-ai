$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$backendRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$toolRoot = [System.IO.Path]::GetFullPath((Join-Path $backendRoot '.tools'))
if (-not $toolRoot.StartsWith($backendRoot + [System.IO.Path]::DirectorySeparatorChar)) {
    throw 'Tool output must remain inside the backend directory.'
}
$toolLock = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'kubeconform-lock.json') -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
$schemaRoot = Join-Path $toolRoot 'schemas'
New-Item -ItemType Directory -Force -Path $schemaRoot | Out-Null

function Get-VerifiedDownload {
    param([string]$Url, [string]$Destination, [string]$ExpectedHash)
    if ((Test-Path -LiteralPath $Destination) -and ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -eq $ExpectedHash)) {
        return
    }
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination -TimeoutSec 60
    if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash) {
        throw "SHA-256 verification failed for $Destination. No validator will be trusted."
    }
}

$archivePath = Join-Path $toolRoot 'kubeconform-windows-amd64.zip'
Get-VerifiedDownload -Url $toolLock.archive_url -Destination $archivePath -ExpectedHash $toolLock.archive_sha256
Get-VerifiedDownload -Url $toolLock.schema_url -Destination (Join-Path $schemaRoot 'deployment-apps-v1.json') -ExpectedHash $toolLock.schema_sha256

# Extract only named entries into fixed project paths; do not expand archive paths.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $binaryEntry = $archive.GetEntry('kubeconform.exe')
    if ($null -eq $binaryEntry) { throw 'The pinned archive has no expected Windows executable.' }
    $binaryPath = Join-Path $toolRoot 'kubeconform.exe'
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($binaryEntry, $binaryPath, $true)
    $licenseEntry = $archive.GetEntry('LICENSE')
    if ($null -ne $licenseEntry) {
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($licenseEntry, (Join-Path $toolRoot 'KUBECONFORM-LICENSE.txt'), $true)
    }
} finally { $archive.Dispose() }
$binaryHash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($toolLock.binary_sha256 -and $binaryHash -ne $toolLock.binary_sha256) {
    throw 'The extracted binary does not match the pinned binary hash.'
}
Write-Output "Kubeconform binary SHA256: $binaryHash"
Write-Output "Kubernetes schema target: $($toolLock.kubernetes_version)"
& $binaryPath -v
if ($LASTEXITCODE -ne 0) { throw 'The installed validator could not start.' }
