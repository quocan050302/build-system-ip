param(
    [int]$BundlerExitCode = 0,
    [string]$ArtifactDir = "$env:RUNNER_TEMP/anti-v9/$env:GITHUB_SHA/$env:GITHUB_RUN_ID-tauri-windows"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

$binaryPath = "src-tauri/target/release/youtube-isolation-manager.exe"
$nsisPattern = "src-tauri/target/release/bundle/nsis/*.exe"

$binaryExists = $false
$binarySize = 0
$binarySha256 = $null
if (Test-Path $binaryPath) {
    $binItem = Get-Item $binaryPath
    if ($binItem.Length -gt 0) {
        $binaryExists = $true
        $binarySize = $binItem.Length
        $binarySha256 = (Get-FileHash -Path $binItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$installerFiles = @()
if (Test-Path "src-tauri/target/release/bundle/nsis") {
    $installerFiles = @(Get-ChildItem -Path $nsisPattern -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 })
}

$installerDetails = @()
foreach ($inst in $installerFiles) {
    $hash = (Get-FileHash -Path $inst.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $installerDetails += @{
        name   = $inst.Name
        path   = $inst.FullName
        bytes  = $inst.Length
        sha256 = $hash
    }
}

$binaryGate = if ($binaryExists) { "PASS" } else { "FAIL" }
$installerGate = if (($BundlerExitCode -eq 0) -and ($installerDetails.Count -gt 0)) { "PASS" } else { "FAIL" }

$manifest = @{
    schema_version              = "anti-v10.0-windows-packaging"
    generated_at_utc            = (Get-Date).ToUniversalTime().ToString("o")
    git_sha                     = "$env:GITHUB_SHA"
    git_run_id                  = "$env:GITHUB_RUN_ID"
    bundler_exit_code           = $BundlerExitCode
    WINDOWS_RELEASE_BINARY_GATE = $binaryGate
    WINDOWS_INSTALLER_GATE      = $installerGate
    release_binary              = @{
        exists = $binaryExists
        path   = $binaryPath
        bytes  = $binarySize
        sha256 = $binarySha256
    }
    nsis_installers             = $installerDetails
}

$manifestPath = Join-Path $ArtifactDir "windows_packaging_manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host "=== Windows Packaging Gate Manifest ==="
Get-Content $manifestPath | Write-Host

if ($binaryGate -ne "PASS") {
    Write-Error "WINDOWS_RELEASE_BINARY_GATE=FAIL: Release binary '$binaryPath' is missing or empty."
    exit 1
}

if ($installerGate -ne "PASS") {
    Write-Error "WINDOWS_INSTALLER_GATE=FAIL: Real NSIS installer under 'src-tauri/target/release/bundle/nsis/*.exe' was not produced (BundlerExitCode=$BundlerExitCode, InstallerCount=$($installerDetails.Count)). Binary-only fallback is strictly prohibited."
    exit 1
}

Write-Host "WINDOWS_RELEASE_BINARY_GATE=PASS and WINDOWS_INSTALLER_GATE=PASS verified."
exit 0
