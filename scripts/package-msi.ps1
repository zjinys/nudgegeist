# package-msi.ps1 - Package Nudgegeist into a Windows MSI and portable ZIP (run on Windows).
#
# Outputs:
#   dist\Nudgegeist-<version>-x64.msi
#   dist\Nudgegeist-<version>-x64.zip
#
# Requires: cargo, WiX Toolset v3.11+ (candle/light via %WIX%\bin or PATH).
param(
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $root
try {
    $rawVersion = (Select-String -Path Cargo.toml -Pattern '^version = "([^"]+)"' |
        Select-Object -First 1).Matches[0].Groups[1].Value
    $version = if ($env:NUDGEGEIST_VERSION) { $env:NUDGEGEIST_VERSION } else { $rawVersion }
    if ($version -notmatch '^\d+\.\d+\.\d+') {
        throw "Version '$version' is invalid for MSI (expected X.Y.Z); override via NUDGEGEIST_VERSION."
    }
    if (-not [System.IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path $root $OutDir }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    if ($env:NUDGEGEIST_SKIP_BUILD -ne "1") {
        Write-Host "[1/3] Building Nudgegeist release binary ..."
        cargo build --release --locked
        if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed" }
    }

    $targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root "target" }
    $releaseDir = Join-Path $targetDir "release"
    $exePath = Join-Path $releaseDir "nudgegeist.exe"
    if (-not (Test-Path $exePath)) {
        throw "Release binary not found: $exePath"
    }

    Write-Host "[2/3] Creating portable ZIP ..."
    $zipStage = Join-Path $env:TEMP ("nudgegeist-zip-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $zipStage | Out-Null
    try {
        Copy-Item $exePath (Join-Path $zipStage "nudgegeist.exe")
        $zipOut = Join-Path $OutDir "Nudgegeist-$version-x64.zip"
        Remove-Item $zipOut -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $zipStage "nudgegeist.exe") -DestinationPath $zipOut
        Write-Host "Created $zipOut"
    } finally {
        Remove-Item $zipStage -Recurse -Force -ErrorAction SilentlyContinue
    }

    $wixBin = if ($env:WIX) { Join-Path $env:WIX "bin" } else { "" }
    $candle = if ($wixBin -and (Test-Path "$wixBin\candle.exe")) { "$wixBin\candle.exe" }
              else { (Get-Command candle.exe -ErrorAction SilentlyContinue).Source }
    if (-not $candle) {
        throw "WiX Toolset v3.x (candle.exe / light.exe) not found. Install via: choco install wixtoolset"
    }
    $wixDir = Split-Path -Parent $candle
    $light = Join-Path $wixDir "light.exe"

    Write-Host "[3/3] Compiling & linking MSI ..."
    $stage = Join-Path $env:TEMP ("nudgegeist-msi-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        $licenseRtf = Join-Path $stage "License.rtf"
        Set-Content -Path $licenseRtf -Value '{\rtf1\ansi Nudgegeist - AI Coding Agent Watchdog and Rule Engine GUI.}'

        $sourceDir = $releaseDir
        $iconPath = Join-Path $root "assets\nudgegeist.ico"

        & $candle -nologo `
            "-dSourceDir=$sourceDir" `
            "-dProductVersion=$version" `
            "-dIconPath=$iconPath" `
            "-dLicenseRtf=$licenseRtf" `
            -arch x64 `
            -out "$stage\" `
            (Join-Path $root "packaging\windows\nudgegeist.wxs")
        if ($LASTEXITCODE -ne 0) { throw "candle failed" }

        $msiOut = Join-Path $OutDir "Nudgegeist-$version-x64.msi"
        Remove-Item $msiOut -Force -ErrorAction SilentlyContinue
        & $light -nologo -ext WixUIExtension `
            -out $msiOut "$stage\nudgegeist.wixobj"
        if ($LASTEXITCODE -ne 0) { throw "light failed" }
        Write-Host "Created $msiOut"
    } finally {
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
} finally {
    Pop-Location
}
