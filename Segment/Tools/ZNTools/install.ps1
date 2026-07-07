#Requires -Version 7
<#
.SYNOPSIS
    Installs the ZNTools PowerShell module directly from GitHub.

.DESCRIPTION
    Downloads the znCommunity repo archive, pulls out the ZNTools module folder
    (Segment/Tools/ZNTools), and copies it into the current user's PowerShell
    Modules path. Safe to re-run — it replaces any existing install of the same name.

.PARAMETER Repo
    GitHub 'owner/repo' to install from. Defaults to '2mOlaf/znCommunity'.

.PARAMETER Branch
    Repo branch to install from. Defaults to 'feature/zntools'.

.PARAMETER Scope
    'CurrentUser' (default) installs to $HOME's PowerShell\Modules path.
    'AllUsers' installs to the system-wide PowerShell\Modules path (requires admin).

.EXAMPLE
    irm https://raw.githubusercontent.com/2mOlaf/znCommunity/feature/zntools/Segment/Tools/ZNTools/install.ps1 | iex

.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/2mOlaf/znCommunity/feature/zntools/Segment/Tools/ZNTools/install.ps1))) -Repo zeronetworks/Community -Branch master
#>
param(
    [string]$Repo = '2mOlaf/znCommunity',
    [string]$Branch = 'feature/zntools',
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser'
)

$ErrorActionPreference = 'Stop'

$moduleName  = 'ZNTools'
$repoZipUrl  = "https://github.com/$Repo/archive/refs/heads/$Branch.zip"
$modSubPath  = 'Segment/Tools/ZNTools'

$installRoot = if ($Scope -eq 'AllUsers') {
    Join-Path $env:ProgramFiles 'PowerShell\Modules'
}
else {
    Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'
}
$installPath = Join-Path $installRoot $moduleName

$work = Join-Path ([System.IO.Path]::GetTempPath()) "$moduleName-install-$([System.Guid]::NewGuid().ToString('N'))"
$zipPath = Join-Path $work "$moduleName.zip"
$extractPath = Join-Path $work 'src'

try {
    New-Item -ItemType Directory -Path $work -Force | Out-Null

    Write-Host "Downloading $moduleName ($Repo@$Branch)..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $repoZipUrl -OutFile $zipPath -UseBasicParsing

    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

    $repoRoot = Get-ChildItem -Path $extractPath -Directory | Select-Object -First 1
    if (-not $repoRoot) {
        throw "Could not find an extracted repo folder under '$extractPath'."
    }

    $moduleSrc = Join-Path $repoRoot.FullName $modSubPath
    if (-not (Test-Path $moduleSrc)) {
        throw "Expected module folder '$modSubPath' not found in downloaded archive."
    }

    if (Test-Path $installPath) {
        Remove-Item -Path $installPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
    Copy-Item -Path $moduleSrc -Destination $installPath -Recurse -Force

    $manifest = Import-PowerShellDataFile -Path (Join-Path $installPath "$moduleName.psd1")
    Write-Host "$moduleName v$($manifest.ModuleVersion) installed to: $installPath" -ForegroundColor Green
    Write-Host "Run: Import-Module $moduleName" -ForegroundColor Green
}
finally {
    if (Test-Path $work) {
        Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
