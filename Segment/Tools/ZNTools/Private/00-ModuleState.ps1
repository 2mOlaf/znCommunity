$script:ModuleAuthor = 'Olaf Gradin'
$script:CommandPrefix = 'ZN'
$script:WelcomeShown = $false

function Show-ZNModuleWelcome {
    Write-Host ""
    Write-Host "Zero Networks Tools module loaded." -ForegroundColor Cyan
    Write-Host "Default auth: uses ZN_API_KEY environment variable (override with -ApiKey / -ApiUrl)." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Quick Start" -ForegroundColor White
    Write-Host ("-" * 70) -ForegroundColor DarkGray
    Write-Host "Networking" -ForegroundColor Yellow
    Write-Host "  Test-ZNPort -Computer <host> -Port <int> [-Continuous]" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Linux Profiles" -ForegroundColor Yellow
    Write-Host "  Get-ZNLinuxProfile" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Segment Clusters" -ForegroundColor Yellow
    Write-Host "  Get-ZNSegmentCluster" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Health Dashboard" -ForegroundColor Yellow
    Write-Host "  Show-ZNHealthDashboard [-IncludeDisconnected] [-ExportCsv <path>]" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Security Events" -ForegroundColor Yellow
    Write-Host "  Get-ZNSecurityEventRate -Period <1h|4h|1d|7d>" -ForegroundColor Gray
    Write-Host ""
    Write-Host "BreakGlass Asset Browser  (load data once, then pipe freely)" -ForegroundColor Yellow
    Write-Host "  Import-ZNBGAssetData [-DataPath <path>]" -ForegroundColor Gray
    Write-Host "  Get-ZNBGAsset | Get-ZNBGAssetSummary | Find-ZNBGAsset <name>" -ForegroundColor Gray
    Write-Host "  Get-ZNBGWindowsAsset | Get-ZNBGLinuxAsset | Get-ZNBGServerAsset | Get-ZNBGClientAsset" -ForegroundColor Gray
    Write-Host "  Get-ZNBGNetworkSegmentedAsset | Get-ZNBGIdentitySegmentedAsset" -ForegroundColor Gray
    Write-Host "  Get-ZNBGAssetCluster | Get-ZNBGClusterMemberAsset <cluster>" -ForegroundColor Gray
    Write-Host "  Get-ZNBGAssetForest | Get-ZNBGAssetSwitch | Get-ZNBGAssetBySource" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Service Management  (manages zn* services)" -ForegroundColor Yellow
    Write-Host "  Invoke-ZNServices -Action <Stop|Start|Restart>" -ForegroundColor Gray
    Write-Host "  Invoke-ZNServices -Action Restart -ComputerName <host>" -ForegroundColor Gray
    Write-Host "  Invoke-ZNServices -Action Restart -AllServers [-ClusterName <name>]" -ForegroundColor Gray
    Write-Host ""
}

function Ensure-ZNWelcomeShown {
    if (-not $script:WelcomeShown) {
        $script:WelcomeShown = $true
        Show-ZNModuleWelcome
    }
}

function Get-ZNAuthorFromCommand {
    param([string]$CommandName)
    $author = $script:ModuleAuthor
    try {
        $definition = (Get-Command $CommandName -ErrorAction Stop).Definition
        $match = [regex]::Match($definition, '(?im)^\s*\.AUTHOR\s+([^\r\n]+)')
        if ($match.Success) {
            $author = $match.Groups[1].Value.Trim()
        }
    } catch {
        $author = $script:ModuleAuthor
    }
    return $author
}

