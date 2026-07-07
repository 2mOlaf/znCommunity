function Show-HealthDashboard {
    <#
    .SYNOPSIS
        Displays the Zero Networks health dashboard for unhealthy assets.
    .PARAMETER ApiUrl
        Optional API base URL override.
    .PARAMETER ApiKey
        Optional API key override; defaults to ZN_API_KEY environment variable.
    .PARAMETER ExportCsv
        Path to export results as CSV.
    .PARAMETER IncludeNA
        Include assets with N/A health state.
    .PARAMETER IncludeDisconnected
        Include a disconnected assets section.
    .PARAMETER IncludeDisconnectedDays
        Include only assets disconnected for at least this many days.
    .AUTHOR
        Olaf Gradin
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl,
        [string]$ApiKey,
        [string]$ExportCsv,
        [switch]$IncludeNA,
        [switch]$IncludeDisconnected,
        [ValidateRange(0, 3650)]
        [int]$IncludeDisconnectedDays
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    function Write-Log {
        param(
            [string]$Message,
            [ValidateSet('Info', 'Warning', 'Error')]
            [string]$Level = 'Info'
        )
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $color = switch ($Level) { 'Warning' { 'Yellow' } 'Error' { 'Red' } default { 'Green' } }
        Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    }

    function Get-IssueName {
        param([int]$Code)
        if ($script:IssueCodeNames.ContainsKey($Code)) { return $script:IssueCodeNames[$Code] }
        return "Issue #$Code"
    }

    function Get-SystemHealth {
        param([string]$BaseUrl, [hashtable]$Headers)
        try {
            $response = Invoke-RestMethod -Uri "$BaseUrl/environments/system-health" -Headers $Headers -Method Get
            return $response.issues ?? @()
        }
        catch {
            Write-Log "Failed to retrieve system health: $($_.Exception.Message)" -Level Error
            return @()
        }
    }

    function Get-AssetHealthState {
        param([string]$BaseUrl, [hashtable]$Headers, [string]$AssetId)
        try {
            $response = Invoke-RestMethod -Uri "$BaseUrl/assets/$AssetId/health-state" -Headers $Headers -Method Get
            return $response.healthState
        }
        catch {
            Write-Log "Failed to get health state for asset $AssetId`: $($_.Exception.Message)" -Level Warning
            return $null
        }
    }

    function Write-SystemHealthSection {
        param([array]$Issues)

        Write-Host "  SYSTEM HEALTH" -ForegroundColor White
        Write-Host ("  " + "-" * 68)

        if (-not $Issues -or $Issues.Count -eq 0) {
            Write-Host "  No system-level issues detected." -ForegroundColor Green
        }
        else {
            foreach ($issue in $Issues) {
                $severityColor = if ($issue.severity -match 'error|critical|high') { 'Red' }
                                 elseif ($issue.severity -match 'warn|medium') { 'Yellow' }
                                 else { 'Cyan' }
                Write-Host ("  [{0,-8}] {1}" -f $issue.severity, $issue.type) -ForegroundColor $severityColor
            }
        }
        Write-Host ""
    }

    function Write-AssetHealthSection {
        param([array]$UnhealthyAssets)

        Write-Host "  ASSET HEALTH SUMMARY" -ForegroundColor White
        Write-Host ("  " + "-" * 68)

        $grouped = $UnhealthyAssets | Group-Object { $_.HealthStatus }
        foreach ($statusCode in $script:SeverityOrder) {
            $label = $script:HealthStatus[$statusCode]
            $group = $grouped | Where-Object { $_.Name -eq $statusCode }
            $count = if ($group) { $group.Count } else { 0 }
            if ($count -gt 0) {
                Write-Host ("  {0,-12} : {1}" -f $label, $count) -ForegroundColor $script:SeverityColor[$statusCode]
            }
        }
        Write-Host ""

        Write-Host "  ASSET DETAILS" -ForegroundColor White
        Write-Host ("  " + "-" * 68)

        foreach ($statusCode in $script:SeverityOrder) {
            $group = $UnhealthyAssets | Where-Object { $_.HealthStatus -eq $statusCode }
            if (-not $group) { continue }

            $label = $script:HealthStatus[$statusCode]
            $color = $script:SeverityColor[$statusCode]

            Write-Host ""
            Write-Host ("  [ {0} ]" -f $label) -ForegroundColor $color

            foreach ($asset in ($group | Sort-Object DisplayName)) {
                Write-Host ("    {0}" -f $asset.DisplayName) -ForegroundColor White

                if ($asset.FQDN -and $asset.FQDN -ne $asset.DisplayName) {
                    Write-Host ("      FQDN   : {0}" -f $asset.FQDN) -ForegroundColor DarkGray
                }
                if ($asset.Domain) {
                    Write-Host ("      Domain : {0}" -f $asset.Domain) -ForegroundColor DarkGray
                }

                if ($asset.Issues -and $asset.Issues.Count -gt 0) {
                    foreach ($issue in $asset.Issues) {
                        $issueName = Get-IssueName -Code $issue.issueCode
                        $detail    = if ($issue.details) { " — $($issue.details)" } else { "" }
                        Write-Host ("      Issue  : {0}{1}" -f $issueName, $detail) -ForegroundColor $color
                    }
                }
                else {
                    Write-Host "      Issue  : (no issue detail available)" -ForegroundColor DarkGray
                }
            }
        }

        Write-Host ""
    }

    function Write-DisconnectedSection {
        param([array]$DisconnectedAssets)

        Write-Host "  DISCONNECTED ASSETS" -ForegroundColor White
        Write-Host ("  " + "-" * 68)

        if (-not $DisconnectedAssets -or $DisconnectedAssets.Count -eq 0) {
            Write-Host "  No disconnected assets detected." -ForegroundColor Green
        }
        else {
            Write-Host ("  Count: {0}" -f $DisconnectedAssets.Count) -ForegroundColor Yellow
            Write-Host ""
            foreach ($asset in ($DisconnectedAssets | Sort-Object DisplayName)) {
                Write-Host ("    {0}" -f $asset.DisplayName) -ForegroundColor White
                if ($asset.FQDN -and $asset.FQDN -ne $asset.DisplayName) {
                    Write-Host ("      FQDN            : {0}" -f $asset.FQDN) -ForegroundColor DarkGray
                }
                if ($asset.Domain) {
                    Write-Host ("      Domain          : {0}" -f $asset.Domain) -ForegroundColor DarkGray
                }
                $statusLabel = $script:HealthStatus[$asset.HealthStatus] ?? 'Unknown'
                Write-Host ("      Health Status   : {0}" -f $statusLabel) -ForegroundColor DarkGray
                if ($asset.LastDisconnectedAt) {
                    Write-Host ("      Last Disconnect : {0}" -f $asset.LastDisconnectedAt) -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
    }

    try {
        if (-not $IncludeDisconnected -and $IncludeDisconnectedDays -gt 0) {
            $IncludeDisconnected = $true
        }

        $key     = Get-ZNApiKey -ApiKey $ApiKey
        $baseUrl = Get-ZNApiBaseUrl -ApiKey $key -ApiUrl $ApiUrl
        $headers = Get-ZNApiHeaders -ApiKey $key

        Write-Log "Fetching system health..."
        $systemIssues = Get-SystemHealth -BaseUrl $baseUrl -Headers $headers

        Write-Log "Retrieving all assets..."
        $allAssets = Get-ZNAllAssets -BaseUrl $baseUrl -Headers $headers
        Write-Log "Total assets retrieved: $($allAssets.Count)"

        $excludeStatuses = if ($IncludeNA) { @(1) } else { @(1, 4) }
        $candidates = $allAssets | Where-Object {
            $status = $_.healthState.healthStatus
            $status -notin $excludeStatuses
        }

        Write-Log "Fetching detailed health state for $($candidates.Count) non-healthy asset(s)..."

        $unhealthyAssets = [System.Collections.Generic.List[object]]::new()
        $csvRows         = [System.Collections.Generic.List[object]]::new()

        foreach ($asset in $candidates) {
            $displayName  = $asset.name ?? $asset.fqdn ?? $asset.id
            $healthDetail = Get-AssetHealthState -BaseUrl $baseUrl -Headers $headers -AssetId $asset.id
            $statusCode   = if ($healthDetail) { $healthDetail.healthStatus } else { $asset.healthState.healthStatus }
            $issues       = if ($healthDetail) { $healthDetail.healthIssuesList } else { @() }

            $unhealthyAssets.Add([PSCustomObject]@{
                Id           = $asset.id
                DisplayName  = $displayName
                FQDN         = $asset.fqdn
                Domain       = $asset.domain
                HealthStatus = $statusCode
                Issues       = $issues
            })

            if ($ExportCsv) {
                if ($issues -and $issues.Count -gt 0) {
                    foreach ($issue in $issues) {
                        $csvRows.Add([PSCustomObject]@{
                            AssetName    = $displayName
                            FQDN         = $asset.fqdn
                            Domain       = $asset.domain
                            HealthStatus = $script:HealthStatus[$statusCode]
                            IssueCode    = $issue.issueCode
                            IssueName    = Get-IssueName -Code $issue.issueCode
                            IssueDetails = $issue.details
                        })
                    }
                }
                else {
                    $csvRows.Add([PSCustomObject]@{
                        AssetName    = $displayName
                        FQDN         = $asset.fqdn
                        Domain       = $asset.domain
                        HealthStatus = $script:HealthStatus[$statusCode]
                        IssueCode    = ''
                        IssueName    = ''
                        IssueDetails = ''
                    })
                }
            }
        }

        $disconnectedAssets = [System.Collections.Generic.List[object]]::new()
        if ($IncludeDisconnected) {
            Write-Log "Identifying disconnected assets..."
            foreach ($asset in (Get-ZNDisconnectedAsset -Assets $allAssets -MinDisconnectedDays $IncludeDisconnectedDays)) {
                $lastDiscDisplay = $asset.LastDisconnectedAt.ToString("yyyy-MM-dd HH:mm UTC")
                $disconnectedAssets.Add([PSCustomObject]@{
                    Id                 = $asset.Id
                    DisplayName        = $asset.DisplayName
                    FQDN               = $asset.FQDN
                    Domain             = $asset.Domain
                    HealthStatus       = $asset.HealthStatus
                    LastDisconnectedAt = $lastDiscDisplay
                })
                if ($ExportCsv) {
                    $csvRows.Add([PSCustomObject]@{
                        AssetName    = $asset.DisplayName
                        FQDN         = $asset.FQDN
                        Domain       = $asset.Domain
                        HealthStatus = $script:HealthStatus[$asset.HealthStatus] ?? 'Unknown'
                        IssueCode    = ''
                        IssueName    = 'Disconnected'
                        IssueDetails = "Since $lastDiscDisplay"
                    })
                }
            }
            Write-Log "Found $($disconnectedAssets.Count) disconnected asset(s)."
        }

        Write-SystemHealthSection -Issues $systemIssues
        if ($IncludeDisconnected) {
            Write-DisconnectedSection -DisconnectedAssets $disconnectedAssets
        }
        if ($unhealthyAssets.Count -eq 0) {
            Write-Host "  All assets are healthy." -ForegroundColor Green
            Write-Host ""
        }
        else {
            Write-AssetHealthSection -UnhealthyAssets $unhealthyAssets
        }

        if ($ExportCsv) {
            $csvRows | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
            Write-Log "Exported $($csvRows.Count) row(s) to $ExportCsv"
        }

    }
    catch {
        Write-Log "Script failed: $($_.Exception.Message)" -Level Error
        throw
    }
}
