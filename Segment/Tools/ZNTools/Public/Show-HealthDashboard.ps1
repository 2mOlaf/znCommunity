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
    .PARAMETER ThrottleLimit
        Max concurrent per-asset health-state lookups. Default 20. Lower this if the API
        starts rate-limiting on very large tenants.
    .PARAMETER DeploymentsClusterId
        Optional. Scope the whole report to one deployment cluster instead of the full tenant.
        Use Get-ZNSegmentCluster to look up a cluster's ID.
    .NOTES
        Author: Olaf Gradin
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl,
        [string]$ApiKey,
        [string]$ExportCsv,
        [switch]$IncludeNA,
        [switch]$IncludeDisconnected,
        [ValidateRange(0, 3650)]
        [int]$IncludeDisconnectedDays,
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 20,
        [string]$DeploymentsClusterId
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

        # /assets/monitored's healthStatus filter looked like a safe way to skip the full fetch
        # (verified an exact match on one tenant), but a second tenant disproved it: a
        # Not-Monitored asset (assetStatus 1) can still carry a real, non-N/A healthStatus from
        # before it stopped being monitored, and /assets/monitored excludes assetStatus 1
        # entirely — so the filtered fetch silently hid a real Error. A health dashboard can't
        # risk hiding a real problem for a speed win, so this always pulls the full population.
        Write-Log "Retrieving all assets..."
        $allAssets = Get-ZNAllAssets -BaseUrl $baseUrl -Headers $headers -DeploymentsClusterId $DeploymentsClusterId
        Write-Log "Total assets retrieved: $($allAssets.Count)"

        $excludeStatuses = if ($IncludeNA) { @(1) } else { @(1, 4) }
        $candidates = $allAssets | Where-Object { $_.healthState.healthStatus -notin $excludeStatuses }

        Write-Log "Fetching detailed health state for $($candidates.Count) non-healthy asset(s)..."

        # The bulk /assets list already carries healthStatus, but its healthIssuesList entries
        # come back with an empty 'details' string — the per-asset /health-state call is the only
        # way to get the actual remediation detail (e.g. which firewall profile, which port rule),
        # so this still has to be an N-call fan-out. Parallelized with a throttle to keep it fast
        # on tenants with thousands of non-healthy assets without hammering the API.
        $healthResults = $candidates | ForEach-Object -Parallel {
            $asset   = $_
            $baseUrl = $using:baseUrl
            $headers = $using:headers
            try {
                $response = Invoke-RestMethod -Uri "$baseUrl/assets/$($asset.id)/health-state" -Headers $headers -Method Get
                [PSCustomObject]@{ AssetId = $asset.id; HealthState = $response.healthState; ErrorMessage = $null }
            }
            catch {
                [PSCustomObject]@{ AssetId = $asset.id; HealthState = $null; ErrorMessage = $_.Exception.Message }
            }
        } -ThrottleLimit $ThrottleLimit

        $healthByAssetId = @{}
        foreach ($result in $healthResults) {
            $healthByAssetId[$result.AssetId] = $result.HealthState
            if ($result.ErrorMessage) {
                Write-Log "Failed to get health state for asset $($result.AssetId): $($result.ErrorMessage)" -Level Warning
            }
        }

        $unhealthyAssets = [System.Collections.Generic.List[object]]::new()
        $csvRows         = [System.Collections.Generic.List[object]]::new()

        foreach ($asset in $candidates) {
            $displayName  = $asset.name ?? $asset.fqdn ?? $asset.id
            $healthDetail = $healthByAssetId[$asset.id]
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
            # Same reasoning as above: /assets/monitored's assetDisconnectedSince filter excludes
            # Not-Monitored/Unmonitorable assets that can still carry real connection state
            # (confirmed ~0.7% of disconnected assets fell into that gap on a live tenant) — an
            # acceptable trade for the metrics-only Get-DisconnectedAssetMetric, but not here.
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
