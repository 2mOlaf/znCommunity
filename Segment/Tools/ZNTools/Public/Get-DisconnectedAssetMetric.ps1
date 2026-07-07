function Get-DisconnectedAssetMetric {
    <#
    .SYNOPSIS
        Reports disconnected ZN asset counts — overall and per deployment cluster — as a metric
        object suitable for feeding a time-series dashboard.

    .DESCRIPTION
        Uses the same disconnected-asset detection as Show-ZNHealthDashboard's -IncludeDisconnected
        section (shared private helpers Get-ZNAllAssets / Get-ZNDisconnectedAsset), but returns
        plain data instead of a console report — no banner, no progress logging — so scheduled/
        unattended runs produce clean output for a metrics pipeline to consume.

        Emits one row per deployment cluster (including "Unclustered" for assets with no cluster
        assigned) plus a final TOTAL row. Every known cluster gets a row on every run, even when
        its count is 0 — so a cluster's time series stays continuous instead of dropping out when
        it briefly has nothing disconnected.

    .PARAMETER ApiUrl
        Optional API base URL override.

    .PARAMETER ApiKey
        Optional API key override; defaults to ZN_API_KEY environment variable.

    .PARAMETER IncludeDisconnectedDays
        Only count assets disconnected for at least this many days. Default: 0 (any asset
        currently disconnected counts, regardless of how long). Same semantics as
        Show-ZNHealthDashboard's parameter of the same name — tune this to match what the
        customer considers "disconnected" for their dashboard.

    .EXAMPLE
        Get-ZNDisconnectedAssetMetric
        Returns one object per cluster plus a TOTAL row for all currently-disconnected assets.

    .EXAMPLE
        Get-ZNDisconnectedAssetMetric -IncludeDisconnectedDays 3
        Only counts assets disconnected for 3+ days — filters out brief blips.

    .EXAMPLE
        Get-ZNDisconnectedAssetMetric | Where-Object ClusterName -eq 'TOTAL' | Select-Object -ExpandProperty DisconnectedCount
        Extracts just the aggregate count, e.g. for a simple single-value metric push.

    .EXAMPLE
        Get-ZNDisconnectedAssetMetric -IncludeDisconnectedDays 1 | ConvertTo-Json
        Produces one JSON metric point per cluster (plus TOTAL) for a scheduled task to POST to a
        metrics endpoint.

    .NOTES
        This command intentionally skips the module's usual welcome/banner block — it's designed
        to run unattended on a schedule, and ASCII art in a metrics job's log is pure noise. On API
        failure it writes a terminating error and returns nothing rather than a fabricated zero —
        callers should treat a missing result as "no data point this run", not "zero disconnected".

    .AUTHOR
        Olaf Gradin
    #>
    [CmdletBinding()]
    param(
        [string]$ApiUrl,
        [string]$ApiKey,

        [ValidateRange(0, 3650)]
        [int]$IncludeDisconnectedDays = 0
    )

    try {
        $key     = Get-ZNApiKey -ApiKey $ApiKey
        $baseUrl = Get-ZNApiBaseUrl -ApiKey $key -ApiUrl $ApiUrl
        $headers = Get-ZNApiHeaders -ApiKey $key

        $allAssets = Get-ZNAllAssets -BaseUrl $baseUrl -Headers $headers
    }
    catch {
        Write-Error "Failed to retrieve assets: $($_.Exception.Message)"
        return
    }

    $timestamp   = Get-Date
    $disconnected = @(Get-ZNDisconnectedAsset -Assets $allAssets -MinDisconnectedDays $IncludeDisconnectedDays)

    $countByCluster = @{}
    foreach ($group in ($disconnected | Group-Object ClusterId)) {
        $countByCluster[$group.Name] = $group.Count
    }

    $clusters = $allAssets | Group-Object deploymentsClusterId | ForEach-Object {
        $sample = $_.Group[0]
        [PSCustomObject]@{
            ClusterId   = $_.Name
            ClusterName = if ($sample.deploymentsCluster -and $sample.deploymentsCluster.name) {
                $sample.deploymentsCluster.name
            } else { 'Unclustered' }
        }
    }

    $rows = foreach ($cluster in ($clusters | Sort-Object ClusterName)) {
        $count = if ($countByCluster.ContainsKey($cluster.ClusterId)) { $countByCluster[$cluster.ClusterId] } else { 0 }
        [PSCustomObject]@{
            Timestamp         = $timestamp
            ClusterId         = $cluster.ClusterId
            ClusterName       = $cluster.ClusterName
            DisconnectedCount = $count
            DaysThreshold     = $IncludeDisconnectedDays
        }
    }

    $rows
    [PSCustomObject]@{
        Timestamp         = $timestamp
        ClusterId         = $null
        ClusterName       = 'TOTAL'
        DisconnectedCount = $disconnected.Count
        DaysThreshold     = $IncludeDisconnectedDays
    }
}
