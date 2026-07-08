function Get-DisconnectedAssetMetric {
    <#
    .SYNOPSIS
        Reports disconnected ZN asset counts — overall and per deployment cluster — as a metric
        object suitable for feeding a time-series dashboard.

    .DESCRIPTION
        Uses the same disconnected-asset detection as Show-ZNHealthDashboard's -IncludeDisconnected
        section (shared private helpers Get-ZNMonitoredAssets / Get-ZNDisconnectedAsset), but
        returns plain data instead of a console report — no banner, no progress logging — so
        scheduled/unattended runs produce clean output for a metrics pipeline to consume.

        Fetches from /assets/monitored rather than the full /assets population — verified that
        every cluster/monitor-type bucket this command reports is already represented among
        monitored assets, so nothing goes missing from the per-cluster breakdown. This does
        exclude a small number of Not-Monitored/Unmonitorable assets that still carry stale
        connection state (~0.7% of disconnected assets on a 7.7k-asset test tenant) — accepted
        deliberately, since an asset ZN isn't monitoring isn't actionable from this metric anyway.

        Emits one row per deployment cluster plus a final TOTAL row. Assets with no Segment Server
        deployment cluster (e.g. Cloud Connector- or Lightweight Agent-monitored assets, which are
        never routed through a customer-run Segment Server) get their own "Unclustered (<monitor
        type>)" row per monitoring mechanism — see Get-ZNAssetClusterLabel — rather than a single
        opaque "Unclustered" bucket that hides which mechanism is actually disconnecting. Every
        known cluster/monitor-type combination gets a row on every run, even when its count is 0 —
        so a series stays continuous instead of dropping out when it briefly has nothing disconnected.

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

        $allAssets = Get-ZNMonitoredAssets -BaseUrl $baseUrl -Headers $headers
    }
    catch {
        Write-Error "Failed to retrieve assets: $($_.Exception.Message)"
        return
    }

    $timestamp   = Get-Date
    $disconnected = @(Get-ZNDisconnectedAsset -Assets $allAssets -MinDisconnectedDays $IncludeDisconnectedDays)

    $countByCluster = @{}
    foreach ($group in ($disconnected | Group-Object ClusterName)) {
        $countByCluster[$group.Name] = $group.Count
    }

    $clusters = $allAssets | ForEach-Object {
        [PSCustomObject]@{
            ClusterId   = $_.deploymentsClusterId
            ClusterName = Get-ZNAssetClusterLabel -Asset $_
        }
    } | Group-Object ClusterName | ForEach-Object {
        [PSCustomObject]@{
            ClusterId   = $_.Group[0].ClusterId
            ClusterName = $_.Name
        }
    }

    $rows = foreach ($cluster in ($clusters | Sort-Object ClusterName)) {
        $count = if ($countByCluster.ContainsKey($cluster.ClusterName)) { $countByCluster[$cluster.ClusterName] } else { 0 }
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
