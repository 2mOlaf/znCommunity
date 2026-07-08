function Get-ZNPagedAssets {
    <#
    .SYNOPSIS
        Cursor-pages through any ZN assets-shaped list endpoint, with optional server-side filters.
    .DESCRIPTION
        Shared plumbing behind Get-ZNAllAssets and Get-ZNMonitoredAssets.

        Uses cursor-based paging (_cursor/nextCursor) rather than _offset. Offset paging drifts
        when the asset list is added to or removed from between page fetches — on a tenant with
        thousands of assets that drift produced duplicate entries across pages (observed ~9%
        duplication on a 7.7k-asset tenant). The cursor is stable against concurrent list changes.

        Filters use the same _filters JSON contract the portal UI sends (confirmed against the
        live API, not documented with a concrete schema in the OpenAPI spec beyond "JSON string
        URI encoded set of filters"): an array of { id, includeValues, excludeValues }. Selection
        values for enum-typed filters (e.g. healthStatus) must be strings, not raw numbers — the
        API rejects numeric values with a "not supported in filter" error.
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$Path,

        [array]$Filters
    )

    $filterQuery = ''
    if ($Filters -and $Filters.Count -gt 0) {
        # -AsArray double-wraps a List[hashtable] (it's not the bare single-element PS array the
        # switch is meant for), and the default -Depth 2 silently flattens includeValues/
        # excludeValues into space-joined strings instead of JSON arrays. Neither shows up as an
        # error — the API just replies "filter id: undefined is not supported".
        $filterJson = ConvertTo-Json -InputObject $Filters -Compress -Depth 5
        $filterQuery = "&_filters=" + [System.Uri]::EscapeDataString($filterJson)
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $limit   = 400
    $cursor  = $null

    do {
        $uri = "$BaseUrl/$Path`?_limit=$limit$filterQuery"
        if ($cursor) { $uri += "&_cursor=$cursor" }
        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get

        if (-not $response.items -or $response.items.Count -eq 0) { break }

        foreach ($item in $response.items) { $results.Add($item) }

        if ($response.items.Count -lt $limit -or -not $response.nextCursor) { break }
        $cursor = $response.nextCursor
    } while ($true)

    return $results
}

function Get-ZNAllAssets {
    <#
    .SYNOPSIS
        Fetches every asset (monitored or not) from the ZN API, optionally scoped to one cluster.
    .DESCRIPTION
        Used where the full asset population is genuinely required — e.g. Show-HealthDashboard's
        -IncludeNA path, which needs to see Not-Monitored assets that /assets/monitored excludes
        by definition.
    .PARAMETER DeploymentsClusterId
        Optional. Scope to a single deployment cluster (see Get-ZNSegmentCluster for IDs).
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [string]$DeploymentsClusterId
    )

    $filters = [System.Collections.Generic.List[hashtable]]::new()
    if ($DeploymentsClusterId) {
        $filters.Add(@{ id = 'deploymentsClusterId'; includeValues = @($DeploymentsClusterId); excludeValues = @() })
    }

    Get-ZNPagedAssets -BaseUrl $BaseUrl -Headers $Headers -Path 'assets' -Filters $filters
}

function Get-ZNMonitoredAssets {
    <#
    .SYNOPSIS
        Fetches all actively-monitored assets from /assets/monitored.
    .DESCRIPTION
        Used by Get-DisconnectedAssetMetric instead of the full /assets population.
        /assets/monitored excludes assetStatus 1 "Not Monitored" and similar unmonitorable
        statuses, roughly halving the fetch on a typical tenant. Verified that every
        cluster/monitor-type bucket Get-DisconnectedAssetMetric reports is still represented
        among monitored assets, so no cluster silently drops from the per-cluster breakdown —
        this does exclude a small number of Not-Monitored/Unmonitorable assets that still carry
        stale connection state (~0.7% of disconnected assets on a 7.7k-asset test tenant),
        accepted deliberately since an asset ZN isn't monitoring isn't actionable from this
        metric anyway.

        Do not reuse this for anything that needs full correctness, like Show-HealthDashboard: a
        Not-Monitored asset can still carry a real, non-N/A health status left over from before
        it stopped being monitored (confirmed on a live tenant), and this endpoint would silently
        hide it. This function intentionally has no health-status/disconnected/cluster filter
        options for that reason — it exists to fetch the full monitored-only population, not a
        server-side-filtered subset.
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    Get-ZNPagedAssets -BaseUrl $BaseUrl -Headers $Headers -Path 'assets/monitored'
}

function Get-ZNAssetClusterLabel {
    <#
    .SYNOPSIS
        Resolves the deployment-cluster display label for a single ZN API asset object.
    .DESCRIPTION
        Shared by Get-ZNDisconnectedAsset and Get-ZNDisconnectedAssetMetric so both commands
        bucket assets into clusters identically.

        Assets assigned to a Segment Server deployment carry a deploymentsCluster.name and get
        that name back verbatim. Assets with no deployment cluster aren't necessarily broken —
        per the assetStatus enum (see OpenAPI schema), assetStatus 7 is "Cloud Connector":
        cloud-native assets that Zero Networks monitors via the cloud provider's API rather than
        routing through a customer-run Segment Server, so they never get a deploymentsClusterId.
        assetStatus 14 ("Lightweight Agent") is similarly agent-direct rather than cluster-routed.
        Rather than lumping all of these into one opaque "Unclustered" bucket, the label is
        qualified with $script:AssetMonitorType so each monitoring mechanism gets its own row.
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [Parameter(Mandatory)]
        [object]$Asset
    )

    if ($Asset.deploymentsCluster -and $Asset.deploymentsCluster.name) {
        return $Asset.deploymentsCluster.name
    }

    $monitorType = $script:AssetMonitorType[$Asset.assetStatus] ?? 'Connector'
    "Unclustered ($monitorType)"
}

function Get-ZNDisconnectedAsset {
    <#
    .SYNOPSIS
        Filters a list of ZN API asset objects down to those currently disconnected.
    .DESCRIPTION
        Shared by Show-HealthDashboard and Get-DisconnectedAssetMetric. An asset counts as
        disconnected when state.isAssetConnected is false and it has a lastDisconnectedAt
        timestamp. -MinDisconnectedDays optionally restricts to assets disconnected for at
        least that many days (0 = no minimum — any currently-disconnected asset qualifies).

        Includes deployment cluster (ClusterId/ClusterName) on each result via
        Get-ZNAssetClusterLabel — no separate cluster lookup call is needed. ClusterName for
        assets with no Segment Server cluster is qualified by monitoring mechanism (e.g.
        "Unclustered (Cloud Connector)") rather than a single flat "Unclustered" bucket.
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Assets,

        [ValidateRange(0, 3650)]
        [int]$MinDisconnectedDays = 0
    )

    $minDisconnectedAt = if ($MinDisconnectedDays -gt 0) {
        (Get-Date).ToUniversalTime().AddDays(-$MinDisconnectedDays)
    } else { $null }

    $candidates = $Assets | Where-Object { $_.state -and $_.state.isAssetConnected -eq $false -and $_.state.lastDisconnectedAt }

    foreach ($asset in $candidates) {
        $lastDisc = try {
            [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddMilliseconds($asset.state.lastDisconnectedAt)
        } catch { $null }

        if (-not $lastDisc -or ($minDisconnectedAt -and $lastDisc -gt $minDisconnectedAt)) { continue }

        [PSCustomObject]@{
            Id                 = $asset.id
            DisplayName        = $asset.name ?? $asset.fqdn ?? $asset.id
            FQDN               = $asset.fqdn
            Domain             = $asset.domain
            HealthStatus       = $asset.healthState.healthStatus
            LastDisconnectedAt = $lastDisc
            ClusterId          = $asset.deploymentsClusterId
            ClusterName        = Get-ZNAssetClusterLabel -Asset $asset
            AssetStatus        = $asset.assetStatus
            MonitorType        = $script:AssetMonitorType[$asset.assetStatus] ?? 'Unknown'
        }
    }
}
