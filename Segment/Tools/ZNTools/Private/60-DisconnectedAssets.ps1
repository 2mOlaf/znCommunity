function Get-ZNAllAssets {
    <#
    .SYNOPSIS
        Fetches every asset from the ZN API, paging through results.
    .DESCRIPTION
        Shared by Show-HealthDashboard and Get-DisconnectedAssetMetric so both commands fetch
        the asset list the same way.
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $allAssets = [System.Collections.Generic.List[object]]::new()
    $offset    = 0
    $limit     = 400

    do {
        $uri      = "$BaseUrl/assets?_limit=$limit&_offset=$offset"
        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get

        if ($response.items -and $response.items.Count -gt 0) {
            foreach ($item in $response.items) { $allAssets.Add($item) }
            $offset += $response.items.Count
            if ($response.items.Count -lt $limit) { break }
        }
        else { break }
    } while ($true)

    return $allAssets
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

    $monitorType = $script:AssetMonitorType[$Asset.assetStatus] ?? 'Unknown'
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
