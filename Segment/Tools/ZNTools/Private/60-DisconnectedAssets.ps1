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

function Get-ZNDisconnectedAsset {
    <#
    .SYNOPSIS
        Filters a list of ZN API asset objects down to those currently disconnected.
    .DESCRIPTION
        Shared by Show-HealthDashboard and Get-DisconnectedAssetMetric. An asset counts as
        disconnected when state.isAssetConnected is false and it has a lastDisconnectedAt
        timestamp. -MinDisconnectedDays optionally restricts to assets disconnected for at
        least that many days (0 = no minimum — any currently-disconnected asset qualifies).

        Includes deployment cluster (ClusterId/ClusterName) on each result, read directly off
        the asset's deploymentsClusterId / deploymentsCluster.name fields — no separate cluster
        lookup call is needed.
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

        $clusterName = if ($asset.deploymentsCluster -and $asset.deploymentsCluster.name) {
            $asset.deploymentsCluster.name
        } else { 'Unclustered' }

        [PSCustomObject]@{
            Id                 = $asset.id
            DisplayName        = $asset.name ?? $asset.fqdn ?? $asset.id
            FQDN               = $asset.fqdn
            Domain             = $asset.domain
            HealthStatus       = $asset.healthState.healthStatus
            LastDisconnectedAt = $lastDisc
            ClusterId          = $asset.deploymentsClusterId
            ClusterName        = $clusterName
        }
    }
}
