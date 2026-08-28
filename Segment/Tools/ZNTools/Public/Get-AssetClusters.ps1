function Get-BGAssetCluster {
    <#
    .SYNOPSIS
        Returns all asset clusters from BreakGlass data with per-cluster asset counts and segmentation breakdown.
    .DESCRIPTION
        Queries the locally-loaded BreakGlass asset data. This is distinct from Get-ZNSegmentCluster,
        which queries the Zero Networks API for Segment Server infrastructure clusters.

        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGAssetCluster | Sort-Object TotalAssets -Descending
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Group-Object ClusterId | ForEach-Object {
        $id = $_.Name
        [PSCustomObject]@{
            ClusterName   = $script:ZNClusterMap[$id] ?? $id
            ClusterId     = $id
            TotalAssets   = $_.Count
            Windows       = ($_.Group | Where-Object osType -eq 2).Count
            Linux         = ($_.Group | Where-Object osType -eq 3).Count
            Servers       = ($_.Group | Where-Object type -eq 2).Count
            Clients       = ($_.Group | Where-Object type -eq 1).Count
            NetSegmented  = ($_.Group | Where-Object IsNetworkSegmented -eq $true).Count
            IdSegmented   = ($_.Group | Where-Object IsIdentitySegmented -eq $true).Count
        }
    } | Sort-Object TotalAssets -Descending
}

function Get-BGClusterMemberAsset {
    <#
    .SYNOPSIS
        Returns BreakGlass assets belonging to a specific cluster. Partial name match, case-insensitive.
    .PARAMETER ClusterName
        Cluster name to match (partial, case-insensitive).
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGClusterMemberAsset "zero.local"
    .EXAMPLE
        Get-ZNBGClusterMemberAsset "zero.local" | Where-Object OS -eq Linux
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ClusterName
    )
    Assert-ZNAssetDataLoaded
    $matchedIds = $script:ZNClusterMap.Keys | Where-Object { $script:ZNClusterMap[$_] -ilike "*$ClusterName*" }
    if (-not $matchedIds) {
        Write-Warning "No cluster matching '$ClusterName'. Run Get-ZNBGAssetCluster to see available clusters."
        return
    }
    $script:ZNAssets | Where-Object ClusterId -in $matchedIds | ConvertTo-EnrichedAsset
}
