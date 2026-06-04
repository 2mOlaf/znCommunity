# Module state for asset browser data (loaded via Import-ZNAssetData)
$script:ZNAssets     = @()
$script:ZNSwitches   = @()
$script:ZNClusterMap = @{}
$script:ZNForests    = @()

$script:EntitySourceMap = @{
    3  = 'Active Directory'
    6  = 'Ansible'
    7  = 'OT'
    8  = 'Workgroup'
    9  = 'Azure AD'
    15 = 'Manual (Linux)'
}

$script:AssetTypeMap = @{
    1 = 'Client'
    2 = 'Server'
}

$script:OsTypeMap = @{
    2 = 'Windows'
    3 = 'Linux'
}

function Assert-ZNAssetDataLoaded {
    if ($script:ZNAssets.Count -eq 0) {
        throw "No asset data loaded. Run Import-ZNAssetData first."
    }
}

function ConvertTo-EnrichedAsset {
    param([Parameter(ValueFromPipeline)] $Asset)
    process {
        [PSCustomObject]@{
            FQDN              = $Asset.Fqdn
            Cluster           = $script:ZNClusterMap[$Asset.ClusterId] ?? $Asset.ClusterId
            ClusterId         = $Asset.ClusterId
            OS                = $script:OsTypeMap[[int]$Asset.osType] ?? "Unknown ($($Asset.osType))"
            Type              = $script:AssetTypeMap[[int]$Asset.type] ?? "Unknown ($($Asset.type))"
            Source            = $script:EntitySourceMap[[int]$Asset.entitySource] ?? "Unknown ($($Asset.entitySource))"
            NetworkSegmented  = $Asset.IsNetworkSegmented
            IdentitySegmented = $Asset.IsIdentitySegmented
            OU                = $Asset.OrganizationalUnit
        }
    }
}
