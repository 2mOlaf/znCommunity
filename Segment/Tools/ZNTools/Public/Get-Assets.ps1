function Get-BG-AssetSummary {
    <#
    .SYNOPSIS
        Returns high-level BreakGlass asset counts: total, OS breakdown, type, segmentation, clusters.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-AssetSummary
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $a = $script:ZNAssets
    [PSCustomObject]@{
        'Total assets'        = $a.Count
        'Windows'             = ($a | Where-Object osType -eq 2).Count
        'Linux'               = ($a | Where-Object osType -eq 3).Count
        'Servers'             = ($a | Where-Object type -eq 2).Count
        'Clients'             = ($a | Where-Object type -eq 1).Count
        'Network segmented'   = ($a | Where-Object IsNetworkSegmented -eq $true).Count
        'Identity segmented'  = ($a | Where-Object IsIdentitySegmented -eq $true).Count
        'Clusters'            = $script:ZNClusterMap.Count
        'AD forests'          = @($script:ZNForests).Count
        'OT switches'         = $script:ZNSwitches.Count
    } | Format-List
}

function Get-BG-Asset {
    <#
    .SYNOPSIS
        Returns all BreakGlass segmented assets as objects. Pipe freely.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-Asset | Where-Object { $_.OS -eq 'Linux' -and $_.NetworkSegmented }
    .EXAMPLE
        Get-ZNBG-Asset | Sort-Object Cluster | Format-Table -AutoSize
    .EXAMPLE
        Get-ZNBG-Asset | Export-Csv assets.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | ConvertTo-EnrichedAsset
}

function Find-BG-Asset {
    <#
    .SYNOPSIS
        Finds BreakGlass assets by partial FQDN or hostname match (case-insensitive).
    .PARAMETER Name
        Partial FQDN or hostname to search for.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Find-ZNBG-Asset "dc01"
    .EXAMPLE
        Find-ZNBG-Asset "contoso" | Select-Object FQDN, Cluster, NetworkSegmented
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    Assert-ZNAssetDataLoaded
    $results = $script:ZNAssets | Where-Object { $_.Fqdn -ilike "*$Name*" } | ConvertTo-EnrichedAsset
    if (-not $results) {
        Write-Warning "No assets matching '$Name'."
        return
    }
    $results
}

function Get-BG-WindowsAsset {
    <#
    .SYNOPSIS
        Returns all Windows assets from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-WindowsAsset | Where-Object Type -eq Server
    .EXAMPLE
        Get-ZNBG-WindowsAsset | Group-Object Cluster | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object osType -eq 2 | ConvertTo-EnrichedAsset
}

function Get-BG-LinuxAsset {
    <#
    .SYNOPSIS
        Returns all Linux assets from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-LinuxAsset | Where-Object NetworkSegmented
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object osType -eq 3 | ConvertTo-EnrichedAsset
}

function Get-BG-ServerAsset {
    <#
    .SYNOPSIS
        Returns all server-type assets (Windows and Linux) from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-ServerAsset | Group-Object OS | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object type -eq 2 | ConvertTo-EnrichedAsset
}

function Get-BG-ClientAsset {
    <#
    .SYNOPSIS
        Returns all client/workstation-type assets from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-ClientAsset | Group-Object Cluster | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object type -eq 1 | ConvertTo-EnrichedAsset
}

function Get-BG-NetworkSegmentedAsset {
    <#
    .SYNOPSIS
        Returns assets with network segmentation currently active from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-NetworkSegmentedAsset | Group-Object OS | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object IsNetworkSegmented -eq $true | ConvertTo-EnrichedAsset
}

function Get-BG-IdentitySegmentedAsset {
    <#
    .SYNOPSIS
        Returns assets with identity segmentation currently active from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-IdentitySegmentedAsset | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object IsIdentitySegmented -eq $true | ConvertTo-EnrichedAsset
}

function Get-BG-AssetBySource {
    <#
    .SYNOPSIS
        Returns asset counts grouped by entity source (Active Directory, Ansible, Workgroup, etc.).
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-AssetBySource
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Group-Object entitySource | ForEach-Object {
        [PSCustomObject]@{
            Source     = $script:EntitySourceMap[[int]$_.Name] ?? "Unknown ($($_.Name))"
            AssetCount = $_.Count
            Servers    = ($_.Group | Where-Object type -eq 2).Count
            Clients    = ($_.Group | Where-Object type -eq 1).Count
        }
    } | Sort-Object AssetCount -Descending
}
