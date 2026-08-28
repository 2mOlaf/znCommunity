function Get-BGAssetSummary {
    <#
    .SYNOPSIS
        Returns high-level BreakGlass asset counts: total, OS breakdown, type, segmentation, clusters.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGAssetSummary
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

function Get-BGAsset {
    <#
    .SYNOPSIS
        Returns all BreakGlass segmented assets as objects. Pipe freely.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGAsset | Where-Object { $_.OS -eq 'Linux' -and $_.NetworkSegmented }
    .EXAMPLE
        Get-ZNBGAsset | Sort-Object Cluster | Format-Table -AutoSize
    .EXAMPLE
        Get-ZNBGAsset | Export-Csv assets.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | ConvertTo-EnrichedAsset
}

function Find-BGAsset {
    <#
    .SYNOPSIS
        Finds BreakGlass assets by partial FQDN or hostname match (case-insensitive).
    .PARAMETER Name
        Partial FQDN or hostname to search for.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Find-ZNBGAsset "dc01"
    .EXAMPLE
        Find-ZNBGAsset "contoso" | Select-Object FQDN, Cluster, NetworkSegmented
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

function Get-BGWindowsAsset {
    <#
    .SYNOPSIS
        Returns all Windows assets from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGWindowsAsset | Where-Object Type -eq Server
    .EXAMPLE
        Get-ZNBGWindowsAsset | Group-Object Cluster | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object osType -eq 2 | ConvertTo-EnrichedAsset
}

function Get-BGLinuxAsset {
    <#
    .SYNOPSIS
        Returns all Linux assets from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGLinuxAsset | Where-Object NetworkSegmented
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object osType -eq 3 | ConvertTo-EnrichedAsset
}

function Get-BGServerAsset {
    <#
    .SYNOPSIS
        Returns all server-type assets (Windows and Linux) from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGServerAsset | Group-Object OS | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object type -eq 2 | ConvertTo-EnrichedAsset
}

function Get-BGClientAsset {
    <#
    .SYNOPSIS
        Returns all client/workstation-type assets from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGClientAsset | Group-Object Cluster | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object type -eq 1 | ConvertTo-EnrichedAsset
}

function Get-BGNetworkSegmentedAsset {
    <#
    .SYNOPSIS
        Returns assets with network segmentation currently active from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGNetworkSegmentedAsset | Group-Object OS | Select-Object Name, Count
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object IsNetworkSegmented -eq $true | ConvertTo-EnrichedAsset
}

function Get-BGIdentitySegmentedAsset {
    <#
    .SYNOPSIS
        Returns assets with identity segmentation currently active from the BreakGlass asset data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGIdentitySegmentedAsset | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    $script:ZNAssets | Where-Object IsIdentitySegmented -eq $true | ConvertTo-EnrichedAsset
}

function Get-BGAssetBySource {
    <#
    .SYNOPSIS
        Returns asset counts grouped by entity source (Active Directory, Ansible, Workgroup, etc.).
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBGAssetData.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Get-ZNBGAssetBySource
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
