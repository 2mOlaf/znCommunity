function Get-BG-AssetForest {
    <#
    .SYNOPSIS
        Returns AD forest and domain configuration with service account info from BreakGlass data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-AssetForest
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    if (-not $script:ZNForests) {
        Write-Warning "No forest configuration found in segmentedAssets.json."
        return
    }
    foreach ($forest in $script:ZNForests) {
        $allDomains = @($forest.PrimaryDomain) + @($forest.SecondaryDomains)
        Write-Host "`nForest: $($forest.PrimaryDomain.DomainDnsName)" -ForegroundColor Cyan
        $allDomains | ForEach-Object {
            $domain = $_
            $rows = @([PSCustomObject]@{
                Domain  = $domain.DomainDnsName
                User    = $domain.AdUserName
                OU      = '(all)'
                Primary = ($domain -eq $forest.PrimaryDomain)
            })
            if ($domain.OuCredentials) {
                foreach ($ou in $domain.OuCredentials) {
                    $rows += [PSCustomObject]@{
                        Domain  = $ou.DomainName
                        User    = $ou.UserName
                        OU      = $ou.OrganizationalUnit
                        Primary = $false
                    }
                }
            }
            $rows
        } | Format-Table -AutoSize
    }
}

function Get-BG-AssetSwitch {
    <#
    .SYNOPSIS
        Returns OT switches from the BreakGlass switches.json data.
    .DESCRIPTION
        Requires BreakGlass asset data to be loaded with Import-ZNBG-AssetData.
    .AUTHOR
        Olaf Gradin
    .EXAMPLE
        Get-ZNBG-AssetSwitch
    #>
    [CmdletBinding()]
    param()
    Assert-ZNAssetDataLoaded
    if ($script:ZNSwitches.Count -eq 0) {
        Write-Warning "No OT switches found (switches.json missing or empty)."
        return
    }
    $script:ZNSwitches
}
