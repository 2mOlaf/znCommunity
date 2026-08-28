function Import-BGAssetData {
    <#
    .SYNOPSIS
        Loads segmented asset and OT switch data from BreakGlass JSON files into the ZNTools session.
    .DESCRIPTION
        Reads segmentedAssets.json and (optionally) switches.json — files maintained by the Zero Networks
        BreakGlass installation — into module state. After loading, use Get-ZNBGAsset,
        Find-ZNBGAsset, Get-ZNBGAssetSummary, and related commands to query the data
        without further API calls.

        Re-run Import-ZNBGAssetData to refresh after segmentedAssets.json has been updated.
    .PARAMETER DataPath
        Path to segmentedAssets.json. Defaults to the BreakGlass installation directory.
    .PARAMETER SwitchesPath
        Path to switches.json. Defaults to the BreakGlass installation directory.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Import-ZNBGAssetData
        Loads from the default BreakGlass installation path.
    .EXAMPLE
        Import-ZNBGAssetData -DataPath ".\segmentedAssets.json"
        Loads from the current directory.
    #>
    [CmdletBinding()]
    param(
        [string]$DataPath    = "C:\Program Files\Zero Networks\Breakglass\segmentedAssets.json",
        [string]$SwitchesPath = "C:\Program Files\Zero Networks\Breakglass\switches.json"
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    if (-not (Test-Path $DataPath)) {
        Write-Error "segmentedAssets.json not found at $DataPath"
        return
    }

    $raw = Get-Content $DataPath | ConvertFrom-Json
    $script:ZNAssets  = $raw.segmentedAssets
    $script:ZNForests = $raw.ForestsConfig

    $script:ZNClusterMap = @{}
    $raw.ClusterIdToName.PSObject.Properties | ForEach-Object {
        $script:ZNClusterMap[$_.Name] = $_.Value
    }

    $script:ZNSwitches = @()
    if (Test-Path $SwitchesPath) {
        $script:ZNSwitches = (Get-Content $SwitchesPath | ConvertFrom-Json).Switches
    }

    Write-Host "Loaded $($script:ZNAssets.Count) segmented assets across $($script:ZNClusterMap.Count) cluster(s)." -ForegroundColor Green
    if ($script:ZNSwitches.Count -gt 0) {
        Write-Host "Loaded $($script:ZNSwitches.Count) OT switch(es)." -ForegroundColor Green
    }
    Write-Host "Use Get-ZNBGAsset, Find-ZNBGAsset, Get-ZNBGAssetSummary, and more to explore the data." -ForegroundColor DarkGray
    Write-Host "Pipe freely — all query functions return objects." -ForegroundColor DarkGray
}
