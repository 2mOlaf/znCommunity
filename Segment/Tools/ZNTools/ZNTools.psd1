@{
    RootModule = 'ZNTools.psm1'
    ModuleVersion = '1.3.0'
    GUID = '1b2c56a5-5f1c-4bf1-9e6f-0b2a3b0e0f52'
    Author = 'Olaf Gradin'
    CompanyName = 'Zero Networks'
    Description = 'Unified Zero Networks tooling module (health, clusters, Linux profiles, networking, security event rates, asset browser, service management, identity sync).'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        # API-backed commands
        'Test-Port', 'Get-LinuxProfile', 'Get-SegmentCluster', 'Show-HealthDashboard',
        # Security event log
        'Get-SecurityEventRate',
        # Service management
        'Invoke-Services',
        # Identity sync
        'Sync-ADUserStatus',
        # BreakGlass asset browser — load data first with Import-ZNBGAssetData
        'Import-BGAssetData',
        'Get-BGAssetSummary', 'Get-BGAsset', 'Find-BGAsset',
        'Get-BGWindowsAsset', 'Get-BGLinuxAsset', 'Get-BGServerAsset', 'Get-BGClientAsset',
        'Get-BGNetworkSegmentedAsset', 'Get-BGIdentitySegmentedAsset', 'Get-BGAssetBySource',
        'Get-BGAssetCluster', 'Get-BGClusterMemberAsset',
        'Get-BGAssetForest', 'Get-BGAssetSwitch'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    DefaultCommandPrefix = 'ZN'
    PrivateData = @{
        PSData = @{
            Tags = @('ZeroNetworks', 'Networking', 'Health', 'PowerShell')
        }
    }
}
