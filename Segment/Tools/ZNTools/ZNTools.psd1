@{
    RootModule = 'ZNTools.psm1'
    ModuleVersion = '1.1.0'
    GUID = '1b2c56a5-5f1c-4bf1-9e6f-0b2a3b0e0f52'
    Author = 'Olaf Gradin'
    CompanyName = 'Zero Networks'
    Description = 'Unified Zero Networks tooling module (health, clusters, Linux profiles, networking, asset browser, service management).'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        # API-backed commands
        'Test-Port', 'Get-LinuxProfile', 'Get-SegmentCluster', 'Show-HealthDashboard',
        # Service management
        'Invoke-Services',
        # BreakGlass asset browser — load data first with Import-BG-AssetData
        'Import-BG-AssetData',
        'Get-BG-AssetSummary', 'Get-BG-Asset', 'Find-BG-Asset',
        'Get-BG-WindowsAsset', 'Get-BG-LinuxAsset', 'Get-BG-ServerAsset', 'Get-BG-ClientAsset',
        'Get-BG-NetworkSegmentedAsset', 'Get-BG-IdentitySegmentedAsset', 'Get-BG-AssetBySource',
        'Get-BG-AssetCluster', 'Get-BG-ClusterMemberAsset',
        'Get-BG-AssetForest', 'Get-BG-AssetSwitch'
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
