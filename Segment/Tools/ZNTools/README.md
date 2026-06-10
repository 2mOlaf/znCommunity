# ZNTools

Unified Zero Networks tooling module — health, clusters, Linux profiles, networking, asset browser, service management, and AD-to-ZN identity sync.

## Quick start
```powershell
Import-Module .\ZNTools\ZNTools.psd1
```

## Authentication
By default, the module uses the `ZN_API_KEY` environment variable (JWT). You can override this per command:
- `-ApiKey` to supply a different token
- `-ApiUrl` to force a specific API base URL (e.g. `https://portal.zeronetworks.com/api/v1`)

API-backed commands require a valid key. Asset browser commands work offline from local JSON files.

## Commands (exported with DefaultCommandPrefix = `ZN`)

### Networking
- `Test-ZNPort -Computer <host> -Port <int> [-Continuous] [-PreferIPv4]`

### Linux Profiles
- `Get-ZNLinuxProfile`

### Segment Clusters
- `Get-ZNSegmentCluster`

### Health Dashboard
- `Show-ZNHealthDashboard [-IncludeDisconnected] [-ExportCsv <path>]`

### Security Events
Queries the Security event log for Windows Filtering Platform (WFP) events, locally or on a remote Segment Server.
- `Get-ZNSecurityEventRate -Period <period>` — local machine
- `Get-ZNSecurityEventRate -Period <period> -ComputerName <host>` — remote via WinRM (current identity)
- `Get-ZNSecurityEventRate -Period <period> -ComputerName <host> -Credential $cred` — remote with explicit credential

Period format: a positive integer followed by `h` (hours) or `d` (days) — e.g. `1h`, `4h`, `1d`, `7d`.
All computation runs on the target machine; only the final numbers are returned across the wire.

### Service Management
Manages all `zn*` services as a group.
- `Invoke-ZNServices -Action <Stop|Start|Restart>` — local machine (requires Administrator)
- `Invoke-ZNServices -Action <action> -ComputerName <host>` — single remote Segment Server via PSRemoting
- `Invoke-ZNServices -Action <action> -AllServers [-ClusterName <name>]` — all Segment Servers via API

### Identity Sync
Syncs disabled AD accounts to inactive status in ZN. One-directional: AD disabled → ZN inactive.
Requires the `ActiveDirectory` module (RSAT) and a ZN API key with write scope.

- `Sync-ZNADUserStatus -WhatIf` — preview which users would be inactivated
- `Sync-ZNADUserStatus -Domain corp.example.com -Note "Q2 offboarding"` — live sync with audit note
- `Sync-ZNADUserStatus -PassThru | Where-Object Action -eq 'Inactivated' | Export-Csv offboarded.csv` — pipe results

Matching uses SID (primary) then UPN (fallback). The ZN audit comment per user records the AD
`whenChanged` timestamp — the closest proxy AD provides for a disable date — plus any `-Note` text.

### BreakGlass Asset Browser
Offline queries against the BreakGlass `segmentedAssets.json` snapshot. Run `Import-ZNBG-AssetData` first.
This is useful to browse a segmentedAssets.json with something more than just a ConvertFrom-JSON command.
The `BG` noun qualifier distinguishes these commands from API-backed commands.

```powershell
Import-ZNBG-AssetData                           # loads segmentedAssets.json and switches.json
Import-ZNBG-AssetData -DataPath .\export.json   # custom path

Get-ZNBG-AssetSummary                           # total counts
Get-ZNBG-Asset                                  # all assets as objects — pipe freely
Find-ZNBG-Asset "dc01"                          # search by partial FQDN

Get-ZNBG-WindowsAsset                           # filter by OS
Get-ZNBG-LinuxAsset
Get-ZNBG-ServerAsset                            # filter by type
Get-ZNBG-ClientAsset

Get-ZNBG-NetworkSegmentedAsset                  # segmentation state
Get-ZNBG-IdentitySegmentedAsset

Get-ZNBG-AssetCluster                           # cluster breakdown
Get-ZNBG-ClusterMemberAsset "zero.local"        # assets in a specific cluster

Get-ZNBG-AssetForest                            # AD forest / domain / service account config
Get-ZNBG-AssetSwitch                            # OT switches from switches.json
Get-ZNBG-AssetBySource                          # counts by entity source (AD, Ansible, etc.)
```

All query functions return objects. Pipe freely:
```powershell
Get-ZNBG-Asset | Where-Object { $_.OS -eq 'Linux' -and $_.NetworkSegmented }
Get-ZNBG-ServerAsset | Group-Object Cluster | Select-Object Name, Count
Get-ZNBG-Asset | Export-Csv assets.csv -NoTypeInformation
```

## Notes
- The module displays a quick-start summary once per session on import or first use.
- Entry-point commands display the banner with author and command name.
- HTML docs: `breakglass/docs/zntools-user-reference.html` (users) and `breakglass/docs/zntools-author-reference.html` (authors).
