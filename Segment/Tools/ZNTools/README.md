# ZNTools

Unified Zero Networks tooling module — health, clusters, Linux profiles, networking, security event rates and log analysis, asset browser, service management, and AD-to-ZN identity sync.

## Quick start

Install directly from GitHub (PowerShell 7+):
```powershell
irm https://raw.githubusercontent.com/2mOlaf/znCommunity/feature/zntools/Segment/Tools/ZNTools/install.ps1 | iex
Import-Module ZNTools
```

Or from a local clone:
```powershell
Import-Module .\ZNTools\ZNTools.psd1
```

To install from a different fork/branch (e.g. the upstream repo once merged):
```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/2mOlaf/znCommunity/feature/zntools/Segment/Tools/ZNTools/install.ps1))) -Repo zeronetworks/Community -Branch master
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

### Disconnected Asset Metric
Quiet, scriptable counterpart to `-IncludeDisconnected` above — no banner, no progress logging —
meant to run unattended on a schedule and feed a time-series dashboard.
- `Get-ZNDisconnectedAssetMetric` — one row per deployment cluster (plus a `TOTAL` row), each with
  `Timestamp`, `ClusterId`, `ClusterName`, `DisconnectedCount`, `DaysThreshold`
- `Get-ZNDisconnectedAssetMetric -IncludeDisconnectedDays 3` — only count assets disconnected 3+ days
- `Get-ZNDisconnectedAssetMetric | ConvertTo-Json` — one JSON metric point per cluster, for a
  scheduled task to push to a metrics endpoint

Every known cluster gets a row every run, even at count `0`, so a cluster's series stays
continuous instead of dropping out. On API failure it writes an error and returns nothing rather
than a fabricated zero — treat a missing result as "no data point this run", not "zero disconnected".

### Security Events
Queries the Security event log for one or more Event IDs, locally or on a remote Segment Server.
Defaults to Windows Filtering Platform (WFP) connection events 5156/5157.
- `Get-ZNSecurityEventRate -Period <period>` — local machine
- `Get-ZNSecurityEventRate -Period <period> -EventId 4688, 4689` — measure other Event ID(s)
- `Get-ZNSecurityEventRate -Period <period> -ComputerName <host>` — remote via WinRM (current identity)
- `Get-ZNSecurityEventRate -Period <period> -ComputerName <host> -Credential $cred` — remote with explicit credential

Period format: a positive integer followed by `h` (hours) or `d` (days) — e.g. `1h`, `4h`, `1d`, `7d`.
All computation runs on the target machine; only the final numbers are returned across the wire.

### Security Log Analysis
Reads the Security log (live, remote, or an offline `.evtx` archive) and ranks Event IDs by count
and by estimated storage size, to understand why a log is filling up or wrapping quickly.
- `Get-ZNSecurityLogAnalysis` — analyze the local live Security log
- `Get-ZNSecurityLogAnalysis -LogPath archive.evtx` — analyze an offline archive
- `Get-ZNSecurityLogAnalysis -ComputerName <host> -ExportCsv report.csv` — query a remote DC and export
- `Get-ZNSecurityLogAnalysis -Hours 24 -MaxEvents 0 -TopN 30` — full 24-hour analysis, no event cap

Each Top N row includes an average/peak events-per-second rate (same bucket math as
`Get-ZNSecurityEventRate`, computed from the same read pass — no second log query). Event IDs that
Zero Networks segmentation depends on are flagged with `*` in the tables and CSV export and must
stay enabled even if flagged as high-volume — see `$script:ZNRequiredEventIds` in
`Private/50-SecurityEventShared.ps1` to update that list over time.

### Service Management
Manages all `zn*` services as a group.
- `Invoke-ZNServices -Action <Stop|Start|Restart>` — local machine (requires Administrator)
- `Invoke-ZNServices -Action <action> -ComputerName <host>` — single remote Segment Server via PSRemoting
- `Invoke-ZNServices -Action <action> -AllServers [-ClusterName <name>]` — all Segment Servers via API

### Identity Sync
Syncs disabled AD accounts to inactive status in ZN. One-directional: AD disabled → ZN inactive.
Requires the `ActiveDirectory` module (RSAT) and a ZN API key with write scope.

- `Sync-ZNADUserStatus -WhatIf` — preview changes and receive performance recommendations
- `Sync-ZNADUserStatus -SearchBase 'OU=Users,DC=corp,DC=example,DC=com' -Note "Q2 offboarding"` — scoped sync
- `Sync-ZNADUserStatus -Since '2025-11-15' -BatchSize 400` — incremental sync, max batch size
- `Sync-ZNADUserStatus -PassThru | Where-Object Action -eq 'Inactivated' | Export-Csv offboarded.csv`

Matching uses SID (primary) then UPN (fallback). Inactivation uses bulk batched API calls
(`-BatchSize`, default 100, max 400). Each batch audit comment records the `whenChanged` date
range for that batch.

Running with `-WhatIf` queries the ZN audit log (1-year retention) for a previous sync by this
tool and surfaces the last-run date as a `-Since` suggestion, along with `-SearchBase` and
`-BatchSize` recommendations based on result set size. The console table is capped at 100 rows;
use `-PassThru` to retrieve the full result set.

### BreakGlass Asset Browser
Offline queries against the BreakGlass `segmentedAssets.json` snapshot. Run `Import-ZNBGAssetData` first.
This is useful to browse a segmentedAssets.json with something more than just a ConvertFrom-JSON command.
The `BG` noun qualifier distinguishes these commands from API-backed commands.

```powershell
Import-ZNBGAssetData                           # loads segmentedAssets.json and switches.json
Import-ZNBGAssetData -DataPath .\export.json   # custom path

Get-ZNBGAssetSummary                           # total counts
Get-ZNBGAsset                                  # all assets as objects — pipe freely
Find-ZNBGAsset "dc01"                          # search by partial FQDN

Get-ZNBGWindowsAsset                           # filter by OS
Get-ZNBGLinuxAsset
Get-ZNBGServerAsset                            # filter by type
Get-ZNBGClientAsset

Get-ZNBGNetworkSegmentedAsset                  # segmentation state
Get-ZNBGIdentitySegmentedAsset

Get-ZNBGAssetCluster                           # cluster breakdown
Get-ZNBGClusterMemberAsset "zero.local"        # assets in a specific cluster

Get-ZNBGAssetForest                            # AD forest / domain / service account config
Get-ZNBGAssetSwitch                            # OT switches from switches.json
Get-ZNBGAssetBySource                          # counts by entity source (AD, Ansible, etc.)
```

All query functions return objects. Pipe freely:
```powershell
Get-ZNBGAsset | Where-Object { $_.OS -eq 'Linux' -and $_.NetworkSegmented }
Get-ZNBGServerAsset | Group-Object Cluster | Select-Object Name, Count
Get-ZNBGAsset | Export-Csv assets.csv -NoTypeInformation
```

## Notes
- The module displays a quick-start summary once per session on import or first use.
- Entry-point commands display the banner with author and command name.
- HTML docs: `breakglass/docs/zntools-user-reference.html` (users) and `breakglass/docs/zntools-author-reference.html` (authors).
