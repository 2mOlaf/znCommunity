---
title: ZNTools Module Roadmap
description: Community scripts selected for formalization into the ZNTools PowerShell module — what changes, why it matters, and what each command will look like when hardened.
---

# ZNTools Module Roadmap

> **Purpose of this document** — Identify community scripts that provide broad operational value and should be formalized into the ZNTools PowerShell module, with generalized parameters, hardened error handling, and the standard module contract (banner, API helpers, consistent output objects). This is a living roadmap; scripts move from *Planned* → *In Design* → *In Progress* → *Shipped*.

---

## Guiding Principles

A community script graduates to a module command when it meets most of these criteria:

| Criterion | What it means |
|---|---|
| **Broad applicability** | Useful to any Zero Networks operator, not just one customer topology or third-party product |
| **Generalizable parameters** | The current script solves 80% of the need; the module command solves 100% with proper parameter sets |
| **Pattern consolidation opportunity** | Two or more community scripts solve the same problem at different levels of polish — the module command replaces them both |
| **API surface ownership** | The operation wraps a ZN REST API endpoint that ZNTools should "own" (rather than every operator re-inventing the HTTP calls) |
| **Error handling and -WhatIf** | The script's logic is solid but needs `-WhatIf`, structured error output, and retry logic to be production-safe |

Scripts that are too vendor-specific (Asimily), belong to a separate ecosystem (Python threat hunting), or are already well-served by the PSGallery module are explicitly excluded — see [Not In Scope](#not-in-scope).

---

## Current Module State

ZNTools v1.1 exposes the following commands (after `DefaultCommandPrefix = 'ZN'` is applied at import):

- `Test-ZNPort` — TCP/UDP port reachability test
- `Get-ZNLinuxProfile` — Linux configuration profile reader
- `Get-ZNSegmentCluster` — Segment Server cluster query
- `Show-ZNHealthDashboard` — Environment health overview
- `Invoke-ZNServices` — ZN service lifecycle management
- `Import-ZNBG-AssetData`, `Get-ZNBG-Asset`, `Find-ZNBG-Asset`, and 12 more `Get-ZNBG-*` commands — offline BreakGlass asset browser

The roadmap adds **14 new commands** across three delivery tiers.

---

## Tier 1 — Direct Formalization

*Scripts that map cleanly to a single new command with minimal scope expansion. Source code is already solid; the work is adopting the module contract.*

---

### `Test-ZNConnectivity`

**Source:** [`Segment/Segment/Troubleshooting/ZNConnectivityTest.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Troubleshooting/ZNConnectivityTest.ps1)

**Status:** `Planned`

**What the script does today:** Tests TCP connectivity and DNS resolution to the 15 required ZN cloud endpoints from the running machine.

**What changes in the module command:**
- Returns a structured `[PSCustomObject[]]` result (endpoint, port, tcpSuccess, dnsSuccess, latencyMs) instead of console-only output
- Adds `-Endpoint` parameter to target a subset of endpoints
- Adds `-PassThru` to surface the objects for pipeline use (e.g. pipe into `Export-Csv`)
- Integrates the ZNTools banner and API-key-free design (no auth needed for a connectivity test)

**Signature:**
```powershell
Test-ZNConnectivity [-Endpoint <string[]>] [-PassThru] [-Quiet]
```

---

### `Add-ZNTrustedAddress`

**Source:** [`Segment/Settings/Add-ZNTrustedInternetAddresses.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Settings/Add-ZNTrustedInternetAddresses.ps1)

**Status:** `Planned`

**What the script does today:** Reads IPs from a text file and adds any not already present to the Trusted External IPs list.

**What changes in the module command:**
- Supports both file path and pipeline input (`[string[]]$IPAddress`)
- Adds `-Remove` switch to support removal of addresses
- Uses `Get-ZNApiHeaders` / `Get-ZNApiBaseUrl` private helpers instead of inline header construction
- Returns the updated trusted address list as output

**Signature:**
```powershell
Add-ZNTrustedAddress [-IPAddress] <string[]> [-ApiKey <string>] [-WhatIf] [-PassThru]
Remove-ZNTrustedAddress [-IPAddress] <string[]> [-ApiKey <string>] [-WhatIf]
```

---

### `Export-ZNAuditLog`

**Source:** [`Segment/Segmentation Server/Get-AuditLogByTimeRange.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segmentation%20Server/Get-AuditLogByTimeRange.ps1)

**Status:** `Planned`

**What the script does today:** Interactive prompts for start/end time, then exports all matching audit events to a CSV file.

**What changes in the module command:**
- Non-interactive: `-Start` and `-End` accept `[DateTime]` objects (no ISO string parsing at runtime)
- Adds `-Last <timespan>` shorthand (e.g. `-Last (New-TimeSpan -Days 7)`)
- Adds `-AuditType` filter using the inline enum the script already defines
- Returns deserialized objects (not just CSV rows), passable to further pipeline commands
- `-OutputPath` optional — if omitted, objects flow to the pipeline; if provided, also writes the CSV

**Signature:**
```powershell
Export-ZNAuditLog -Start <DateTime> -End <DateTime> [-AuditType <AuditType[]>] [-OutputPath <string>] [-ApiKey <string>]
Export-ZNAuditLog -Last <TimeSpan> [-AuditType <AuditType[]>] [-OutputPath <string>] [-ApiKey <string>]
```

---

### `Approve-ZNRuleCleanup`

**Source:** [`Segment/Segment/Rules/Approve-ZNProposedDeletes.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Rules/Approve-ZNProposedDeletes.ps1)

**Status:** `Planned`

**What the script does today:** Fetches all proposed-delete rules and approves them, with optional filters for inactive-asset rules or zero-hit rules.

**What changes in the module command:**
- Uses standard ZNTools `-WhatIf` (inherits from `CmdletBinding(SupportsShouldProcess)`)
- Returns a result object per rule (ruleId, approved, reason, whatIfOnly) for audit trail use
- Adds `-Direction Inbound|Outbound|Both` (script today is inbound only)
- Adds `-ReasonFilter <string>` for ad-hoc filtering beyond the two built-in switches

**Signature:**
```powershell
Approve-ZNRuleCleanup [-Direction <string>] [-InactiveAssetsOnly] [-NoHitsOnly] [-ReasonFilter <string>] [-ApiKey <string>] [-WhatIf]
```

---

### `Find-ZNConflictingGPO`

**Source:** [`Segment/Settings/Active Directory/Get-ADGPOsWithFWRules.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Settings/Active%20Directory/Get-ADGPOsWithFWRules.ps1)

**Status:** `Planned`

**What the script does today:** Finds non-ZN GPOs that contain Windows Firewall settings in any of the four firewall registry paths.

**What changes in the module command:**
- Returns structured objects (GPO name, GUID, affected firewall paths) instead of console-only output
- Runs GPO checks in parallel (`ForEach-Object -Parallel`) for large environments
- Adds `-Domain` parameter for cross-domain checks
- Adds `-ExcludeGPO <string[]>` to suppress known-safe exceptions

**Signature:**
```powershell
Find-ZNConflictingGPO [-Domain <string>] [-ExcludeGPO <string[]>] [-ApiKey <string>]
```

---

## Tier 2 — Pattern Consolidation

*Multiple community scripts solve the same operational problem at different levels of polish. The module command replaces them all with a single, well-parameterized command.*

---

### `Get-ZNStaleAsset` ← 4 scripts consolidated

**Sources:**
- [`get-AssetsStaleConnection.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/get-AssetsStaleConnection.ps1) — disconnected + old lastLogon
- [`Get-NoIPAssets.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Get-NoIPAssets.ps1) — no IP addresses registered
- [`auditMonitoredAssets.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/audit-monitored-assets/auditMonitoredAssets.ps1) — expected vs. actual monitored comparison
- [`get-assetAuditDates.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/get-assetAuditDates.ps1) — last audit event per asset

**Status:** `In Design`

**The evolution story:** Four scripts each probe a different dimension of "staleness." `Get-NoIPAssets` and `get-AssetsStaleConnection` are raw API queries with results in a variable. `auditMonitoredAssets` does the comparison logic but requires two side-input files. `get-assetAuditDates` provides the temporal dimension. The module command unifies all four stale-detection strategies under one interface.

**What changes in the module command:**
- `-Condition` accepts `NoIP | Disconnected | NotMonitored | All` (combinable)
- `-DisconnectedDays <int>` replaces the hardcoded `$n = 180` variable
- `-CompareFrom <string[]>` (pipeline or array) replaces the `targeted-assets.csv` file requirement
- Returns a consistent `[ZNStaleAsset]` object with AssetId, Name, Condition, LastSeen, Recommendation
- No file-based inputs required — everything flows from the ZN API or the pipeline

**Signature:**
```powershell
Get-ZNStaleAsset [-Condition <StaleCondition[]>] [-DisconnectedDays <int>] [-CompareFrom <string[]>] [-ApiKey <string>]
```

---

### `Invoke-ZNLearning` ← 4 scripts consolidated

**Sources:**
- [`Add-AssetsToLearning.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Add-AssetsToLearning.ps1) — file-based input, resolves FQDNs
- [`Move-ProtectToLearning.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Move-ProtectToLearning.ps1) — all protected → unprotect → queue
- [`set-extendLearning.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/set-extendLearning.ps1) — extend queued assets by N days
- [`Unprotect-ZNLearningButNotConnected.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Unprotect-ZNLearningButNotConnected.ps1) — unprotect disconnected learning assets

**Status:** `In Design`

**The evolution story:** These scripts represent the full asset learning lifecycle expressed as four separate tools. The PSGallery module has `Invoke-ZNAssetNetworkQueue` but without maintenance window support, file-based input, or the extend/requeue patterns. The community scripts fill those gaps but each requires manual editing to configure. The module command makes all of it composable.

**What changes in the module command:**
- `-AssetId` (pipeline-bindable) and `-FromFile <path>` and `-FromProtected` parameter sets
- `-Days <int>` for learning duration (default 30)
- `-ExtendOnly` — only extends assets already in learning; does not requeue
- `-MaintenanceWindowId <string>` — maintenance window support the PSGallery module omits
- `-CleanupDisconnected` — finds and unprotects learning assets with `assetStatus = 1`
- `-WhatIf` supported throughout
- Batch size managed internally (100 per API call), progress bar for large sets

**Signature:**
```powershell
Invoke-ZNLearning [-AssetId <string[]>] [-FromFile <string>] [-Days <int>] [-MaintenanceWindowId <string>] [-ApiKey <string>] [-WhatIf]
Invoke-ZNLearning -FromProtected [-Days <int>] [-MaintenanceWindowId <string>] [-ApiKey <string>] [-WhatIf]
Invoke-ZNLearning -ExtendOnly [-Days <int>] [-ApiKey <string>] [-WhatIf]
Invoke-ZNLearning -CleanupDisconnected [-ApiKey <string>] [-WhatIf]
```

---

### `New-ZNOTAsset` ← 2 scripts consolidated

**Sources:**
- [`CreateOTAssets.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/CreateOTAssets.ps1) — basic CSV import, hardcoded type 12 (Hypervisor)
- [`New-OtAsset.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/New-OtAsset/New-OtAsset.ps1) — full type support, JWT URL detection, dry-run, single or CSV

**Status:** `In Progress`

**The evolution story:** `CreateOTAssets.ps1` is generation 1 — it works but hardcodes the asset type. `New-OtAsset.ps1` is generation 2 — it decodes the JWT to find the right API URL, supports all 28 OT/IoT device types, has dry-run, and handles both single-asset and CSV bulk modes. The module command is generation 3: it swaps the ad-hoc JWT decoding for `Get-ZNApiBaseUrl`, adds the ZNTools banner, and validates the type parameter against the enum.

**What changes in the module command:**
- Uses `Get-ZNApiBaseUrl` / `Get-ZNApiHeaders` from the module's private helpers
- `-Type` parameter becomes a `[ValidateSet]` or enum covering all 28 OT device types
- `-CsvFilePath` accepts a path; `-IPAddress` / `-Name` / `-Fqdn` accept individual values
- `-DryRun` → `-WhatIf` (standard PowerShell pattern)
- Outputs a `[ZNAssetResult]` object (assetId, displayName, ip, created) for pipeline use

**Signature:**
```powershell
New-ZNOTAsset -IPAddress <string> -Name <string> [-Type <OTAssetType>] [-Fqdn <string>] [-ApiKey <string>] [-WhatIf]
New-ZNOTAsset -CsvFilePath <string> [-ApiKey <string>] [-WhatIf]
```

---

### `Set-ZNGroupMembership` ← 3 scripts consolidated

**Sources:**
- [`Update-ZNGroupMembers.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Update-ZNGroupMembers.ps1) — CIDR ranges → ZN item IDs → PUT group members
- [`Add-AssetsToTagGroup.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Add-AssetsToTagGroup.ps1) — CSV assets → batch add to tag group
- [`create-GroupEnv.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/create-GroupEnv.ps1) — CSV with environment column → create groups + add members

**Status:** `Planned`

**The evolution story:** These three scripts reveal a core gap: the PSGallery module has `Add-ZNTagGroupsMember` but nothing for custom groups, nothing that accepts CIDR notation, and nothing that creates groups from tabular data. The CIDR → ZN item ID encoding in `Update-ZNGroupMembers.ps1` is a non-obvious bit of platform knowledge that should live in the module, not in every operator's clipboard.

**What changes in the module command:**
- `-GroupId` accepts any group type (custom `g:c:*`, tag `g:t:*`)
- `-MembersFromCidr <string[]>` handles the CIDR → `b:12{hex}` encoding internally
- `-MembersFromCsv <path>` handles the FQDN-lookup-and-batch pattern from `Add-AssetsToTagGroup`
- `-CreateIfMissing` triggers the auto-create-and-verify flow from `create-GroupEnv`
- `-Replace` (default: additive) to enable full membership replacement
- `-WhatIf` shows what would change without calling the PUT endpoint

**Signature:**
```powershell
Set-ZNGroupMembership -GroupId <string> [-MembersFromCidr <string[]>] [-MembersFromCsv <string>] [-Replace] [-WhatIf] [-ApiKey <string>]
New-ZNEnvironmentGroup -CsvFilePath <string> [-CreateIfMissing] [-WhatIf] [-ApiKey <string>]
```

---

### `Set-ZNAssetCluster` ← direct promotion

**Source:** [`Pin-AssetsToClusters.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Pin%20Assets%20To%20Clusters/Pin-AssetsToClusters.ps1)

**Status:** `In Progress`

**The evolution story:** This is the most mature community script — PS7+, full parameter sets, dry-run, OU path resolution, CSV bulk, cluster listing, template export. It is functionally module-ready. The primary work is adopting the ZNTools module contract: swap the inline headers for `Get-ZNApiHeaders`, adopt the module's banner, add `SupportsShouldProcess`, and export from the manifest.

**What changes in the module command:**
- Inline JWT decode and header construction → module private helpers
- `$PortalUrl` default via `Get-ZNApiBaseUrl`
- `$DryRun` → standard `[CmdletBinding(SupportsShouldProcess)]` `-WhatIf`
- Output objects surface through the pipeline (not just console progress)
- `-ListDeploymentClusters` → separate `Get-ZNDeploymentCluster` command following the module's single-responsibility pattern

**Signature:**
```powershell
Set-ZNAssetCluster -AssetId <string> -DeploymentClusterId <string> [-Unpin] [-WhatIf] [-ApiKey <string>]
Set-ZNAssetCluster -OUPath <string> -DeploymentClusterId <string> [-Unpin] [-WhatIf] [-ApiKey <string>]
Set-ZNAssetCluster -CsvPath <string> [-Unpin] [-WhatIf] [-ApiKey <string>]
Get-ZNDeploymentCluster [-ApiKey <string>]
```

---

## Tier 3 — Expanded Capabilities

*Scripts with good ideas that need significant redesign to be module-worthy. Scope is expanded beyond what the script does today.*

---

### `Invoke-ZNIdentityLearning` ← 2 scripts + expansion

**Sources:**
- [`Add-ClientsToIdentityLearning.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Identity%20Segment/Add-ClientsToIdentityLearning.ps1)
- [`get-currentSVCAccounts.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Identity%20Segment/get-currentSVCAccounts.ps1)

**Status:** `Planned`

**The evolution story:** Two separate scripts, each hard-scoped (clients only; service accounts only). Together they form the "identity learning onboarding" workflow. The module command generalizes both into a single interface with asset-type and user-type targeting.

**What changes:**
- `-AssetType Clients|Servers|OT` parameter set for the asset-side learning queue
- `-UserType ServiceAccount|User` parameter set for the user-side learning queue
- `-ActiveWithin <int>` replaces the hardcoded 180-day filter
- `-IdentityProtectionStatus` filter for pre-screening
- Batching and progress reporting built in

**Signature:**
```powershell
Invoke-ZNIdentityLearning -AssetType <string> [-Days <int>] [-ApiKey <string>] [-WhatIf]
Invoke-ZNIdentityLearning -UserType <string> [-ActiveWithin <int>] [-Days <int>] [-ApiKey <string>] [-WhatIf]
```

---

### `Update-ZNBlockRule` ← 2 scripts + expansion

**Sources:**
- [`Update-ZNBlockRulewithRiskyIps.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Rules/Update-ZNBlockRulewithRiskyIps.ps1) — add risky IPs from last 24h activity
- [`Update-ZNOutboundBlockfromURLFile.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Rules/Update-ZNOutboundBlockfromURLFile.ps1) — replace outbound block with URL file

**Status:** `Planned`

**The evolution story:** Both scripts update block rules but from completely different sources and with different behaviors (additive vs. replace). The module command expresses this cleanly through parameter sets, making the "which source?" decision explicit rather than requiring two separate scripts.

**What changes:**
- `-RuleId` accepts a rule ID; rule lookup by name (`-RuleName`) also supported
- `-Direction Inbound|Outbound` is explicit
- `-AddFromActivity` triggers the "last N hours, high-risk sources" pattern; `-ActivityHours` and `-RiskLevel` tune it
- `-FromUrlFile <path>` triggers the URL replacement pattern
- `-Replace` (default for URL file) vs. additive (default for activity-based)
- `-WhatIf` shows what IPs/URLs would be added/replaced

**Signature:**
```powershell
Update-ZNBlockRule -RuleId <string> -AddFromActivity [-ActivityHours <int>] [-RiskLevel <string>] [-WhatIf] [-ApiKey <string>]
Update-ZNBlockRule -RuleId <string> -FromUrlFile <string> [-Replace] [-WhatIf] [-ApiKey <string>]
```

---

### `Import-ZNAssetLabel` ← redesign

**Source:** [`Import-AssetLabels.ps1`](https://github.com/zeronetworks/Community/blob/master/Segment/Segment/Asset%20Management/Import-AssetLabels.ps1)

**Status:** `Planned`

**The evolution story:** The script requires `ImportExcel` — a heavyweight dependency just to read an `.xlsx` file. The core operation (resolve asset by name, POST labels to the API) is valuable but the input mechanism is the bottleneck. The module command generalizes to CSV and removes the ImportExcel dependency.

**What changes:**
- Accepts CSV (not Excel) with configurable column-name mappings
- Accepts pipeline input of `[PSCustomObject]@{AssetId='...'; Labels=@{}}` for full automation
- `-LabelKey` / `-LabelValue` for single-label interactive use
- Lookups cached per run to avoid redundant API calls for the same asset
- `-WhatIf` shows what labels would be applied

**Signature:**
```powershell
Import-ZNAssetLabel -CsvFilePath <string> [-AssetColumn <string>] [-DomainSuffix <string>] [-WhatIf] [-ApiKey <string>]
Import-ZNAssetLabel -AssetId <string> -LabelKey <string> -LabelValue <string> [-WhatIf] [-ApiKey <string>]
```

---

## Not In Scope

Scripts explicitly excluded from the module roadmap, with rationale:

| Script | Reason |
|---|---|
| `Parse-AsimilyExport.ps1` | Vendor-specific integration — useful pattern to reference, but the Asimily data model does not generalize |
| Threat Hunting tools (Python) | Separate Python ecosystem; not PowerShell module territory |
| `ZN_Troubleshooter_v01.ps1` | Retired |
| `getSecretMicrosoftAuth.ps1` | Microsoft Graph operations outside ZN API scope |
| `Login-ZNAADSAML.ps1` | Authentication plumbing that would conflict with future module auth handling |
| `breakglass-single.ps1` | Break glass belongs in the pre-installed scripts, not ZNTools |
| `CollectSMBDetails.ps1` | ETW tracing specialist diagnostics — not broadly operational |
| `znlog-filter.ps1` | Segment Server–specific log analysis; too narrow for a general module command |
| `purgeKerberosOnHosts.ps1` | IT ops task not specific enough to ZN to belong in ZNTools |
| `install-CloudConnectorAPI.ps1` | Installer wrapper — belongs as a standalone install-time script |
| Linux connector shell scripts | Not PowerShell module territory |
| `Sync-BreakGlassDirectory` | Useful but specific to a replication topology |
| `sample.ps1` | Reference only |
| `zn-approve.py` | Python — see Threat Hunting note |

---

## Command Summary

| Command | Tier | Status | Source Scripts |
|---|---|---|---|
| `Test-ZNConnectivity` | 1 | Planned | ZNConnectivityTest.ps1 |
| `Add-ZNTrustedAddress` | 1 | Planned | Add-ZNTrustedInternetAddresses.ps1 |
| `Remove-ZNTrustedAddress` | 1 | Planned | *(new — inverse of above)* |
| `Export-ZNAuditLog` | 1 | Planned | Get-AuditLogByTimeRange.ps1 |
| `Approve-ZNRuleCleanup` | 1 | Planned | Approve-ZNProposedDeletes.ps1 |
| `Find-ZNConflictingGPO` | 1 | Planned | Get-ADGPOsWithFWRules.ps1 |
| `Get-ZNStaleAsset` | 2 | In Design | 4 asset query scripts |
| `Invoke-ZNLearning` | 2 | In Design | 4 asset lifecycle scripts |
| `New-ZNOTAsset` | 2 | In Progress | CreateOTAssets + New-OtAsset |
| `Set-ZNGroupMembership` | 2 | Planned | 3 group management scripts |
| `New-ZNEnvironmentGroup` | 2 | Planned | create-GroupEnv.ps1 |
| `Set-ZNAssetCluster` | 2 | In Progress | Pin-AssetsToClusters.ps1 |
| `Get-ZNDeploymentCluster` | 2 | In Progress | *(split from Set-ZNAssetCluster)* |
| `Invoke-ZNIdentityLearning` | 3 | Planned | 2 identity scripts |
| `Update-ZNBlockRule` | 3 | Planned | 2 block rule scripts |
| `Import-ZNAssetLabel` | 3 | Planned | Import-AssetLabels.ps1 |
