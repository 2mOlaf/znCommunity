function Sync-ADUserStatus {
    <#
    .SYNOPSIS
        Syncs disabled Active Directory accounts to inactive status in the Zero Networks platform.
    .DESCRIPTION
        Queries Active Directory for disabled user accounts and compares them against AD-sourced
        users in the Zero Networks platform. Users disabled in AD but still active in ZN are marked
        inactive via the ZN API using bulk batched calls. The ZN audit comment records the AD
        whenChanged date range for each batch — the closest proxy for a disable date that AD
        natively provides — plus an optional admin note.

        Matching uses SID as the primary key, falling back to UserPrincipalName. The AD query
        uses an LDAP filter evaluated on the DC for efficiency. ZN queries use the maximum page
        size of 400 to minimise round-trips.

        In WhatIf mode the function additionally queries the ZN audit log for a previous sync
        and surfaces performance recommendations (SearchBase, -Since, batch sizing) based on
        the result set.

        This sync is one-directional: AD disabled → ZN inactive. It does not reactivate users.
        Requires the ActiveDirectory PowerShell module (RSAT).
    .PARAMETER ApiKey
        Optional API key override; defaults to ZN_API_KEY environment variable.
    .PARAMETER ApiUrl
        Optional API base URL override (e.g., https://portal.zeronetworks.com/api/v1).
    .PARAMETER Domain
        AD domain name to query. Defaults to the current user's domain.
    .PARAMETER Server
        Specific domain controller FQDN to target. Takes precedence over -Domain.
    .PARAMETER Credential
        PSCredential for the AD query when alternate credentials are required.
    .PARAMETER SearchBase
        AD OU distinguished name to scope the query
        (e.g., 'OU=Users,DC=corp,DC=example,DC=com'). Without this the entire domain is
        scanned. Strongly recommended for large directories.
    .PARAMETER Since
        Only process AD accounts with whenChanged on or after this date. Use for incremental
        runs after an initial full sync. WhatIf mode suggests the correct date automatically
        from the ZN audit log. Note: accounts disabled before this cutoff that were never
        previously synced will be skipped.
    .PARAMETER BatchSize
        Number of users per bulk inactivation API call. Default: 100. Range: 1–400. Each
        batch produces one ZN audit entry with a shared comment containing the whenChanged
        date range of that batch.
    .PARAMETER Note
        Admin note appended to each batch's ZN audit comment (e.g., "Q2 offboarding").
    .PARAMETER PassThru
        Emit one result object per user to the pipeline. The console table is capped at 100
        rows; use -PassThru to retrieve the full result set.
    .EXAMPLE
        Sync-ZNADUserStatus -WhatIf
        Preview changes and receive performance recommendations for the current domain.
    .EXAMPLE
        Sync-ZNADUserStatus -SearchBase 'OU=Corp Users,DC=corp,DC=example,DC=com' -Note "Q2 offboarding"
        Sync a specific OU with an audit note.
    .EXAMPLE
        Sync-ZNADUserStatus -Since '2025-11-15' -BatchSize 200
        Incremental sync: only accounts modified since Nov 15, batched in groups of 200.
    .EXAMPLE
        Sync-ZNADUserStatus -PassThru | Where-Object Action -eq 'Inactivated' | Export-Csv offboarded.csv -NoTypeInformation
        Run the sync and export inactivated users to CSV.
    .NOTES
        Author: Olaf Gradin
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$ApiKey,
        [string]$ApiUrl,
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase,
        [datetime]$Since,
        [ValidateRange(1, 400)]
        [int]$BatchSize = 100,
        [string]$Note,
        [switch]$PassThru
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    # ── Prerequisite ──────────────────────────────────────────────────────────
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Error (
            'The ActiveDirectory module is required. ' +
            'Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
        )
        return
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $isWhatIf  = ($WhatIfPreference -ne 'SilentlyContinue')
    $modeLabel = if ($isWhatIf) { 'WhatIf — no changes will be made' } else { 'Live' }

    $token   = Get-ZNApiKey    -ApiKey $ApiKey
    $baseUrl = Get-ZNApiBaseUrl -ApiKey $token -ApiUrl $ApiUrl
    $headers = Get-ZNApiHeaders -ApiKey $token

    Write-Host ''
    Write-Host '  AD → ZN Identity Status Sync' -ForegroundColor Cyan
    $adTarget = $Server ?? $Domain
    if ($adTarget)    { Write-Host "  Target     : $adTarget"                              -ForegroundColor DarkGray }
    if ($SearchBase)  { Write-Host "  SearchBase : $SearchBase"                            -ForegroundColor DarkGray }
    if ($PSBoundParameters.ContainsKey('Since')) { Write-Host "  Since      : $($Since.ToString('yyyy-MM-dd'))"       -ForegroundColor DarkGray }
    Write-Host         "  Mode       : $modeLabel"                                          -ForegroundColor DarkGray
    Write-Host ''

    # ── Step 1: Query AD for disabled accounts ────────────────────────────────
    Write-Host '  Querying AD for disabled user accounts...' -ForegroundColor Yellow

    # LDAP filter is evaluated on the DC — more efficient than the PS Filter parameter.
    # The bitwise rule 1.2.840.113556.1.4.803 checks the ACCOUNTDISABLE flag (0x2).
    $ldapFilter = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
    if ($PSBoundParameters.ContainsKey('Since')) {
        $sinceGT    = $Since.ToUniversalTime().ToString('yyyyMMddHHmmss') + '.0Z'
        $ldapFilter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(whenChanged>=$sinceGT))"
    }

    $adParams = @{
        LDAPFilter     = $ldapFilter
        ResultPageSize = 1000
        Properties     = 'SID', 'UserPrincipalName', 'SamAccountName',
                         'whenChanged', 'Description', 'distinguishedName', 'DisplayName'
    }
    if ($SearchBase) { $adParams.SearchBase = $SearchBase }
    if ($adTarget)   { $adParams.Server     = $adTarget   }
    if ($Credential) { $adParams.Credential = $Credential }

    try {
        $disabledAdUsers = @(Get-ADUser @adParams)
    }
    catch {
        Write-Error "AD query failed: $($_.Exception.Message)"
        return
    }

    Write-Host "  Found $($disabledAdUsers.Count) disabled AD account$(if ($disabledAdUsers.Count -ne 1) { 's' })." -ForegroundColor DarkGray

    if ($disabledAdUsers.Count -eq 0) {
        Write-Host ''
        return
    }

    $adBySid = @{}
    $adByUpn = @{}
    foreach ($u in $disabledAdUsers) {
        $sid = $u.SID.Value
        if ($sid) { $adBySid[$sid] = $u }
        if ($u.UserPrincipalName) { $adByUpn[$u.UserPrincipalName.ToLower()] = $u }
    }

    # ── Step 2: Query ZN for AD users (active + inactive, paginated) ──────────
    Write-Host '  Querying Zero Networks for active AD users...'   -ForegroundColor Yellow

    # source=3 = Active Directory; ZN filter format uses "id"/"value" keys
    $sourceFilter = [Uri]::EscapeDataString('[{"id":"source","value":3}]')
    $pageSize     = 400  # API maximum

    function Get-ZNUserPage {
        param([string]$Ep, [string]$Base, [hashtable]$Hdrs, [string]$Filter, [int]$Limit)
        $all    = [System.Collections.Generic.List[object]]::new()
        $offset = 0
        do {
            try {
                $resp = Invoke-RestMethod `
                    -Uri     "${Base}/${Ep}?_limit=${Limit}&_offset=${offset}&_filters=${Filter}" `
                    -Method  Get `
                    -Headers $Hdrs
            }
            catch {
                $code = $_.Exception.Response.StatusCode.value__
                $body = Get-ZNErrorBody $_
                Write-Error "ZN query failed (${Ep}): Status ${code}"
                if ($body) { Write-Error "Response body: ${body}" }
                return $null
            }
            $page = @()
            if ($resp.items)           { $page = @($resp.items) }
            elseif ($resp -is [array]) { $page = @($resp)       }
            $all.AddRange($page)
            $offset += $Limit
        } while ($page.Count -eq $Limit)
        return ,$all.ToArray()
    }

    $znActive = Get-ZNUserPage -Ep 'users'          -Base $baseUrl -Hdrs $headers -Filter $sourceFilter -Limit $pageSize
    if ($null -eq $znActive) { return }
    Write-Host "  Found $($znActive.Count) active AD user$(if ($znActive.Count -ne 1) { 's' }) in ZN." -ForegroundColor DarkGray

    Write-Host '  Querying Zero Networks for inactive AD users...' -ForegroundColor Yellow
    $znInactive = Get-ZNUserPage -Ep 'users/inactive' -Base $baseUrl -Hdrs $headers -Filter $sourceFilter -Limit $pageSize
    if ($null -eq $znInactive) {
        Write-Warning 'Could not retrieve inactive users from ZN — already-inactive entries will not be shown.'
        $znInactive = @()
    }
    Write-Host "  Found $($znInactive.Count) inactive AD user$(if ($znInactive.Count -ne 1) { 's' }) in ZN." -ForegroundColor DarkGray
    Write-Host ''

    # ── Step 3: Match and classify ────────────────────────────────────────────
    $matchedSids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $results   = [System.Collections.Generic.List[pscustomobject]]::new()
    $toProcess = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($znUser in $znActive) {
        $adUser = $null
        if ($znUser.sid -and $adBySid.ContainsKey($znUser.sid)) {
            $adUser = $adBySid[$znUser.sid]
        }
        if (-not $adUser) {
            $upn = if ($znUser.principalName)    { $znUser.principalName    } `
              elseif ($znUser.userPrincipleName) { $znUser.userPrincipleName } `
              else                                { $null                    }
            if ($upn -and $adByUpn.ContainsKey($upn.ToLower())) {
                $adUser = $adByUpn[$upn.ToLower()]
            }
        }
        if (-not $adUser) { continue }

        $sid    = if ($znUser.sid) { $znUser.sid } else { $adUser.SID.Value }
        $name   = if ($znUser.name)         { $znUser.name         } `
             elseif ($adUser.DisplayName)   { $adUser.DisplayName  } `
             else                            { $adUser.SamAccountName }
        $dom    = if ($znUser.domain)                    { $znUser.domain } `
             elseif ($adUser.UserPrincipalName)          { $adUser.UserPrincipalName -replace '^.*@', '' } `
             else                                         { '' }
        $adMod  = if ($adUser.whenChanged) { $adUser.whenChanged.ToString('yyyy-MM-dd') } else { 'Unknown' }
        $action = if ($isWhatIf) { 'WouldInactivate' } else { 'Inactivate' }

        $row = [pscustomobject]@{
            Name       = $name
            Domain     = $dom
            ADModified = $adMod
            ZNStatus   = 'Active'
            Action     = $action
            ZNUserId   = $znUser.id
            SID        = $sid
        }
        $null = $matchedSids.Add($sid)
        $results.Add($row)
        $toProcess.Add([pscustomobject]@{
            ZNId   = $znUser.id
            ZNName = $name
            AdUser = $adUser
            Row    = $row
        })
    }

    foreach ($znUser in $znInactive) {
        $adUser = $null
        if ($znUser.sid -and $adBySid.ContainsKey($znUser.sid)) {
            $adUser = $adBySid[$znUser.sid]
        }
        if (-not $adUser) {
            $upn = if ($znUser.principalName)    { $znUser.principalName    } `
              elseif ($znUser.userPrincipleName) { $znUser.userPrincipleName } `
              else                                { $null                    }
            if ($upn -and $adByUpn.ContainsKey($upn.ToLower())) {
                $adUser = $adByUpn[$upn.ToLower()]
            }
        }
        if (-not $adUser) { continue }

        $sid   = if ($znUser.sid) { $znUser.sid } else { $adUser.SID.Value }
        $name  = if ($znUser.name)         { $znUser.name         } `
            elseif ($adUser.DisplayName)   { $adUser.DisplayName  } `
            else                            { $adUser.SamAccountName }
        $dom   = if ($znUser.domain)       { $znUser.domain       } `
            elseif ($adUser.UserPrincipalName) { $adUser.UserPrincipalName -replace '^.*@', '' } `
            else                            { '' }
        $adMod = if ($adUser.whenChanged) { $adUser.whenChanged.ToString('yyyy-MM-dd') } else { 'Unknown' }

        $null = $matchedSids.Add($sid)
        $results.Add([pscustomobject]@{
            Name       = $name
            Domain     = $dom
            ADModified = $adMod
            ZNStatus   = 'Inactive'
            Action     = 'AlreadyInactive'
            ZNUserId   = $znUser.id
            SID        = $sid
        })
    }

    foreach ($adUser in $disabledAdUsers) {
        if ($matchedSids.Contains($adUser.SID.Value)) { continue }
        $upn   = $adUser.UserPrincipalName
        $dom   = if ($upn) { $upn -replace '^.*@', '' } else { $Domain ?? '' }
        $adMod = if ($adUser.whenChanged) { $adUser.whenChanged.ToString('yyyy-MM-dd') } else { 'Unknown' }
        $results.Add([pscustomobject]@{
            Name       = if ($adUser.DisplayName) { $adUser.DisplayName } else { $adUser.SamAccountName }
            Domain     = $dom
            ADModified = $adMod
            ZNStatus   = '—'
            Action     = 'NotInZN'
            ZNUserId   = $null
            SID        = $adUser.SID.Value
        })
    }

    # ── Step 4: Display table (capped at 100 rows) ────────────────────────────
    $tableLimit = 100

    $sorted = $results | Sort-Object @{
        Expression = {
            switch ($_.Action) {
                { $_ -in 'Inactivate', 'WouldInactivate' } { 0 }
                'AlreadyInactive'                            { 1 }
                'NotInZN'                                    { 2 }
                default                                      { 3 }
            }
        }
    }, Name

    $displayRows = if ($results.Count -gt $tableLimit) { @($sorted)[0..($tableLimit - 1)] } else { $sorted }

    $col = '  {0,-28} {1,-22} {2,-14} {3,-14} {4}'
    $sep = '-' * 28

    Write-Host ($col -f 'Name', 'Domain', 'AD Modified', 'ZN Status', 'Action') -ForegroundColor Cyan
    Write-Host ($col -f $sep, ('-' * 22), ('-' * 14), ('-' * 14), ('-' * 22)) -ForegroundColor DarkGray

    foreach ($r in $displayRows) {
        $color = switch ($r.Action) {
            { $_ -in 'Inactivate', 'WouldInactivate' } { 'Yellow'   }
            default                                      { 'DarkGray' }
        }
        $label = switch ($r.Action) {
            'Inactivate'      { 'Inactivate'      }
            'WouldInactivate' { 'Would inactivate' }
            'AlreadyInactive' { 'Already inactive' }
            'NotInZN'         { 'Not found in ZN'  }
            default            { $r.Action          }
        }
        Write-Host ($col -f $r.Name, $r.Domain, $r.ADModified, $r.ZNStatus, $label) -ForegroundColor $color
    }

    if ($results.Count -gt $tableLimit) {
        Write-Host ''
        Write-Host "  … $($results.Count - $tableLimit) more rows not shown. Use -PassThru to retrieve all $($results.Count) results." -ForegroundColor DarkGray
    }
    Write-Host ''

    # ── Step 5: Apply changes (bulk batched API calls) ────────────────────────
    $countInactivated = 0
    $countFailed      = 0

    if (-not $isWhatIf -and $toProcess.Count -gt 0) {
        $target = "$($toProcess.Count) user$(if ($toProcess.Count -ne 1) { 's' })"
        if ($PSCmdlet.ShouldProcess($target, 'Inactivate in Zero Networks')) {
            for ($i = 0; $i -lt $toProcess.Count; $i += $BatchSize) {
                $batchEnd   = [Math]::Min($i + $BatchSize - 1, $toProcess.Count - 1)
                $batch      = @($toProcess[$i..$batchEnd])

                # Build shared comment: include whenChanged date range for this batch
                $dates = @(
                    $batch |
                    ForEach-Object { $_.AdUser.whenChanged } |
                    Where-Object   { $_ } |
                    Sort-Object
                )
                $commentParts = @('AD sync')
                if ($dates.Count -eq 1) {
                    $commentParts += "AD whenChanged: $($dates[0].ToString('yyyy-MM-dd'))"
                } elseif ($dates.Count -gt 1) {
                    $first = $dates[0].ToString('yyyy-MM-dd')
                    $last  = $dates[-1].ToString('yyyy-MM-dd')
                    $commentParts += "AD whenChanged range: $first to $last"
                }
                if ($Note) { $commentParts += "Note: $Note" }

                $body = @{
                    items   = @($batch | ForEach-Object { $_.ZNId })
                    comment = ($commentParts -join ' | ')
                } | ConvertTo-Json -Compress

                try {
                    Invoke-RestMethod `
                        -Uri     "$baseUrl/users/actions/inactivate" `
                        -Method  Post `
                        -Headers $headers `
                        -Body    $body | Out-Null

                    foreach ($entry in $batch) {
                        $entry.Row.Action = 'Inactivated'
                        $countInactivated++
                    }
                }
                catch {
                    $code    = $_.Exception.Response.StatusCode.value__
                    $errBody = Get-ZNErrorBody $_
                    $errMsg  = try { ($errBody | ConvertFrom-Json).message } catch { $null }

                    if ($errMsg -eq 'Permission Denied') {
                        Write-Error 'Inactivate failed: ZN API key requires write scope.'
                        return
                    }
                    Write-Warning "Batch $([Math]::Floor($i / $BatchSize) + 1) failed: Status $code ($($batch.Count) users affected)"
                    if ($errBody) { Write-Warning "Response body: $errBody" }
                    foreach ($entry in $batch) {
                        $entry.Row.Action = 'Failed'
                        $countFailed++
                    }
                }
            }
        }
    }

    # ── Step 6: Summary ───────────────────────────────────────────────────────
    $countWillAct = @($results | Where-Object Action -in 'WouldInactivate', 'Inactivate').Count
    $countAlready = @($results | Where-Object Action -eq 'AlreadyInactive').Count
    $countNotInZN = @($results | Where-Object Action -eq 'NotInZN').Count

    $parts = if ($isWhatIf) {
        @(
            "$countWillAct would be inactivated",
            "$countAlready already inactive",
            "$countNotInZN not found in ZN"
        )
    } else {
        $p = @(
            "$countInactivated inactivated",
            "$countAlready already inactive",
            "$countNotInZN not found in ZN"
        )
        if ($countFailed -gt 0) { $p += "$countFailed failed" }
        $p
    }

    $summaryColor = if ($isWhatIf) { 'Cyan' } elseif ($countFailed -gt 0) { 'Yellow' } else { 'Green' }
    $prefix       = if ($isWhatIf) { '  Summary (WhatIf): ' } else { '  Summary: ' }

    Write-Host ($prefix + ($parts -join ' | ')) -ForegroundColor $summaryColor
    Write-Host ''

    # ── Step 7: WhatIf performance recommendations ────────────────────────────
    if ($isWhatIf) {
        # Query ZN audit log for the most recent previous sync from this tool.
        # Our runs are identifiable by the "AD sync" prefix in the details field.
        $lastSyncDate = $null
        try {
            $auditSearch = [Uri]::EscapeDataString('AD sync')
            $auditResp   = Invoke-RestMethod `
                -Uri     "$baseUrl/audit?_limit=1&_search=$auditSearch&order=desc" `
                -Method  Get `
                -Headers $headers
            $lastAudit   = if ($auditResp.items) { @($auditResp.items)[0] } else { $null }
            if ($lastAudit -and $lastAudit.details -match '^AD sync') {
                $lastSyncDate = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$lastAudit.timestamp).LocalDateTime
            }
        }
        catch { }  # Non-fatal — recommendations are advisory

        $batchCount   = [Math]::Ceiling($countWillAct / $BatchSize)
        $hasRec       = $lastSyncDate -or
                        (-not $SearchBase -and $disabledAdUsers.Count -gt 500) -or
                        $results.Count -gt $tableLimit -or
                        $countWillAct -gt 0

        if ($hasRec) {
            Write-Host '  Performance Recommendations' -ForegroundColor Cyan
            Write-Host ('  ' + ('─' * 62)) -ForegroundColor DarkGray
            Write-Host ''

            if ($results.Count -gt $tableLimit) {
                Write-Host "  • Table capped at $tableLimit rows ($($results.Count) total)." -ForegroundColor DarkGray
                Write-Host "    Add -PassThru and pipe to Export-Csv or Where-Object for the full set." -ForegroundColor DarkGray
                Write-Host ''
            }

            if ($lastSyncDate) {
                $sinceSuggestion = $lastSyncDate.Date.ToString('yyyy-MM-dd')
                Write-Host "  • Previous sync detected: $($lastSyncDate.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Yellow
                Write-Host "    Use -Since '$sinceSuggestion' on the next run to limit the AD query" -ForegroundColor DarkGray
                Write-Host "    to accounts modified since that date, reducing scope significantly." -ForegroundColor DarkGray
                Write-Host "    Caution: -Since skips accounts disabled before the cutoff that were" -ForegroundColor DarkGray
                Write-Host "    not captured in the previous run." -ForegroundColor DarkGray
                Write-Host ''
            }

            if (-not $SearchBase -and $disabledAdUsers.Count -gt 500) {
                Write-Host "  • $($disabledAdUsers.Count) disabled accounts found scanning the full domain." -ForegroundColor Yellow
                Write-Host "    Use -SearchBase to scope the AD query to a specific OU:" -ForegroundColor DarkGray
                Write-Host "    -SearchBase 'OU=Users,DC=corp,DC=example,DC=com'" -ForegroundColor DarkGray
                Write-Host ''
            }

            if ($countWillAct -gt 0) {
                $callWord = if ($batchCount -eq 1) { 'call' } else { 'calls' }
                Write-Host "  • $countWillAct accounts to inactivate → $batchCount bulk API $callWord at -BatchSize $BatchSize." -ForegroundColor DarkGray
                if ($countWillAct -gt $BatchSize) {
                    Write-Host "    Increase -BatchSize (max 400) to reduce API calls further." -ForegroundColor DarkGray
                }
                Write-Host ''
            }
        }

        Write-Host '  Run without -WhatIf to apply.' -ForegroundColor DarkGray
        Write-Host ''
    }

    # ── Step 8: PassThru ──────────────────────────────────────────────────────
    if ($PassThru) {
        $results | Select-Object Name, Domain, ADModified, ZNStatus, Action, ZNUserId, SID
    }
}
