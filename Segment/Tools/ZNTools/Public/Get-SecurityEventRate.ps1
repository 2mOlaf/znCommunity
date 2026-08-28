function Get-SecurityEventRate {
    <#
    .SYNOPSIS
        Shows average and peak rates per second for one or more Security-log Event IDs.
    .NOTES
        Author: Olaf Gradin
    .DESCRIPTION
        Queries the Security event log (live, remote, or an offline .evtx archive) for the
        specified Event ID(s) and reports average and peak events-per-second rates per ID and
        combined, plus estimated event log write throughput in KB/s or MB/s derived by sampling
        event XML sizes.

        Defaults to EventId 5156 (WFP connection allowed) and 5157 (WFP connection blocked) — the
        original purpose of this command. Pass -EventId to measure the rate of any other Event
        ID(s), e.g. the Top N Event IDs surfaced by Get-SecurityLogAnalysis.

        Peak rate is computed from 1-second buckets for periods up to 1 hour, and from 1-minute
        buckets (normalized to per-second) for longer periods or whenever -LogPath is used without
        -Period.

        When -ComputerName is specified the entire query and computation runs remotely via
        Invoke-Command (WinRM), so only the final numbers are returned across the wire.

        When -LogPath is specified instead, -Period becomes optional: omit it to compute rates
        over the entire span of matching events observed in the file, or supply it to look back
        from the newest matching event in the file (not the current time — an archived file has
        no meaningful "now").
    .PARAMETER Period
        Time period to analyze. Suffix with 'h' for hours (e.g. '1h', '4h', '24h') or 'd' for days
        (e.g. '1d', '7d'). Must be a positive integer followed by 'h' or 'd'.

        Required for live/remote queries. Optional with -LogPath: when supplied, the window is
        measured backward from the most recent matching event in the file; when omitted, the
        entire observed span of matching events in the file is used.
    .PARAMETER EventId
        One or more Security-log Event IDs to measure. Default: 5156, 5157 (WFP connections).
    .PARAMETER LogPath
        Path to an offline .evtx archive to analyze instead of a live log. Mutually exclusive
        with -ComputerName. See -Period for how the analysis window is determined in this mode.
    .PARAMETER ComputerName
        Optional. Run the query against a remote machine via WinRM (PSRemoting). Requires the
        Windows Remote Management service to be running and accessible on the target. Mutually
        exclusive with -LogPath.
    .PARAMETER Credential
        Optional. PSCredential to authenticate the remote session. Only used with -ComputerName.
    .EXAMPLE
        Get-ZNSecurityEventRate -Period 1h
        Shows WFP event rates on the local machine for the last 1 hour.
    .EXAMPLE
        Get-ZNSecurityEventRate -Period 4h -ComputerName segment01.zero.local
        Shows WFP event rates on segment01 for the last 4 hours using the current session identity.
    .EXAMPLE
        Get-ZNSecurityEventRate -Period 1h -EventId 4688, 4689
        Shows process creation/exit rates for the last hour.
    .EXAMPLE
        $cred = Get-Credential
        Get-ZNSecurityEventRate -Period 1d -ComputerName segment01.zero.local -Credential $cred
        Shows WFP event rates on segment01 for the last day, authenticating with explicit credentials.
    .EXAMPLE
        Get-ZNSecurityEventRate -LogPath "E:\Logs\Archive-Security-2026-07-05.evtx"
        Shows WFP event rates over the entire span of matching events in the archive.
    .EXAMPLE
        Get-ZNSecurityEventRate -LogPath "E:\Logs\Archive-Security-2026-07-05.evtx" -Period 4h -EventId 4688, 4689
        Shows process creation/exit rates for the 4 hours leading up to the newest matching event
        in the archive.
    #>
    [CmdletBinding()]
    param(
        [ValidatePattern('^\d+(h|d)$')]
        [string]$Period,

        [int[]]$EventId = @(5156, 5157),

        [Parameter(HelpMessage = 'Path to an offline .evtx archive')]
        [string]$LogPath,

        [string]$ComputerName,

        [PSCredential]$Credential
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    if ($LogPath -and $ComputerName) {
        Write-Error '-LogPath and -ComputerName are mutually exclusive.'
        return
    }
    if (-not $LogPath -and -not $Period) {
        Write-Error '-Period is required unless -LogPath is specified (offline files default to the entire observed span in the file).'
        return
    }

    if ($LogPath) {
        $requestedLogPath = $LogPath
        $LogPath = (Resolve-Path -LiteralPath $LogPath -ErrorAction SilentlyContinue)?.Path
        if (-not $LogPath) {
            Write-Error "File not found: $requestedLogPath"
            return
        }
        if ([System.IO.Path]::GetExtension($LogPath) -ne '.evtx') {
            Write-Warning "File extension is not .evtx — will attempt to read anyway."
        }
    }

    $idList = $EventId -join ', '
    $target = if ($LogPath) { "$(Split-Path $LogPath -Leaf) (offline file)" }
              elseif ($ComputerName) { $ComputerName }
              else { 'localhost' }

    $periodValue = $null
    $periodUnit  = $null
    if ($Period) {
        $null = $Period -match '^(\d+)(h|d)$'
        $periodValue = [int]$Matches[1]
        $periodUnit  = $Matches[2]
    }
    $unitWord = if ($periodUnit -eq 'h') { if ($periodValue -eq 1) { 'hour' } else { 'hours' } }
                elseif ($periodUnit -eq 'd') { if ($periodValue -eq 1) { 'day' } else { 'days' } }
                else { $null }

    # FullSpan mode: offline file, no -Period. The window can't be known ahead of time — there's
    # no "now" to anchor to and no time index in a .evtx — so it's only known once the file has
    # been read and the actual first/last matching-event timestamps are in hand.
    $fullSpan = [bool]($LogPath -and -not $Period)

    $startTime    = $null
    $endTime      = $null
    $totalSeconds = 0
    $bucketSec    = 60

    if (-not $fullSpan) {
        if ($LogPath) {
            # Anchor -Period to the newest matching event in the file rather than wall-clock "now".
            # Get-WinEvent returns offline .evtx events newest-first by default, so -MaxEvents 1
            # finds it without scanning the rest of the file.
            try {
                $anchorEvt = Get-WinEvent -FilterHashtable @{ Path = $LogPath; Id = $EventId } -MaxEvents 1 -ErrorAction Stop
            } catch {
                if ($_.Exception.Message -match 'No events were found') { $anchorEvt = $null }
                else {
                    Write-Error "Failed to read ${LogPath}: $($_.Exception.Message)"
                    return
                }
            }
            if (-not $anchorEvt) {
                Write-Host ""
                Write-Host "  No events found for EventId $idList in $LogPath." -ForegroundColor Yellow
                Write-Host ""
                return
            }
            $endTime = $anchorEvt.TimeCreated
        } else {
            $endTime = Get-Date
        }
        $startTime    = if ($periodUnit -eq 'h') { $endTime.AddHours(-$periodValue) } else { $endTime.AddDays(-$periodValue) }
        $totalSeconds = ($endTime - $startTime).TotalSeconds
        $bucketSec    = if ($totalSeconds -le 3600) { 1 } else { 60 }
    }

    Write-Host ""
    Write-Host "  Security Event Rate Analysis" -ForegroundColor Cyan
    Write-Host "  Target   : $target" -ForegroundColor DarkGray
    Write-Host "  Event ID : $idList" -ForegroundColor DarkGray
    if ($fullSpan) {
        Write-Host "  Period   : Entire file (observed span, computed after reading)" -ForegroundColor DarkGray
    } else {
        Write-Host "  Period   : Last $periodValue $unitWord$(if ($LogPath) { ' (anchored to newest matching event in file)' })" -ForegroundColor DarkGray
        Write-Host "  From     : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
        Write-Host "  To       : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
    }
    Write-Host ""

    $queryMsg = if ($LogPath) { "  Reading $LogPath for EventId $idList..." }
                elseif ($ComputerName) { "  Querying Security event log on $ComputerName for EventId $idList..." }
                else               { "  Querying Security event log for EventId $idList..." }
    Write-Host $queryMsg -ForegroundColor Yellow

    # All heavy work runs inside this block — locally via & or remotely via Invoke-Command.
    # Keeping computation co-located with the events avoids deserializing raw event objects
    # across the wire and means .ToXml() is always available for size sampling.
    # For live/remote queries, StartTime/EndTime are computed inside the block (using the target
    # machine's own clock) unless explicitly supplied — passing DateTime objects across WinRM
    # boundaries causes timezone shifts. For an offline file, StartTime/EndTime are always
    # supplied by the caller (anchored to the file's own timestamps, not a machine clock) except
    # in FullSpan mode, where there's no window to filter by yet — every matching event is read
    # and the observed first/last timestamps become the window after the fact.
    # $FullSpan is a plain boolean, not [switch] — ArgumentList/positional invocation binds
    # switch parameters unreliably (a positionally-passed $true silently becomes False).
    $computeBlock = {
        param($TotalSeconds, $BucketSec, $EventIds, $Path, $StartTime, $EndTime, $FullSpan)

        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

        $filterHash = @{ Id = $EventIds }
        if ($Path) { $filterHash.Path = $Path } else { $filterHash.LogName = 'Security' }

        if (-not $FullSpan) {
            if (-not $StartTime) {
                $EndTime   = Get-Date
                $StartTime = $EndTime.AddSeconds(-$TotalSeconds)
            }
            $filterHash.StartTime = $StartTime
            $filterHash.EndTime   = $EndTime
        }

        try {
            $events = @(Get-WinEvent -FilterHashtable $filterHash -ErrorAction Stop)
        } catch {
            if ($_.Exception.Message -match 'No events were found') {
                $events = @()
            } elseif ($_.Exception.Message -match 'Access is denied' -or $_.CategoryInfo.Category -eq 'PermissionDenied') {
                return [PSCustomObject]@{ AccessDenied = $true; IsAdmin = $isAdmin }
            } else {
                throw
            }
        }

        # Per-ID counts and rate buckets, plus a combined "all IDs" bucket set for the total row.
        # Bucket key is derived from each event's own absolute timestamp (ticks), not an offset
        # from a known StartTime — this lets FullSpan mode bucket correctly even though the
        # window isn't known until after every matching event has been read.
        $ticksPerBucket = [long]$BucketSec * 10000000L

        $countsById  = @{}
        $bucketsById = @{}
        foreach ($id in $EventIds) { $countsById[$id] = 0L; $bucketsById[$id] = @{} }
        $bucketsAll = @{}

        $logStart = [DateTime]::MaxValue
        $logEnd   = [DateTime]::MinValue

        foreach ($evt in $events) {
            $id = $evt.Id
            if (-not $countsById.ContainsKey($id)) { $countsById[$id] = 0L; $bucketsById[$id] = @{} }
            $countsById[$id]++

            $ts = $evt.TimeCreated
            if ($FullSpan) {
                if ($ts -lt $logStart) { $logStart = $ts }
                if ($ts -gt $logEnd)   { $logEnd   = $ts }
            }

            $slot = [long][math]::Floor($ts.Ticks / $ticksPerBucket)
            $idBuckets = $bucketsById[$id]
            if ($idBuckets.ContainsKey($slot)) { $idBuckets[$slot]++ } else { $idBuckets[$slot] = 1 }
            if ($bucketsAll.ContainsKey($slot)) { $bucketsAll[$slot]++ } else { $bucketsAll[$slot] = 1 }
        }

        $sampleMax = [math]::Min(100, $events.Count)
        $step = [math]::Max(1, [int][math]::Floor($events.Count / [math]::Max(1, $sampleMax)))
        $totalSampleBytes = 0; $sampleCount = 0
        for ($i = 0; $i -lt $events.Count -and $sampleCount -lt $sampleMax; $i += $step) {
            $totalSampleBytes += [System.Text.Encoding]::UTF8.GetByteCount($events[$i].ToXml())
            $sampleCount++
        }
        $avgEvtBytes = if ($sampleCount -gt 0) { $totalSampleBytes / $sampleCount } else { 0 }

        $observedSeconds = if ($FullSpan -and $logStart -ne [DateTime]::MaxValue) { ($logEnd - $logStart).TotalSeconds } else { $TotalSeconds }

        [PSCustomObject]@{
            AccessDenied    = $false
            IsAdmin         = $isAdmin
            Total           = $events.Count
            CountsById      = $countsById
            BucketsById     = $bucketsById
            BucketsAll      = $bucketsAll
            AvgEvtBytes     = $avgEvtBytes
            SampleCount     = $sampleCount
            ObservedStart   = if ($FullSpan) { $logStart } else { $StartTime }
            ObservedEnd     = if ($FullSpan) { $logEnd } else { $EndTime }
            ObservedSeconds = $observedSeconds
        }
    }

    if ($ComputerName) {
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $computeBlock
            ArgumentList = $totalSeconds, $bucketSec, $EventId, $null, $null, $null, $false
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $invokeParams.Credential = $Credential }
        try {
            $result = Invoke-Command @invokeParams
        } catch {
            Write-Host ""
            Write-Error "Failed to connect to ${ComputerName}: $($_.Exception.Message)"
            return
        }
    } else {
        try {
            $result = & $computeBlock $totalSeconds $bucketSec $EventId $LogPath $startTime $endTime $fullSpan
        } catch {
            Write-Error "Failed to query Security event log: $($_.Exception.Message)"
            return
        }
    }

    if (-not $result.AccessDenied -and $fullSpan -and $result.Total -gt 0) {
        $totalSeconds = $result.ObservedSeconds
        $startTime    = $result.ObservedStart
        $endTime      = $result.ObservedEnd
        Write-Host "  Observed span: $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) -> $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))  ($([math]::Round($totalSeconds / 3600, 1)) hours)" -ForegroundColor DarkGray
        Write-Host ""
    }

    if ($result.AccessDenied) {
        Write-Host ""
        Write-Host "  Access denied reading the Security event log$(if ($ComputerName) { " on $ComputerName" })." -ForegroundColor Red
        Write-Host "  Re-run this command in an elevated (Administrator) session." -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    Write-Host "  Found $($result.Total) event$(if ($result.Total -ne 1) { 's' })." -ForegroundColor DarkGray
    Write-Host ""

    if ($result.Total -eq 0) {
        Write-Host "  No events found for the specified period." -ForegroundColor Yellow
        Write-Host ""

        if (-not $result.IsAdmin) {
            Write-Host "  The Security event log requires Administrator privileges." -ForegroundColor Red
            Write-Host "  Re-run this command in an elevated (Administrator) session." -ForegroundColor DarkGray
            Write-Host ""
        }

        Write-Host "  Verify audit policy:  auditpol /get /category:*" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    function Format-DataRate {
        param([double]$Bps)
        if ($Bps -ge 1MB) { "$([math]::Round($Bps / 1MB, 2)) MB/s" }
        else               { "$([math]::Round($Bps / 1KB, 2)) KB/s" }
    }

    # Per-ID rate stats share the same bucket math Get-SecurityLogAnalysis uses, so "events/sec"
    # means the same thing everywhere in this module.
    $perEvent = foreach ($id in $EventId) {
        $rate = Get-ZNBucketedRate -Buckets $result.BucketsById[$id] -Count $result.CountsById[$id] `
            -TotalSeconds $totalSeconds -BucketSeconds $bucketSec
        [PSCustomObject]@{
            EventID     = $id
            Description = $script:ZNSecurityEventDescriptions[$id] ?? "EventID $id"
            ZNRequired  = $id -in $script:ZNRequiredEventIds
            Count       = $rate.Count
            Avg         = $rate.Avg
            Peak        = $rate.Peak
        }
    }
    $totalRate = Get-ZNBucketedRate -Buckets $result.BucketsAll -Count $result.Total `
        -TotalSeconds $totalSeconds -BucketSeconds $bucketSec

    $fmt = "  {0,-34} {1,7} {2,10} {3,10} {4,10} {5,10}"
    $sep = "-" * 34

    Write-Host ($fmt -f "Event", "Count", "Avg /sec", "Avg KB/s", "Peak /sec", "Peak KB/s") -ForegroundColor Cyan
    Write-Host ($fmt -f $sep, "-------", "----------", "----------", "----------", "----------") -ForegroundColor DarkGray

    $anyRequired = $false
    foreach ($row in $perEvent) {
        $avgBps  = $row.Avg  * $result.AvgEvtBytes
        $peakBps = $row.Peak * $result.AvgEvtBytes
        $marker  = if ($row.ZNRequired) { $anyRequired = $true; ' *' } else { '' }
        $label   = "$($row.EventID)  $($row.Description)$marker"
        Write-Host ($fmt -f $label, $row.Count, $row.Avg, (Format-DataRate $avgBps), $row.Peak, (Format-DataRate $peakBps)) -ForegroundColor White
    }

    Write-Host ($fmt -f $sep, "-------", "----------", "----------", "----------", "----------") -ForegroundColor DarkGray
    $totalAvgBps  = $totalRate.Avg  * $result.AvgEvtBytes
    $totalPeakBps = $totalRate.Peak * $result.AvgEvtBytes
    Write-Host ($fmt -f "Total", $totalRate.Count, $totalRate.Avg, (Format-DataRate $totalAvgBps), $totalRate.Peak, (Format-DataRate $totalPeakBps)) -ForegroundColor Green
    Write-Host ""

    if ($anyRequired) {
        Write-Host "  * Required for Zero Networks segmentation — this audit subcategory must remain enabled." -ForegroundColor DarkYellow
    }

    Write-Host "  KB/s = Security event log write rate  (avg event size: $([math]::Round($result.AvgEvtBytes / 1KB, 1)) KB, sampled $($result.SampleCount) of $($result.Total) events)" -ForegroundColor DarkGray
    Write-Host ""

    if ($bucketSec -eq 60) {
        Write-Host "  Note: Peak calculated from 1-minute windows, normalized to events/sec." -ForegroundColor DarkGray
        Write-Host ""
    }
}
