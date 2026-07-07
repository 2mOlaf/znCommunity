function Get-SecurityEventRate {
    <#
    .SYNOPSIS
        Shows average and peak rates per second for one or more Security-log Event IDs.
    .AUTHOR
        Olaf Gradin
    .DESCRIPTION
        Queries the Security event log for the specified Event ID(s) over a specified period and
        reports average and peak events-per-second rates per ID and combined, plus estimated event
        log write throughput in KB/s or MB/s derived by sampling event XML sizes.

        Defaults to EventId 5156 (WFP connection allowed) and 5157 (WFP connection blocked) — the
        original purpose of this command. Pass -EventId to measure the rate of any other Event
        ID(s), e.g. the Top N Event IDs surfaced by Get-SecurityLogAnalysis.

        Peak rate is computed from 1-second buckets for periods up to 1 hour, and from 1-minute
        buckets (normalized to per-second) for longer periods.

        When -ComputerName is specified the entire query and computation runs remotely via
        Invoke-Command (WinRM), so only the final numbers are returned across the wire.
    .PARAMETER Period
        Time period to analyze. Suffix with 'h' for hours (e.g. '1h', '4h', '24h') or 'd' for days
        (e.g. '1d', '7d'). Must be a positive integer followed by 'h' or 'd'.
    .PARAMETER EventId
        One or more Security-log Event IDs to measure. Default: 5156, 5157 (WFP connections).
    .PARAMETER ComputerName
        Optional. Run the query against a remote machine via WinRM (PSRemoting). Requires the
        Windows Remote Management service to be running and accessible on the target.
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
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^\d+(h|d)$')]
        [string]$Period,

        [int[]]$EventId = @(5156, 5157),

        [string]$ComputerName,

        [PSCredential]$Credential
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    $null = $Period -match '^(\d+)(h|d)$'
    $value = [int]$Matches[1]
    $unit  = $Matches[2]

    $endTime   = Get-Date
    $startTime = if ($unit -eq 'h') { $endTime.AddHours(-$value) } else { $endTime.AddDays(-$value) }
    $unitWord  = if ($unit -eq 'h') { if ($value -eq 1) { 'hour' } else { 'hours' } } `
                 else               { if ($value -eq 1) { 'day'  } else { 'days'  } }
    $periodLabel  = "$value $unitWord"
    $totalSeconds = ($endTime - $startTime).TotalSeconds
    $bucketSec    = if ($totalSeconds -le 3600) { 1 } else { 60 }

    $target = if ($ComputerName) { $ComputerName } else { 'localhost' }
    $idList = $EventId -join ', '

    Write-Host ""
    Write-Host "  Security Event Rate Analysis" -ForegroundColor Cyan
    Write-Host "  Target   : $target" -ForegroundColor DarkGray
    Write-Host "  Event ID : $idList" -ForegroundColor DarkGray
    Write-Host "  Period   : Last $periodLabel" -ForegroundColor DarkGray
    Write-Host "  From     : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
    Write-Host "  To       : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
    Write-Host ""

    $queryMsg = if ($ComputerName) { "  Querying Security event log on $ComputerName for EventId $idList..." }
                else               { "  Querying Security event log for EventId $idList..." }
    Write-Host $queryMsg -ForegroundColor Yellow

    # All heavy work runs inside this block — locally via & or remotely via Invoke-Command.
    # Keeping computation co-located with the events avoids deserializing raw event objects
    # across the wire and means .ToXml() is always available for size sampling.
    # Time window is computed inside the block so the filter always uses the target machine's
    # local clock — passing DateTime objects across WinRM boundaries causes timezone shifts.
    $computeBlock = {
        param($TotalSeconds, $BucketSec, $EventIds)

        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

        $endTime   = Get-Date
        $startTime = $endTime.AddSeconds(-$TotalSeconds)

        $filterHash = @{
            LogName   = 'Security'
            Id        = $EventIds
            StartTime = $startTime
            EndTime   = $endTime
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
        $countsById  = @{}
        $bucketsById = @{}
        foreach ($id in $EventIds) { $countsById[$id] = 0L; $bucketsById[$id] = @{} }
        $bucketsAll = @{}

        foreach ($evt in $events) {
            $id = $evt.Id
            if (-not $countsById.ContainsKey($id)) { $countsById[$id] = 0L; $bucketsById[$id] = @{} }
            $countsById[$id]++

            $slot = [long][math]::Floor(($evt.TimeCreated - $startTime).TotalSeconds / $BucketSec)
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

        [PSCustomObject]@{
            AccessDenied = $false
            IsAdmin      = $isAdmin
            Total        = $events.Count
            CountsById   = $countsById
            BucketsById  = $bucketsById
            BucketsAll   = $bucketsAll
            AvgEvtBytes  = $avgEvtBytes
            SampleCount  = $sampleCount
        }
    }

    if ($ComputerName) {
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $computeBlock
            ArgumentList = $totalSeconds, $bucketSec, $EventId
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
            $result = & $computeBlock $totalSeconds $bucketSec $EventId
        } catch {
            Write-Error "Failed to query Security event log: $($_.Exception.Message)"
            return
        }
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
