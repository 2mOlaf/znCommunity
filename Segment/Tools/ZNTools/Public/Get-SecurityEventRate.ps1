function Get-SecurityEventRate {
    <#
    .SYNOPSIS
        Shows average and peak rates per second for WFP security events 5156 (allowed) and 5157 (blocked).
    .AUTHOR
        Olaf Gradin
    .DESCRIPTION
        Queries the Security event log for Windows Filtering Platform connection events
        (EventId 5156 — permitted, EventId 5157 — blocked) over a specified period and reports
        average and peak events-per-second rates for each event type and combined, plus
        estimated event log write throughput in KB/s or MB/s derived by sampling event XML sizes.

        Peak rate is computed from 1-second buckets for periods up to 1 hour, and from 1-minute
        buckets (normalized to per-second) for longer periods.

        When -ComputerName is specified the entire query and computation runs remotely via
        Invoke-Command (WinRM), so only the final numbers are returned across the wire.
    .PARAMETER Period
        Time period to analyze. Suffix with 'h' for hours (e.g. '1h', '4h', '24h') or 'd' for days
        (e.g. '1d', '7d'). Must be a positive integer followed by 'h' or 'd'.
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
        $cred = Get-Credential
        Get-ZNSecurityEventRate -Period 1d -ComputerName segment01.zero.local -Credential $cred
        Shows WFP event rates on segment01 for the last day, authenticating with explicit credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^\d+(h|d)$')]
        [string]$Period,

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

    Write-Host ""
    Write-Host "  WFP Security Event Rate Analysis" -ForegroundColor Cyan
    Write-Host "  Target : $target" -ForegroundColor DarkGray
    Write-Host "  Period : Last $periodLabel" -ForegroundColor DarkGray
    Write-Host "  From   : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
    Write-Host "  To     : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
    Write-Host ""

    $queryMsg = if ($ComputerName) { "  Querying Security event log on $ComputerName for EventId 5156 / 5157..." }
                else               { "  Querying Security event log for EventId 5156 / 5157..." }
    Write-Host $queryMsg -ForegroundColor Yellow

    # All heavy work runs inside this block — locally via & or remotely via Invoke-Command.
    # Keeping computation co-located with the events avoids deserializing raw event objects
    # across the wire and means .ToXml() is always available for size sampling.
    # Time window is computed inside the block so the filter always uses the target machine's
    # local clock — passing DateTime objects across WinRM boundaries causes timezone shifts.
    $computeBlock = {
        param($TotalSeconds, $BucketSec)

        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

        $endTime   = Get-Date
        $startTime = $endTime.AddSeconds(-$TotalSeconds)

        $filterHash = @{
            LogName   = 'Security'
            Id        = 5156, 5157
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

        $events5156 = @($events | Where-Object Id -eq 5156)
        $events5157 = @($events | Where-Object Id -eq 5157)

        $avg5156 = [math]::Round($events5156.Count / $TotalSeconds, 4)
        $avg5157 = [math]::Round($events5157.Count / $TotalSeconds, 4)
        $avgAll  = [math]::Round($events.Count     / $TotalSeconds, 4)

        $buckets5156 = @{}; $buckets5157 = @{}; $bucketsAll = @{}
        foreach ($evt in $events) {
            $slot = [long][math]::Floor(($evt.TimeCreated - $startTime).TotalSeconds / $BucketSec)
            if ($evt.Id -eq 5156) {
                if ($buckets5156.ContainsKey($slot)) { $buckets5156[$slot]++ } else { $buckets5156[$slot] = 1 }
            } else {
                if ($buckets5157.ContainsKey($slot)) { $buckets5157[$slot]++ } else { $buckets5157[$slot] = 1 }
            }
            if ($bucketsAll.ContainsKey($slot)) { $bucketsAll[$slot]++ } else { $bucketsAll[$slot] = 1 }
        }

        $peak5156 = if ($buckets5156.Count) { [math]::Round(($buckets5156.Values | Measure-Object -Maximum).Maximum / $BucketSec, 4) } else { 0 }
        $peak5157 = if ($buckets5157.Count) { [math]::Round(($buckets5157.Values | Measure-Object -Maximum).Maximum / $BucketSec, 4) } else { 0 }
        $peakAll  = if ($bucketsAll.Count)  { [math]::Round(($bucketsAll.Values  | Measure-Object -Maximum).Maximum / $BucketSec, 4) } else { 0 }

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
            Count5156    = $events5156.Count
            Count5157    = $events5157.Count
            Avg5156      = $avg5156
            Avg5157      = $avg5157
            AvgAll       = $avgAll
            Peak5156     = $peak5156
            Peak5157     = $peak5157
            PeakAll      = $peakAll
            AvgEvtBytes  = $avgEvtBytes
            SampleCount  = $sampleCount
        }
    }

    if ($ComputerName) {
        $invokeParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $computeBlock
            ArgumentList = $totalSeconds, $bucketSec
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
            $result = & $computeBlock $totalSeconds $bucketSec
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

        Write-Host "  Verify audit policy:  auditpol /get /subcategory:'Filtering Platform Connection'" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    function Format-DataRate {
        param([double]$Bps)
        if ($Bps -ge 1MB) { "$([math]::Round($Bps / 1MB, 2)) MB/s" }
        else               { "$([math]::Round($Bps / 1KB, 2)) KB/s" }
    }

    $avgBps5156  = $result.Avg5156  * $result.AvgEvtBytes
    $avgBps5157  = $result.Avg5157  * $result.AvgEvtBytes
    $avgBpsAll   = $result.AvgAll   * $result.AvgEvtBytes
    $peakBps5156 = $result.Peak5156 * $result.AvgEvtBytes
    $peakBps5157 = $result.Peak5157 * $result.AvgEvtBytes
    $peakBpsAll  = $result.PeakAll  * $result.AvgEvtBytes

    $fmt = "  {0,-30} {1,7} {2,10} {3,10} {4,10} {5,10}"
    $sep = "-" * 30

    Write-Host ($fmt -f "Event", "Count", "Avg /sec", "Avg KB/s", "Peak /sec", "Peak KB/s") -ForegroundColor Cyan
    Write-Host ($fmt -f $sep, "-------", "----------", "----------", "----------", "----------") -ForegroundColor DarkGray
    Write-Host ($fmt -f "5156  WFP Permitted Connection", $result.Count5156, $result.Avg5156, (Format-DataRate $avgBps5156),  $result.Peak5156, (Format-DataRate $peakBps5156)) -ForegroundColor White
    Write-Host ($fmt -f "5157  WFP Blocked Connection",   $result.Count5157, $result.Avg5157, (Format-DataRate $avgBps5157),  $result.Peak5157, (Format-DataRate $peakBps5157)) -ForegroundColor White
    Write-Host ($fmt -f $sep, "-------", "----------", "----------", "----------", "----------") -ForegroundColor DarkGray
    Write-Host ($fmt -f "Total", $result.Total, $result.AvgAll, (Format-DataRate $avgBpsAll), $result.PeakAll, (Format-DataRate $peakBpsAll)) -ForegroundColor Green
    Write-Host ""
    Write-Host "  KB/s = Security event log write rate  (avg event size: $([math]::Round($result.AvgEvtBytes / 1KB, 1)) KB, sampled $($result.SampleCount) of $($result.Total) events)" -ForegroundColor DarkGray
    Write-Host ""

    if ($bucketSec -eq 60) {
        Write-Host "  Note: Peak calculated from 1-minute windows, normalized to events/sec." -ForegroundColor DarkGray
        Write-Host ""
    }
}
