function Get-SecurityLogAnalysis {
    <#
    .SYNOPSIS
        Analyze the Windows Security event log to identify top Event IDs by count, rate, and
        estimated storage size — to understand why your log is wrapping.

    .DESCRIPTION
        Reads the Security log (live or from an offline .evtx archive) and builds two ranked
        tables:
          1. Top Event IDs by COUNT  — what fires most often (includes avg/peak events-per-second)
          2. Top Event IDs by SIZE   — what consumes the most storage

        Rate is computed with the same bucket math as Get-SecurityEventRate (see
        Get-ZNBucketedRate), from timestamps collected during this same read pass — so no second
        pass over the log is needed, and it works against offline .evtx files too.

        Size is estimated by sampling the XML representation of the first N events per Event ID
        and extrapolating. .evtx binary storage is more compact than raw XML, so treat the size
        column as a relative indicator, not an absolute byte count.

        Event IDs that Zero Networks segmentation depends on (see $script:ZNRequiredEventIds) are
        flagged with a "*" in both tables and in the CSV export — those audit subcategories must
        stay enabled even if this analysis shows them as high-volume.

        Designed for Domain Controllers, member servers, and workstations. Currently analyzes the
        Security log only, but -LogPath will happily read any .evtx you point it at — if that's a
        different channel (e.g. System, or Windows Firewall With Advanced Security), IDs from that
        channel are already recognized (see $script:ZNSecurityEventDescriptions) since a couple of
        the Zero Networks -required IDs live outside the Security log.

    .NOTES
        Run as Administrator or with an account that has "Manage auditing and security log"
        or "Read" permission on the Security log.

        Common high-volume culprits on DCs:
          4769 — Kerberos service ticket requests (TGS) — can reach 1M+/hour
          4624/4634 — Logon/Logoff pairs
          5156/5158 — Windows Filtering Platform (disable DS Access auditing if not needed)
          4662/4663 — DS object / file object access (check SACL scope)
          4688/4689 — Process create/exit (if process audit is enabled)
          4703 — Token right adjusted (verbose; often safe to suppress via audit policy)
          4776 — NTLM authentication (indicates NTLM still in use)

        Author: Olaf Gradin

    .PARAMETER LogPath
        Path to an offline .evtx file. Mutually exclusive with -ComputerName.

    .PARAMETER TopN
        Number of top Event IDs to display per table. Default: 25.

    .PARAMETER MaxEvents
        Maximum events to read. Default: 500,000. Use 0 to read the entire log (slow on
        large files — a 4 GB log may contain 1–5 million events). Rate figures are only as
        accurate as the events actually read, same as the count/size figures.

    .PARAMETER SampleSize
        Number of events per Event ID to use for XML size sampling. Default: 100.
        Higher values give better size accuracy; lower values are faster.

    .PARAMETER Hours
        Restrict to events from the last N hours (live log only). Default: 0 (all events
        currently in the log).

    .PARAMETER ComputerName
        Remote computer whose live Security log to query. Requires WinRM / RPC access.

    .PARAMETER ExportCsv
        If specified, writes the full (all Event IDs, not just Top N) results to this
        CSV path.

    .EXAMPLE
        Get-ZNSecurityLogAnalysis
        Analyze the local live Security log, default settings.

    .EXAMPLE
        Get-ZNSecurityLogAnalysis -LogPath "E:\Logs\Archive-Security-2026-07-05.evtx"
        Analyze an offline archive.

    .EXAMPLE
        Get-ZNSecurityLogAnalysis -Hours 24 -MaxEvents 0 -TopN 30
        Full 24-hour analysis with no event cap, show top 30.

    .EXAMPLE
        Get-ZNSecurityLogAnalysis -ComputerName "DC01.corp.local" -ExportCsv "C:\Temp\DC01.csv"
        Query a remote DC and export results.

    .EXAMPLE
        # Queue up multiple offline archives (run from the folder containing the .evtx files)
        Get-ChildItem *.evtx | ForEach-Object {
            Get-ZNSecurityLogAnalysis -LogPath $_.FullName -ExportCsv "$($_.BaseName).csv"
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, HelpMessage = 'Path to an offline .evtx archive')]
        [string]$LogPath,

        [Parameter(HelpMessage = 'Top N event IDs to show per table (1-100)')]
        [ValidateRange(1, 100)]
        [int]$TopN = 25,

        [Parameter(HelpMessage = 'Max events to read; 0 = unlimited')]
        [ValidateRange(0, [long]::MaxValue)]
        [long]$MaxEvents = 500000,

        [Parameter(HelpMessage = 'Events per EventID to XML-sample for size (5-1000)')]
        [ValidateRange(5, 1000)]
        [int]$SampleSize = 100,

        [Parameter(HelpMessage = 'Restrict to last N hours (live log only; 0 = all)')]
        [ValidateRange(0, 8760)]
        [int]$Hours = 0,

        [Parameter(HelpMessage = 'Remote computer name')]
        [string]$ComputerName,

        [Parameter(HelpMessage = 'Export full results to this CSV path')]
        [string]$ExportCsv
    )

    # Scoped to this function only — does not affect the rest of the module's error handling.
    $ErrorActionPreference = 'Stop'

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    # ─── Formatting helpers ────────────────────────────────────────────────────

    function Format-Bytes {
        param([long]$n)
        if ($n -ge 1GB) { return '{0:N2} GB' -f ($n / 1GB) }
        if ($n -ge 1MB) { return '{0:N2} MB' -f ($n / 1MB) }
        if ($n -ge 1KB) { return '{0:N2} KB' -f ($n / 1KB) }
        return "$n B"
    }

    function Get-Bar {
        param([double]$Pct, [int]$Width = 24)
        $filled = [Math]::Max(0, [Math]::Min($Width, [Math]::Round($Pct / 100.0 * $Width)))
        return ('█' * $filled) + ('░' * ($Width - $filled))
    }

    function Write-SectionHeader {
        param([string]$Title)
        $bar = '─' * 78
        Write-Host "`n$bar" -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor White
        Write-Host "$bar" -ForegroundColor Cyan
    }

    # ─── Parameter validation ──────────────────────────────────────────────────

    if ($LogPath -and $ComputerName) {
        Write-Error '-LogPath and -ComputerName are mutually exclusive.'
        return
    }

    if ($LogPath) {
        $LogPath = (Resolve-Path -LiteralPath $LogPath -ErrorAction SilentlyContinue)?.Path
        if (-not $LogPath) {
            Write-Error "File not found: $LogPath"
            return
        }
        if ([System.IO.Path]::GetExtension($LogPath) -ne '.evtx') {
            Write-Warning "File extension is not .evtx — will attempt to read anyway."
        }
    }

    if ($ExportCsv) {
        $csvDir = Split-Path $ExportCsv -Parent
        if ($csvDir -and -not (Test-Path $csvDir)) {
            Write-Error "Export directory does not exist: $csvDir"
            return
        }
    }

    # ─── Build Get-WinEvent arguments ──────────────────────────────────────────

    $geArgs        = @{}
    $fileSizeLabel = $null

    if ($LogPath) {
        $geArgs.Path   = $LogPath
        $sourceLabel   = "Offline file  : $(Split-Path $LogPath -Leaf)"
        $fileSize      = (Get-Item $LogPath).Length
        $fileSizeLabel = "File size     : $(Format-Bytes $fileSize)"
    } else {
        $filter = @{ LogName = 'Security' }
        if ($Hours -gt 0) {
            $filter.StartTime = (Get-Date).AddHours(-$Hours)
        }
        $geArgs.FilterHashtable = $filter

        if ($ComputerName) {
            $geArgs.ComputerName = $ComputerName
            $sourceLabel = "Remote log    : Security on $ComputerName"
            try {
                $logInfo = Get-WinEvent -ListLog Security -ComputerName $ComputerName -ErrorAction SilentlyContinue
                if ($logInfo) {
                    # MaximumSizeInBytes is the effective configured max (GPO or local policy).
                    # Current file size requires filesystem access; skip for remote to avoid
                    # dependency on admin shares or WinRM file access.
                    $fileSizeLabel = "Max configured: $(Format-Bytes $logInfo.MaximumSizeInBytes)  (GPO/policy-enforced maximum)"
                }
            } catch { }
        } else {
            $sourceLabel = "Live log      : Security on $env:COMPUTERNAME"
            try {
                $logInfo = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
                if ($logInfo) {
                    # LogFilePath may contain %SystemRoot% — expand before calling Get-Item
                    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($logInfo.LogFilePath)
                    $currentSize  = (Get-Item -LiteralPath $expandedPath -ErrorAction SilentlyContinue)?.Length
                    $currentStr   = if ($null -ne $currentSize) { Format-Bytes $currentSize } else { 'unknown' }
                    # MaximumSizeInBytes is the effective configured max (reflects GPO if applied)
                    $fileSizeLabel = "Log file size : $currentStr  (max configured: $(Format-Bytes $logInfo.MaximumSizeInBytes))"
                }
            } catch { }
        }
    }

    if ($MaxEvents -gt 0) { $geArgs.MaxEvents = $MaxEvents }

    # ─── Run parameters display ────────────────────────────────────────────────

    Write-Host "  $sourceLabel" -ForegroundColor Yellow
    if ($fileSizeLabel) { Write-Host "  $fileSizeLabel" -ForegroundColor Yellow }
    if ($Hours -gt 0)   { Write-Host "  Time window   : Last $Hours hour(s)" -ForegroundColor Yellow }
    $maxLabel = if ($MaxEvents -eq 0) { 'unlimited (--all events--)' } else { ('{0:N0}' -f $MaxEvents) + ' event cap' }
    Write-Host "  Event limit   : $maxLabel" -ForegroundColor Yellow
    Write-Host "  Size sampling : First $SampleSize events per EventID" -ForegroundColor Yellow
    Write-Host "  Top N         : $TopN per table`n" -ForegroundColor Yellow

    if ($MaxEvents -gt 0) {
        Write-Host "  NOTE: With -MaxEvents $($MaxEvents.ToString('N0')), results reflect a sample of the log." -ForegroundColor DarkYellow
        Write-Host "        Use -MaxEvents 0 for a complete analysis (significantly slower).`n" -ForegroundColor DarkYellow
    }

    Write-Host "  Reading events... (large logs may take several minutes)`n" -ForegroundColor DarkYellow

    # ─── Event ingestion ───────────────────────────────────────────────────────
    # Rate buckets are collected here, in the same pass, so no second query against the log
    # is needed to get avg/peak events-per-second (see Get-ZNBucketedRate). Bucket key is
    # derived from the event's own timestamp ticks, so it doesn't depend on scan order or
    # knowing the log's start time up front. Fixed at 1-minute granularity — fine-grained
    # enough to be useful, coarse enough to stay cheap on multi-million-event logs.
    $BucketSeconds = 60
    $ticksPerBucket = [long]$BucketSeconds * 10000000L

    $counts      = [System.Collections.Generic.Dictionary[int, long]]::new()
    $xmlSizes    = [System.Collections.Generic.Dictionary[int, System.Collections.Generic.List[int]]]::new()
    $firstSeen   = [System.Collections.Generic.Dictionary[int, datetime]]::new()
    $lastSeen    = [System.Collections.Generic.Dictionary[int, datetime]]::new()
    $bucketsById = [System.Collections.Generic.Dictionary[int, System.Collections.Generic.Dictionary[long, int]]]::new()

    $totalRead  = [long]0
    $readStart  = [DateTime]::Now
    $logStart   = [DateTime]::MaxValue
    $logEnd     = [DateTime]::MinValue

    try {
        Get-WinEvent @geArgs -ErrorAction SilentlyContinue | ForEach-Object {
            $id = [int]$_.Id
            $ts = $_.TimeCreated

            # ── Track this event ID ──────────────────────────────────────────
            if (-not $counts.ContainsKey($id)) {
                $counts[$id]      = 0L
                $xmlSizes[$id]    = [System.Collections.Generic.List[int]]::new()
                $firstSeen[$id]   = $ts
                $lastSeen[$id]    = $ts
                $bucketsById[$id] = [System.Collections.Generic.Dictionary[long, int]]::new()
            }

            $counts[$id]++

            # ── Rate bucket for this event ───────────────────────────────────
            $bucketKey = [long][math]::Floor($ts.Ticks / $ticksPerBucket)
            $idBuckets = $bucketsById[$id]
            if ($idBuckets.ContainsKey($bucketKey)) { $idBuckets[$bucketKey]++ } else { $idBuckets[$bucketKey] = 1 }

            # ── Sample XML size (only up to SampleSize events per ID) ────────
            if ($xmlSizes[$id].Count -lt $SampleSize) {
                try {
                    $xmlSizes[$id].Add([System.Text.Encoding]::UTF8.GetByteCount($_.ToXml()))
                } catch {
                    # ToXml() can fail if the provider message template is unavailable
                    # (common with offline files from a different machine); skip silently
                }
            }

            # ── Track per-ID and overall time range ──────────────────────────
            if ($ts -lt $firstSeen[$id]) { $firstSeen[$id] = $ts }
            if ($ts -gt $lastSeen[$id])  { $lastSeen[$id]  = $ts }
            if ($ts -lt $logStart)       { $logStart = $ts }
            if ($ts -gt $logEnd)         { $logEnd   = $ts }

            $totalRead++

            # ── Progress update every 25k events ─────────────────────────────
            if ($totalRead % 25000 -eq 0) {
                $elapsed = ([DateTime]::Now - $readStart).TotalSeconds
                $rate    = if ($elapsed -gt 0) { [long]($totalRead / $elapsed) } else { 0 }
                Write-Progress -Activity 'Reading Security Events' `
                    -Status ('{0:N0} events  |  {1} unique IDs  |  {2:N0} evt/s' -f `
                        $totalRead, $counts.Count, $rate) `
                    -PercentComplete -1
            }
        }
    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -notmatch 'No events were found') {
            Write-Warning "Error during event read: $errMsg"
        }
    }

    Write-Progress -Activity 'Reading Security Events' -Completed

    $readDuration = [DateTime]::Now - $readStart

    # ─── Guard: no events ───────────────────────────────────────────────────────

    if ($totalRead -eq 0) {
        Write-Host "`n  No events were found with the specified criteria." -ForegroundColor Red
        if (-not $LogPath) {
            Write-Host "  Verify that Security auditing is enabled and you have log read permissions." -ForegroundColor DarkYellow
        }
        return
    }

    $logSpan = if ($logStart -ne [DateTime]::MaxValue) { $logEnd - $logStart } else { [TimeSpan]::Zero }

    # ─── Build result objects ───────────────────────────────────────────────────

    $results = foreach ($id in $counts.Keys) {
        $count   = $counts[$id]
        $samples = $xmlSizes[$id]

        if ($samples.Count -gt 0) {
            $avgBytes = [long]($samples | Measure-Object -Average).Average
        } else {
            $avgBytes = 0L   # no samples (ToXml unavailable for this ID)
        }

        $estTotalBytes = $avgBytes * $count
        $pctCount      = [Math]::Round($count / $totalRead * 100.0, 2)
        $desc          = $script:ZNSecurityEventDescriptions[$id] ?? '(unknown)'
        $span          = $lastSeen[$id] - $firstSeen[$id]
        $rate          = Get-ZNBucketedRate -Buckets $bucketsById[$id] -Count $count `
            -TotalSeconds $logSpan.TotalSeconds -BucketSeconds $BucketSeconds

        [PSCustomObject]@{
            EventID        = $id
            Description    = $desc
            ZNRequired     = $id -in $script:ZNRequiredEventIds
            Count          = $count
            PctOfTotal     = $pctCount
            AvgPerSec      = $rate.Avg
            PeakPerSec     = $rate.Peak
            AvgXmlBytes    = $avgBytes
            EstTotalBytes  = $estTotalBytes
            SampleCount    = $samples.Count
            FirstSeen      = $firstSeen[$id]
            LastSeen       = $lastSeen[$id]
            SpanMinutes    = [Math]::Round($span.TotalMinutes, 1)
        }
    }

    # Sort into the two views
    $byCount = $results | Sort-Object -Property Count -Descending
    $bySize  = $results | Sort-Object -Property EstTotalBytes -Descending

    # Grand totals
    $totalEstBytes = ($results | Measure-Object -Property EstTotalBytes -Sum).Sum
    $uniqueIDs     = $results.Count
    $anyRequired   = ($results | Where-Object ZNRequired).Count -gt 0

    # ─── Summary ─────────────────────────────────────────────────────────────────

    Write-SectionHeader 'ANALYSIS SUMMARY'

    $ratePerHour = if ($logSpan.TotalHours -gt 0) {
        [long]($totalRead / $logSpan.TotalHours)
    } else { 0 }

    Write-Host ''
    Write-Host ("  Events read      : {0:N0}" -f $totalRead) -ForegroundColor White
    Write-Host ("  Unique Event IDs : {0}" -f $uniqueIDs) -ForegroundColor White
    Write-Host ("  Est. total XML   : {0}  (relative indicator; actual .evtx is binary-compressed)" -f (Format-Bytes $totalEstBytes)) -ForegroundColor White

    if ($logStart -ne [DateTime]::MaxValue) {
        Write-Host ("  Log span         : {0:yyyy-MM-dd HH:mm:ss}  →  {1:yyyy-MM-dd HH:mm:ss}" -f $logStart, $logEnd) -ForegroundColor White
        Write-Host ("                     {0:N1} hours  ({1:N1} days)" -f $logSpan.TotalHours, $logSpan.TotalDays) -ForegroundColor White
        if ($ratePerHour -gt 0) {
            Write-Host ("  Avg event rate   : {0:N0} events/hour  |  {1:N0} events/day" -f $ratePerHour, ($ratePerHour * 24)) -ForegroundColor White
        }
    }
    if ($MaxEvents -gt 0 -and $totalRead -ge $MaxEvents) {
        Write-Host ("  [!] Hit -MaxEvents cap. Increase cap or use -MaxEvents 0 for full analysis.") -ForegroundColor DarkYellow
    }
    Write-Host ("  Read duration    : {0:N1} seconds" -f $readDuration.TotalSeconds) -ForegroundColor DarkGray

    # ─── Table renderer ──────────────────────────────────────────────────────────

    function Write-EventTable {
        param(
            [array]$Data,
            [long]$TotalRead,
            [int]$TopN,
            [switch]$ShowRate
        )

        $top = $Data | Select-Object -First $TopN

        # Column widths
        $rankW = 4
        $idW   = 7
        $cntW  = 12
        $pctW  = 7
        $avgRW = 8
        $pkRW  = 8
        $avgW  = 10
        $estW  = 12
        $barW  = 22

        if ($ShowRate) {
            $fmtHdr  = "{0,-$rankW}  {1,-$idW}  {2,$cntW}  {3,$pctW}  {4,$avgRW}  {5,$pkRW}  {6,$avgW}  {7,$estW}  {8,-$barW}  {9}"
            $fmtData = $fmtHdr
            $hdr = $fmtHdr -f 'Rank', 'EventID', 'Count', '%Total', 'Avg/s', 'Peak/s', 'AvgXml', 'EstTotal', 'Distribution', 'Description'
        } else {
            $fmtHdr  = "{0,-$rankW}  {1,-$idW}  {2,$cntW}  {3,$pctW}  {4,$avgW}  {5,$estW}  {6,-$barW}  {7}"
            $fmtData = $fmtHdr
            $hdr = $fmtHdr -f 'Rank', 'EventID', 'Count', '%Total', 'AvgXml', 'EstTotal', 'Distribution', 'Description'
        }

        $div = '-' * $hdr.Length

        Write-Host "`n  $hdr" -ForegroundColor DarkCyan
        Write-Host "  $div" -ForegroundColor DarkGray

        $rank = 0
        foreach ($r in $top) {
            $rank++
            $bar      = Get-Bar -Pct $r.PctOfTotal -Width $barW
            $sizeNote = if ($r.SampleCount -eq 0) { '  (no sample)' } else { '' }
            $reqMark  = if ($r.ZNRequired) { ' *' } else { '' }
            $descText = "$($r.Description)$reqMark$sizeNote"

            if ($ShowRate) {
                $row = $fmtData -f `
                    $rank,
                    $r.EventID,
                    ('{0:N0}' -f $r.Count),
                    ('{0:N1}%' -f $r.PctOfTotal),
                    ('{0:N1}' -f $r.AvgPerSec),
                    ('{0:N1}' -f $r.PeakPerSec),
                    (Format-Bytes $r.AvgXmlBytes),
                    (Format-Bytes $r.EstTotalBytes),
                    $bar,
                    $descText
            } else {
                $row = $fmtData -f `
                    $rank,
                    $r.EventID,
                    ('{0:N0}' -f $r.Count),
                    ('{0:N1}%' -f $r.PctOfTotal),
                    (Format-Bytes $r.AvgXmlBytes),
                    (Format-Bytes $r.EstTotalBytes),
                    $bar,
                    $descText
            }

            # Highlight the top 3 rows
            $color = switch ($rank) {
                1       { 'Yellow' }
                2       { 'White' }
                3       { 'Gray' }
                default { 'DarkGray' }
            }
            Write-Host "  $row" -ForegroundColor $color
        }

        Write-Host "  $div" -ForegroundColor DarkGray
        $othersCount = $Data.Count - $TopN
        if ($othersCount -gt 0) {
            $otherEvents  = ($Data | Select-Object -Skip $TopN | Measure-Object -Property Count        -Sum).Sum
            $otherBytes   = ($Data | Select-Object -Skip $TopN | Measure-Object -Property EstTotalBytes -Sum).Sum
            Write-Host ("  ... {0} more event IDs: {1:N0} events ({2:N1}%),  {3} est. XML" -f `
                $othersCount, $otherEvents,
                ($otherEvents / $TotalRead * 100.0),
                (Format-Bytes $otherBytes)) -ForegroundColor DarkGray
        }
    }

    # ─── Table 1: Top by COUNT ───────────────────────────────────────────────────

    Write-SectionHeader ("TOP $TopN EVENT IDs — BY COUNT  (most frequent)")
    Write-Host ''
    Write-Host '  The events generating the most log entries. High counts drive both log wrap' -ForegroundColor DarkGray
    Write-Host '  frequency and CPU overhead in the event log service. Avg/Peak are events per' -ForegroundColor DarkGray
    Write-Host '  second, using 1-minute buckets over the full log span shown above.' -ForegroundColor DarkGray

    Write-EventTable -Data $byCount -TotalRead $totalRead -TopN $TopN -ShowRate

    # ─── Table 2: Top by ESTIMATED SIZE ─────────────────────────────────────────

    Write-SectionHeader ("TOP $TopN EVENT IDs — BY ESTIMATED SIZE  (most storage impact)")
    Write-Host ''
    Write-Host '  The events consuming the most log storage (Count × AvgXmlSize).' -ForegroundColor DarkGray
    Write-Host '  A low-count event with large payloads can still dominate storage.' -ForegroundColor DarkGray

    Write-EventTable -Data $bySize -TotalRead $totalRead -TopN $TopN

    if ($anyRequired) {
        Write-Host ''
        Write-Host "  * Required for Zero Networks segmentation — do not disable this audit subcategory," -ForegroundColor DarkYellow
        Write-Host "    even if it shows up as high-volume above." -ForegroundColor DarkYellow
    }

    # ─── Top contributors breakdown ──────────────────────────────────────────────

    Write-SectionHeader 'CUMULATIVE COVERAGE — BY COUNT'
    Write-Host ''
    Write-Host '  How many Event IDs account for 50%, 80%, and 95% of all events.' -ForegroundColor DarkGray
    Write-Host ''

    $cumCount      = [long]0
    $rank          = 0
    $milestones    = @(50, 80, 95)
    $nextMilestone = 0

    foreach ($r in $byCount) {
        $rank++
        $cumCount += $r.Count
        $pct = $cumCount / $totalRead * 100.0

        while ($nextMilestone -lt $milestones.Count -and $pct -ge $milestones[$nextMilestone]) {
            Write-Host ("  {0,3}% of events  →  top {1,4} Event ID(s)" -f $milestones[$nextMilestone], $rank) -ForegroundColor White
            $nextMilestone++
        }

        if ($nextMilestone -ge $milestones.Count) { break }
    }

    # ─── Audit policy hints ──────────────────────────────────────────────────────

    Write-SectionHeader 'AUDIT POLICY GUIDANCE'
    Write-Host ''
    Write-Host '    - Run: auditpol /get /category:*  to see current audit policy.' -ForegroundColor DarkGray
    Write-Host '    - Use Advanced Audit Policy (subcategories) rather than basic audit policy.' -ForegroundColor DarkGray
    Write-Host '    - Microsoft Baseline: https://aka.ms/audit-policy-recommendations' -ForegroundColor DarkGray
    Write-Host '    - CIS Benchmark audit settings are a good baseline for most environments.' -ForegroundColor DarkGray
    if ($anyRequired) {
        Write-Host '    - Event IDs marked "*" above are required for Zero Networks segmentation.' -ForegroundColor DarkGray
    }

    # ─── CSV export ───────────────────────────────────────────────────────────────

    if ($ExportCsv) {
        try {
            $results |
                Sort-Object -Property Count -Descending |
                Select-Object EventID, Description, ZNRequired, Count, PctOfTotal,
                    AvgPerSec, PeakPerSec,
                    @{N = 'AvgXmlBytes'; E = { $_.AvgXmlBytes }},
                    @{N = 'AvgXmlSize'; E = { Format-Bytes $_.AvgXmlBytes }},
                    @{N = 'EstTotalBytes'; E = { $_.EstTotalBytes }},
                    @{N = 'EstTotalSize'; E = { Format-Bytes $_.EstTotalBytes }},
                    SampleCount, FirstSeen, LastSeen, SpanMinutes |
                Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8

            Write-Host "`n  CSV exported: $ExportCsv  ($($results.Count) rows)" -ForegroundColor Green
        } catch {
            Write-Warning "CSV export failed: $($_.Exception.Message)"
        }
    }

    # ─── Footer ───────────────────────────────────────────────────────────────────

    $line78 = '=' * 78
    Write-Host "`n$line78" -ForegroundColor Cyan
    Write-Host ("  Analysis complete.  {0:N0} events  |  {1} unique IDs  |  {2:N1}s" -f `
        $totalRead, $uniqueIDs, $readDuration.TotalSeconds) -ForegroundColor DarkCyan
    Write-Host "$line78`n" -ForegroundColor Cyan
}
