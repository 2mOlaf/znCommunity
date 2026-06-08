function Show-Banner {
    <#
    .SYNOPSIS
        Displays the Zero Networks ASCII banner with author and script metadata.
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [string]$Author = "",
        [string]$ScriptName = "",
        [string]$Version = "",
        [switch]$ShowThemeInfo
    )

    function Get-StringDisplayWidth {
        # Measures actual terminal column width by probing cursor position before/after a write.
        # Handles ZWJ sequences and wide emoji that .Length cannot account for.
        # Writes and immediately erases so the caller's content covers any artifact.
        param([string]$Text)
        if ([Console]::IsOutputRedirected -or $Text.Length -eq 0) { return $Text.Length }
        try {
            $c = [Console]::CursorLeft
            $r = [Console]::CursorTop
            [Console]::Write($Text)
            $w = [Console]::CursorLeft - $c + ([Console]::CursorTop - $r) * [Console]::WindowWidth
            [Console]::SetCursorPosition($c, $r)
            [Console]::Write([string]::new(' ', $w))
            [Console]::SetCursorPosition($c, $r)
            return $w
        } catch {
            return $Text.Length
        }
    }

    function Get-ConsoleTheme {
        try {
            $backgroundColor = $Host.UI.RawUI.BackgroundColor
            $lightBackgrounds = @('White', 'Gray', 'Yellow', 'Cyan', 'Magenta')
            if ($backgroundColor -in $lightBackgrounds) { return 'Light' } else { return 'Dark' }
        } catch {
            return 'Dark'
        }
    }

    $theme = Get-ConsoleTheme

    if ($theme -eq 'Light') {
        $ZeroGreen     = "DarkGreen"
        $PrimaryText   = "Black"
        $SecondaryText = "DarkGray"
        $AccentText    = "DarkBlue"
    } else {
        $ZeroGreen     = "Green"
        $PrimaryText   = "White"
        $SecondaryText = "Gray"
        $AccentText    = "Cyan"
    }

    # Pre-measure emoji display widths on the blank line before rendering begins.
    # The top border immediately overwrites the probe position, so no artifact is visible.
    Write-Host ""
    $baseText   = "👨‍💻 Author: "
    $clockText  = "⏰ "
    $baseWidth  = Get-StringDisplayWidth $baseText
    $clockWidth = Get-StringDisplayWidth $clockText

    # Super pain in the ass, but here's the source: https://patorjk.com/software/taag/#p=display&f=Fire+Font-s&t=ZERO+Networks&x=none&v=4&h=4&w=80&we=false
    # Top border
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $ZeroGreen

    # FIGlet-style ZERO banner
    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "     )     (       )       )                                  " -ForegroundColor 'DarkRed' -NoNewline
    Write-Host (" " * 14) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "  ( /(     )\ ) ( /(    ( /(         )                  )     " -ForegroundColor 'Red' -NoNewline
    Write-Host (" " * 14) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "  )\())(  (()/( )\())   )\())  (  ( /((  (       (   ( /(     " -ForegroundColor 'DarkYellow' -NoNewline
    Write-Host (" " * 14) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host " ((_)\ )\  /(_)|(_)\   ((_)\  ))\ )\())\))(   (  )(  )\())(   " -ForegroundColor 'DarkYellow' -NoNewline
    Write-Host (" " * 14) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "  _((_|(_)(_))   ((_)   _((_)/((_|_))((_)()\  )\(()\((_)\ )\ " -ForegroundColor 'Yellow' -NoNewline
    Write-Host (" " * 15) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host " |_  /| __| _ \ / _ \  | \| " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "(_)) | |__(()((_)((_)((_) |(_|(_)" -ForegroundColor 'Yellow' -NoNewline
    Write-Host (" " * 15) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "  / / | _||   /| (_) | | .`` / -_)|  _\ V  V / _ \ '_| / /(_-<" -ForegroundColor $ZeroGreen -NoNewline
    Write-Host (" " * 15) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host " /___||___|_|_\ \___/  |_|\_\___| \__|\_/\_/\___/_| |_|\_\/__/" -ForegroundColor $ZeroGreen -NoNewline
    Write-Host (" " * 14) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "                               " -ForegroundColor $PrimaryText -NoNewline
    Write-Host (" " * 45) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "                                     " -ForegroundColor $PrimaryText -NoNewline
    Write-Host "The Hottest µ-Segmentation Solution!" -ForegroundColor $AccentText -NoNewline
    Write-Host (" " * 3) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    # Separator line
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor $ZeroGreen

    # Author / script line — padding uses measured display widths, not .Length
    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline

    $availableSpace = 76
    $authorText  = $Author
    $scriptText  = if ($ScriptName) { " | Script: $ScriptName" } else { "" }
    $versionText = if ($Version -and $ScriptName) { " v$Version" } else { "" }

    $totalWidth = $baseWidth + $authorText.Length + $scriptText.Length + $versionText.Length
    if ($totalWidth -gt $availableSpace) {
        $initials   = ($Author -split ' ' | ForEach-Object { $_.Substring(0,1).ToUpper() }) -join '.'
        $authorText = $initials
        $totalWidth = $baseWidth + $authorText.Length + $scriptText.Length + $versionText.Length
        if ($totalWidth -gt $availableSpace -and $ScriptName) {
            $availableForScript = $availableSpace - $baseWidth - $authorText.Length - " | Script: ".Length - $versionText.Length - 3
            if ($availableForScript -gt 10) {
                $scriptText = " | Script: $($ScriptName.Substring(0, [Math]::Min($ScriptName.Length, $availableForScript)))..."
            } else {
                $scriptText  = ""
                $versionText = ""
            }
        }
    }

    Write-Host $baseText -ForegroundColor $PrimaryText -NoNewline
    Write-Host $authorText -ForegroundColor $AccentText -NoNewline

    if ($scriptText) {
        Write-Host " | Script: " -ForegroundColor $PrimaryText -NoNewline
        Write-Host ($scriptText.Replace(" | Script: ", "")) -ForegroundColor $AccentText -NoNewline
    }
    if ($versionText) {
        Write-Host $versionText -ForegroundColor $SecondaryText -NoNewline
    }

    $finalWidth = $baseWidth + $authorText.Length + $scriptText.Length + $versionText.Length
    Write-Host (" " * [Math]::Max(0, $availableSpace - $finalWidth + 3)) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    # Timestamp line
    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host $clockText -ForegroundColor $AccentText -NoNewline
    Write-Host $timestamp -ForegroundColor $SecondaryText -NoNewline
    Write-Host (" " * [Math]::Max(0, $availableSpace - $clockWidth - $timestamp.Length - 1)) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $ZeroGreen

    if ($ShowThemeInfo) {
        try {
            $bgColor = $Host.UI.RawUI.BackgroundColor
            Write-Host "🎨 Theme: $theme | Background: $bgColor" -ForegroundColor $SecondaryText
        } catch {
            Write-Host "🎨 Theme: $theme | Background: Unable to detect" -ForegroundColor $SecondaryText
        }
    }

    Write-Host ""
}
