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
        $ZeroGreen = "DarkGreen"
        $PrimaryText = "Black"
        $SecondaryText = "DarkGray"
        $AccentText = "DarkBlue"
    } else {
        $ZeroGreen = "Green"
        $PrimaryText = "White"
        $SecondaryText = "Gray"
        $AccentText = "Cyan"
    }

    # Super pain in the ass, but here's the source: https://patorjk.com/software/taag/#p=display&f=Fire+Font-s&t=ZERO+Networks&x=none&v=4&h=4&w=80&we=false
    # Clear some space
    Write-Host ""
    
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
    
    # Author and script info with intelligent line length handling
    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    
    # Calculate available space (78 chars total minus emoji and separators)
    $baseText = "👨‍💻 Author: "
    $availableSpace = 76
    
    # Build the info line components
    $authorText = $Author
    $scriptText = if ($ScriptName) { " | Script: $ScriptName" } else { "" }
    $versionText = if ($Version -and $ScriptName) { " v$Version" } else { "" }

    $totalLength = $baseText.Length + $authorText.Length + $scriptText.Length + $versionText.Length
    if ($totalLength -gt $availableSpace) {
        $initials = ($Author -split ' ' | ForEach-Object { $_.Substring(0,1).ToUpper() }) -join '.'
        $authorText = $initials
        $totalLength = $baseText.Length + $authorText.Length + $scriptText.Length + $versionText.Length
        if ($totalLength -gt $availableSpace -and $ScriptName) {
            $availableForScript = $availableSpace - $baseText.Length - $authorText.Length - " | Script: ".Length - $versionText.Length - 3
            if ($availableForScript -gt 10) {
                $truncatedScript = $ScriptName.Substring(0, [Math]::Min($ScriptName.Length, $availableForScript)) + "..."
                $scriptText = " | Script: $truncatedScript"
            } else {
                $scriptText = ""
                $versionText = ""
            }
        }
    }

    Write-Host $baseText -ForegroundColor $PrimaryText -NoNewline
    Write-Host $authorText -ForegroundColor $AccentText -NoNewline

    if ($scriptText) {
        Write-Host " | Script: " -ForegroundColor $PrimaryText -NoNewline
        $displayScript = $scriptText.Replace(" | Script: ", "")
        Write-Host $displayScript -ForegroundColor $AccentText -NoNewline
    }

    if ($versionText) {
        Write-Host $versionText -ForegroundColor $SecondaryText -NoNewline
    }

    $finalLength = $baseText.Length + $authorText.Length + $scriptText.Length + $versionText.Length
    $padding = $availableSpace - $finalLength
    Write-Host (" " * [Math]::Max(0, $padding)) -NoNewline
    Write-Host " ║" -ForegroundColor $ZeroGreen

    Write-Host "║ " -ForegroundColor $ZeroGreen -NoNewline
    Write-Host "⏰ " -ForegroundColor $AccentText -NoNewline
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host $timestamp -ForegroundColor $SecondaryText -NoNewline
    $padding = 75 - ("⏰ " + $timestamp).Length
    Write-Host (" " * [Math]::Max(0, $padding)) -NoNewline
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
