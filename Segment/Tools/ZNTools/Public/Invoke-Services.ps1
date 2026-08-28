function Invoke-Services {
    <#
    .SYNOPSIS
        Stops, starts, or restarts Zero Networks services locally, on a single remote
        Segment Server, or across all Segment Servers discovered via the ZN API.
    .DESCRIPTION
        Manages all services matching 'zn*' as a group. Supports three execution scopes:

          Local      — runs on this machine (requires Administrator)
          Remote     — connects to a single named host or IP via PSRemoting
          AllServers — queries the Zero Networks API for all Segment Server deployments
                       and performs the action on each, with optional cluster filtering.

        API key is read from the ZN_API_KEY environment variable by default.
        PSRemoting (WinRM) must be enabled and reachable on remote Segment Servers.
    .PARAMETER Action
        Lifecycle action to perform: Stop, Start, or Restart.
    .PARAMETER ComputerName
        Target a single remote Segment Server by hostname or IP address.
    .PARAMETER Credential
        PSCredential for PSRemoting authentication. If omitted, the current session
        identity is used (suitable when running from a Segment Server in domain).
    .PARAMETER AllServers
        Discover all Segment Server deployments from the Zero Networks API and
        perform the action on each.
    .PARAMETER ClusterName
        When used with -AllServers, limits the operation to Segment Servers in the named
        cluster. Partial match, case-insensitive. Uses in-memory cluster map if
        Import-ZNAssetData has been run, otherwise falls back to deployment name matching.
    .PARAMETER ApiKey
        Zero Networks API key. Defaults to the ZN_API_KEY environment variable.
    .PARAMETER ApiUrl
        Override the API base URL.
    .NOTES
        Author: Olaf Gradin
    .EXAMPLE
        Invoke-ZNServices -Action Restart
        Restarts ZN services on the local machine. Requires Administrator.
    .EXAMPLE
        Invoke-ZNServices -Action Restart -ComputerName segment02.zero.local
        Restarts ZN services on a remote Segment Server via PSRemoting.
    .EXAMPLE
        Invoke-ZNServices -Action Restart -AllServers
        Restarts ZN services on every Segment Server in the environment.
    .EXAMPLE
        Invoke-ZNServices -Action Stop -AllServers -ClusterName "zero.local"
        Stops ZN services only on Segment Servers in the zero.local deployment cluster.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Stop', 'Start', 'Restart')]
        [string]$Action,

        [Parameter(Mandatory, ParameterSetName = 'Remote')]
        [string]$ComputerName,

        [Parameter(ParameterSetName = 'Remote')]
        [Parameter(ParameterSetName = 'AllServers')]
        [PSCredential]$Credential,

        [Parameter(Mandatory, ParameterSetName = 'AllServers')]
        [switch]$AllServers,

        [Parameter(ParameterSetName = 'AllServers')]
        [string]$ClusterName,

        [Parameter(ParameterSetName = 'AllServers')]
        [string]$ApiKey,

        [Parameter(ParameterSetName = 'AllServers')]
        [string]$ApiUrl
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    $ServicePattern = 'zn*'

    $ActionBlock = {
        param([string]$Action, [string]$Pattern)

        function Get-ZNSvcStatus {
            Get-Service | Where-Object Name -like $Pattern |
                Select-Object Name, DisplayName, Status
        }

        $services = Get-Service | Where-Object Name -like $Pattern

        if ($services.Count -eq 0) {
            Write-Warning "No services matching '$Pattern' found on $env:COMPUTERNAME."
            return
        }

        Write-Host "`n[$env:COMPUTERNAME] Before:" -ForegroundColor DarkGray
        Get-ZNSvcStatus | Format-Table -AutoSize

        switch ($Action) {
            'Stop' {
                Write-Host "[$env:COMPUTERNAME] Stopping..." -ForegroundColor Yellow
                $services | Stop-Service -Force -ErrorAction Continue
                $services | ForEach-Object {
                    try   { $_.WaitForStatus('Stopped', (New-TimeSpan -Seconds 30)) }
                    catch { Write-Warning "[$env:COMPUTERNAME] Timed out waiting for '$($_.Name)' to stop." }
                }
            }
            'Start' {
                Write-Host "[$env:COMPUTERNAME] Starting..." -ForegroundColor Yellow
                $services | Start-Service -ErrorAction Continue
                $services | ForEach-Object {
                    try   { $_.WaitForStatus('Running', (New-TimeSpan -Seconds 30)) }
                    catch { Write-Warning "[$env:COMPUTERNAME] Timed out waiting for '$($_.Name)' to start." }
                }
            }
            'Restart' {
                Write-Host "[$env:COMPUTERNAME] Stopping..." -ForegroundColor Yellow
                $services | Stop-Service -Force -ErrorAction Continue
                $services | ForEach-Object {
                    try   { $_.WaitForStatus('Stopped', (New-TimeSpan -Seconds 30)) }
                    catch { Write-Warning "[$env:COMPUTERNAME] Timed out waiting for '$($_.Name)' to stop." }
                }
                Write-Host "[$env:COMPUTERNAME] Starting..." -ForegroundColor Yellow
                $fresh = Get-Service | Where-Object Name -like $Pattern
                $fresh | Start-Service -ErrorAction Continue
                $fresh | ForEach-Object {
                    try   { $_.WaitForStatus('Running', (New-TimeSpan -Seconds 30)) }
                    catch { Write-Warning "[$env:COMPUTERNAME] Timed out waiting for '$($_.Name)' to start." }
                }
            }
        }

        Write-Host "[$env:COMPUTERNAME] After:" -ForegroundColor DarkGray
        Get-ZNSvcStatus | Format-Table -AutoSize
    }

    function Invoke-LocalServiceAction {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error "Local execution requires an Administrator session."
            return
        }
        & $ActionBlock -Action $Action -Pattern $ServicePattern
    }

    function Invoke-RemoteServiceAction {
        param([string]$Target)
        Write-Host "`nConnecting to $Target..." -ForegroundColor Cyan
        $params = @{
            ComputerName   = $Target
            ScriptBlock    = $ActionBlock
            ArgumentList   = $Action, $ServicePattern
            Authentication = 'Negotiate'
            ErrorAction    = 'Stop'
        }
        if ($Credential) { $params['Credential'] = $Credential }
        try {
            Invoke-Command @params
        }
        catch {
            Write-Warning "Could not connect to $Target`: $_"
        }
    }

    function Resolve-ServiceClusterFilter {
        param([string]$Name)
        # Use in-memory cluster map if asset data has been loaded via Import-ZNAssetData
        if ($script:ZNClusterMap.Count -gt 0) {
            $match = $script:ZNClusterMap.GetEnumerator() |
                Where-Object { $_.Value -ilike "*$Name*" } |
                Select-Object -First 1
            if ($match) {
                Write-Host "Resolved cluster '$($match.Value)' (ID: $($match.Key))" -ForegroundColor DarkGray
                return @{ By = 'id'; Value = $match.Key }
            }
        }
        Write-Host "Filtering by deployment name (run Import-ZNAssetData for cluster ID resolution)." -ForegroundColor DarkGray
        return @{ By = 'name'; Value = $Name }
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Remote' {
            Invoke-RemoteServiceAction -Target $ComputerName
        }
        'AllServers' {
            $token   = Get-ZNApiKey -ApiKey $ApiKey
            $baseUrl = Get-ZNApiBaseUrl -ApiKey $token -ApiUrl $ApiUrl
            $headers = Get-ZNApiHeaders -ApiKey $token

            try {
                $response    = Invoke-RestMethod -Uri "$baseUrl/environments/deployments" -Headers $headers -Method Get -ErrorAction Stop
                $deployments = $response.items
            }
            catch {
                $errBody = Get-ZNErrorBody $_
                Write-Error "Failed to retrieve deployments from API: $($_.Exception.Message)"
                if ($errBody) { Write-Error "Response body: $errBody" }
                return
            }

            if ($ClusterName) {
                $filter = Resolve-ServiceClusterFilter -Name $ClusterName
                $deployments = if ($filter.By -eq 'id') {
                    $deployments | Where-Object { $_.id -eq $filter.Value }
                } else {
                    $deployments | Where-Object { $_.name -ilike "*$($filter.Value)*" }
                }

                if (-not $deployments) {
                    Write-Warning "No deployments matched cluster '$ClusterName'."
                    return
                }
            }

            Write-Host "Targeting $(@($deployments).Count) Segment Server(s)..." -ForegroundColor Yellow

            foreach ($deployment in $deployments) {
                $target = if ($deployment.name) { $deployment.name } else { $deployment.ipAddress }
                Invoke-RemoteServiceAction -Target $target
            }
        }
        default {
            Invoke-LocalServiceAction
        }
    }
}
