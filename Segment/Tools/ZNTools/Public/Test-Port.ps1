function Test-Port {
    <#
    .SYNOPSIS
        Tests TCP connectivity to a host/port.
    .PARAMETER PreferIPv4
        Prefer IPv4 when resolving and connecting.
    .NOTES
        Author: Olaf Gradin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Computer,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$Millisecond = 1000,
        [switch]$Continuous,
        [switch]$PreferIPv4
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name

    function Get-RouteSourceIp {
        param(
            [Parameter(Mandatory)]
            [string]$Computer,

            [switch]$PreferIPv4
        )

        try {
            $addresses = [System.Net.Dns]::GetHostAddresses($Computer)
            if ($PreferIPv4) {
                $addr = $addresses |
                    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                    Select-Object -First 1
            } else {
                $addr = $addresses | Select-Object -First 1
            }

            if (-not $addr) {
                return $null
            }

            $family = if ($PreferIPv4) { [System.Net.Sockets.AddressFamily]::InterNetwork } else { $addr.AddressFamily }
            $socket = New-Object System.Net.Sockets.Socket(
                $family,
                [System.Net.Sockets.SocketType]::Dgram,
                [System.Net.Sockets.ProtocolType]::Udp
            )

            try {
                $remoteEP = New-Object System.Net.IPEndPoint($addr, 65535)
                $socket.Connect($remoteEP)
                return ([System.Net.IPEndPoint]$socket.LocalEndPoint).Address.IPAddressToString
            }
            finally {
                $socket.Dispose()
            }
        }
        catch {
            return $null
        }
    }

    function Invoke-PortCheck {
        param(
            [string]$Computer,
            [int]$Port,
            [int]$Timeout,
            [switch]$PreferIPv4
        )

        if ($PreferIPv4) {
            $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
        } else {
            $client = [System.Net.Sockets.TcpClient]::new()
        }

        try {
            if ($PreferIPv4) {
                $addr = [System.Net.Dns]::GetHostAddresses($Computer) |
                    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                    Select-Object -First 1
                if (-not $addr) { throw "No IPv4 address found for $Computer" }
                $async = $client.BeginConnect($addr, $Port, $null, $null)
            } else {
                $async = $client.BeginConnect($Computer, $Port, $null, $null)
            }
            $connected = $async.AsyncWaitHandle.WaitOne($Timeout, $false)

            $sourceIp = $null

            if ($connected) {
                $client.EndConnect($async)
                $localEndPoint = [System.Net.IPEndPoint]$client.Client.LocalEndPoint
                $sourceIp = $localEndPoint.Address.IPAddressToString
            }

            [pscustomobject]@{
                Timestamp = Get-Date
                Computer  = $Computer
                Port      = $Port
                SourceIP  = $sourceIp
                Success   = [bool]$connected
            }
        }
        catch {
            [pscustomobject]@{
                Timestamp = Get-Date
                Computer  = $Computer
                Port      = $Port
                SourceIP  = $null
                Success   = $false
            }
        }
        finally {
            $client.Close()
        }
    }

    if ($Continuous) {
        $lastSuccess = $null
        $lastSourceIp = $null

        while ($true) {
            $result = Invoke-PortCheck -Computer $Computer -Port $Port -Timeout $Millisecond -PreferIPv4:$PreferIPv4
            $stamp  = $result.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')

            if ($result.Success) {
                $lastSourceIp = $result.SourceIP
                $lastSuccess = $true
                Write-Host "[$stamp] PASS  Source=$($lastSourceIp) -> Target=$($result.Computer):$($result.Port)" -ForegroundColor Green
            }
            else {
                if ($lastSuccess -ne $false) {
                    $lastSourceIp = Get-RouteSourceIp -Computer $Computer -PreferIPv4:$PreferIPv4
                }

                $lastSuccess = $false
                Write-Host "[$stamp] FAIL  Source=$($lastSourceIp) -> Target=$($result.Computer):$($result.Port)" -ForegroundColor Red
            }
        }
    }
    else {
        $result = Invoke-PortCheck -Computer $Computer -Port $Port -Timeout $Millisecond -PreferIPv4:$PreferIPv4

        if (-not $result.Success) {
            $result.SourceIP = Get-RouteSourceIp -Computer $Computer -PreferIPv4:$PreferIPv4
        }

        $result
    }
}
