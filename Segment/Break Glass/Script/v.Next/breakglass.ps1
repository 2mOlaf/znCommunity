#Requires -Version 7

<#
.SYNOPSIS
    This script is used to provide a break glass method in case of issues with Zero Networks Segment.

.DESCRIPTION
    This script is designed to handle network and identity segmentation break glass scenarios for both Windows and Linux environments. Usage is only recommended if immediate access is required and other methods, such as Zero Networks Cloud Break Glass, are unavailable. 
    It supports multiple operation modes including privileged access, general access, and port testing. The script can operate exclusively on Windows or Linux assets, or both simultaneously, with additional features like SSH key usage for Linux and credential management for Windows.

.PARAMETER Windows
    Indicates that the script will operate on Windows assets. This switch is mandatory when operating in the 'Windows' or 'Both' parameter sets.

.PARAMETER Linux
    Indicates that the script will operate on Linux assets. This switch is mandatory when operating in the 'Linux' or 'Both' parameter sets.

.PARAMETER LinuxUseSSHKey
    When operating on Linux assets, this switch enables the use of an SSH key for authentication.

.PARAMETER Mode
    Specifies the operation mode of the script. Valid options are 'Privileged', 'All', or 'TestPort'. This parameter is applicable to both Windows and Linux.

.PARAMETER Network
    If specified, the script will perform operations related to network segmentation.

.PARAMETER Identity
    If specified, the script will handle operations related to identity segmentation.

.PARAMETER ServersOnly
    Limits the operation of the script to server assets only.

.PARAMETER DisableBlockRule
    Disables any blocking rules that are in place as part of the script's operation.

.PARAMETER DeploymentClusterName
    Limits the operation of the script to assets belonging to the specified deployment cluster (case insensitive). If not specified, the script will operate on assets across all deployment clusters. This parameter is applicable to both Windows and Linux.

.PARAMETER Asset
    Allows running breakglass on a single asset using shortname or fqdn

.EXAMPLE
    PS> .\BreakGlass.ps1 -Windows -Mode Privileged -Network
    This example runs the script for Windows assets opening all inbound privileged ports such as RDP and WinRM, focusing on network segmentation.

.EXAMPLE
    PS> .\BreakGlass.ps1 -Linux -LinuxUseSSHKey -Network -Mode All -ServersOnly 
    Runs the script for Linux server assets, opening all inbound ports requesting credentials from the user interactively.

.EXAMPLE
    PS> .\BreakGlass.ps1 -Asset linuxserver.contoso.local -Linux -LinuxUseSSHKey -Network -Mode All 
    Runs the script for a single linux server, opening all inbound ports using an SSH key.

.EXAMPLE
    PS> .\BreakGlass.ps1 -IPAddress 1.1.1.1 -Windows -Network -Mode All
    Runs the script for a single windows assset, opening all inbound ports requesting credentials from the user interactively.

.EXAMPLE
    PS> .\BreakGlass.ps1 -IPAddress 1.1.1.1 -Windows -Network -Mode All -ADUserName contoso.local\Administrator -ADSvcPassword password
    Runs the script for a single windows asset, opening all inbound ports using explicitly provided AD credentials.

.EXAMPLE
    PS> .\BreakGlass.ps1 -Windows -Mode All -Network -DeploymentClusterName "zero.local"
    Runs the script for Windows assets in the "Zero.local" deployment cluster only.

.NOTES
    Requires PowerShell 7 or higher. Ensure that the necessary modules and permissions are in place before running the script.

.LINK
    Consult the Zero Networks Admin Guide for more information.

#>


param (
    [Parameter(Mandatory = $true, ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [switch]
    $Windows,

    [Parameter(Mandatory = $true, ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [switch]
    $Linux,

    [Parameter(Mandatory = $true, ParameterSetName = "WindowsAndLinux")]
    [switch]
    $WindowsAndLinux,

    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [switch]
    $LinuxUseSSHKey,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [ValidateSet("Privileged", "All")]
    [string]
    $Mode,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [switch]
    $Network,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [switch]
    $Identity,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [switch]
    $ServersOnly,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [switch]
    $DisableBlockRule,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [string]
    $ADUserName,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [string]
    $ADSvcPassword,

    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [string]
    $LinuxUserName,

    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [Parameter(ParameterSetName = "Asset")]
    [Parameter(ParameterSetName = "IP")]
    [string]
    $LinuxSvcPassword,

    [Parameter(Mandatory = $true, ParameterSetName = "Asset")]
    [string]
    $Asset,

    [Parameter(Mandatory = $true, ParameterSetName = "IP")]
    [string]
    $IPAddress,

    [Parameter(ParameterSetName = "Windows")]
    [Parameter(ParameterSetName = "Linux")]
    [Parameter(ParameterSetName = "WindowsAndLinux")]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete)
        $segmentedAssetsPath = "C:\Program Files\Zero Networks\Breakglass\segmentedAssets.json"

        $clusterIdToName = (Get-Content $segmentedAssetsPath | ConvertFrom-Json).ClusterIdToName

        $clusterIdToName.PSObject.Properties | ForEach-Object {
            $name = $_.Value

            if ($name -like "$wordToComplete*") {
                if ($name -match '\s') {
                    "'$name'"
                } else {
                    $name
                }
            }
        }
    })]
    [ValidateScript({
        $segmentedAssetsPath = "C:\Program Files\Zero Networks\Breakglass\segmentedAssets.json"

        if (-not (Test-Path $segmentedAssetsPath)) {
            throw "segmentedAssets.json not found at $segmentedAssetsPath."
        }

        $clusterIdToName = (Get-Content $segmentedAssetsPath | ConvertFrom-Json).ClusterIdToName

        foreach ($entry in $clusterIdToName.PSObject.Properties) {
            if ($entry.Value -ieq $_) {
                return $true
            }
        }

        $validNames = $clusterIdToName.PSObject.Properties | ForEach-Object { "'$($_.Value)'" }

        if ($validNames.Count -eq 0) {
            throw "'$_' is not a valid deployment cluster. No deployment clusters were found in segmentedAssets.json."
        }

        throw "'$_' is not a valid deployment cluster. Use quotes if the name contains spaces, notice that the name is case sensitive. Valid options: $($validNames -join ', ')."
    })]
    [string]
    $DeploymentClusterName

)

enum LinuxFirewallType {
    Iptables = 1
    Nftables = 2
}

Function Invoke-WindowsBreakGlass {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AssetFQDN,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        [bool]$BreakGlassNetwork = $false,
        [bool]$BreakGlassIdentity = $false,
        [switch]$DisableBlockRule = $false,
        [string]$Mode,
        [string]$success_list,
        [string]$failed_list
    )

    $ps = New-PSSession -ComputerName $AssetFQDN -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue -ErrorVariable errmsg

    if ($ps -ne $null ) {
        write-host "Connection established to asset, running breakglass: $AssetFQDN"

        Invoke-Command -Session $ps -FilePath Internal\remoteWindowsBreakglass.ps1 -ArgumentList ($BreakGlassNetwork, $BreakGlassIdentity, $Mode, $DisableBlockRule) -ErrorAction SilentlyContinue -ErrorVariable errmsg | Out-Null

        write-output "removing session"
        Remove-PSSession $ps
        
        if ($errmsg -eq '' -or $errmsg.count -eq 0) {
            Add-Content -Path $success_list -Value $AssetFQDN
        } else {
			Write-Warning "Errors running breakglass on $AssetFQDN - $errmsg"
			Add-Content -Path $failed_list -Value ($AssetFQDN + " Error: " + $errmsg)
        }
    } else {
        Write-Warning "Could NOT connect to $AssetFQDN"
        Add-Content -Path $failed_list -Value ($AssetFQDN + " Error: " + $errmsg)
    }
}

$WinBGDefinition = (Get-Command Invoke-WindowsBreakGlass).Definition

Function Invoke-LinuxBreakGlass {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AssetFQDN,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        [switch]$useKey = $false,
        [string]$LinuxSSHKey,
        [switch]$Network = $false,
        [string]$Mode,
        [ValidateSet("iptables", "nftables")]
        [string]$AppliedFirewallType,
        [string]$success_list,
        [string]$failed_list
    )

    if ($useKey -eq $true) {
        # write-host "SSH with key"
        $ssh = New-SSHSession -ComputerName $AssetFQDN -KeyFile $LinuxSSHKey -Credential $Credential -AcceptKey -ErrorAction SilentlyContinue -ErrorVariable errmsg -KnownHost (Get-SSHOpenSSHKnownHost -LocalFile $env:TEMP\$AssetFQDN_known_hosts.json) -Verbose
    } else {
        # write-host "SSH no key, password"
        $ssh = New-SSHSession -ComputerName $AssetFQDN -Credential $Credential -AcceptKey -ErrorAction SilentlyContinue -ErrorVariable errmsg -KnownHost (Get-SSHOpenSSHKnownHost -LocalFile $env:TEMP\$AssetFQDN_known_hosts.json) -Verbose
    }
    if ($null -ne $ssh ) {
        function Insert-IptablesBgRule {
            param (
                $stream,
                $chain,
                [switch]$OnlyPrivileged
            )

            if ($OnlyPrivileged) {
                $rule = "{'protocol': 'tcp', 'multiport': {'dports': '22,23,445'}, 'target': 'ACCEPT'}"
            } else {
                $rule = "{'target': 'ACCEPT'}"
            }

            $command = "python -c `"import iptc; table = iptc.Table(iptc.Table.FILTER); chain = iptc.Chain(table, '$chain'); rule = iptc.easy.encode_iptc_rule($rule); chain.insert_rule(rule, 0)`" 2>>breakglass_errors || echo 'breakglass: iptables backend unavailable or insert failed on this host, skipping' >>breakglass_errors"
            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $command -ErrorAction Stop -ErrorVariable errmsg | Out-Null
        }

        function Insert-NftablesBgRule {
            param (
                $stream,
                $chain,
                [switch]$OnlyPrivileged
            )

            if ($OnlyPrivileged) {
                $body = "tcp dport { 22, 23, 445 } accept"
            } else {
                $body = "accept"
            }

            $command = "python -c `"import sys, subprocess, nftables; lib = next((line.split('=> ')[-1].strip() for line in subprocess.check_output(['ldconfig', '-p'], universal_newlines=True).splitlines() if 'libnftables.so' in line), ''); exec('try:\n n = nftables.Nftables(lib) if lib else nftables.Nftables()\nexcept Exception:\n n = nftables.Nftables()'); chk = lambda r: sys.stderr.write('breakglass nft insert failed: {}\n'.format(r[2])) if r[0] != 0 else None; chk(n.cmd('insert rule ip zn_filter_ipv4 $chain $body')); chk(n.cmd('insert rule ip6 zn_filter_ipv6 $chain $body'))`" 2>>breakglass_errors || echo 'breakglass: nftables backend unavailable or insert failed on this host, skipping' >>breakglass_errors"

            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $command -ErrorAction Stop -ErrorVariable errmsg | Out-Null
        }

        write-host "Connection established to asset: $AssetFQDN"
        #Establish a stream for sudo su
        $stream = $ssh.Session.CreateShellStream("ps-ssh", 0, 0, 0, 0, 100)
        Invoke-SSHStreamShellCommand -ShellStream $stream -Command "sudo su" -ErrorAction stop -ErrorVariable errmsg | Out-Null

        if ($Network -eq $true) {
            $KillExistingCollectorCommand = "(pid=`$(pgrep -a python | grep ''ZeroNetworks'' | cut -d ' ' -f1); if [ ! -z `$pid ]; then kill -9 `$pid; fi)"
            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $KillExistingCollectorCommand -ErrorAction Stop -ErrorVariable errmsg | Out-Null

            $ActivatePythonVirtualEnvCommand = ". ./.zn-internal/venv3/bin/activate || . ./.zn-internal/venv2/bin/activate"
            Invoke-SSHStreamShellCommand -ShellStream $stream -Command $ActivatePythonVirtualEnvCommand -ErrorAction stop -ErrorVariable errmsg | Out-Null

            if ($AppliedFirewallType -eq "iptables") {
                $SetXtablesLibDir = "python -c 'import iptc' || export XTABLES_LIBDIR=`$(cat '.zn-internal/cached_xtables_libdir')"
                Invoke-SSHStreamShellCommand -ShellStream $stream -Command $SetXtablesLibDir  -ErrorAction stop -ErrorVariable errmsg | Out-Null

                if ($Mode -eq "All" ) {
                    Write-Output "Adding Zero Networks Break Glass All rule (iptables) on $AssetFQDN"
                    Insert-IptablesBgRule -stream $stream -chain "INPUT"
                    Insert-IptablesBgRule -stream $stream -chain "OUTPUT"
                }
                elseif ($Mode -eq "Privileged") {
                    Write-Output "Adding Zero Networks Break Glass Privileged rule (iptables) on $AssetFQDN"
                    Insert-IptablesBgRule -stream $stream -chain "INPUT" -OnlyPrivileged
                    Insert-IptablesBgRule -stream $stream -chain "OUTPUT"
                }
            }
            elseif ($AppliedFirewallType -eq "nftables") {
                if ($Mode -eq "All" ) {
                    Write-Output "Adding Zero Networks Break Glass All rule (nftables) on $AssetFQDN"
                    Insert-NftablesBgRule -stream $stream -chain "INPUT"
                    Insert-NftablesBgRule -stream $stream -chain "OUTPUT"
                }
                elseif ($Mode -eq "Privileged") {
                    Write-Output "Adding Zero Networks Break Glass Privileged rule (nftables) on $AssetFQDN"
                    Insert-NftablesBgRule -stream $stream -chain "INPUT" -OnlyPrivileged
                    Insert-NftablesBgRule -stream $stream -chain "OUTPUT"
                }
            }
            else {
                Write-Output "Unsupported firewall type '$AppliedFirewallType' for $AssetFQDN, skipping network break glass"
            }
        }
        Remove-SSHSession $ssh | Out-Null
        if ($errmsg -eq '' -or $errmsg.count -eq 0) {
            Add-Content -Path $success_list -Value $AssetFQDN
        }
    } else {
        Write-Output "Could NOT connect to $AssetFQDN"
        Add-Content -Path $failed_list -Value ($AssetFQDN + " Error: " + $errmsg)
    }
}

$LinBGDefinition = (Get-Command Invoke-LinuxBreakGlass).Definition

Function Add-DomainCredential {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $true)]
        [string]$User,
        [Parameter(Mandatory = $false)]
        [string]$OrganizationalUnit = $null,
        [Parameter(Mandatory = $false)]
        [string]$Password = $null
    )
    
    if ($Password) {
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    } else {
        if ($OrganizationalUnit) {
            $PasswordPrompt = "Please enter the password for OU $OrganizationalUnit - $Domain\$User"
        } else {
            $PasswordPrompt = "Please enter the password for $Domain\$User"
        }
        $securePassword = Read-Host $PasswordPrompt -AsSecureString
    }
    
    $userName = "$Domain\$User"
    
    $object = @{
        "Domain"             = $Domain
        "OrganizationalUnit" = $OrganizationalUnit
        "Credential"         = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword
    }
    
    return New-Object -TypeName PSObject -Property $object
}

# Handle Inputs
if (!$PSBoundParameters['Network'] -and !$PSBoundParameters['Identity']) {
    Write-Host "Please specify either -Network or -Identity"
    exit
}
if (!$PSBoundParameters['Windows'] -and !$PSBoundParameters['Linux'] -and !$PSBoundParameters['WindowsAndLinux']) {
    Write-Host "Please specify either -Windows or -Linux or -WindowsAndLinux parameters"
    exit
}
if ($PSBoundParameters['Network'] -and !$PSBoundParameters['mode']) {
    Write-Host "Please specify a mode when using -Network"
    exit
}
if ($PSBoundParameters["mode"] -eq "TestPort") {
    $global:port = Read-Host 'Enter the port to use for testing'
}

# Validate that ADUserName and ADSvcPassword must be used together
if ($PSBoundParameters['ADUserName'] -and !$PSBoundParameters['ADSvcPassword']) {
    Write-Host "Error: -ADUserName requires -ADSvcPassword to be specified as well." -ForegroundColor Red
    exit
}
if ($PSBoundParameters['ADSvcPassword'] -and !$PSBoundParameters['ADUserName']) {
    Write-Host "Error: -ADSvcPassword requires -ADUserName to be specified as well." -ForegroundColor Red
    exit
}
# Validate that LinuxUserName and LinuxSvcPassword must be used together
if ($PSBoundParameters['LinuxUserName'] -and !$PSBoundParameters['LinuxSvcPassword']) {
    Write-Host "Error: -LinuxUserName requires -LinuxSvcPassword to be specified as well." -ForegroundColor Red
    exit
}
if ($PSBoundParameters['LinuxSvcPassword'] -and !$PSBoundParameters['LinuxUserName']) {
    Write-Host "Error: -LinuxSvcPassword requires -LinuxUserName to be specified as well." -ForegroundColor Red
    exit
}
if ($PSBoundParameters['Asset']) {
    $AssetFQDN = Resolve-DnsName $Asset -ErrorAction SilentlyContinue
    if ($AssetFQDN.Type -contains "A") {
        Write-Host "Asset: $Asset found in DNS, attempting to BreakGlass"
        $AssetFQDN = ($AssetFQDN | where { $_.Type -eq "A" } | Select -First 1).Name
        $AssetDomain = $AssetFQDN.Substring($AssetFQDN.IndexOf(".") + 1)
    } else {
        write-Host "Asset: $Asset not found in DNS, please try with FQDN." -ForegroundColor red
        exit
    }
}

if ($PSBoundParameters['IPAddress']) {
    $AssetFQDN = Resolve-DnsName $IPAddress
    if ($AssetFQDN.Type -contains "PTR") {
        Write-Host "IPAddress: $IPAddress found in DNS, attempting to BreakGlass"
        $AssetFQDN = ($AssetFQDN | where { $_.Type -eq "PTR" } | Select -First 1).NameHost
        $AssetDomain = $AssetFQDN.Substring($AssetFQDN.IndexOf(".") + 1)
    }
    else {
        write-Host "IPAddress: $IPAddress not found in DNS, please try with FQDN."
        exit
    }
}

#Load segmented Assets early to avoid prompting for credentials when single asset is missing.
#Only the multi-asset modes use the inventory; single asset (-Asset/-IPAddress) does not.
if (-not $PSBoundParameters['Asset'] -and -not $PSBoundParameters['IPAddress']) {
    $segmentedAssetsJson = Get-Content "C:\Program Files\Zero Networks\Breakglass\segmentedAssets.json" | ConvertFrom-Json
    $segmentedAssets = $segmentedAssetsJson.segmentedAssets
    if ($null -eq $segmentedAssets) {
        Write-Host "segmentedAssets.json not found."
        exit
    }
}

$filteredClusterId = $null
if ($PSBoundParameters.ContainsKey('DeploymentClusterName')) {
    $clusterIdToName = $segmentedAssetsJson.ClusterIdToName

    foreach ($entry in $clusterIdToName.PSObject.Properties) {
        if ($entry.Value -ieq $DeploymentClusterName) {
            $filteredClusterId = $entry.Name
            Write-Host "Scoping to deployment cluster: $($entry.Value) ($filteredClusterId)"
            break
        }
    }
}


if ($PSBoundParameters['Linux'] -or $PSBoundParameters['WindowsAndLinux']) {
    $global:linuxSSHKey = $null

    if (!$PSBoundParameters['LinuxUseSSHKey']) {
        if ($PSBoundParameters['LinuxUserName']) {
            $linuxUsername = $LinuxUserName
        } else {
            $linuxUsername = Read-Host 'Enter the username for the Linux User'
        }
        if ($PSBoundParameters['LinuxSvcPassword']) {
            $LinuxSecretPassword = ConvertTo-SecureString $LinuxSvcPassword -AsPlainText -Force
        } else {
            $LinuxSecretPassword = Read-Host 'Enter password for the Linux User' -AsSecureString
        }
        $LinuxCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $linuxUsername, $LinuxSecretPassword
    } else {
        if ($PSBoundParameters['LinuxUserName']) {
            $linuxUsername = $LinuxUserName
        } else {
            $linuxUsername = Read-Host 'Enter the username for the Linux User'
        }
        $LinuxCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $linuxUsername, (New-Object System.Security.SecureString)
        $global:linuxSSHKey = Read-Host 'Enter the path to the SSH Key file'
    }

}

#check for SSH Module
if (!(Get-Module -ListAvailable | Where-Object { $_.Name -eq "POSH-SSH" })) {
    Write-Host "POSH-SSH Module not found. Installing now."
    Install-Module -Name Posh-SSH -Force -ErrorVariable errmsg
    if ($errmsg) {
        Write-Host "Error installing Posh-SSH Module from web. Using Local source."
        New-Item C:\Temp\NuPkg -ItemType Directory -Force | Out-Null
        copy-item "C:\Program Files\Zero Networks\BreakGlass\posh-ssh.3.1.1.nupkg" C:\Temp\NuPkg -Force | Out-Null
        Register-PSRepository -Name LocalPackages -SourceLocation C:\Temp\NuPkg -InstallationPolicy Trusted
        Install-Module -Name Posh-SSH -Repository LocalPackages -Force -ErrorVariable errmsg
        Unregister-PSRepository LocalPackages
    }
}

# Setup logging files
$success_list = "./success_list.txt"
$failed_list = "./failed_list.txt"
Out-file -FilePath $success_list
Out-File -FilePath $failed_list

# Type 1 = Client 2 = Server
# Entity Source 3 = AD, 6 = Ansible, 7 = OT, 8 = Workgroup, 9 = AzureAD, 15 = Manual Linux

#Handle multiple windows assets
if ($PSBoundParameters['Windows'] -or $PSBoundParameters['WindowsAndLinux'] -and !$PSBoundParameters['Asset'] -and !$PSBoundParameters['IPAddress']) {

    $creds = @()
    if ($PSBoundParameters['ADUserName']) {
        if ($PSBoundParameters['ADUserName'] -like "*\*") {
            $domain = $PSBoundParameters['ADUserName'].Split("\")[0]
            $user = $PSBoundParameters['ADUserName'].Split("\")[1]
        } elseif ($PSBoundParameters['ADUserName'] -like "*@*") {
            $domain = $PSBoundParameters['ADUserName'].Split("@")[1]
            $user = $PSBoundParameters['ADUserName'].Split("@")[0]
        } else {
            Write-Host "Invalid username format. Please use either domain\username or user@domain.com"
            break
        }
        $creds += Add-DomainCredential -Domain $domain -User $user -Password $ADSvcPassword
    } else {
        $ADInfo = $segmentedAssetsJson
        if ($null -eq $ADInfo) {
            Write-Host "segmentedAssets.json not found or empty."
            exit
        }
        foreach ($forest in $ADInfo.ForestsConfig) {
            $creds += Add-DomainCredential -Domain $forest.PrimaryDomain.DomainDnsName -User $forest.PrimaryDomain.AdUserName
            
            if ($forest.PrimaryDomain.OuCredentials) {
                foreach ($ouCred in $forest.PrimaryDomain.OuCredentials) {
                    $creds += Add-DomainCredential -Domain $ouCred.DomainName -User $ouCred.UserName -OrganizationalUnit $ouCred.OrganizationalUnit
                }
            }
            
            foreach ($secondaryDomain in $forest.SecondaryDomains) {
                $creds += Add-DomainCredential -Domain $secondaryDomain.DomainDnsName -User $secondaryDomain.AdUserName
                
                if ($secondaryDomain.OuCredentials) {
                    foreach ($ouCred in $secondaryDomain.OuCredentials) {
                        $creds += Add-DomainCredential -Domain $ouCred.DomainName -User $ouCred.UserName -OrganizationalUnit $ouCred.OrganizationalUnit
                    }
                }
            }
        }
    }

    if ($ServersOnly) {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 3 -and $_.type -eq 2 -and $_.osType -eq 2 }
    } else {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 3 -and $_.osType -eq 2 } | Sort-Object -Property type -Descending
    }

    if ($filteredClusterId) {
        $members = $members | Where-Object { $_.ClusterId -eq $filteredClusterId }
    }

    if ($members.count -eq 0) {
        Write-Host "No Windows Assets found in the segmented assets list"
    } else {
        $members | ForEach-Object -ThrottleLimit 100 -Parallel {
            ${function:Invoke-WindowsBreakGlass} = $($using:WinBGDefinition)
            if ($null -eq $_.Fqdn ) {
                write-host "Error occurred with object $_ "
                break
            }

            $AssetFQDN = $_.Fqdn

            $breakGlassAssetNetwork = $($using:Network) -and $_.IsNetworkSegmented
            $breakGlassAssetIdentity = $($using:Identity) -and $_.IsIdentitySegmented

            if ($breakGlassAssetNetwork -or $breakGlassAssetIdentity) {
                $assetDomain = $AssetFQDN.Substring($AssetFQDN.IndexOf(".") + 1)
                $assetOU = $_.OrganizationalUnit
                $Credential = $null
                
                # Try to find OU-specific credential first if asset has an OU
                if ($assetOU -and $assetOU.Trim() -ne "") {
                    $Credential = ($($using:creds) | Where-Object { $_.Domain -like $assetDomain -and $_.OrganizationalUnit -eq $assetOU }).Credential
                }
                
                # Fall back to domain-only credential if no OU match found
                if (-not $Credential) {
                    $Credential = ($($using:creds) | Where-Object { $_.Domain -like $assetDomain -and (-not $_.OrganizationalUnit) }).Credential
                }

                Write-Host "Establishing session to $AssetFQDN using $($Credential.UserName)" -ForegroundColor Green

                Invoke-WindowsBreakGlass -AssetFQDN $AssetFQDN -Credential $Credential -BreakGlassNetwork $breakGlassAssetNetwork -BreakGlassIdentity $breakGlassAssetIdentity -DisableBlockRule:$($using:DisableBlockRule) -Mode $($using:Mode) -success_list $($using:success_list) -failed_list $($using:failed_list)
            } else {
                Write-Output "Asset $AssetFQDN is not segmented for the requested segmentation types. Skipping"
            }
        }
    }
    $members = $null
}

#Handle Single Windows Asset
if ($PSBoundParameters['Asset'] -or $PSBoundParameters['IPAddress'] -and $PSBoundParameters['Windows']) {


    $breakGlassAssetNetwork = $PSBoundParameters['Network'] -eq $true
    $breakGlassAssetIdentity = $PSBoundParameters['Identity'] -eq $true

    if (!$PSBoundParameters['ADUserName'] -and !$PSBoundParameters['ADSvcPassword']) {
        $Domain = Read-Host 'Enter the domain name: '
        $ADUserName = Read-Host 'Enter the AD account name: '
        $Credential = (Add-DomainCredential -Domain $Domain  -User $ADUserName).Credential
    }else{
        $Credential = (Add-DomainCredential -Domain $PSBoundParameters['ADUserName'].Split("\")[0]  -User $PSBoundParameters['ADUserName'].Split("\")[1] -Password $PSBoundParameters['ADSvcPassword']).Credential
    }
    Write-Host "Establishing session to $AssetFQDN using $($Credential.UserName)" -ForegroundColor Green
    Invoke-WindowsBreakGlass -AssetFQDN $AssetFQDN -Credential $Credential -BreakGlassNetwork $breakGlassAssetNetwork -BreakGlassIdentity $breakGlassAssetIdentity -DisableBlockRule:$PSBoundParameters['DisableBlockRule'] -Mode $PSBoundParameters['Mode'] -success_list $success_list -failed_list $failed_list
}

#Handle Linux Assets
if ($PSBoundParameters['Linux'] -or $PSBoundParameters['WindowsAndLinux'] -and !$PSBoundParameters['Asset'] -and !$PSBoundParameters['IPAddress']) {
    if ($ServersOnly) {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 6 -or $_.entitySource -eq 15 -or $_.entitySource -eq 3 -and $_.type -eq 2 -and $_.osType -eq 3 }
    } else {
        $members = $segmentedAssets | Where-Object { $_.entitySource -eq 6 -or $_.entitySource -eq 15 -or $_.entitySource -eq 3 -and $_.osType -eq 3 } | Sort-Object -Property type -Descending
    }

    if ($filteredClusterId) {
        $members = $members | Where-Object { $_.ClusterId -eq $filteredClusterId }
    }

    if ($members.count -eq 0) {
        Write-Host "No Linux Assets found in the segmented assets list"
    } else {

        foreach ($member in $members) {
            $firewallType = [LinuxFirewallType]$member.AppliedFirewallType
            $member | Add-Member -NotePropertyName "AppliedFirewallTypeName" -NotePropertyValue $firewallType.ToString().ToLower() -Force
        }

        $members | ForEach-Object -ThrottleLimit 100 -Parallel {
            ${function:Invoke-LinuxBreakGlass} = $($using:LinBGDefinition)
            if ($null -eq $_.Fqdn) {
                write-host "Error occurred with object $_ "
                break
            }
            $AssetFQDN = $_.Fqdn
            $connect = $false
            if ($_.IsNetworkSegmented -eq $true) {
                if ($_.IsNetworkSegmented -eq $true -and $($using:Network)) {
                    $connect = $true
                }
                if ($connect -eq $true) {

                }
                Write-Host "Establishing session to $AssetFQDN...."

                # Determine $useKeyParam based on whether $global:linuxSSHKey is set
                $useKeyParam = if ($using:global:linuxSSHKey) { $true } else { $false }
                Invoke-LinuxBreakGlass -AssetFQDN $AssetFQDN -Credential $($using:LinuxCredential) -useKey:$useKeyParam -LinuxSSHKey $($using:global:linuxSSHKey) -Network:$($using:Network) -Mode $($using:Mode) -AppliedFirewallType $_.AppliedFirewallTypeName -success_list $($using:success_list) -failed_list $($using:failed_list)
            }
            else {
                Write-Output "Asset $AssetFQDN is not segmented. Skipping"
            }
        }
    }
}

#Handle Single Linux Asset
if ($PSBoundParameters['Asset'] -or $PSBoundParameters['IPAddress'] -and $PSBoundParameters['Linux']) {
    Write-Host "Establishing session to $AssetFQDN...."
   
    # Determine $useKey based on whether $global:linuxSSHKey is set
    $useKey = if ($global:linuxSSHKey) { $true } else { $false }

    foreach ($firewallType in @("iptables", "nftables")) {
        try {
            Invoke-LinuxBreakGlass  -AssetFQDN $AssetFQDN -Credential $LinuxCredential -useKey:$useKey -LinuxSSHKey $($global:linuxSSHKey) -Network:$PSBoundParameters['Network'] -Mode $PSBoundParameters['Mode'] -AppliedFirewallType $firewallType -success_list $success_list -failed_list $failed_list
        } catch {
            Write-Host "Break glass attempt for firewall type $firewallType on $AssetFQDN did not complete: $_"
        }
    }
    
}


#Cleanup
$creds = $null
$members = $null
$Credential = $null
$LinuxCredential = $null
$WinRMSecretPassword = $null
$LinuxSecretPassword = $null
$global:linuxSSHKey = $null
 