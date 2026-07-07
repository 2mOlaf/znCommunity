# Event IDs that Zero Networks segmentation depends on for enforcement, discovery, or audit
# evidence. These must never be disabled/removed from audit policy, even if a log-volume
# analysis flags them as high-frequency. Maintained as a single flat array (regardless of
# which log/channel each ID lives in) so it's simple to update as requirements change.
#   1500, 1502            - System log (Group Policy processing)
#   4688, 4689             - Security log (process creation / exit)
#   4624, 4625, 4634       - Security log (logon success / failure / logoff)
#   5156, 5157             - Security log (WFP connection allowed / blocked)
#   5712                   - Security log (RPC call attempted)
#   2003-2006, 2052, 2071, - Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
#   2073, 2082, 2099         (only relevant if this tool is pointed at that log's .evtx export)
$script:ZNRequiredEventIds = @(
    1500, 1502,
    4688, 4689,
    4624, 4625, 4634,
    5156, 5157,
    5712,
    2003, 2004, 2005, 2006, 2052, 2071, 2073, 2082, 2099
)

# Event ID -> friendly description, spanning the Security log and the other log sources
# this tool may encounter (System, Windows Firewall With Advanced Security). Covers the
# most common Security events on DCs, servers, and workstations, plus every ID referenced
# by $script:ZNRequiredEventIds above.
$script:ZNSecurityEventDescriptions = @{
    1500 = 'Group Policy event (System log)'
    1502 = 'Group Policy event (System log)'
    4608 = 'Windows starting up'
    4609 = 'Windows shutting down'
    4616 = 'System time changed'
    4624 = 'Logon success'
    4625 = 'Logon failure'
    4634 = 'Logoff'
    4647 = 'User-initiated logoff'
    4648 = 'Logon with explicit credentials'
    4649 = 'Replay attack detected'
    4656 = 'Handle to object requested'
    4657 = 'Registry value modified'
    4658 = 'Handle to object closed'
    4660 = 'Object deleted'
    4661 = 'Handle to SAM object requested'
    4662 = 'Directory object operation'
    4663 = 'Object access attempt'
    4670 = 'Object permissions changed'
    4672 = 'Special privilege logon'
    4673 = 'Privileged service called'
    4674 = 'Operation on privileged object'
    4688 = 'Process creation'
    4689 = 'Process exit'
    4696 = 'Primary token assigned'
    4697 = 'Service installed in SCM'
    4698 = 'Scheduled task created'
    4699 = 'Scheduled task deleted'
    4700 = 'Scheduled task enabled'
    4701 = 'Scheduled task disabled'
    4702 = 'Scheduled task updated'
    4703 = 'Token right adjusted'
    4704 = 'User right assigned'
    4705 = 'User right removed'
    4706 = 'New domain trust created'
    4707 = 'Domain trust removed'
    4713 = 'Kerberos policy changed'
    4715 = 'Object SACL changed'
    4719 = 'System audit policy changed'
    4720 = 'User account created'
    4722 = 'User account enabled'
    4723 = 'Password change attempt'
    4724 = 'Password reset'
    4725 = 'User account disabled'
    4726 = 'User account deleted'
    4728 = 'Member added to security global group'
    4729 = 'Member removed from security global group'
    4731 = 'Security local group created'
    4732 = 'Member added to security local group'
    4733 = 'Member removed from security local group'
    4735 = 'Security local group changed'
    4737 = 'Security global group changed'
    4738 = 'User account changed'
    4739 = 'Domain policy changed'
    4740 = 'Account locked out'
    4741 = 'Computer account created'
    4742 = 'Computer account changed'
    4743 = 'Computer account deleted'
    4754 = 'Security universal group created'
    4755 = 'Security universal group changed'
    4756 = 'Member added to security universal group'
    4757 = 'Member removed from security universal group'
    4764 = 'Group type changed'
    4767 = 'Account unlocked'
    4768 = 'Kerberos TGT requested (AS-REQ)'
    4769 = 'Kerberos service ticket requested (TGS-REQ)'
    4770 = 'Kerberos ticket renewed'
    4771 = 'Kerberos pre-auth failed'
    4772 = 'Kerberos auth ticket request failed'
    4773 = 'Kerberos service ticket request failed'
    4776 = 'NTLM credential validation'
    4778 = 'Session reconnected to Window Station'
    4779 = 'Session disconnected from Window Station'
    4800 = 'Workstation locked'
    4801 = 'Workstation unlocked'
    4802 = 'Screen saver invoked'
    4803 = 'Screen saver dismissed'
    4820 = 'Kerberos TGT denied (device restriction)'
    4826 = 'Boot configuration data loaded'
    4902 = 'Per-user audit policy table created'
    4904 = 'Security event source registered'
    4905 = 'Security event source unregistered'
    4906 = 'CrashOnAuditFail value changed'
    4907 = 'Auditing settings changed on object'
    4912 = 'Per-user audit policy changed'
    4946 = 'Windows Firewall rule added'
    4947 = 'Windows Firewall rule modified'
    4948 = 'Windows Firewall rule deleted'
    4950 = 'Windows Firewall setting changed'
    4954 = 'Windows Firewall Group Policy changed'
    5031 = 'Firewall blocked app from accepting connections'
    5033 = 'Firewall driver started'
    5034 = 'Firewall driver stopped'
    5136 = 'DS object modified'
    5137 = 'DS object created'
    5138 = 'DS object restored'
    5139 = 'DS object moved'
    5140 = 'Network share accessed'
    5141 = 'DS object deleted'
    5142 = 'Network share created'
    5143 = 'Network share modified'
    5144 = 'Network share deleted'
    5145 = 'Network share access check'
    5152 = 'WFP: packet blocked'
    5154 = 'WFP: app allowed to listen'
    5155 = 'WFP: app blocked from listening'
    5156 = 'WFP: connection allowed'
    5157 = 'WFP: connection blocked'
    5158 = 'WFP: bind permitted'
    5159 = 'WFP: bind blocked'
    5376 = 'Credential Manager creds backed up'
    5377 = 'Credential Manager creds restored'
    5712 = 'RPC call attempted'
    6272 = 'NPS: network access granted'
    6273 = 'NPS: network access denied'
    6274 = 'NPS: request discarded'
    6276 = 'NPS: user quarantined'
    6277 = 'NPS: access granted (probation)'
    6278 = 'NPS: full access granted'
    6279 = 'NPS: account locked (repeated failures)'
    6280 = 'NPS: account unlocked'
    # Microsoft-Windows-Windows Firewall With Advanced Security/Firewall — only encountered if
    # this tool is pointed at that channel's .evtx export rather than the Security log.
    2003 = 'Firewall settings changed (Firewall log)'
    2004 = 'Firewall rule added (Firewall log)'
    2005 = 'Firewall rule changed (Firewall log)'
    2006 = 'Firewall rule deleted (Firewall log)'
    2052 = 'Windows Firewall event (Firewall log)'
    2071 = 'Windows Firewall event (Firewall log)'
    2073 = 'Windows Firewall event (Firewall log)'
    2082 = 'Windows Firewall event (Firewall log)'
    2099 = 'Windows Firewall event (Firewall log)'
}

function Get-ZNBucketedRate {
    <#
    .SYNOPSIS
        Computes average and peak per-second event rate from a bucket-index -> count dictionary.
    .DESCRIPTION
        Shared rate math used by both Get-SecurityEventRate and Get-SecurityLogAnalysis so the
        two commands compute "events per second" identically. Average is Count over the full
        analysis window; peak is the busiest single bucket, normalized back to a per-second rate.
    .AUTHOR
        Olaf Gradin
    #>
    param(
        [System.Collections.IDictionary]$Buckets,

        [Parameter(Mandatory)]
        [long]$Count,

        [Parameter(Mandatory)]
        [double]$TotalSeconds,

        [Parameter(Mandatory)]
        [int]$BucketSeconds
    )

    $avg = if ($TotalSeconds -gt 0) { [math]::Round($Count / $TotalSeconds, 4) } else { 0 }

    $peak = 0
    if ($Buckets -and $Buckets.Count -gt 0) {
        $maxInBucket = ($Buckets.Values | Measure-Object -Maximum).Maximum
        $peak = [math]::Round($maxInBucket / $BucketSeconds, 4)
    }

    [PSCustomObject]@{
        Count = $Count
        Avg   = $avg
        Peak  = $peak
    }
}
