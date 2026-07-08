$script:HealthStatus = @{
    0 = 'Unspecified'
    1 = 'Healthy'
    2 = 'Error'
    3 = 'Warning'
    4 = 'N/A'
    5 = 'Retrying'
    6 = 'Blocker'
}

$script:SeverityOrder = @(6, 2, 3, 5, 0, 4)

$script:SeverityColor = @{
    6 = 'Red'
    2 = 'Red'
    3 = 'Yellow'
    5 = 'Cyan'
    0 = 'Gray'
    4 = 'DarkGray'
}

# Wording matches the assetStatus enum description in the ZN OpenAPI spec.
$script:AssetMonitorType = @{
    1  = 'Not Monitored'
    2  = 'Segment Server'
    4  = "Can't Be Monitored (Unsupported OS)"
    5  = "Can't Be Monitored (Unmonitorable)"
    6  = "Can't Be Monitored (Unmonitorable)"
    7  = 'Cloud Connector'
    8  = 'Not Monitored (Ansible Unreachable)'
    9  = 'Not Monitored (Cloud Connector Uninstalled)'
    10 = 'Not Monitored (Cloud Connector Required)'
    12 = "Can't Be Monitored (Inactive Entity)"
    13 = 'Stalked Externally'
    14 = 'Lightweight Agent'
}

# Verbatim from the healthIssue.issueCode enum description in the ZN OpenAPI spec, including
# the spec's own typos (e.g. "Unexpted", "Segmneted", "Cound not") — kept as-is so this map stays
# traceable to its source of truth rather than silently diverging from it again.
$script:IssueCodeNames = @{
    0    = 'Unspecified'
    1    = 'Unknown'
    2    = 'Access Denied'
    3    = 'IO Device Issue'
    4    = 'DotNet 3.5'
    5    = 'WMI Corrupted'
    6    = 'URL Filtering'
    7    = 'Out of Space'
    8    = 'Unsupported HMAC'
    9    = 'Unsupported Encryption'
    10   = 'Setup Script Failed'
    11   = 'Slow MFA'
    12   = 'Unexpted GPO Rules'
    13   = 'Zero Networks GPO Rule Mismatch'
    14   = 'Audit Mismatch'
    15   = 'Asset ID Mismatch'
    16   = 'Unsupported HTTP Version'
    17   = 'Registry Marked for Deletion'
    18   = 'Unable to add to automation group'
    19   = 'Incorrect Username or Password'
    20   = 'RPC Open Source Installed'
    21   = 'Timeout during initialization'
    22   = 'Data collection timeout'
    23   = 'Not in Sudoers'
    24   = 'Invalid SSH Key'
    25   = 'Events Unavailable'
    26   = 'SSH Password Incorrect'
    27   = 'SSH Password Expired'
    28   = 'Segmneted Users not found'
    29   = 'Unsupported Python Versions'
    30   = 'Cound not query segmented users'
    31   = 'Switch unreachable'
    32   = 'Switch communication issue'
    33   = 'Interface protection resource exceeded'
    34   = 'Unsupported Package Manager'
    35   = 'Firewall disabled by GPO'
    36   = 'Linux firewall logs oversized'
    1000 = 'First blocker issue code'
    1001 = 'Cluster node ipv6 disabled'
    1002 = 'Local rules merge disallowed'
}
