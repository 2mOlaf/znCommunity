function Get-SegmentCluster {
    <#
    .SYNOPSIS
        Lists segment server clusters and their segment servers.
    .PARAMETER ApiKey
        Optional API key override; defaults to ZN_API_KEY environment variable.
    .PARAMETER ApiUrl
        Optional API base URL override (e.g., https://portal.zeronetworks.com/api/v1).
    .NOTES
        Author: Olaf Gradin
    #>
    [CmdletBinding()]
    param(
        [string]$ApiKey,
        [string]$ApiUrl
    )

    Ensure-ZNWelcomeShown
    $author = Get-ZNAuthorFromCommand -CommandName $MyInvocation.MyCommand.Name
    Show-Banner -Author $author -ScriptName $MyInvocation.MyCommand.Name
    $token = Get-ZNApiKey -ApiKey $ApiKey
    $baseUrl = Get-ZNApiBaseUrl -ApiKey $token -ApiUrl $ApiUrl
    $headers = Get-ZNApiHeaders -ApiKey $token

    try {
        $clusterResponse = Invoke-RestMethod -Uri "$baseUrl/environments/cluster" -Method Get -Headers $headers
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDesc = $_.Exception.Response.StatusDescription
        $errBody    = Get-ZNErrorBody $_
        Write-Error "Cluster request failed: Status $statusCode - $statusDesc"
        if ($errBody) { Write-Error "Response body: $errBody" }
        return
    }

    $clusterNameById = @{}
    if ($clusterResponse.items) {
        foreach ($c in @($clusterResponse.items)) {
            if ($c.id -and $c.name) { $clusterNameById[$c.id] = $c.name }
        }
    }

    try {
        $response = Invoke-RestMethod -Uri "$baseUrl/environments/deployments" -Method Get -Headers $headers

        $items = @()
        if ($response.items) { $items = @($response.items) }
        elseif ($response -is [array]) { $items = @($response) }
        elseif ($response.item) { $items = @($response.item) }

        if ($items.Count -eq 0) { return }

        $clusters = @{}

        foreach ($d in $items) {
            $clusterId = $d.deploymentsClusterId
            if (-not $clusterId) { $clusterId = $d.clusterId }
            if (-not $clusterId -and $d.cluster) { $clusterId = $d.cluster.id }

            $clusterName = $d.clusterName
            if (-not $clusterName -and $d.cluster) { $clusterName = $d.cluster.name }
            if (-not $clusterName -and $clusterId -and $clusterNameById.ContainsKey($clusterId)) {
                $clusterName = $clusterNameById[$clusterId]
            }
            if (-not $clusterName) { $clusterName = "Unclustered" }

            $key = "$clusterId|$clusterName"
            if (-not $clusters.ContainsKey($key)) {
                $clusters[$key] = [ordered]@{
                    clusterId   = $clusterId
                    clusterName = $clusterName
                    servers     = @()
                }
            }

            $clusters[$key].servers += [ordered]@{
                id        = $d.id
                name      = $d.name
                ipAddress = $d.ipAddress
            }
        }

        foreach ($cluster in $clusters.Values) {
            [pscustomobject]@{
                ClusterName    = $cluster.clusterName
                SegmentServers = @($cluster.servers | ForEach-Object { $_.name })
                ClusterId      = $cluster.clusterId
            }
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDesc = $_.Exception.Response.StatusDescription
        $errBody    = Get-ZNErrorBody $_
        Write-Error "Deployments request failed: Status $statusCode - $statusDesc"
        if ($errBody) { Write-Error "Response body: $errBody" }
    }
}
