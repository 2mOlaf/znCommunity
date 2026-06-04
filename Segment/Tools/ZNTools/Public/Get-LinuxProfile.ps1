function Get-LinuxProfile {
    <#
    .SYNOPSIS
        Lists Linux configuration profiles.
    .DESCRIPTION
        Queries Zero Networks for Linux configuration profiles and returns Name/Id objects.
    .OUTPUTS
        PSCustomObject with Name and Id for each Linux Configuration Profile.
    .PARAMETER ApiKey
        Optional API key override; defaults to ZN_API_KEY environment variable.
    .PARAMETER ApiUrl
        Optional API base URL override (e.g., https://portal.zeronetworks.com/api/v1).
    .AUTHOR
        Olaf Gradin
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
        $response = Invoke-RestMethod -Uri "$baseUrl/settings/asset-management/linux/profile" -Method Get -Headers $headers
        $items = @()
        if ($response.items) { $items = @($response.items) }
        elseif ($response -is [array]) { $items = @($response) }
        elseif ($response.item) { $items = @($response.item) }

        foreach ($p in $items) {
            [pscustomobject]@{
                Name = $p.name
                Id   = $p.id
            }
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDesc = $_.Exception.Response.StatusDescription
        $errBody    = Get-ZNErrorBody $_
        $errMessage = $null
        if ($errBody) {
            try {
                $errMessage = ($errBody | ConvertFrom-Json).message
            } catch {
                $errMessage = $null
            }
        }
        Write-Error "Request failed: Status $statusCode - $statusDesc"
        if ($errBody) { Write-Error "Response body: $errBody" }
        switch ($errMessage) {
            "Permission Denied" { Write-Error "This API requires a read/write token!" }
        }
    }
}
