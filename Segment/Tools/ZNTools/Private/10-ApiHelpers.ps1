function Get-ZNErrorBody {
    param($ErrorRecord)
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return $ErrorRecord.ErrorDetails.Message
    }
    try {
        $stream = $ErrorRecord.Exception.Response.GetResponseStream()
        $stream.Position = 0
        return (New-Object System.IO.StreamReader($stream)).ReadToEnd()
    } catch { return "" }
}

function Get-ZNApiKey {
    param([string]$ApiKey)
    if ($ApiKey) { return $ApiKey }
    $envKey = [System.Environment]::GetEnvironmentVariable("ZN_API_KEY")
    if ($envKey) { return $envKey }
    throw "API key must be provided via -ApiKey or ZN_API_KEY environment variable"
}

function Parse-JWT {
    param([string]$Token)
    $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    while ($payload.Length % 4) { $payload += "=" }
    [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

function Get-ZNApiBaseUrl {
    param(
        [string]$ApiKey,
        [string]$ApiUrl
    )
    if ($ApiUrl) { return $ApiUrl.TrimEnd('/') }
    try {
        $decoded = Parse-JWT -Token $ApiKey
        return ("https://{0}/api/v1" -f $decoded.aud).TrimEnd('/')
    }
    catch {
        return "https://portal.zeronetworks.com/api/v1"
    }
}

function Get-ZNApiHeaders {
    param([string]$ApiKey)
    return @{
        'Authorization' = $ApiKey
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
    }
}
