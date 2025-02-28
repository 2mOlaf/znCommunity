# Install the AzureAD module if not already installed
if (-not (Get-Module -ListAvailable -Name AzureAD)) {
    Install-Module -Name AzureAD -Force
}

# Import the AzureAD module
Import-Module AzureAD

# Connect to AzureAD
Connect-AzureAD

# Define the Azure Multi-Factor Authentication (MFA) App ID
$AzureMFAAppID = "981f26a1-7f43-403b-a875-f8b09b8cd720"

# Get the AzureAD service principal ObjectId for the MFA App ID
$AzureMFAObjID = Get-AzureADServicePrincipal -Filter "AppId eq '$AzureMFAAppID'" | Select-Object -ExpandProperty ObjectId

# Set the end date for the ClientSecret
$endDate = (Get-Date).AddYears(2)

# Pwsh Core flavor because the module is different
if ($PSVersionTable.PSEdition -eq "Core") {

    if (-Not (Get-Module -ListAvailable -Name Az)) {
        if ($IsElevated) {
            Install-Module -Name Az -AllowClobber -Force
        } else {
            Write-Host -ForegroundColor Red "AzureAD Module is not installed and you are not running in an elevated session."
            Write-Host -ForegroundColor Red "Please run Powershell as an Administrator and try again."
            return
        }
        
    }

    if (-Not (Get-AzContext).Account | Out-Null) {
        $login = "Connect-AzAccount"
        if ($TenantId) { $login += " -Tenant $($TenantId)" }
        else { write-warning "skipping Tenant specificity on connecting to AzureAD"}
        Invoke-Expression $login | Out-Null
    }

    # Get the Azure Multi-Factor Authentication (MFA) App ID from Zero Networks Enterprise App (Gallery Entity)
    $AzureMFAAppID = (Get-AzADServicePrincipal -DisplayNameBeginsWith 'zero networks').AppId

    # Get the AzureAD service principal ObjectId for the MFA App ID
    $AzureMFAObj = Get-AzADServicePrincipal -ApplicationId $AzureMFAAppID

    # Generate a new secret and set its expiry based on $endDate variable
    $ClientSecret = New-AzADSpCredential -ObjectId $AzureMFAObj.Id -EndDate $endDate | Select-Object -ExpandProperty secretText


} else {
    if (-not (Get-Module -ListAvailable -Name AzureAD)) {
        if ($IsElevated) {
            Install-Module -Name AzureAD -Repository PSGallery -AllowClobber -Force
        } else {
            Write-Host -ForegroundColor Red "AzureAD Module is not installed and you are not running in an elevated session."
            Write-Host -ForegroundColor Red "Please run Powershell as an Administrator and try again."
            return
        }
    }

    # Connect to AzureAD
    try {Get-AzureADTenantDetail | Out-Null}
    catch {
        $login = "Connect-AzureAD"
        
        if ($TenantId) { $login += " -TenantId $($TenantId)" }
        else { write-warning "skipping Tenant specificity on connecting to AzureAD"}
        
        Invoke-Expression $login | Out-Null
    }

    # Get the Azure Multi-Factor Authentication (MFA) App ID from Zero Networks Enterprise App (Gallery Entity)
    $AzureMFAAppID = (Get-AzureADServicePrincipal -Filter "DisplayName eq 'Zero Networks'").AppId

    # Get the AzureAD service principal ObjectId for the MFA App ID
    $AzureMFAObjID = Get-AzureADServicePrincipal -Filter "AppId eq '$AzureMFAAppID'" | Select-Object -ExpandProperty ObjectId

    # Generate a new secret and set its expiry based on $endDate variable
$ClientSecret = New-AzureADServicePrincipalPasswordCredential -ObjectId $AzureMFAObjID -EndDate $endDate | Select-Object -ExpandProperty Value
}

# Print the ClientSecret
Write-Host "ClientSecret: $ClientSecret"