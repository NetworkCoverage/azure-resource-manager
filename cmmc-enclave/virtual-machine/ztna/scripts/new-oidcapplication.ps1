param (
    [Parameter()]
    [ValidateSet('AzureCloud', 'AzureUSGovernment')]
    [System.String]$Environment = 'AzureCloud',

    [Parameter(Mandatory = $true)]
    [System.String]$ControllerDNSName,

    [System.Management.Automation.SwitchParameter]$GrantConsent
)

'Microsoft.Graph.Groups', 'Microsoft.Graph.Applications' | ForEach-Object {
    if (-not (Get-Module -ListAvailable -Name $_)) {
        Write-Host 'Installing missing module: $_...'
        Install-Module -Name $_ -Scope CurrentUser -Force
    }
    Import-Module $_ -Force
}

$ConnectMgGraphParams = @{
    NoWelcome = $true        
    Scopes = 'Group.ReadWrite.All', 'Directory.ReadWrite.All', 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All'
    Environment = if ($Environment -eq 'AzureUSGovernment') {'USGov'} else {'Global'}
}
Write-Host 'Connecting to Microsoft Graph using interactive login with required scopes...'
Connect-MgGraph @ConnectMgGraphParams    

$ConnectAzAccountParams = @{
    Environment = $Environment
    UseDeviceAuthentication = if ($env:ACC_CLOUD -or $env:AZUREPS_HOST_ENVIRONMENT -like '*CloudShell*') {$true} else {$false}
}
Write-Host 'Connecting to Azure...'
Connect-AzAccount @ConnectAzAccountParams | Out-Null
$TenantId = (Get-AzContext).Tenant.Id

Write-Host 'Creating OIDC App...'
# Create the OIDC App
$AppParams = @{
    DisplayName = 'Appgate OIDC Identity Provider'
    GroupMembershipClaims = 'SecurityGroup'
    PublicClient = @{
        RedirectUris = @('http://localhost:29001/oidc')
    }
    Spa = @{
        RedirectUris = @(('https://{0}:8443/ui/' -f $ControllerDNSName))
    }
    OptionalClaims = @{
        idToken = @(@{
            name = 'groups'
            essential = $false
            additionalProperties = @('sam_account_name')
        })
        accessToken = @(@{
            name = 'groups'
            essential = $false
        })
    }
    RequiredResourceAccess = @(@{
        ResourceAppId = '00000003-0000-0000-c000-000000000000'  # Microsoft Graph
        ResourceAccess = @(@{
            Id = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d' # openid
            Type = 'Scope'
        })
    })
}

$App = New-MgApplication @AppParams

Write-Host 'Creating service principal...'
# Create the service principal for the app registration
$SpParams = @{
    AccountEnabled = $true
    AppId = $App.AppId
    DisplayName = 'Appgate OIDC Identity Provider'
    NotificationEmailAddresses = 'support@netcov.com'
    Tags = @(
        "WindowsAzureActiveDirectoryIntegratedApp",
        "HideApp"
    )
}
$Sp = New-MgServicePrincipal @SpParams

# Build the consent URL
$ConsentBaseUrl = if ((Get-AzContext).Environment.Name -eq 'AzureUSGovernment') {'https://login.microsoftonline.us'} else {'https://login.microsoftonline.com'}
$ConsentUrl = ('{0}/{1}/adminconsent?client_id={2}' -f $ConsentBaseUrl, $TenantId, $App.AppId)

# Get the Microsoft Graph service principal
# This is needed to grant admin consent for the app to use Microsoft Graph API
$GraphSp = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

# Create a client secret
Write-Host "Adding client secret..."

$PasswordCred = $null
$maxWait = 180  # 3 minutes
$interval = 5
$elapsed = 0

while (-not $PasswordCred -and $elapsed -lt $maxWait) {
    try {
        $PasswordCred = New-AzADAppCredential -ApplicationId $App.AppId -EndDate (Get-Date).AddDays(180) -ErrorAction SilentlyContinue
    } catch {
        if ($_.Exception.Message -like "*does not exist*") {
            Write-Host "Waiting for application to become available... retrying in $interval seconds"
            Start-Sleep -Seconds $interval
            $elapsed += $interval
        } else {
            throw $_
        }
    }
}

if (-not $PasswordCred) {
    Write-Warning "Timed out waiting for application to become available after $maxWait seconds."
    Write-Host "Cleaning up application and service principal..."

    try {
        if ($Sp) {
            Remove-MgServicePrincipal -ServicePrincipalId $Sp.Id -ErrorAction SilentlyContinue
        }
        if ($App) {
            Remove-MgApplication -ApplicationId $App.Id -ErrorAction SilentlyContinue
        }
        Write-Host "Cleanup completed."
    } catch {
        Write-Warning "Cleanup encountered an error: $_"
    }

    throw "Exiting script due to client secret creation failure."
}

# Admin Consent Logic
if (-not $GrantConsent -or -not $GraphSp) {
    if (-not $GrantConsent -and -not $GraphSp) {
        Write-Host 'Microsoft Graph API service principal not found. Granting admin consent using the URL...'
    }
    if ($env:ACC_CLOUD -or $env:AZUREPS_HOST_ENVIRONMENT -like '*CloudShell*') {
        Write-Host ('To grant admin consent, use a web browser to open the page {0} then sign in with a Global Admin account and accept the prompt to authorize the app.' -f $ConsentUrl)
        Read-Host "`nPress [Enter] once you have completed admin consent"
    }
    else {
        Write-Host 'Opening browser to grant admin consent...'
        Start-Process $ConsentUrl
        Read-Host "`nPress [Enter] once you have completed admin consent"
    }
}
else {
    Write-Host 'Granting admin consent using Microsoft Graph API...'
    $PermissionGrantParams = @{
        ClientId = $sp.Id
        ConsentType = 'AllPrincipals'
        ResourceId = $GraphSp.Id
        Scope = 'openid profile offline_access'
    }
    New-MgOauth2PermissionGrant @PermissionGrantParams
}

# Create dynamic group for Appgate users
Write-Host "Creating dynamic group 'Appgate OIDC Users'..."

$DynamicRule = "((user.companyName -eq `"$CompanyName`") or (user.companyName -eq `"Network Coverage`")) and (user.accountEnabled -eq true)"

$GroupParams = @{
    DisplayName     = 'Appgate OIDC Users'
    Description     = 'Users allowed to authenticate to Appgate via OIDC'
    MailEnabled     = $false
    MailNickname    = (New-Guid).ToString().Substring(0,10)
    SecurityEnabled = $true
    GroupTypes      = @('DynamicMembership')
    MembershipRule  = $DynamicRule
    MembershipRuleProcessingState = 'On'
}

$OidcGroup = New-MgGroup -DisplayName 'Appgate OIDC Users' -MailEnabled:$False  -MailNickName (New-Guid).ToString().Substring(0,10) -SecurityEnabled #New-MgGroup @GroupParams
Write-Host "Group created with Object ID: $($OidcGroup.Id)"

Write-Host "Assigning group to the application (service principal)..."

# Assign the group to the service principal
$AssignmentParams = @{
    PrincipalId = $OidcGroup.Id             # the group
    ServicePrincipalId  = $Sp.Id                    # the app's service principal
    AppRoleId   = '00000000-0000-0000-0000-000000000000'  # default role assignment
}

New-MgServicePrincipalAppRoleAssignment @AssignmentParams

Write-Host "Group successfully assigned to application."

# Output useful data
Write-Host ('App registration complete')
Write-Host ('Display Name           : {0}' -f $App.DisplayName)
Write-Host ('Client ID              : {0}' -f $App.AppId)
Write-Host ('ClientSecret           : {0}' -f $PasswordCred.SecretText)
Write-Host ('Object ID              : {0}' -f $App.Id)
Write-Host ('Service Principal ID   : {0}' -f $Sp.Id)
Write-Host ('Tenant ID              : {0}' -f $TenantId)
Write-Host ('OIDC metadata URL      : {0}/{1}/v2.0/.well-known/openid-configuration' -f $ConsentBaseUrl, $TenantId)
Write-Host ('OIDC issuer            : {0}/{1}/v2.0' -f $ConsentBaseUrl, $TenantId)

# Save output to JSON for automation
$AppMetadata = @{
    DisplayName        = $App.DisplayName
    ClientId           = $App.AppId
    ClientSecret       = $PasswordCred.SecretText
    TenantId           = $TenantId
    ObjectId           = $App.Id
    ServicePrincipalId = $Sp.Id
    OidcMetadataUrl    = ('{0}/{1}/v2.0/.well-known/openid-configuration' -f $ConsentBaseUrl, $TenantId)
    OidcIssuer         = ('{0}/{1}/v2.0' -f $ConsentBaseUrl, $TenantId)
}

$JsonPath = "appgate-iodc-app.json"
$AppMetadata | ConvertTo-Json -Depth 3 | Set-Content -Path $JsonPath -Encoding UTF8

Write-Host ("App metadata saved to file: {0}" -f (Resolve-Path $JsonPath))
