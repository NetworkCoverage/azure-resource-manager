param (
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,

    [Parameter()]
    [ValidateSet("AzureCloud", "AzureUSGovernment")]
    [string]$Environment = "AzureCloud",

    [switch]$GrantConsent
)

# Determine if running in Cloud Shell
$IsCloudShell = $false
if ($env:ACC_CLOUD -or $env:AZUREPS_HOST_ENVIRONMENT -like "*CloudShell*") {
    $IsCloudShell = $true
    Write-Host "☁️` Running in Azure Cloud Shell. Using existing authenticated context."
}

# Try to get current Az context
$Context = Get-AzContext -ErrorAction SilentlyContinue

# Authenticate if not in Cloud Shell and no context is available
if (-not $IsCloudShell -and -not $Context) {
    Write-Host "🔐` No Azure context found. Attempting interactive login..."
    Connect-AzAccount -Environment $Environment
    $Context = Get-AzContext
}

# Register the app
$App = New-AzADApplication -DisplayName $DisplayName
Write-Host ("✅` App registered: {0}" -f $App.AppId)

# Create the service principal
$Sp = New-AzADServicePrincipal -ApplicationId $App.AppId
Write-Host ("✅` Service principal created: {0}" -f $Sp.Id)

# Define Microsoft Graph permissions
$GraphAppId = "00000003-0000-0000-c000-000000000000"
$Permissions = @(
    @{ Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"; Type = "Role" }, # RoleManagement.ReadWrite.Directory
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }  # Directory.Read.All
)

# Apply Graph permissions
Set-AzADApplication -ObjectId $App.Id -RequiredResourceAccess @(
    @{
        ResourceAppId = $GraphAppId
        ResourceAccess = $Permissions
    }
)
Write-Host "🔐` Microsoft Graph permissions assigned."

# Admin consent
if ($GrantConsent) {
    switch ($Context.Environment.Name) {
        "AzureCloud" { $GraphResourceUrl = "https://graph.microsoft.com" }
        "AzureUSGovernment" { $GraphResourceUrl = "https://graph.microsoft.us" }
        default { throw "Unsupported Azure environment: $Environment" }
    }

    Write-Host "🔁 Attempting to automatically grant admin consent..."
    $Token = (Get-AzAccessToken -ResourceUrl $GraphResourceUrl).Token
    $Headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }

    $GraphSp = Invoke-RestMethod -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals?filter=appId eq '{0}'" -f $GraphAppId) -Headers $Headers
    $GraphSpId = $GraphSp.value[0].id

    $RoleIds = @(
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", # RoleManagement.ReadWrite.Directory
        "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
    )

    foreach ($RoleId in $RoleIds) {
        $Payload = @{
            principalId = $Sp.Id
            resourceId = $GraphSpId
            appRoleId  = $RoleId
        } | ConvertTo-Json -Depth 3

        $ConsentParams = @{
            Uri     = ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $Sp.Id)
            Method  = "POST"
            Headers = $Headers
            Body    = $Payload
        }

        Invoke-RestMethod @ConsentParams
        Write-Host ("✅ Granted app role: {0}" -f $RoleId)
    }
}
else {
    $ConsentUrl = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/apiPermissions/appId/{0}/isMSAApp~/false" -f $App.AppId

    if ($IsCloudShell) {
        Write-Host "`n🔗 Grant consent manually by visiting the following URL:`n$ConsentUrl`n"
        Write-Warning "⚠️` Admin consent must be granted manually unless you use the -GrantConsent switch."
    }
    else {
        Start-Process $ConsentUrl
        Write-Warning "⚠️` Admin consent must be granted manually unless you use the -GrantConsent switch."
    }
}

# Assign RBAC role
$RoleAssignmentParams = @{
    ObjectId           = $Sp.Id
    RoleDefinitionName = "User Access Administrator"
    Scope              = "/subscriptions/{0}" -f $Context.Subscription.Id
}
New-AzRoleAssignment @RoleAssignmentParams
Write-Host "✅` Assigned 'User Access Administrator' role at subscription scope."

# Create a client secret
$Expiry = (Get-Date).AddDays(180)
$PasswordCred = New-AzADAppCredential -ApplicationId $App.AppId -EndDate $Expiry

# Output App ID and Secret Value
Write-Host "`n🔐` Application created and credentials generated successfully:`n"
Write-Host ("  AppId        : {0}" -f $App.AppId)
Write-Host ("  ClientSecret : {0}" -f $PasswordCred.SecretText)
Write-Host ("  TenantId     : {0}" -f $Context.Tenant.Id)
Write-Host ("  Subscription : {0}" -f $Context.Subscription.Id)