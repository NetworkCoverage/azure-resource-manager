param (
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter()]
    [string]$Environment = "AzureCloud",

    [switch]$GrantConsent
)

# Connect to Azure (supports AzureCloud, AzureUSGovernment, etc.)
Connect-AzAccount -Environment $Environment

# Register the app
$app = New-AzADApplication -DisplayName $DisplayName -IdentifierUris "api://$((New-Guid).Guid)" -AvailableToOtherTenants $false
Write-Host "✅ App registered: $($app.AppId)"

# Create the service principal
$sp = New-AzADServicePrincipal -ApplicationId $app.AppId
Write-Host "✅ Service principal created: $($sp.Id)"

# Define Microsoft Graph permissions
$graphAppId = "00000003-0000-0000-c000-000000000000"
$permissions = @(
    @{ Id = "06da0dbc-49e2-44d2-8312-53f166ab848a"; Type = "Role" }, # RoleManagement.ReadWrite.Directory
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }  # Directory.Read.All
)

# Apply Graph permissions
Set-AzADApplication -ObjectId $app.Id -RequiredResourceAccess @(
    @{
        ResourceAppId = $graphAppId
        ResourceAccess = $permissions
    }
)
Write-Host "🔐 Microsoft Graph permissions assigned."

# Admin consent
if ($GrantConsent) {
    Write-Host "🔁 Attempting to automatically grant admin consent..."
    $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -Environment $Environment).Token
    $headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

    $graphSp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?filter=appId eq '$graphAppId'" -Headers $headers
    $graphSpId = $graphSp.value[0].id

    $roleIds = @(
        "06da0dbc-49e2-44d2-8312-53f166ab848a", # RoleManagement.ReadWrite.Directory
        "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
    )

    foreach ($roleId in $roleIds) {
        $payload = @{
            principalId = $sp.Id
            resourceId = $graphSpId
            appRoleId = $roleId
        } | ConvertTo-Json -Depth 3

        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.Id)/appRoleAssignments" `
                          -Method POST -Headers $headers -Body $payload
        Write-Host "✅ Granted app role: $roleId"
    }
}
else {
    # Open the Azure Portal for manual consent
    Start-Process "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/apiPermissions/appId/$($app.AppId)/isMSAApp~/false"
    Write-Warning "⚠️ Admin consent must be granted manually unless you use the -GrantConsent switch."
}

# Assign RBAC role
$roleAssignmentParams = @{
    ObjectId           = $sp.Id
    RoleDefinitionName = "User Access Administrator"
    Scope              = "/subscriptions/$SubscriptionId"
}
New-AzRoleAssignment @roleAssignmentParams
Write-Host "✅ Assigned 'User Access Administrator' role at subscription scope."