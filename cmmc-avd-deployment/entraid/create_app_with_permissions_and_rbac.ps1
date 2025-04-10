param (
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

# Connect to Azure
Connect-AzAccount

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

# Grant admin consent
Write-Host "Granting admin consent..."
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
$headers = @{ Authorization = "Bearer $token" }
$consentUri = "https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments" -f $sp.Id

# Note: Graph admin consent must be granted using Microsoft Graph REST API via Graph Explorer or a privileged user.
# Here we notify the user of manual fallback:
Start-Process "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/apiPermissions/appId/$($app.AppId)/isMSAApp~/false"
Write-Warning "⚠️ Admin consent must be granted manually unless using elevated privileges and Graph API."

# Assign RBAC role at subscription
$roleAssignmentParams = @{
    ObjectId           = $sp.Id
    RoleDefinitionName = "User Access Administrator"
    Scope              = "/subscriptions/$SubscriptionId"
}
New-AzRoleAssignment @roleAssignmentParams
Write-Host "✅ Assigned 'User Access Administrator' role at subscription scope."