param (
    [Parameter(Mandatory = $true)]
    [string]$ApplicationId,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

# Get the service principal
$sp = Get-AzADServicePrincipal -ApplicationId $ApplicationId

if (-not $sp) {
    Write-Error "Service principal not found for ApplicationId: $ApplicationId"
    exit 1
}

# Define role assignment
$roleDefinitionName = "User Access Administrator"
$scope = "/subscriptions/$SubscriptionId"

# Assign the role
New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName $roleDefinitionName -Scope $scope
Write-Host "✅ Assigned '$roleDefinitionName' to service principal at $scope"