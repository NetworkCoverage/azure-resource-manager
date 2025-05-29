param (
    [Parameter(Mandatory = $true)]
    [System.String]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [System.String] $ApplicationGroupName,

    [Parameter(Mandatory = $true)]
    [System.String] $HostPoolFriendlyName,

    [Parameter()]
    [System.String]$CustomerName,

    [Parameter()]
    [System.Management.Automation.SwitchParameter]$IsCustomerResourceGroup
)

'Microsoft.Graph.Groups' | ForEach-Object {
    if (-not (Get-Module -ListAvailable -Name $_)) {
        Write-Host ('Installing missing module: {0}...' -f $_)
        Install-Module -Name $_ -Scope CurrentUser -Force
    }
    Import-Module $_ -Force
}

# Ensure proper Graph scopes are present
$RequiredScopes = @("Group.ReadWrite.All")
try {$Context = Get-MgContext} catch {$Context = $null}
$ExistingScopes = if ($Context) {$Context.Scopes} else {@()}
if (-not $Context -or ($RequiredScopes | Where-Object {$_ -notin $ExistingScopes})) {
    $Scopes = $ExistingScopes + $RequiredScopes | Select-Object -Unique
    Connect-MgGraph -NoWelcome -Scopes $Scopes -Environment 'USGov'
}

Write-Host "Connecting to Azure for RBAC..."
Connect-AzAccount -Environment AzureUSGovernment -UseDeviceAuthentication
 
# Add the "Desktop Virtualization Power On Off Contributor" role to the resource group allowing the automatic startup and shutdown of AVDs
$parameters = @{
    RoleDefinitionName = 'Desktop Virtualization Power On Off Contributor'
    ApplicationId = "9cdead84-a844-4324-93f2-b2e6bb768d07"
    ResourceGroupName = $ResourceGroupName
}
Write-Host "Assigning the 'Desktop Virtualization Power On Off Contributor' role to the resource group $ResourceGroupName"
New-AzRoleAssignment @parameters

# If one does not exist create a group for administrative users and assign the 'Virtual Machine Administrator Login' role to the group
$AdminGroup = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:Virtual Machine Administrator Login"'
if ($null -eq $AdminGroup) {
    $parameters = @{
        DisplayName = 'Virtual Machine Administrator Login'
        MailEnabled = $false 
        MailNickName = (New-Guid).ToString().Substring(0,10)
        SecurityEnabled = $true
        Description = 'Members of this group will be assigned the Virtual Machine Administrator Login role. This role enables user to view Virtual Machines in the portal and login as administrator'
        MembershipRule = "(user.companyName -eq `"Network Coverage`") and (user.accountEnabled -eq true)"
        MembershipRuleProcessingState = 'On'
        GroupTypes = 'DynamicMembership'
    }
    Write-Host "Creating the 'Virtual Machine Administrator Login' group..."
    $AdminGroup = New-MgGroup @parameters
    Start-Sleep -Seconds 180 # give time for azure to propagate the new group    
}
$parameters = @{
    ObjectId = $AdminGroup.Id
    RoleDefinitionName = 'Virtual Machine Administrator Login'
    ResourceGroupName = $ResourceGroupName
}
Write-Host "Assigning the 'Virtual Machine Administrator Login' role to the 'Virtual Machine Administrator Login' group..."
New-AzRoleAssignment @parameters 


if ($IsCustomerResourceGroup) {    
    # If one does not exist create a group for non adminstrative users and assign the 'Virtual Machine User Login' role to the group
    $NonAdminGroup = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:Virtual Machine User Login"'
    if ($null -eq $NonAdminGroup) {
        $parameters = @{
            DisplayName = 'Virtual Machine User Login'
            MailEnabled = $false 
            MailNickName = (New-Guid).ToString().Substring(0,10)
            SecurityEnabled = $true
            Description = 'Members of this group will be assigned the Virtual Machine User Login role. This role enables authentication to Azure AD joined VMs'
            MembershipRule = ("(user.companyName -eq `"{0}`") and (user.accountEnabled -eq true)" -f $CompanyName)
            MembershipRuleProcessingState = 'On'
            GroupTypes = 'DynamicMembership'
        }
        write-host "Creating the 'Virtual Machine User Login' group..."
        $NonAdminGroup = New-MgGroup @parameters
        Start-Sleep -Seconds 180 # give time for azure to propagate the new group
    }
    $parameters = @{
        ObjectId = $NonAdminGroup.Id
        RoleDefinitionName = 'Virtual Machine User Login'
        ResourceGroupName = $ResourceGroupName
    }
    Write-Host "Assigning the 'Virtual Machine User Login' role to the 'Virtual Machine User Login' group..."
    New-AzRoleAssignment @parameters 
}

# Create a groups of users to assign to the AVD application
$parameters = @{
    DisplayName = ('{0} Users' -f $HostPoolFriendlyName)
    MailEnabled = $false 
    MailNickName = (New-Guid).ToString().Substring(0,10)
    SecurityEnabled = $true
    Description = ('Members of this group are assigned to the desktop application group for {0}' -f $HostPoolFriendlyName)
    MembershipRule = if ($IsCustomerResourceGroup) {("(user.companyName -eq `"{0}`") and (user.accountEnabled -eq true)" -f $CompanyName)} else {"(user.companyName -eq `"Network Coverage`") and (user.accountEnabled -eq true)"}
    MembershipRuleProcessingState = 'On'
    GroupTypes = 'DynamicMembership'
}
Write-Host ("Creating the '{0} Users' group..." -f $HostPoolFriendlyName)
$Group = New-MgGroup @parameters

Start-Sleep -Seconds 180 # give time for azure to propgate the new group

# Assign groups to the host pool desktop application group
$parameters = @{
    ObjectId = $Group.Id
    ResourceName = $ApplicationGroupName
    ResourceGroupName = $ResourceGroupName
    RoleDefinitionName = 'Desktop Virtualization User'
    ResourceType = 'Microsoft.DesktopVirtualization/applicationGroups'
}
write-host ("Assigning the 'Desktop Virtualization User' role to the '{0} Users' group..." -f $HostPoolFriendlyName)
New-AzRoleAssignment @parameters

<# 
Service principal -	Application ID
Azure Virtual Desktop - 9cdead84-a844-4324-93f2-b2e6bb768d07
Azure Virtual Desktop Client - a85cf173-4192-42f8-81fa-777a763e6e2c
Azure Virtual Desktop ARM Provider - 50e95039-b200-4007-bc97-8d5790743a63
#>