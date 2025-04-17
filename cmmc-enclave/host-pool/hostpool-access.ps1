param (
    [System.String] $CompanyName,
    [System.String] $HostPoolName,
    [System.String] $HostPoolFriendlyName,
    [System.String] $ResourceGroupName
)

Connect-AzAccount -Environment AzureUSGovernment
Connect-MgGraph -Scopes "Group.ReadWrite.All" -Environment USGov

# Add the "Desktop Virtualization Power On Off Contributor" role to the resource group allowing the automatic startup and shutdown of AVDs
$parameters = @{
    RoleDefinitionName = 'Desktop Virtualization Power On Off Contributor'
    ApplicationId = "9cdead84-a844-4324-93f2-b2e6bb768d07"
    ResourceGroupName = $ResourceGroupName
}
New-AzRoleAssignment @parameters

# If one does not exist create a group for non adminstrative users and assign the 'Virtual Machine User Login' role to the group
$NonAdminGroup = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:Virtual Machine User Login"'
if ($null -eq $NonAdminGroup) {
    $parameters = @{
        DisplayName = 'Virtual Machine User Login'
        MailEnabled = $False 
        MailNickName = (New-Guid).ToString().Substring(0,10)
        SecurityEnabled = $true
        Description = 'Members of this group will be assigned the Virtual Machine User Login role. This role enables authentication to Azure AD joined VMs'
        MembershipRule = ("(user.companyName -eq `"{0}`") and (user.accountEnabled -eq true)" -f $CompanyName)
        MembershipRuleProcessingState = 'On'
        GroupTypes = 'DynamicMembership'
    }
    $NonAdminGroup = New-MgGroup @parameters
    Start-Sleep -Seconds 180 # give time for azure to propagate the new group
}
$parameters = @{
    ObjectId = $NonAdminGroup.Id
    RoleDefinitionName = 'Virtual Machine User Login'
    ResourceGroupName = $ResourceGroupName
}
New-AzRoleAssignment @parameters 


# If one does not exist create a group for administrative users and assign the 'Virtual Machine Administrator Login' role to the group
$AdminGroup = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:Virtual Machine Administrator Login"'
if ($null -eq $AdminGroup) {
    $parameters = @{
        DisplayName = 'Virtual Machine Administrator Login'
        MailEnabled = $False 
        MailNickName = (New-Guid).ToString().Substring(0,10)
        SecurityEnabled = $true
        Description = 'Members of this group will be assigned the Virtual Machine Administrator Login role. This role enables user to view Virtual Machines in the portal and login as administrator'
        MembershipRule = "(user.companyName -eq `"Network Coverage`") and (user.accountEnabled -eq true)"
        MembershipRuleProcessingState = 'On'
        GroupTypes = 'DynamicMembership'
    }
    $AdminGroup = New-MgGroup @parameters
    
    Start-Sleep -Seconds 180 # give time for azure to propagate the new group    
}
$parameters = @{
    ObjectId = $AdminGroup.Id
    RoleDefinitionName = 'Virtual Machine Administrator Login'
    ResourceGroupName = $ResourceGroupName
}
New-AzRoleAssignment @parameters 

# Create a groups of users to assign to the AVD application
$parameters = @{
    DisplayName = ('{0} Users' -f $HostPoolFriendlyName)
    MailEnabled = $False 
    MailNickName = (New-Guid).ToString().Substring(0,10)
    SecurityEnabled = $true
    Description = ('Members of this group are assigned to the desktop application group for {0}' -f $HostPoolFriendlyName)
}
$Group = New-MgGroup @parameters

Start-Sleep -Seconds 180 # give time for azure to propgate the new group

# Assign groups to the host pool desktop application group
$parameters = @{
    ObjectId = $Group.Id
    ResourceName = $HostPoolName
    ResourceGroupName = $ResourceGroupName
    RoleDefinitionName = 'Desktop Virtualization User'
    ResourceType = 'Microsoft.DesktopVirtualization/applicationGroups'
}

New-AzRoleAssignment @parameters

<# 
Service principal -	Application ID
Azure Virtual Desktop - 9cdead84-a844-4324-93f2-b2e6bb768d07
Azure Virtual Desktop Client - a85cf173-4192-42f8-81fa-777a763e6e2c
Azure Virtual Desktop ARM Provider - 50e95039-b200-4007-bc97-8d5790743a63
#>