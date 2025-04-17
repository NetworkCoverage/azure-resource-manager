param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [string]$CompanyName,

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'DeploymentScript')]
    [ValidateSet("AzureCloud", "AzureUSGovernment")]
    [string]$Environment = "AzureCloud",

    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [string[]]$LicenseName,

    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [string]$ApplicationId,

    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [switch]$DeploymentScriptMode
)

'Microsoft.Graph.Groups', 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Identity.Governance' | ForEach-Object {
    if (-not (Get-Module -ListAvailable -Name $_)) {
        Write-Host "Installing missing module: $_..."
        Install-Module -Name $_ -Scope CurrentUser -Force
    }
    Import-Module $_ -Force
}

# Connect to Microsoft Graph and Azure
if ($PSCmdlet.ParameterSetName -eq 'DeploymentScript') {
    $ConnectMgGraphParams = @{
        NoWelcome = $true
        ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, (ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force)
    }
    if ($Environment -eq "AzureUSGovernment") {
        $ConnectMgGraphParams['Environment'] = "USGov"
    }
    Write-Host "Connecting to Microsoft Graph using client credentials..."
    Connect-MgGraph @ConnectMgGraphParams
    
    $ConnectAzAccountParams = @{
        Environment = $Environment
        ServicePrincipal = $true
        ApplicationId = $ApplicationId
        Credential = $ClientSecretCredential
    }
    Write-Host "Connecting to Azure for RBAC using service principal..."
    Connect-AzAccount @ConnectAzAccountParams
}
else {
    $ConnectMgGraphParams = @{
        NoWelcome = $true        
        Scopes = "Group.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"
    }    
    if ($Environment -eq "AzureUSGovernment") {
        $ConnectMgGraphParams['Environment'] = "USGov"
    }
    Write-Host "Connecting to Microsoft Graph using interactive login with required scopes..."
    Connect-MgGraph @ConnectMgGraphParams    

    Write-Host "Connecting to Azure for RBAC using service principal..."
    Connect-AzAccount -Environment $Environment -UseDeviceAuthentication
}

# Check for required licensns in tenant
$licenses = Get-MgSubscribedSku

$requiredLicenses = @(
    'AAD_PREMIUM_P2*',              # For Entra PIM features
    'ENTERPRISE_MOBILITY_S5*',      # Microsoft Entra ID Governance
    'AAD_GOV_PREMIUM_P2*'           # If you're in USGov and it's named differently
)

if (-not ($licenses.SkuPartNumber -match ($requiredLicenses -join '|'))) {
    throw "Required Microsoft Entra P2 or Governance license not found in tenant. Please assign a valid license before running this script."
}

# All groups defined here
$GroupSets = @{
    PimGroups = @{
        ServiceDeskGroup = @{
            DisplayName = "Service Desk PIM Eligible Role Assignments"
            Description = "Members of this group will be assigned administrative roles for the Service Desk team via PIM."
            Roles = @("User Administrator", "Intune Administrator", "Exchange Administrator", "SharePoint Administrator" , "Groups Administrator", "Global Reader" )
        }
        ComplianceGroup = @{
            DisplayName = "Compliance PIM Eligible Role Assignments"
            Description = "Members of this group will be assigned administrative roles for the Compliance team via PIM."
            Roles = @("User Administrator", "Authentication Administrator", "Cloud App Security Administrator", "Security Administrator", "Groups Administrator", "Global Reader")
        }
        SecOpsGroup = @{
            DisplayName = "Security Operations PIM Eligible Role Assignments"
            Description = "Members of this group will be assigned administrative roles for the Security Operations team via PIM."
            Roles = @("Security Operator", "User Administrator", "Authentication Administrator", "Intune Administrator", "Exchange Administrator", "Global Reader")
        }
        EscalationEngineersGroup = @{
            DisplayName = "Escalation Engineers PIM Eligible Role Assignments"
            Description = "Members of this group will be assigned administrative roles for the escalation engineering team via PIM."
            Roles = @("Cloud App Security Operator", "Security Administrator", "Intune Administrator", "Authentication Administrator", "Global Reader")
        }
        SecEngGroup = @{
            DisplayName = "Security Engineering PIM Eligible Role Assignments"
            Description = "Members of this group will be assigned administrative roles for the Security Engineering team via PIM."
            Roles = @("Cloud Application Administrator", "Cloud App Security Administrator", "Security Administrator", "Global Reader")
        }
        GlobalAdminGroup = @{
            DisplayName = "Global Admin PIM Eligible Role Assignments"
            Description = "Members of this group will be assigned the Global Administrator role via PIM."
            Roles = @("Global Administrator")
        }
    }
    RbacGroups = @{
        OwnerGroup = @{
            DisplayName = "Owner RBAC Role Assignments"
            Description = "Members will be assigned to the Owner role for the subscription(s)."
            Roles = "Owner"
        }
        ContributorGroup = @{
            DisplayName = "Contributor RBAC Role Assignments"
            Description = "Members will be assigned to the Contributor role."
            Roles = "Contributor"
        }
        BillingReaderGroup = @{
            DisplayName = "Billing Reader RBAC Role Assignments"
            Description = "Members will be assigned to the Billing Reader role."
            Roles = "Billing Reader"
        }
    }
    MFAGroup = @{
        MFAExemptionGroup = @{
            DisplayName = "Multifactor Authentication Exempt"
            Description = "Members of this group are exempt from multifactor authentication requirements."
        }
    }
    DynamicGroups = @{
        SsprGroup = @{
            DisplayName = "Self Service Password Reset Enabled"
            Description = "Members are permitted to use SSPR. Membership is based on company name and enabled accounts."
            GroupTypes = @("DynamicMembership")
            Rule = "((user.companyName -eq `"$CompanyName`") or (user.companyName -eq `"Network Coverage`")) and (user.accountEnabled -eq true)"
        }
        AllUsersGroup = @{
            DisplayName = "All Users"
            Description = "Members in this dynamic user group have an account that is enabled."
            GroupTypes = @("DynamicMembership")
            Rule = "(user.accountEnabled -eq true)"
        }
        LicensedUsersGroup = @{
            DisplayName = ("{0} Licensed Users" -f $(if ($LicenseName.Count -gt 1) {($LicenseName -join " | ")} else {$LicenseName}))
            Description = ("Members in this dynamic user group will have an {0} license assigned." -f $(if ($LicenseName.Count -gt 1) {($LicenseName -join " | ")} else {$LicenseName}))
            GroupTypes = @("DynamicMembership")
            Rule = "(user.companyName -eq `"$CompanyName`") and (user.accountEnabled -eq true)"
        }
        AllWindowsDevicesGroup = @{
            DisplayName = "All Windows 10 and Later Devices"
            Description = "Members in this dynamic device group are all devices with active accounts with Windows operating systems that are version 10 or later"
            GroupTypes = @("DynamicMembership")
            Rule = '(device.accountEnabled -eq True) and (device.deviceOSType -eq "Windows") and ((device.deviceOSVersion -startsWith "10.0.1") or (device.deviceOSVersion -startsWith "10.0.2"))'
        }
    }
}

# Unified loop
foreach ($GroupType in $GroupSets.Keys) {
    foreach ($GroupKey in $GroupSets[$GroupType].Keys) {
        $Group = $GroupSets[$GroupType][$GroupKey]
        Write-Host ("Creating {0} group: {1}" -f $(switch ($GroupType) { 'PimGroups' {'PIM'} 'RbacGroups' {'RBAC'} 'DynamicGroups' {'Dynamic'} default { 'the' }}), $Group.DisplayName)

        # Base parameter splat
        $Params = @{
            DisplayName = $Group.DisplayName
            Description = $Group.Description
            MailEnabled = $false
            MailNickname = (New-Guid).ToString().Substring(0,10)
            SecurityEnabled = $true
            GroupTypes = @()
        }

        # Add dynamic group-specific settings
        if ($GroupType -eq 'DynamicGroups') {
            $Params.GroupTypes = $Group.GroupTypes
            $Params.MembershipRule = $Group.Rule
            $Params.MembershipRuleProcessingState = "On"
        }

        if ($GroupType -eq 'PimGroups') {
            $Params.IsAssignableToRole = $true
        }        

        # Send command
        $CreatedGroup = New-MgGroup @Params
        if ($PSCmdlet.ParameterSetName -eq 'DeploymentScript') {
            $DeploymentScriptOutputs[$GroupKey] = $CreatedGroup.Id
        }

        if ($GroupType -eq 'PimGroups' -or $GroupType -eq 'RbacGroups') {
            Write-Host "Waiting 60 seconds for group creation to propagate..."
            Start-Sleep -Seconds 60
        }

        # Handle PIM role assignments
        if ($GroupType -eq 'PimGroups') {
            Write-Host ("Assigning PIM roles to group: {0}" -f $Group.DisplayName)
            foreach ($RoleName in $Group.Roles) {
                $Template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName }
                if (-not $Template) {
                    Write-Warning "Role template '$RoleName' not found. Skipping."
                    continue
                }

                $ActiveRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq $RoleName }
                if (-not $ActiveRole) {
                    New-MgDirectoryRole -RoleTemplateId $Template.Id | Out-Null # Suppress output
                    $ActiveRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq $RoleName }
                }

                $AssignmentParameters = @{
                    action = "adminAssign"
                    justification = "Initial PIM setup for $($Group.DisplayName)"
                    roleDefinitionId = $ActiveRole.RoleTemplateId
                    directoryScopeId = "/"
                    principalId = $CreatedGroup.Id
                    scheduleInfo = @{
                        startDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                        expiration = @{
                            type = "noExpiration"
                        }
                    }
                }

                $MaxAttempts = 3
                $Success = $false
                $Attempt = 1

                while (-not $success -and $Attempt -le $MaxAttempts) {
                    try {
                        Write-Host ("Attempt {0}: Assigning role {1} to group {2}..." -f $Attempt, $RoleName, $Group.DisplayName)
                        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest @AssignmentParameters -ErrorAction Stop | Out-Null
                        Write-Host "Role $RoleName successfully assigned."
                        $Success = $true
                    }
                    catch {
                        Write-Warning ("Attempt {0} failed for {1}: {2}" -f $Attempt, $RoleName, $_.Exception.Message)
                        if ($Attempt -lt $maxAttempts) {
                            Write-Host "Waiting 30 seconds before retrying..."
                            Start-Sleep -Seconds 30
                        }
                        $Attempt++
                    }
                }

                if (-not $Success) {
                    throw ("Failed to assign role {0} to group {1} after {2} attempts." -f $RoleName, $($Group.DisplayName), $maxAttempts)
                }                
            }
        }

        # Handle RBAC role assignment
        elseif ($GroupType -eq 'RbacGroups') {
            Write-Host ("Assigning RBAC roles to group: {0}" -f $Group.DisplayName)

            $Condition = '(
                (
                !(ActionMatches{''Microsoft.Authorization/roleAssignments/write''})
                )
                OR 
                (
                @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAllValues:GuidNotEquals {8e3af657-a8ff-443c-a75c-2fe8c4bcb635, f58310d9-a9f6-439a-9e8d-f62e7b41a168, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9}
                )
                )
                AND
                (
                (
                !(ActionMatches{''Microsoft.Authorization/roleAssignments/delete''})
                )
                OR 
                (
                @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAllValues:GuidNotEquals {8e3af657-a8ff-443c-a75c-2fe8c4bcb635, f58310d9-a9f6-439a-9e8d-f62e7b41a168, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9}
                )
            )'

            $RoleParams = @{
                ObjectId = $CreatedGroup.Id
                RoleDefinitionName = $Group.Roles
                Scope = ('/subscriptions/{0}' -f (Get-AzContext).Subscription.Id)
            }

            if ($Group.Roles -eq 'Owner') {
                $RoleParams['Condition'] = $Condition
            }

            $MaxAttempts = 3
            $Attempt = 1
            $Success = $false

            while (-not $Success -and $Attempt -le $MaxAttempts) {
                try {
                    Write-Host ("Attempt {0}: Assigning role {1} to group {2}..." -f $Attempt, $Group.Roles, $Group.DisplayName)
                    New-AzRoleAssignment @RoleParams -ErrorAction Stop | Out-Null
                    Write-Host ("Role {0} successfully assigned to group {1}." -f $Group.Roles, $Group.DisplayName)
                    $Success = $true
                }
                catch {
                    Write-Warning ("Attempt {0} failed for role {1}: {2}" -f $Attempt, $Group.Roles, $_.Exception.Message)
                    if ($Attempt -lt $MaxAttempts) {
                        Write-Host ("Waiting 30 seconds before retrying...")
                        Start-Sleep -Seconds 30
                    }
                    $Attempt++
                }
            }

            if (-not $Success) {
                throw ("Failed to assign role {0} to group {1} after {2} attempts." -f $Group.Roles, $Group.DisplayName, $MaxAttempts)
            }
        }

    }
}

# Output all group IDs
#$DeploymentScriptOutputs