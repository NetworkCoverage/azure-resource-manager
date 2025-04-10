param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ApplicationId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$CompanyName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

# Authenticate to Microsoft Graph
$SecuredPassword = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPassword
Connect-MgGraph -TenantId $TenantId -Environment USGov -ClientSecretCredential $ClientSecretCredential -NoWelcome

# Authenticate to Azure for RBAC assignments
Connect-AzAccount -ServicePrincipal -TenantId $TenantId -ApplicationId $ApplicationId -Credential $ClientSecretCredential

# Initialize output
$DeploymentScriptOutputs = @{}

# All groups defined here
$GroupSets = @{
    PimGroups = @{
        ServiceDeskGroup = @{
            DisplayName = "Service Desk PIM Eligible Role Assignments"
            Description = "Members of this group will be assigned administrative roles for the Service Desk team via PIM."
            Roles = @("User Administrator", "Intune Administrator", "Exchange Administrator", "SharePoint Administrator", "Groups Administrator", "Global Reader")
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
            DisplayName = "Owner"
            Description = "Members will be assigned to the Owner role for the subscription(s)."
            Roles = "Owner"
        }
        ContributorGroup = @{
            DisplayName = "Contributor"
            Description = "Members will be assigned to the Contributor role."
            Roles = "Contributor"
        }
        BillingReaderGroup = @{
            DisplayName = "Billing Reader"
            Description = "Members will be assigned to the Billing Reader role."
            Roles = "Billing Reader"
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
    }
}

# Unified loop
foreach ($GroupType in $GroupSets.Keys) {
    foreach ($GroupKey in $GroupSets[$GroupType].Keys) {
        $Group = $GroupSets[$GroupType][$GroupKey]
        Write-Host "Creating $GroupType group: $($Group.DisplayName)"

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

        $CreatedGroup = New-MgGroup @Params
        $DeploymentScriptOutputs[$GroupKey] = $CreatedGroup.Id

        # Handle PIM role assignments
        if ($GroupType -eq 'PimGroups') {
            foreach ($RoleName in $Group.Roles) {
                $Template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName }
                if (-not $Template) {
                    Write-Warning "Role template '$RoleName' not found. Skipping."
                    continue
                }

                $ActiveRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq $RoleName }
                if (-not $ActiveRole) {
                    Enable-MgDirectoryRole -DirectoryRoleTemplateId $Template.Id
                    $ActiveRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq $RoleName }
                }

                New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter @{
                    PrincipalId = $CreatedGroup.Id
                    RoleDefinitionId = $ActiveRole.RoleTemplateId
                    DirectoryScopeId = "/"
                    Action = "adminAssign"
                    Justification = "Initial PIM setup for $($Group.DisplayName)"
                    ScheduleInfo = @{
                        StartDateTime = (Get-Date).ToString("o")
                        Expiration = @{ Type = "NoExpiration" }
                    }
                }
            }
        }

        # Handle RBAC role assignment
        elseif ($GroupType -eq 'RbacGroups') {
            $RoleParams = @{
                ObjectId = $CreatedGroup.Id
                RoleDefinitionName = $Group.Roles
                Scope = "/subscriptions/$SubscriptionId"
            }
            New-AzRoleAssignment @RoleParams
        }
    }
}

# Output all group IDs
$DeploymentScriptOutputs