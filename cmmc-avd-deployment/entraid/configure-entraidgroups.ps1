param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [string]$CompanyName,

    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [string]$ApplicationId,

    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true, ParameterSetName = 'DeploymentScript')]
    [switch]$DeploymentScriptMode
)


'Microsoft.Graph.Groups', 'Microsoft.Graph.DirectoryManagement', 'Microsoft.Graph.Identity.Governance' | ForEach-Object {
    if (-not (Get-Module -ListAvailable -Name $_)) {
        Write-Host "📦 Installing missing module: $_..."
        Install-Module -Name $_ -Scope CurrentUser -Force
    }
    Import-Module $_ -Force
}

switch ($PSCmdlet.ParameterSetName) {
    'DeploymentScript' {
        # Authenticate using client secret (Deployment Script mode)
        $SecuredPassword = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
        $ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPassword

        Write-Host "🔐 Connecting to Microsoft Graph using client credentials..."
        Connect-MgGraph -Environment USGov -ClientSecretCredential $ClientSecretCredential -NoWelcome

        Write-Host "🔐 Connecting to Azure for RBAC using service principal..."
        Connect-AzAccount -ServicePrincipal -ApplicationId $ApplicationId -Credential $ClientSecretCredential

        $DeploymentScriptOutputs = @{}
    }

    'Default' {
        if ($env:ACC_CLOUD == "AzureCloudShell") {
            Write-Host "☁️ Detected Cloud Shell environment. Using current context for Microsoft Graph..."
            Connect-MgGraph -Environment USGov
        }
        else {
            Write-Host "🧑‍💻 Using interactive login with required scopes..."
            Connect-MgGraph -Scopes "Group.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"
        }
    }
}

# Check for required licensns in tenant
$licenses = Get-MgSubscribedSku

$requiredLicenses = @(
    'AAD_PREMIUM_P2',               # For Entra PIM features
    'ENTERPRISE_MOBILITY_S5',      # Microsoft Entra ID Governance
    'AAD_GOV_PREMIUM_P2'           # If you're in USGov and it's named differently
)

if (-not ($licenses.SkuPartNumber -match ($requiredLicenses -join '|'))) {
    throw "❌ Required Microsoft Entra P2 or Governance license not found in tenant. Please assign a valid license before running this script."
}


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
        #$DeploymentScriptOutputs[$GroupKey] = $CreatedGroup.Id

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
                Scope = ('/subscriptions/{0}' -f (Get-AzContext).Subscription.Id)
            }
            New-AzRoleAssignment @RoleParams
        }
    }
}

# Output all group IDs
#$DeploymentScriptOutputs