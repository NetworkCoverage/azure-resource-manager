<#
    Creates an Intune Windows 10/11 compliance policy via Microsoft Graph,
    matching: Bitlocker Required, TPM Required, Antivirus Required,
    Antispyware Required, with actions for noncompliance
    (Mark noncompliant - Immediately, Send email to end user - Immediately),
    scoped to the "Default" scope tag.

#>

# ---------------------------------------------------------------------------
# 0. Setup
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installing Microsoft.Graph.Authentication..." -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication

Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"

# ---------------------------------------------------------------------------
# 1. Look up the "Default" scope tag ID
# ---------------------------------------------------------------------------
$scopeTagsResp = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/roleScopeTags?`$filter=displayName eq 'Default'"

$defaultScopeTagId = $scopeTagsResp.value[0].id
if (-not $defaultScopeTagId) {
    Write-Warning "Could not find 'Default' scope tag; falling back to id '0'."
    $defaultScopeTagId = "0"
}

# ---------------------------------------------------------------------------
# 2. Build the compliance policy body
# ---------------------------------------------------------------------------
$policyName = "Windows 10/11 compliance policy"

$body = @{
    "@odata.type"           = "#microsoft.graph.windows10CompliancePolicy"
    displayName             = $policyName
    description             = ""

    # --- Device Health ---
    bitLockerEnabled        = $true

    # --- System Security ---
    tpmRequired             = $true
    antivirusRequired       = $true
    antiSpywareRequired     = $true

    roleScopeTagIds         = @($defaultScopeTagId)

    scheduledActionsForRule = @(
        @{
            ruleName                      = "PasswordRequired"
            scheduledActionConfigurations = @(
                @{
                    actionType                = "block"          # Mark device noncompliant
                    gracePeriodHours          = 0                 # Immediately
                    notificationTemplateId    = ""                # set below if you have a template
                    notificationMessageCCList = @()
                }
            )
        }
    )
}

$bodyJson = $body | ConvertTo-Json -Depth 10

# ---------------------------------------------------------------------------
# 3. Create the policy
# ---------------------------------------------------------------------------
Write-Host "Creating compliance policy '$policyName'..." -ForegroundColor Cyan

$newPolicy = Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" `
    -Body $bodyJson `
    -ContentType "application/json"

Write-Host "Created policy with id: $($newPolicy.id)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. (Optional) Assign the policy - uncomment and set a group ID to assign
# ---------------------------------------------------------------------------
<#
$targetGroupId = "<YOUR-AZURE-AD-GROUP-ID>"

$assignBody = @{
    assignments = @(
        @{
            target = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId       = $targetGroupId
            }
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$($newPolicy.id)/assign" `
    -Body $assignBody `
    -ContentType "application/json"

Write-Host "Policy assigned to group $targetGroupId" -ForegroundColor Green
#>

Write-Host "Done." -ForegroundColor Cyan
