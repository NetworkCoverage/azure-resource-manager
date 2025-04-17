# Entra ID Group Provisioning Script

## Overview

This script automates the creation of essential Entra ID security groups and role assignments. It is intended to be used in scenarios such as Infrastructure as Code (IaC) deployments using Azure Resource Manager (ARM) templates via the `deploymentScript` resource.

The script supports:

1. Creating **PIM-eligible Entra ID groups** and assigning roles like User Administrator, Global Reader, Security Administrator, etc.
2. Creating **RBAC-based groups** and assigning Azure roles at the subscription scope (e.g., Owner, Contributor, Billing Reader).
3. Creating a **dynamic group for Self-Service Password Reset (SSPR)** based on company name and account status.

---

## Functionality Details

### 🔐 PIM Groups

- Each PIM group is created and assigned Entra ID roles as eligible via PIM.
- These roles must be activated by users through the PIM portal.

### ⚙️ RBAC Groups

- Each RBAC group is assigned a built-in Azure role (`Owner`, `Contributor`, or `Billing Reader`) at the specified subscription level using `New-AzRoleAssignment`.

### 🔁 SSPR Dynamic Group

- A dynamic group named `Self Service Password Reset Enabled` is created.
- Membership is based on the following rule:

```plaintext
((user.companyName -eq "YourCompanyName") or (user.companyName -eq "Network Coverage")) and (user.accountEnabled -eq true)
```

#### ⚠️ Note:
Microsoft Graph PowerShell does **not support** full configuration of SSPR policy via script as of April 2025. The following settings must be configured manually via the Azure portal:

- Number of security questions to register and reset
- Security question selection
- Enabling the password reset policy for the group

Steps:
1. Go to **Entra ID > Password Reset**
2. Select the **"Self Service Password Reset Enabled"** group
3. Configure the desired registration/reset question settings

---

## Parameters

| Parameter       | Description                          |
|----------------|--------------------------------------|
| `TenantId`      | The Entra ID (Azure AD) tenant ID    |
| `ApplicationId` | The service principal App ID         |
| `ClientSecret`  | Secret used for app authentication   |
| `CompanyName`   | The organization name for SSPR rule  |
| `SubscriptionId`| The subscription where RBAC is scoped|

---

## ARM DeploymentScript Example - Arguments

```json
"arguments": "-TenantId \"00000000-0000-0000-0000-000000000000\" -ApplicationId \"11111111-1111-1111-1111-111111111111\" -ClientSecret \"s3cr3t!\" -CompanyName \"Contoso\" -SubscriptionId \"22222222-2222-2222-2222-222222222222\""
```

> ⚠️ Remember to double-escape quotes in your ARM templates.

---

## Outputs

After execution, the following group IDs are returned as script outputs for use in your ARM template or external tools:

- `ssprGroupId`
- `serviceDeskGroupId`
- `complianceGroupId`
- `secOpsGroupId`
- `escalationEngineersGroupId`
- `secEngGroupId`
- `globalAdminGroupId`
- `ownerGroupId`
- `contributorGroupId`
- `billingReaderGroupId`

These outputs can be referenced like:

```json
"[reference('YourDeploymentScriptName').outputs.ownerGroupId]"
```