param (
    [System.Management.Automation.SwitchParameter] $GpuVms
)

#region functions
function Invoke-IntuneRestoreDeviceConfiguration {
    <#
    .SYNOPSIS
    Restore Intune Device Configurations
    
    .DESCRIPTION
    Restore Intune Device Configurations from JSON files per Device Configuration Policy from the specified Path.
    
    .PARAMETER Path
    Root path where backup files are located, created with the Invoke-IntuneBackupDeviceConfigurations function
    
    .EXAMPLE
    Invoke-IntuneRestoreDeviceConfiguration -Path "C:\temp" -RestoreById $true
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet("v1.0", "Beta")]
        [string]$ApiVersion = "Beta"
    )

    #Connect to MS-Graph if required
    if($null -eq (Get-MgContext)){
        connect-mggraph -scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All" 
    }

    # Get all device configurations
    $deviceConfigurations = Get-ChildItem -Path "$path\Device Configurations" -File -ErrorAction SilentlyContinue
    
    foreach ($deviceConfiguration in $deviceConfigurations) {
        $deviceConfigurationContent = Get-Content -LiteralPath $deviceConfiguration.FullName -Raw | ConvertFrom-Json

        $deviceConfigurationDisplayName = $deviceConfigurationContent.displayName

        # Remove properties that are not available for creating a new configuration
        $requestBodyObject = $deviceConfigurationContent | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
        # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
        if ($requestBodyObject.supportsScopeTags) {
            $requestBodyObject.supportsScopeTags = $false
        }

        $requestBodyObject.PSObject.Properties | Foreach-Object {
            if ($null -ne $_.Value) {
                if ($_.Value.GetType().Name -eq "DateTime") {
                    $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                }
            }
        }

        $requestBody = $requestBodyObject  | ConvertTo-Json -Depth 100

        # Restore the device configuration
        try {
            $null = Invoke-MgGraphRequest -Method POST -body $requestBody.toString() -Uri "$ApiVersion/deviceManagement/deviceConfigurations" -ErrorAction Stop
            [PSCustomObject]@{
                "Action" = "Restore"
                "Type"   = "Device Configuration"
                "Name"   = $deviceConfigurationDisplayName
                "Path"   = "Device Configurations\$($deviceConfiguration.Name)"
            }
        }
        catch {
            Write-Verbose "$deviceConfigurationDisplayName - Failed to restore Device Configuration" -Verbose
            Write-Error $_ -ErrorAction Continue
        }
    }
}

function Invoke-IntuneRestoreConfigurationPolicy {
    <#
    .SYNOPSIS
    Restore Intune Settings Catalog Policies
    
    .DESCRIPTION
    Restore Intune Settings Catalog Policies from JSON files per Settings Catalog Policy from the specified Path.
    
    .PARAMETER Path
    Root path where backup files are located, created with the Invoke-IntuneBackupConfigurationPolicy function
    
    .EXAMPLE
    Invoke-IntuneRestoreConfigurationPolicy -Path "C:\temp"
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet("v1.0", "Beta")]
        [string]$ApiVersion = "Beta"
    )

    #Connect to MS-Graph if required
    if($null -eq (Get-MgContext)){
        connect-mggraph -scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All" 
    }

    # Get all Settings Catalog Policies
    $configurationPolicies = Get-ChildItem -Path "$Path\Settings Catalog" -File -ErrorAction SilentlyContinue

    foreach ($configurationPolicy in $configurationPolicies) {
        $configurationPolicyContent = Get-Content -LiteralPath $configurationPolicy.FullName -Raw | ConvertFrom-Json

        # Remove properties that are not available for creating a new configuration
        $requestBody = $configurationPolicyContent | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, settingCount, creationSource | ConvertTo-Json -Depth 100

        # Restore the Settings Catalog Policy
        try {
            $null = Invoke-MgGraphRequest -Method POST -Body $requestBody.toString() -Uri "$ApiVersion/deviceManagement/configurationPolicies" -ErrorAction Stop
            [PSCustomObject]@{
                "Action" = "Restore"
                "Type"   = "Settings Catalog"
                "Name"   = $configurationPolicy.BaseName
                "Path"   = "Settings Catalog\$($configurationPolicy.Name)"
            }
        }
        catch {
            Write-Verbose "$($configurationPolicy.FullName) - Failed to restore Settings Catalog Policy" -Verbose
            Write-Error $_ -ErrorAction Continue
        }
    }
}

function Invoke-IntuneRestoreDeviceCompliancePolicy {
    <#
    .SYNOPSIS
    Restore Intune Device Compliance Policies
    
    .DESCRIPTION
    Restore Intune Device Compliance Policies from JSON files per Device Compliance Policy from the specified Path.
    
    .PARAMETER Path
    Root path where backup files are located, created with the Invoke-IntuneBackupDeviceCompliancePolicy function
    
    .EXAMPLE
    Invoke-IntuneRestoreDeviceCompliance -Path "C:\temp" -RestoreById $true
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet("v1.0", "Beta")]
        [string]$ApiVersion = "Beta"
    )

     #Connect to MS-Graph if required
     if($null -eq (Get-MgContext)){
        connect-mggraph -scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All" 
    }

    # Get all Device Compliance Policies
    $deviceCompliancePolicies = Get-ChildItem -Path "$Path\Device Compliance Policies" -File -ErrorAction SilentlyContinue
	
    foreach ($deviceCompliancePolicy in $deviceCompliancePolicies) {
        $deviceCompliancePolicyContent = Get-Content -LiteralPath $deviceCompliancePolicy.FullName  -Raw | ConvertFrom-Json

        $deviceCompliancePolicyDisplayName = $deviceCompliancePolicyContent.displayName

        # Remove properties that are not available for creating a new configuration
        $requestBody = $deviceCompliancePolicyContent | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime 

        # If missing, adds a default required block scheduled action to the compliance policy request body, as this value is not returned when retrieving compliance policies.
        if (-not ($requestBody.scheduledActionsForRule)) {
            $scheduledActionsForRule = @(
                @{
                    ruleName = "PasswordRequired"
                    scheduledActionConfigurations = @(
                        @{
                            actionType = "block"
                            gracePeriodHours = 0
                            notificationTemplateId = ""
                        }
                    )
                }
            )
            $requestBody | Add-Member -NotePropertyName scheduledActionsForRule -NotePropertyValue $scheduledActionsForRule
        }
        
        $requestBodyJson = $requestBody | ConvertTo-Json -Depth 100

        # Restore the Device Compliance Policy
        try {
            $null = Invoke-MgGraphRequest -Method POST -body $requestBodyJson.toString() -Uri "beta/deviceManagement/deviceCompliancePolicies" -ErrorAction Stop
            [PSCustomObject]@{
                "Action" = "Restore"
                "Type"   = "Device Compliance Policy"
                "Name"   = $deviceCompliancePolicyDisplayName
                "Path"   = "Device Compliance Policies\$($deviceCompliancePolicy.Name)"
            }
        }
        catch {
            Write-Verbose "$deviceCompliancePolicyDisplayName - Failed to restore Device Compliance Policy" -Verbose
            Write-Error $_ -ErrorAction Continue
        }
    }
}

# Assignment functions need work
function Invoke-IntuneRestoreDeviceConfigurationAssignment {
    <#
    .SYNOPSIS
    Restore Intune Device Configuration Assignments
    
    .DESCRIPTION
    Restore Intune Device Configuration Assignments from JSON files per Device Configuration Policy from the specified Path.
    
    .PARAMETER Path
    Root path where backup files are located, created with the Invoke-IntuneBackupDeviceConfigurationAssignment function

    .PARAMETER RestoreById
    If RestoreById is set to true, assignments will be restored to Intune Device Management Scripts that match the id.

    If RestoreById is set to false, assignments will be restored to Intune Device Management Scripts that match the file name.
    This is necessary if the Device Management Script was restored from backup, because then a new Device Management Script is created with a new unique ID.
    
    .EXAMPLE
    Invoke-IntuneRestoreDeviceConfigurationAssignment -Path "C:\temp" -RestoreById $true
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [bool]$RestoreById = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet("v1.0", "Beta")]
        [string]$ApiVersion = "Beta"
    )

    #Connect to MS-Graph if required
    if($null -eq (Get-MgContext)){
        connect-mggraph -scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All" 
    }

    # Get all policies with assignments
    $deviceConfigurations = Get-ChildItem -Path "$Path\Device Configurations\Assignments" -File -ErrorAction SilentlyContinue
	
    foreach ($deviceConfiguration in $deviceConfigurations) {
        $deviceConfigurationAssignments = Get-Content -LiteralPath $deviceConfiguration.FullName | ConvertFrom-Json
        $deviceConfigurationName = $deviceConfiguration.BaseName

        # Create the base requestBody
        $requestBody = @{
            assignments = @()
        }
        
        # Add assignments to restore to the request body
        foreach ($deviceConfigurationAssignment in $deviceConfigurationAssignments) {
            $requestBody.assignments += @{
                "target" = $deviceConfigurationAssignment.target
            }
        }

        # Convert the PowerShell object to JSON
        $requestBody = $requestBody | ConvertTo-Json -Depth 100

        # Get the Device Configuration we are restoring the assignments for
        try {
            if ($restoreById) {
                $deviceConfigurationObject = Invoke-MgGraphRequest -Uri "$apiVersion/deviceManagement/deviceConfigurations/$($deviceConfigurationAssignment.sourceid)" | Get-MGGraphAllPages
            }   
            else {
                $deviceConfigurationObject = Invoke-MgGraphRequest -Uri "$apiVersion/deviceManagement/deviceConfigurations" | Get-MGGraphAllPages | Where-Object displayName -eq $deviceConfigurationName
                if (-not ($deviceConfigurationObject)) {
                    Write-Verbose "Error retrieving Intune Device Configuration for $($deviceConfiguration.FullName). Skipping assignment restore" -Verbose
                    continue
                }
            }
        }
        catch {
            Write-Verbose "Error retrieving Intune Device Configuration for $($deviceConfiguration.FullName). Skipping assignment restore" -Verbose
            Write-Error $_ -ErrorAction Continue
            continue
        }

        # Restore the assignments
        try {
            $null = Invoke-MgGraphRequest -Method POST -body $requestBody.toString() -Uri "$apiVersion/deviceManagement/deviceConfigurations/$($deviceConfigurationObject.id)/assign" -ErrorAction Stop
            [PSCustomObject]@{
                "Action" = "Restore"
                "Type"   = "Device Configuration Assignments"
                "Name"   = $deviceConfigurationObject.displayName
                "Path"   = "Device Configurations\Assignments\$($deviceConfiguration.Name)"
            }
        }
        catch {
            Write-Verbose "$($deviceConfigurationObject.displayName) - Failed to restore Device Configuration Assignment(s)" -Verbose
            Write-Error $_ -ErrorAction Continue
        }
    }
}

function Invoke-IntuneRestoreConfigurationPolicyAssignment {
    <#
    .SYNOPSIS
    Restore Intune Configuration Policy Assignments
    
    .DESCRIPTION
    Restore Intune Configuration Policy Assignments from JSON files per Configuration Policy from the specified Path.
    
    .PARAMETER Path
    Root path where backup files are located, created with the Invoke-IntuneBackupConfigurationPolicyAssignment function

    .PARAMETER RestoreById
    If RestoreById is set to true, assignments will be restored to Intune Device Management Scripts that match the id.

    If RestoreById is set to false, assignments will be restored to Intune Device Management Scripts that match the file name.
    This is necessary if the Device Management Script was restored from backup, because then a new Device Management Script is created with a new unique ID.
    
    .EXAMPLE
    Invoke-IntuneBackupConfigurationPolicyAssignment -Path "C:\temp" -RestoreById $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [bool]$RestoreById = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet("v1.0", "Beta")]
        [string]$ApiVersion = "Beta"
    )

    #Connect to MS-Graph if required
    if($null -eq (Get-MgContext)){
        connect-mggraph -scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All" 
    }

    # Get all policies with assignments
    $configurationPolicies = Get-ChildItem -Path "$Path\Settings Catalog\Assignments" -File -ErrorAction SilentlyContinue
	
    foreach ($configurationPolicy in $configurationPolicies) {
        $configurationPolicyAssignments = Get-Content -LiteralPath $configurationPolicy.FullName | ConvertFrom-Json
        $configurationPolicyId = ($configurationPolicyAssignments[0]).id.Split("_")[0]
        $configurationPolicyName = $configurationPolicy.BaseName
		
        # Create the base requestBody
        $requestBody = @{
            assignments = @()
        }
        
        # Add assignments to restore to the request body
        foreach ($configurationPolicyAssignment in $configurationPolicyAssignments) {
            $requestBody.assignments += @{
                "target" = $configurationPolicyAssignment.target
            }
        }

        # Convert the PowerShell object to JSON
        $requestBody = $requestBody | ConvertTo-Json -Depth 100

        # Get the Configuration Policy we are restoring the assignments for
        try {
            if ($restoreById) {
                $configurationPolicyObject = Invoke-MgGraphRequest -method GET -Uri "$apiVersion/deviceManagement/configurationPolicies/$configurationPolicyId"
            }
            else {
                $configurationPolicyObject =  Invoke-MgGraphRequest -method GET -Uri "$apiVersion/deviceManagement/configurationPolicies" | Get-MgGraphAllPages | Where-Object name -eq $configurationPolicyName 
                if (-not ($configurationPolicyObject)) {
                    Write-Verbose "Error retrieving Intune Session Catalog for $($configurationPolicy.FullName). Skipping assignment restore" -Verbose
                    continue
                }
            }
        }
        catch {
            Write-Verbose "Error retrieving Intune Session Catalog for $($configurationPolicy.FullName). Skipping assignment restore" -Verbose
            Write-Error $_ -ErrorAction Continue
            continue
        }

        # Restore the assignments
        try {
            $null = Invoke-MgGraphRequest -method POST -body $requestBody.toString() -Uri "$apiVersion/deviceManagement/configurationPolicies/$($configurationPolicyObject.id)/assign" -ErrorAction Stop
            [PSCustomObject]@{
                "Action" = "Restore"
                "Type"   = "Settings Catalog Assignments"
                "Name"   = $configurationPolicyObject.name
                "Path"   = "Settings Catalog\Assignments\$($configurationPolicy.Name)"
            }
        }
        catch {
            Write-Verbose "$($configurationPolicyObject.name) - Failed to restore Settings Catalog Assignment(s)" -Verbose
            Write-Error $_ -ErrorAction Continue
        }
    }
}

function Invoke-IntuneRestoreDeviceCompliancePolicyAssignment {
    <#
    .SYNOPSIS
    Restore Intune Device Compliance Policy Assignments
    
    .DESCRIPTION
    Restore Intune Device Compliance Policy Assignments from JSON files per Device Compliance Policy from the specified Path.
    
    .PARAMETER Path
    Root path where backup files are located, created with the Invoke-IntuneBackupDeviceCompliancePolicyAssignment function

    .PARAMETER RestoreById
    If RestoreById is set to true, assignments will be restored to Intune Device Management Scripts that match the id.

    If RestoreById is set to false, assignments will be restored to Intune Device Management Scripts that match the file name.
    This is necessary if the Device Management Script was restored from backup, because then a new Device Management Script is created with a new unique ID.
    
    .EXAMPLE
    Invoke-IntuneRestoreDeviceCompliancePolicyAssignment -Path "C:\temp" -RestoreById $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [bool]$RestoreById = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet("v1.0", "Beta")]
        [string]$ApiVersion = "Beta"
    )

    #Connect to MS-Graph if required
    if ($null -eq (Get-MgContext)) {
        connect-mggraph -scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All" 
    }

    # Get all policies with assignments
    $deviceCompliancePolicies = Get-ChildItem -Path "$Path\Device Compliance Policies\Assignments" -File -ErrorAction SilentlyContinue
	
    foreach ($deviceCompliancePolicy in $deviceCompliancePolicies) {
        $deviceCompliancePolicyAssignments = Get-Content -LiteralPath $deviceCompliancePolicy.FullName | ConvertFrom-Json
        $deviceCompliancePolicyId = ($deviceCompliancePolicyAssignments[0]).id.Split("_")[0]
        $deviceCompliancePolicyName = $deviceCompliancePolicy.BaseName 

        # Create the base requestBody
        $requestBody = @{
            assignments = @()
        }

        # Add assignments to restore to the request body
        foreach ($deviceCompliancePolicyAssignment in $deviceCompliancePolicyAssignments) {
            $requestBody.assignments += @{
                "target" = $deviceCompliancePolicyAssignment.target
            }
        }

        # Convert the PowerShell object to JSON
        $requestBody = $requestBody | ConvertTo-Json -Depth 100

        # Get the Device Compliance Policy we are restoring the assignments for
        try {
            if ($restoreById) {
                $deviceCompliancePolicyObject = Invoke-MgGraphRequest -Uri "$ApiVersion/deviceManagement/deviceCompliancePolicies/$deviceCompliancePolicyId" | Get-MGGraphAllPages
            }
            else {
                $deviceCompliancePolicyObject = Invoke-MgGraphRequest -Uri "$ApiVersion/deviceManagement/deviceCompliancePolicies" | Get-MGGraphAllPages | Where-Object displayName -eq $deviceCompliancePolicyName
                if (-not ($deviceCompliancePolicyObject)) {
                    Write-Verbose "Error retrieving Intune Compliance Policy for $($deviceCompliancePolicy.FullName). Skipping assignment restore" -Verbose
                    continue
                }
            }
        }
        catch {
            Write-Verbose "Error retrieving Intune Device Compliance Policy for $($deviceCompliancePolicy.FullName). Skipping assignment restore" -Verbose
            Write-Error $_ -ErrorAction Continue
            continue
        }

        # Restore the assignments
        try {
            $null = Invoke-MgGraphRequest -Method POST -Body $requestBody.toString() -Uri "$ApiVersion/deviceManagement/deviceCompliancePolicies/$($deviceCompliancePolicyObject.id)/assign" -ErrorAction Stop
            [PSCustomObject]@{
                "Action" = "Restore"
                "Type"   = "Device Compliance Policy Assignments"
                "Name"   = $deviceCompliancePolicyObject.displayName
                "Path"   = "Device Compliance Policies\Assignments\$($deviceCompliancePolicy.Name)"
            }
        }
        catch {
            Write-Verbose "$($deviceCompliancePolicyObject.displayName) - Failed to restore Device Compliance Policy Assignment(s)" -Verbose
            Write-Error $_ -ErrorAction Continue
        }
    }
}

#endregion

Connect-MgGraph -Scopes "Group.ReadWrite.All" -Environment USGov

<# Group for the following settings catalog intune device configuration profiles
    - Configure device and resource redirection
    - Configure OneDrive settings
    - Configure Windows NTP client
    - Enable interactive logon banner
    - Enable interactive logon banner
#>
$AvdHostGroup = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:All Azure Virtual Desktop Hosts"'
if ($null -eq $AvdHostGroup) {
    $parameters = @{
        DisplayName = 'All Azure Virtual Desktop Hosts'
        MailEnabled = $False 
        MailNickName = (New-Guid).ToString().Substring(0,10)
        SecurityEnabled = $true
        Description = 'Devices in this group are all Azure Virtual Desktop hosts'
        MembershipRule = "(device.accountEnabled -eq True) and ((device.displayName -startsWith `"avd`") or (device.displayName -startsWith `"cad-avd`") or (device.displayName -startsWith `"mgmt-avd`"))"
        MembershipRuleProcessingState = 'On'
        GroupTypes = 'DynamicMembership'
    }
    $AvdHostGroup = New-MgGroup @parameters
}

# Group for all Window 10 and later devices
$AllWindows10Group = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:All Windows 10 and later Devices"'
if ($null -eq $AllWindows10Group) {
    $parameters = @{
        DisplayName = 'All Windows 10 and later Devices'
        MailEnabled = $False 
        MailNickName = (New-Guid).ToString().Substring(0,10)
        SecurityEnabled = $true
        Description = 'Devices in this group are all Windows 10 and later devices'
        MembershipRule = "(device.accountEnabled -eq True) and (device.deviceOSType -eq `"Windows`") and ((device.deviceOSVersion -startsWith `"10.0.1`") or (device.deviceOSVersion -startsWith `"10.0.2`"))"
        MembershipRuleProcessingState = 'On'
        GroupTypes = 'DynamicMembership'
    }
    $AllWindows10Group = New-MgGroup @parameters
}

# Group for the "Configure GPU acceleration for Azure Virtual Desktop" settings catalog intune device configuration profile
if ($GpuVms) {
    $AvdGpuGroup = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:GPU-optimized Azure VMs"'
    if ($null -eq $AvdGpuGroup) {
        $parameters = @{
            DisplayName = 'GPU-optimized Azure VMs'
            MailEnabled = $False 
            MailNickName = (New-Guid).ToString().Substring(0,10)
            SecurityEnabled = $true
            Description = 'Devices in this group are all Azure Virtual Desktop hosts with a GPU'
            MembershipRule = "(device.accountEnabled -eq True) and (device.displayName -startsWith `"cad-avd`")"
            MembershipRuleProcessingState = 'On'
            GroupTypes = 'DynamicMembership'
        }
        $AvdGpuGroup = New-MgGroup @parameters
    }
}

# Group for the "Configure Azure Virtual Desktop session host" settings catalog intune device configuration profile
