#Microsoft.RDInfra.RDPowerShell and Get-Package both require powershell 5.0 or higher.
#Requires -Version 5.0

<#
.SYNOPSIS
Common functions to be used by DSC scripts
#>

# Setting to Tls12 due to Azure web app security requirements
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

<# [CalledByARMTemplate] #>
function Write-Log {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        # note: can't use variable named '$Error': https://github.com/PowerShell/PSScriptAnalyzer/blob/master/RuleDocumentation/AvoidAssignmentToAutomaticVariable.md
        [switch]$Err
    )
     
    try {
        $DateTime = Get-Date -Format "MM-dd-yy HH:mm:ss"
        $Invocation = "$($MyInvocation.MyCommand.Source):$($MyInvocation.ScriptLineNumber)"

        if ($Err) {
            $Message = "[ERROR] $Message"
        }
        
        Add-Content -Value "$DateTime - $Invocation - $Message" -Path "$([environment]::GetEnvironmentVariable('TEMP', 'Machine'))\ScriptLog.log"
    }
    catch {
        throw [System.Exception]::new("Some error occurred while writing to log file with message: $Message", $PSItem.Exception)
    }
}

function AddDefaultUsers {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$TenantName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true)]
        [string]$ApplicationGroupName,

        [Parameter(Mandatory = $false)]
        [string]$DefaultUsers
    )
    $ErrorActionPreference = "Stop"

    Write-Log "Adding Default users. Argument values: App Group: $ApplicationGroupName, TenantName: $TenantName, HostPoolName: $HostPoolName, DefaultUsers: $DefaultUsers"

    # Sanitizing DefaultUsers string
    $DefaultUsers = $DefaultUsers.Replace("`"", "").Replace("'", "").Replace(" ", "")

    if (-not ([string]::IsNullOrEmpty($DefaultUsers))) {
        $UserList = $DefaultUsers.split(",", [System.StringSplitOptions]::RemoveEmptyEntries)

        foreach ($user in $UserList) {
            try {
                Add-RdsAppGroupUser -TenantName "$TenantName" -HostPoolName "$HostPoolName" -AppGroupName $ApplicationGroupName -UserPrincipalName $user
                Write-Log "Successfully assigned user $user to App Group: $ApplicationGroupName. Other details -> TenantName: $TenantName, HostPoolName: $HostPoolName."
            }
            catch {
                Write-Log -Err "An error ocurred assigining user $user to App Group $ApplicationGroupName. Other details -> TenantName: $TenantName, HostPoolName: $HostPoolName."
                Write-Log -Err ($PSItem | Format-List -Force | Out-String)
            }
        }
    }
}

function ValidateServicePrincipal {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$isServicePrincipal,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AadTenantId = ""
    )

    if ($isServicePrincipal -eq "True") {
        if ([string]::IsNullOrEmpty($AadTenantId)) {
            throw "When IsServicePrincipal = True, AadTenant ID is mandatory. Please provide a valid AadTenant ID."
        }
    }
}

function Is1809OrLater {
    $OSVersionInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    if ($null -ne $OSVersionInfo) {
        if ($null -ne $OSVersionInfo.ReleaseId) {
            Write-Log -Message "Build: $($OSVersionInfo.ReleaseId)"
            $rdshIs1809OrLaterBool = @{$true = $true; $false = $false }[$OSVersionInfo.ReleaseId -ge 1809]
        }
    }
    return $rdshIs1809OrLaterBool
}

<# [CalledByARMTemplate] #>
function ExtractDeploymentAgentZipFile {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$DeployAgentLocation
    )

    if (Test-Path $DeployAgentLocation) {
        Remove-Item -Path $DeployAgentLocation -Force -Confirm:$false -Recurse
    }
    
    New-Item -Path "$DeployAgentLocation" -ItemType directory -Force
    
    # Locating and extracting DeployAgent.zip
    $DeployAgentFromRepo = (LocateFile -Name 'DeployAgent.zip' -SearchPath $ScriptPath -Recurse)
    
    Write-Log -Message "Extracting 'Deployagent.zip' file into '$DeployAgentLocation' folder inside VM"
    Expand-Archive $DeployAgentFromRepo -DestinationPath "$DeployAgentLocation"
}

<# [CalledByARMTemplate] #>
function isRdshServer {
    $rdshIsServer = $true

    $OSVersionInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    
    if ($null -ne $OSVersionInfo) {
        if ($null -ne $OSVersionInfo.InstallationType) {
            $rdshIsServer = @{$true = $true; $false = $false }[$OSVersionInfo.InstallationType -eq "Server"]
        }
    }

    return $rdshIsServer
}


<#
.Description
Call this function using dot source notation like ". AuthenticateRdsAccount" because the Add-RdsAccount function this calls creates variables using the AllScope option that other WVD poweshell module functions like Set-RdsContext require. Note that this creates a variable named "$authentication" that will overwrite any existing variable with that name in the scope this is dot sourced to.

Calling code should set $ErrorActionPreference = "Stop" before calling this function to ensure that detailed error information is thrown if there is an error.
#>
function AuthenticateRdsAccount {
    param(
        [Parameter(mandatory = $true)]
        [string]$DeploymentUrl,
    
        [Parameter(mandatory = $true)]
        [pscredential]$Credential,
    
        [switch]$ServicePrincipal,
    
        [Parameter(mandatory = $false)]
        [AllowEmptyString()]
        [string]$TenantId = ""
    )

    if ($ServicePrincipal) {
        Write-Log -Message "Authenticating using service principal $($Credential.username) and Tenant id: $TenantId"
    }
    else {
        $PSBoundParameters.Remove('ServicePrincipal')
        $PSBoundParameters.Remove('TenantId')
        Write-Log -Message "Authenticating using user $($Credential.username)"
    }
    
    $authentication = $null
    try {
        $authentication = Add-RdsAccount @PSBoundParameters
        if (!$authentication) {
            throw $authentication
        }
    }
    catch {
        throw [System.Exception]::new("Error authenticating Windows Virtual Desktop account, ServicePrincipal = $ServicePrincipal", $PSItem.Exception)
    }
    
    Write-Log -Message "Windows Virtual Desktop account authentication successful. Result:`n$($authentication | Out-String)"
}

function SetTenantGroupContextAndValidate {
    param(
        [Parameter(mandatory = $true)]
        [string]$TenantGroupName,

        [Parameter(mandatory = $true)]
        [string]$TenantName
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    # Set context to the appropriate tenant group
    $currentTenantGroupName = (Get-RdsContext).TenantGroupName
    if ($TenantGroupName -ne $currentTenantGroupName) {
        Write-Log -Message "Running switching to the $TenantGroupName context"

        try {
            #As of Microsoft.RDInfra.RDPowerShell version 1.0.1534.2001 this throws a System.NullReferenceException when the TenantGroupName doesn't exist.
            Set-RdsContext -TenantGroupName $TenantGroupName
        }
        catch {
            throw [System.Exception]::new("Error setting RdsContext using tenant group ""$TenantGroupName"", this may be caused by the tenant group not existing or the user not having access to the tenant group", $PSItem.Exception)
        }
    }
    
    $tenants = $null
    try {
        $tenants = (Get-RdsTenant -Name $TenantName)
    }
    catch {
        throw [System.Exception]::new("Error getting the tenant with name ""$TenantName"", this may be caused by the tenant not existing or the account doesn't have access to the tenant", $PSItem.Exception)
    }
    
    if (!$tenants) {
        throw "No tenant with name ""$TenantName"" exists or the account doesn't have access to it."
    }
}

function LocateFile {
    param (
        [Parameter(mandatory = $true)]
        [string]$Name,
        [string]$SearchPath = '.',
        [switch]$Recurse
    )
    
    Write-Log -Message "Locating '$Name' within: '$SearchPath'"
    $Path = (Get-ChildItem "$SearchPath\" -Filter $Name -Recurse:$Recurse).FullName
    if ((-not $Path) -or (-not (Test-Path $Path))) {
        throw "'$Name' file not found at '$SearchPath'"
    }
    if (@($Path).Length -ne 1) {
        throw "Multiple '$Name' files found at '$SearchPath': [`n$Path`n]"
    }

    return $Path
}

function ImportRDPSMod {
    param(
        [string]$Source = 'attached',
        [string]$ArtifactsPath
    )

    $ErrorActionPreference = "Stop"

    $ModName = 'Microsoft.RDInfra.RDPowershell'
    $Mod = (get-module $ModName)

    if ($Mod) {
        Write-Log -Message 'RD PowerShell module already imported (Not going to re-import)'
        return
    }
        
    $Path = 'C:\_tmp_RDPSMod\'
    if (test-path $Path) {
        Write-Log -Message "Remove tmp dir '$Path'"
        Remove-Item -Path $Path -Force -Recurse
    }
    
    if ($Source -eq 'attached') {
        if ((-not $ArtifactsPath) -or (-not (test-path $ArtifactsPath))) {
            throw "invalid param: ArtifactsPath = '$ArtifactsPath'"
        }

        # Locating and extracting PowerShellModules.zip
        $ZipPath = (LocateFile -Name 'PowerShellModules.zip' -SearchPath $ArtifactsPath -Recurse)

        Write-Log -Message "Extracting RD PowerShell module file '$ZipPath' into '$Path'"
        Expand-Archive $ZipPath -DestinationPath $Path -Force
        Write-Log -Message "Successfully extracted RD PowerShell module file '$ZipPath' into '$Path'"
    }
    else {
        $Version = ($Source.Trim().ToLower() -split 'gallery@')[1]
        if ($null -eq $Version -or $Version.Trim() -eq '') {
            throw "invalid param: Source = $Source"
        }

        Write-Log -Message "Downloading RD PowerShell module (version: v$Version) from PowerShell Gallery into '$Path'"
        if ($Version -eq 'latest') {
            Save-Module -Name $ModName -Path $Path -Force
        }
        else {
            Save-Module -Name $ModName -Path $Path -Force -RequiredVersion (new-object System.Version($Version))
        }
        Write-Log -Message "Successfully downloaded RD PowerShell module (version: v$Version) from PowerShell Gallery into '$Path'"
    }

    $DLLPath = (LocateFile -Name "$ModName.dll" -SearchPath $Path -Recurse)

    Write-Log -Message "Importing RD PowerShell module DLL '$DLLPath"
    Import-Module $DLLPath -Force
    Write-Log -Message "Successfully imported RD PowerShell module DLL '$DLLPath"
}

<# [CalledByARMTemplate] #>
function GetCurrSessionHostName {
    $Wmi = (Get-WmiObject win32_computersystem)
    return "$($Wmi.DNSHostName).$($Wmi.Domain)"
}

<# [CalledByARMTemplate] #>
function GetSessionHostDesiredStates {
    return ('Available', 'NeedsAssistance')
}

<# [CalledByARMTemplate] #>
function IsRDAgentRegistryValidForRegistration {
    $ErrorActionPreference = "Stop"

    $RDInfraReg = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent' -ErrorAction SilentlyContinue
    if (!$RDInfraReg) {
        return @{
            result = $false;
            msg    = 'RD Infra registry missing';
        }
    }
    Write-Log -Message 'RD Infra registry exists'

    Write-Log -Message 'Check RD Infra registry values to see if RD Agent is registered'
    if ($RDInfraReg.RegistrationToken -ne '') {
        return @{
            result = $false;
            msg    = 'RegistrationToken in RD Infra registry is not empty'
        }
    }
    if ($RDInfraReg.IsRegistered -ne 1) {
        return @{
            result = $false;
            msg    = "Value of 'IsRegistered' in RD Infra registry is $($RDInfraReg.IsRegistered), but should be 1"
        }
    }
    
    return @{
        result = $true
    }
}

<# [CalledByARMTemplate] indirectly because this is called by InstallRDAgents #>
function RunMsiWithRetry {
    param(
        [Parameter(mandatory = $true)]
        [string]$programDisplayName,

        [Parameter(mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$argumentList, #Must have at least 1 value

        [Parameter(mandatory = $true)]
        [string]$msiOutputLogPath,

        [Parameter(mandatory = $false)]
        [switch]$isUninstall,

        [Parameter(mandatory = $false)]
        [switch]$msiLogVerboseOutput
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    if ($msiLogVerboseOutput) {
        $argumentList += "/l*vx+ ""$msiOutputLogPath""" 
    }
    else {
        $argumentList += "/liwemo+! ""$msiOutputLogPath"""
    }

    $retryTimeToSleepInSec = 30
    $retryCount = 0
    $sts = $null
    do {
        $modeAndDisplayName = ($(if ($isUninstall) { "Uninstalling" } else { "Installing" }) + " $programDisplayName")

        if ($retryCount -gt 0) {
            Write-Log -Message "Retrying $modeAndDisplayName in $retryTimeToSleepInSec seconds because it failed with Exit code=$sts This will be retry number $retryCount"
            Start-Sleep -Seconds $retryTimeToSleepInSec
        }

        Write-Log -Message ( "$modeAndDisplayName" + $(if ($msiLogVerboseOutput) { " with verbose msi logging" } else { "" }))


        $processResult = Start-Process -FilePath "msiexec.exe" -ArgumentList $argumentList -Wait -Passthru
        $sts = $processResult.ExitCode

        $retryCount++
    } 
    while ($sts -eq 1618 -and $retryCount -lt 20) # Error code 1618 is ERROR_INSTALL_ALREADY_RUNNING see https://docs.microsoft.com/en-us/windows/win32/msi/-msiexecute-mutex .

    if ($sts -eq 1618) {
        Write-Log -Err "Stopping retries for $modeAndDisplayName. The last attempt failed with Exit code=$sts which is ERROR_INSTALL_ALREADY_RUNNING"
        throw "Stopping because $modeAndDisplayName finished with Exit code=$sts"
    }
    else {
        Write-Log -Message "$modeAndDisplayName finished with Exit code=$sts"
    }

    return $sts
}


<#
.DESCRIPTION
Parse registration token to get claim section of the token

.PARAMETER token
The registration token

[CalledByARMTemplate]
#>
function ParseRegistrationToken {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistrationToken
    )
 
    Set-StrictMode -Version 1.0
    $ClaimsSection = $RegistrationToken.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($ClaimsSection.Length % 4) { 
        $ClaimsSection += "=" 
    }
    
    $ClaimsByteArray = [System.Convert]::FromBase64String($ClaimsSection)
    $ClaimsArray = [System.Text.Encoding]::ASCII.GetString($ClaimsByteArray)
    $Claims = $ClaimsArray | ConvertFrom-Json
    return $Claims
}

<#
.DESCRIPTION
Get Agent MSI endpoint. If the endpoint cannot be obtained, this method returns a null value to the caller

.PARAMETER BrokerAgentApi
AgentMsiController endpoint on broker, which will return the agent msi endpoints

.PARAMETER HostpoolId
The Hostpool Id

[CalledByARMTemplate]
#>
function GetAgentMSIEndpoint {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $BrokerAgentApi
    )

    Set-StrictMode -Version 1.0
    $ErrorActionPreference = "Stop"

    try {
        Write-Log -Message "Invoking broker agent api $BrokerAgentApi to get msi endpoint"
        $result = Invoke-WebRequest -Uri $BrokerAgentApi -UseBasicParsing
        $responseJson = $result.Content | ConvertFrom-Json
    }
    catch {
        $responseBody = $_.ErrorDetails.Message
        Write-Log -Err $responseBody
        return $null
    }

    Write-Log -Message "Obtained agent msi endpoint $($responseJson.agentEndpoint)"
    return $responseJson.agentEndpoint
}

<#
.DESCRIPTION
Download Agent MSI from storage blob if they are available

.PARAMETER AgentEndpoint
The Agent MSI storage blob endpoint which will downloaded on the session host

.PARAMETER AgentInstallerFolder
The destination folder to download the MSI

[CalledByARMTemplate]
#>
function DownloadAgentMSI {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrivateLinkAgentEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentDownloadFolder
    )
    
    Set-StrictMode -Version 1.0

    $AgentInstaller = $null

    try {
        Write-Log -Message "Trying to download agent msi from $AgentEndpoint"
        Invoke-WebRequest -Uri $AgentEndpoint -OutFile "$AgentDownloadFolder\RDAgent.msi"
        $AgentInstaller = Join-Path $AgentDownloadFolder "RDAgent.msi"
    } 
    catch {
        Write-Log -Err "Error while downloading agent msi from $AgentEndpoint"
        Write-Log -Err $_.Exception.Message
    }

    if (-not $AgentInstaller) {
        try {
            Write-Log -Message "Trying to download agent msi from $PrivateLinkAgentEndpoint"
            Invoke-WebRequest -Uri $AgentEndpoint -OutFile "$AgentDownloadFolder\RDAgent.msi"
            $AgentInstaller = Join-Path $AgentDownloadFolder "RDAgent.msi"
        } 
        catch {
            Write-Log -Err "Error while downloading agent msi from $PrivateLinkAgentEndpoint"
            Write-Log -Err $_.Exception.Message
        }
    }

    return $AgentInstaller
}

<#
.DESCRIPTION
Downloads the latest agent msi from storage blob.

.PARAMETER RegistrationToken
A Token that contains the Broker endpoint

.PARAMETER AgentInstallerFolder
The folder to which to download the agent msi

[CalledByARMTemplate]
#>
function GetAgentInstaller {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistrationToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentInstallerFolder
    )

    Try {
        $ParsedToken = ParseRegistrationToken $RegistrationToken
        if (-not $ParsedToken.GlobalBrokerResourceIdUri) {
            Write-Log -Message "Unable to obtain broker agent check endpoint"
            return
        }

        $BrokerAgentUri = [System.UriBuilder] $ParsedToken.GlobalBrokerResourceIdUri
        $BrokerAgentUri.Path = "api/agentMsi/v1/agentVersion"
        $BrokerAgentUri = $BrokerAgentUri.Uri.AbsoluteUri
        Write-Log -Message "Obtained broker agent api $BrokerAgentUri"

        $AgentMSIEndpointUri = [System.UriBuilder] (GetAgentMSIEndpoint $BrokerAgentUri)
        if (-not $AgentMSIEndpointUri) {
            Write-Log -Message "Unable to get Agent MSI endpoints from storage blob"
            return
        }

        $AgentDownloadFolder = New-Item -Path $AgentInstallerFolder -Name "RDAgent" -ItemType "directory" -Force
        $PrivateLinkAgentMSIEndpointUri = [System.UriBuilder] $AgentMSIEndpointUri.Uri.AbsoluteUri
        $PrivateLinkAgentMSIEndpointUri.Host = "$($ParsedToken.EndpointPoolId).$($AgentMSIEndpointUri.Host)"
        Write-Log -Message "Attempting to download agent msi from $($AgentMSIEndpointUri.Uri.AbsoluteUri), or $($AgentMSIEndpointUri.Uri.AbsoluteUri)"

        $AgentInstaller = DownloadAgentMSI $AgentMSIEndpointUri $PrivateLinkAgentMSIEndpointUri $AgentDownloadFolder
        if (-not $AgentInstaller) {
            Write-Log -Message "Failed to download agent msi from $AgentMSIEndpointUri"
        } else {
            Write-Log "Successfully downloaded the agent from $AgentMSIEndpointUri"
        }

        return $AgentInstaller
    } 
    Catch {
        Write-Log -Err "There was an error while downloading agent msi"
        Write-Log -Err $_.Exception.Message
    }
}

<#
.DESCRIPTION
Uninstalls any existing RDAgent BootLoader and RD Infra Agent installations and then installs the RDAgent BootLoader and RD Infra Agent using the specified registration token.

.PARAMETER AgentInstallerFolder
Required path to MSI installer file

.PARAMETER AgentBootServiceInstallerFolder
Required path to MSI installer file

[CalledByARMTemplate]
#>
function InstallRDAgents {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentInstallerFolder,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentBootServiceInstallerFolder,
    
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistrationToken,
    
        [Parameter(mandatory = $false)]
        [switch]$EnableVerboseMsiLogging,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseAgentDownloadEndpoint = $false
    )

    $ErrorActionPreference = "Stop"

    Write-Log -Message "Boot loader folder is $AgentBootServiceInstallerFolder"
    $AgentBootServiceInstaller = LocateFile -SearchPath $AgentBootServiceInstallerFolder -Name "*.msi"

    if ($UseAgentDownloadEndpoint) {
        Write-Log -Message "Obtaining agent installer"
        $AgentInstaller = GetAgentInstaller $RegistrationToken $AgentInstallerFolder
        if (-not $AgentInstaller) {
            Write-Log -Message "Unable to download latest agent msi from storage blob. Using the agent msi from the extension."
        }
    }

    if (-not $AgentInstaller) {
        Write-Log -Message "Installing the bundled agent msi"
        $AgentInstaller = LocateFile -SearchPath $AgentInstallerFolder -Name "*.msi"
    }

    $msiNamesToUninstall = @(
        @{ msiName = "Remote Desktop Services Infrastructure Agent"; displayName = "RD Infra Agent"; logPath = "C:\Users\AgentUninstall.txt"}, 
        @{ msiName = "Remote Desktop Agent Boot Loader"; displayName = "RDAgentBootLoader"; logPath = "C:\Users\AgentBootLoaderUnInstall.txt"}
    )
    
    foreach($u in $msiNamesToUninstall) {
        while ($true) {
            try {
                $installedMsi = Get-Package -ProviderName msi -Name $u.msiName
            }
            catch {
                #Ignore the error if it was due to no packages being found.
                if ($PSItem.FullyQualifiedErrorId -eq "NoMatchFound,Microsoft.PowerShell.PackageManagement.Cmdlets.GetPackage") {
                    break
                }
    
                throw;
            }
    
            $oldVersion = $installedMsi.Version
            $productCodeParameter = $installedMsi.FastPackageReference
    
            RunMsiWithRetry -programDisplayName "$($u.displayName) $oldVersion" -isUninstall -argumentList @("/x $productCodeParameter", "/quiet", "/qn", "/norestart", "/passive") -msiOutputLogPath $u.logPath -msiLogVerboseOutput:$EnableVerboseMsiLogging
        }
    }

    Write-Log -Message "Installing RD Infra Agent on VM $AgentInstaller"
    RunMsiWithRetry -programDisplayName "RD Infra Agent" -argumentList @("/i $AgentInstaller", "/quiet", "/qn", "/norestart", "/passive", "REGISTRATIONTOKEN=$RegistrationToken") -msiOutputLogPath "C:\Users\AgentInstall.txt" -msiLogVerboseOutput:$EnableVerboseMsiLogging

    Write-Log -Message "Installing RDAgent BootLoader on VM $AgentBootServiceInstaller"
    RunMsiWithRetry -programDisplayName "RDAgent BootLoader" -argumentList @("/i $AgentBootServiceInstaller", "/quiet", "/qn", "/norestart", "/passive") -msiOutputLogPath "C:\Users\AgentBootLoaderInstall.txt" -msiLogVerboseOutput:$EnableVerboseMsiLogging

    $bootloaderServiceName = "RDAgentBootLoader"
    $startBootloaderRetryCount = 0
    while ( -not (Get-Service $bootloaderServiceName -ErrorAction SilentlyContinue)) {
        $retry = ($startBootloaderRetryCount -lt 6)
        $msgToWrite = "Service $bootloaderServiceName was not found. "
        if ($retry) { 
            $msgToWrite += "Retrying again in 30 seconds, this will be retry $startBootloaderRetryCount" 
            Write-Log -Message $msgToWrite
        } 
        else {
            $msgToWrite += "Retry limit exceeded" 
            Write-Log -Err $msgToWrite
            throw $msgToWrite
        }
            
        $startBootloaderRetryCount++
        Start-Sleep -Seconds 30
    }

    Write-Log -Message "Starting service $bootloaderServiceName"
    Start-Service $bootloaderServiceName
}
# SIG # Begin signature block
# MIIoZAYJKoZIhvcNAQcCoIIoVTCCKFECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxF4IaVUFJ8Ces
# y4JXjNfp1/NklOulcxm2VKtR5+nS/6CCDWowggY1MIIEHaADAgECAhMzAAAACWMn
# 7YqGMfm5AAAAAAAJMA0GCSqGSIb3DQEBDAUAMIGEMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1
# aWxkIFRvb2xzIFBDQSAyMDIwMB4XDTI0MDYxOTE4MTUzMVoXDTI1MDYxNzE4MTUz
# MVowgYQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNV
# BAMTJVdpbmRvd3MgSW50ZXJuYWwgQnVpbGQgVG9vbHMgQ29kZVNpZ24wggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8hzd2IEs+Z6vJe1Ph36MjW51GBPHT
# ZZIYQRpyRgt+QuGPo4kbBnIiR1owrowXKYA4xiRiFq2nZOavdegFrxTAlFn1aCdQ
# 6ncidMVi4xUoY3AUyXAKXDL8wXDX1nmSpvT0HDm1c7QsIYCFNM4r7M6HaHA+k8JL
# jQyJN5piljfTiGTrnpJoBpbGMQluq8p11WX155BgWZ4EMAfh32nqO7HKXjZ6CFd2
# Cfn+8tfdQ/SCh9TxpJ8xM0gV+7bLI/2/bhvyBy2t5wN8nE0BvhDHqexqb2uOgcbG
# fR01Xf3wfPUhsP9P5gx6kEtbTOu/p+alng0SIGJbMh8IEikqTpE7vXKZAgMBAAGj
# ggGcMIIBmDAgBgNVHSUEGTAXBggrBgEFBQcDAwYLKwYBBAGCN0w3AQEwHQYDVR0O
# BBYEFHXvI7qCMN5A9CA67E5+euuA7osXMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQL
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTQ1ODIwNCs1MDIzNjgw
# HwYDVR0jBBgwFoAUoH7qzmTrA0eRsqGw6GOA4/ZOZaEwaAYDVR0fBGEwXzBdoFug
# WYZXaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvV2luZG93cyUy
# MEludGVybmFsJTIwQnVpbGQlMjBUb29scyUyMFBDQSUyMDIwMjAuY3JsMHUGCCsG
# AQUFBwEBBGkwZzBlBggrBgEFBQcwAoZZaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9XaW5kb3dzJTIwSW50ZXJuYWwlMjBCdWlsZCUyMFRvb2xz
# JTIwUENBJTIwMjAyMC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAgQ1dOCwKwdC7GiZd++nSi3Zf0JFdql5djuONH/K1eYBkr8gmTJRcA+vCjNPa
# JdDOglcMjNb9v7TmfSfwoxq1MILay5t+W4QmlR+C7fIDTLZik/XSml+flbBiOjmk
# eEADJkhHpqU5aIxQZ89fa5fgrzyexW5XFSCCJSUOJCp/TujNu6m9RWG7ugsN2KPZ
# uF0aj5gUAmQQaUeRK7GZd9EHO9DKDUMl3ZbNAmcnKaV1jRQcrt4To6GGSLiCc1lp
# b5LrZnYdmiwGpLzBVGnrhK7z6vbyuhuUkO9HRwFWokeRGcwsCwXon/1woxsWWrR1
# V9b+1Wib/ZifdaprivedWI288rJyd5n7k0v+UYdj3HjoZUWovMnr7m5zmwHohJ/2
# P8uLU8aYIjb7olTDU5dbfopa2og6B+Ijq2Y1N0hc7uM+VY3wJcYp4bJF3gGxRmK2
# 1fDN592NWfjk2lKtB0tZ38LREVLcf4k7J3ENzjuamEgWkmECPvYtTuTdr+v4sgaA
# X37RdZB6zTsF2K5mXhlonscMNU4ThKCIM/aTfVAIaOPhSXwiHnEqZzqoFYYCl5k8
# LHY/JbUDfXROnAABXDVgDkSfPMpg0qYXDflrOO0I0ehKTg3g+D8X5C1La6+d3cuP
# 3C/DI/0zSVzaqawAATXWHcxlH/R8F2N/3Xn0sk4HlvoES28wggctMIIFFaADAgEC
# AhMzAAAAVlq1acsdlGgsAAAAAABWMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBT
# ZXJ2aWNlcyBQYXJ0bmVyIFJvb3QwHhcNMjAwMjA1MjIzNDEyWhcNMzUwMjA1MjI0
# NDEyWjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEuMCwG
# A1UEAxMlV2luZG93cyBJbnRlcm5hbCBCdWlsZCBUb29scyBQQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJeO8Bi8BZ0LmiWJmxhr8XqilrM9
# 8Le3i6/bgnolF1sE2w8obZr5HmO8FnkT+2TPpVMWsvnz8NaybPtns+i1a3lX+F85
# uM2pX+kBnaUPjRNZ4Nr4eYZeTNsu+fvJkkuFg1dcQqRypLdSbpSz4NSb6rjFxF7i
# Z2A7JnhVaR2eKSmFMCNH8fLz10ORthw/YwS1xvw/Lm5TU+YSRQWfydS+wgfMPapg
# oXtrOp28UH+HXoySBu0uQYC6azrB/eTPNiDQO4TlAJdWzV4yvLSpEKIVisUZTAQL
# cE9wVumQQvG8HKIF3v5hr+U/5aDEOJaqlNPqff99mYSuajKHQWPV4wJUHMohX93j
# nz7HhtJLhf/UeVglNcKayiiTI0NcCJbyPxD1/nCy2F3wnTmrF43lHJHHeNIunrNI
# sI6OhbELkWIZiVp83Dt9/5db2ULbdf564qRZAO2VUlvD0dFA1Ii9GZbqSThenYsY
# 0gnmZ1QIMJVJIt0zPUY1E0W+n/zkEedBM+jbaBw6De+zBNxTjpDg3qf1nRibmXGW
# SXv3uvyqzW+EnAozTUdr1LCCbsQTlEH+gzHG9nQy4zl1gTbbPMF77Lokxhueg/kr
# sHlsSGDI/GIBYu4fVvlU6uzAfahuQaFnIj5WHNkN6qwIFDFmNvpPRk+yOoMLAAm9
# XHKK1BxyOKixu/VTAgMBAAGjggGbMIIBlzAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFKB+6s5k6wNHkbKhsOhjgOP2TmWhMFQGA1Ud
# IARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSNuOM2u9Xe
# l8uvDk17vlofCBv6BjBRBgNVHR8ESjBIMEagRKBChkBodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3Js
# MF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3J0
# MA0GCSqGSIb3DQEBDAUAA4ICAQBhSN9+w4ld9lyw3LwLhTlDV2sWMjpAjfOdbLFa
# tPpsSjVGHLBrfL+Y97dUfqCYNMYS5ByP41eRtKvrkby60pPxDjow8L/3tOVZmENd
# BU3vn28f7wCNy5gilO444fz4cBbUUQHnc94nMsODly3N6ohm5gGq7p0h9klLX/l5
# hbe2Rxl5UsJo3EuK8yqP7xz7thbL4QosQNsKiEFM91o8Q/Frdt+/gni6OTWVjCNM
# YHVB4CWttzJyvP8A1IzH0HEBG95Rdd9HMeudsYOHRuM4A0elUvRqOnsfqP7Zs46X
# NtBogW/IacvPGeuy3AHXIgMfFk35P9Mrt/ipDuqPy07faWLr0d+2++fWGv0yMSEf
# 0VWsMIYUK7fnmO+WK2j74KO/hFj3c+G/psecslWdT6zpeLntMB0IkqxN+Gw+qzc9
# 1vol2TEMHP2pITosnXYt33nZ9XR9YQmvMHBxwcF6qUALem5nOYMu574bCK6iOJdF
# SMfaUiLGppk7LOID0saA965KSWyxcpsxgvGnovjeUV1rJkN/NyPI3m5+t5w0v54J
# V2iCjgnsuF90m0cb2E3UUdEsbC6gBppQ/038OBoWMeVcd2ppmwP5O5vL5s4fCUp5
# p/og24gdqwrLJMZ+dHYVf3MsRqm7Lx3OVuxTuqbguRui+FdJtoBR/dMGFCWho1JE
# 8Qud9TGCGlAwghpMAgEBMIGcMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1aWxkIFRvb2xz
# IFBDQSAyMDIwAhMzAAAACWMn7YqGMfm5AAAAAAAJMA0GCWCGSAFlAwQCAQUAoIHU
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD8SN5ZH8JLnhkvuim9YG2xu/TUFwvy
# KI/HTljJiLTJvzBoBgorBgEEAYI3AgEMMVowWKA6gDgAVwBpAG4AZABvAHcAcwAg
# AEIAdQBpAGwAZAAgAFQAbwBvAGwAcwAgAEkAbgB0AGUAcgBuAGEAbKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAmmsACOjCej+j
# X09Pg+8G5UbTm1lyrDdoOmRvrSvIGTypoYW9WA5zyB6QOMg1fQ1dB+wQF4HMK01b
# D1FsNCwoPtfTmV8vO63/rApbWe6FLJD+0JXsIeOX/fU9mkFt30jwhfYAykgp/KIa
# dOWYsRIgmTiVzq1Tgllboi2hWOazK+7Uqipftwj5wUrUS7dz3m4nD+OV1pTqZ9Nc
# 8udpftqzGeFdLWNkxmCBDqe4K0Ss8KJbSvk6T4VtCyWiO7PMRmzP9D5WjKv2Wsma
# NwxbzYmNMagZ6aU/BHnO7glNNaDs7WumusfAYcjsbUkt82UlgK87T0umsT7Zb/tZ
# ghMiVB+7B6GCF60wghepBgorBgEEAYI3AwMBMYIXmTCCF5UGCSqGSIb3DQEHAqCC
# F4YwgheCAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFaBgsqhkiG9w0BCRABBKCCAUkE
# ggFFMIIBQQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCgMpXHmQk1
# QRHEClPJJun81zEeSIJepVX4OUEqX1bReQIGZ2LV2dM7GBMyMDI1MDEwODA2NTE0
# NS40NDVaMASAAgH0oIHZpIHWMIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo0QzFBLTA1RTAtRDk0
# NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEfswggco
# MIIFEKADAgECAhMzAAAB/xI4fPfBZdahAAEAAAH/MA0GCSqGSIb3DQEBCwUAMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI0MDcyNTE4MzExOVoXDTI1
# MTAyMjE4MzExOVowgdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRl
# ZDEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjRDMUEtMDVFMC1EOTQ3MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAyeiV0pB7bg8/qc/mkiDdJXnzJWPYgk9mTGeI3pzQ
# psyrRJREWcKYHd/9db+g3z4dU4VCkAZEXqvkxP5QNTtBG5Ipexpph4PhbiJKwvX+
# US4KkSFhf1wflDAY1tu9CQqhhxfHFV7vhtmqHLCCmDxhZPmCBh9/XfFJQIUwVZR8
# RtUkgzmN9bmWiYgfX0R+bDAnncUdtp1xjGmCpdBMygk/K0h3bUTUzQHb4kPf2ylk
# KPoWFYn2GNYgWw8PGBUO0vTMKjYD6pLeBP0hZDh5P3f4xhGLm6x98xuIQp/RFnzB
# bgthySXGl+NT1cZAqGyEhT7L0SdR7qQlv5pwDNerbK3YSEDKk3sDh9S60hLJNqP7
# 1iHKkG175HAyg6zmE5p3fONr9/fIEpPAlC8YisxXaGX4RpDBYVKpGj0FCZwisiZs
# xm0X9w6ZSk8OOXf8JxTYWIqfRuWzdUir0Z3jiOOtaDq7XdypB4gZrhr90KcPTDRw
# vy60zrQca/1D1J7PQJAJObbiaboi12usV8axtlT/dCePC4ndcFcar1v+fnClhs9u
# 3Fn6LkHDRZfNzhXgLDEwb6dA4y3s6G+gQ35o90j2i6amaa8JsV/cCF+iDSGzAxZY
# 1sQ1mrdMmzxfWzXN6sPJMy49tdsWTIgZWVOSS9uUHhSYkbgMxnLeiKXeB5MB9QMc
# OScCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTD+pXk/rT/d7E/0QE7hH0wz+6UYTAf
# BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
# hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBe
# MFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Nl
# cnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE
# AwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAOSNN5MpLiyunm866frWIi0hdazKNLgRp
# 3WZPfhYgPC3K/DNMzLliYQUAp6WtgolIrativXjOG1lIjayG9r6ew4H1n5XZdDfJ
# 12DLjopap5e1iU/Yk0eutPyfOievfbsIzTk/G51+uiUJk772nVzau6hI2KGyGBJO
# vAbAVFR0g8ppZwLghT4z3mkGZjq/O4Z/PcmVGtjGps2TCtI4rZjPNW8O4c/4aJRm
# YQ/NdW91JRrOXRpyXrTKUPe3kN8N56jpl9kotLhdvd89RbOsJNf2XzqbAV7XjV4c
# aCglA2btzDxcyffwXhLu9HMU3dLYTAI91gTNUF7BA9q1EvSlCKKlN8N10Y4iU0ny
# IkfpRxYyAbRyq5QPYPJHGA0Ty0PD83aCt79Ra0IdDIMSuwXlpUnyIyxwrDylgfOG
# yysWBwQ/js249bqQOYPdpyOdgRe8tXdGrgDoBeuVOK+cRClXpimNYwr61oZ2/kPM
# zVrzRUYMkBXe9WqdSezh8tytuulYYcRK95qihF0irQs6/WOQJltQX79lzFXE9FFl
# n9Mix0as+C4HPzd+S0bBN3A3XRROwAv016ICuT8hY1InyW7jwVmN+OkQ1zei66Lr
# U5RtAz0nTxx5OePyjnTaItTSY4OGuGU1SXaH49JSP3t8yGYA/vorbW4VneeD721F
# gwaJToHFkOIwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqG
# SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4X
# YDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTz
# xXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7
# uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlw
# aQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedG
# bsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXN
# xF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03
# dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9
# ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5
# UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReT
# wDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZ
# MBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8
# RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAE
# VTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAww
# CgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQD
# AgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb
# 186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29t
# L3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoG
# CCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9
# MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2Lpyp
# glYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OO
# PcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8
# DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA
# 0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1Rt
# nWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjc
# ZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq7
# 7EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJ
# C4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328
# y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYID
# VjCCAj4CAQEwggEBoYHZpIHWMIHTMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25z
# IExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo0QzFBLTA1RTAtRDk0
# NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAqROMbMS8JcUlcnPkwRLFRPXFspmggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsFAAIFAOsoWjMwIhgPMjAy
# NTAxMDgwMTU4MTFaGA8yMDI1MDEwOTAxNTgxMVowdDA6BgorBgEEAYRZCgQBMSww
# KjAKAgUA6yhaMwIBADAHAgEAAgILwzAHAgEAAgITDTAKAgUA6ymrswIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBCwUAA4IBAQAkc1B8wKW3/82mvQYK3JhjTrp42co6vG0H
# Ucgs28VDkLZgn5GkhxnB7V7Znnr/2gwyYlT0E9sIX8OSBEGNSwkeTWKEYlYMuVIG
# M6bMmMv+zBaVJTdohBBXbtI7dslygjQT/v3SEJtB9Jtzn1xMTJc8wuCGZQitP0f1
# 3NnLGKNBhWnqiKnSnGRPEovCc6gxSLB81G9/uWOrFcH2SeLXwJanPR8tWsgWUvkO
# PhFuWCk4PDYhOuWqnuuDBVscuSgiQY446UBj8Md5HaUkOu4kXH4voUcyZ3P7h778
# BDp1rwWjvYlw2w30eSVihV8bYgrnRdvnmfvuvwcC+giWCfrkJOcAMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAH/Ejh898Fl
# 1qEAAQAAAf8wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgZY3wZXyW0aEpeAP/yrI45Iqr8DuDCqjY
# 7i86mYTwfL4wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDkMu++yQJ3aayc
# IuMT6vA7JNuMaVOI3qDjSEV8upyn/TCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAAB/xI4fPfBZdahAAEAAAH/MCIEIKtTGGLTyOWiI2rJ
# Qma88tofl6vZixQmzdVZ9EatjO47MA0GCSqGSIb3DQEBCwUABIICAJEU4gEYtyRs
# fTPohL2vTMUvQgDe/UDNZf72BVbulklYkub5a/DpAccVnHoBteTZv+MygWMPwttz
# kmV9CY/RYgHQFor92pGvMlLndQMcOdTzvL0QG0kGJzmKKRohUhmYnAy/5QttWTTZ
# MdtbyN1LRAXLXu+vBqACO9Bvf0pZfhjFI5RuGfX0Qe4ds/5VK5MVLO6HhLlIb8xz
# BU0gXVLIWwOufo9SVfbdc9T2o5ODVgE+RYrvqaWWDw4bRjfakWNVUh1j3UmUHi9h
# jF+/YC0P+Eugc12K4f8OBEIorc0LGvbAVivU4wBkWwWRBZhVf/OcV36ew8nviMtI
# vHibFTjRD3nzJFZZ+5mfYSUBOEJiVTS5p5OIi4Axy5tdbE3W0bHMQLr5g0guQyuc
# FdOA57WtfxZdQYUAfo7KoTX3KswgcQb2wnFlIhb3nsXfYq3vwAzJNBgavKHTdQk1
# 5EkZOfuYOVc/q5+8+RS2PkAXxnJBZvI5B2RQVeV4NifKnUUE6vWKAtMDnBH56MN2
# JbewsUhBKxnv5AGGMkgr07KXosIfNy0SFdIOdvCmMhcyH0TGeBQ0VK7y+qwGTcAX
# J7Jglx7zkPiRGQ/IT4iqFzaji1TWgrSqt/kgnw5GHef74aZSPk5fVmePKy3cLu8y
# aq7IxpNBzf1Nb4JyGvRF+oOhK+oBNLFS
# SIG # End signature block
