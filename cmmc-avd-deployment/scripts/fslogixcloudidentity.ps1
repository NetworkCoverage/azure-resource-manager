function Register-EventScript {
    param (
        [System.String] $eventToRegister, # Either Startup or Shutdown
        [System.String] $script,
        [System.String] $scriptParameters
    )
    
    $path = "$env:systemRoot\System32\GroupPolicy\Machine\Scripts\$eventToRegister"
    if (-not (Test-Path $path)) {
        # path HAS to be available for this to work
        New-Item -path $path -itemType Directory
    }

    # Add script to Group Policy through the Registry
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$eventToRegister\0\0",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\$eventToRegister\0\0" |
    ForEach-Object { 
        if (-not (Test-Path $_)) {
            New-Item -path $_ -Force
        }
    }

    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$eventToRegister\0",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\$eventToRegister\0" |
    ForEach-Object {
        New-ItemProperty -path "$_" -Name DisplayName -PropertyType String -Value "Local Group Policy" -Force
        New-ItemProperty -path "$_" -Name FileSysPath -PropertyType String -Value "$env:systemRoot\System32\GroupPolicy\Machine"  -Force
        New-ItemProperty -path "$_" -Name GPO-ID -PropertyType String -Value "LocalGPO" -Force
        New-ItemProperty -path "$_" -Name GPOName -PropertyType String -Value "Local Group Policy" -Force
        New-ItemProperty -path "$_" -Name PSScriptOrder -PropertyType DWord -Value 1  -Force
        New-ItemProperty -path "$_" -Name SOM-ID -PropertyType String -Value "Local" -Force
    }
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$eventToRegister\0\0",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\$eventToRegister\0\0" |
    ForEach-Object {
        New-ItemProperty -path "$_" -Name Script -PropertyType String -Value $script -Force 
        New-ItemProperty -path "$_" -Name Parameters -PropertyType String -Value $scriptParameters -Force
        New-ItemProperty -path "$_" -Name IsPowershell -PropertyType DWord -Value 1 -Force
        New-ItemProperty -path "$_" -Name ExecTime -PropertyType QWord -Value 0 -Force
    }
}

function Set-FsLogixProfile {    
    param (
        [System.String] $StorageAccount,
        [System.String] $Share,            
        [System.String] $Secret,
        [System.Boolean] $USGovEnvironment = $true
    )

    if ($USGovEnvironment) {$FileServer = ('{0}.file.core.usgovcloudapi.net' -f $StorageAccount)} else {$FileServer = ('{0}.file.core.windows.net' -f $StorageAccount)}
    $User = ("localhost\{0}" -f $StorageAccount)
    $ProfileShare = ("\\{0}\{1}" -f $FileServer, $Share)

    if (-not (Test-Path -Path "C:\Temp")) {New-Item -Path $env:SystemDrive -Name "Temp" -ItemType Directory}
    Start-Transcript -Path "C:\Temp\fslogix.log"

    if (-not (Test-Path -Path "HKLM:\SOFTWARE\FSLogix")) {New-Item -Path "HKLM:\SOFTWARE" -Name "FSLogix" -ErrorAction Ignore}
    if (-not (Test-Path -Path "HKLM:\SOFTWARE\FSLogix\Profiles")) {
        New-Item -Path "HKLM:\SOFTWARE\FSLogix" -Name "Profiles" -ErrorAction Ignore
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "Enabled" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VHDLocations" -Value $ProfileShare -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ConcurrentUserSessions" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "DeleteLocalProfileWhenVHDShouldApply" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "FlipFlopProfileDirectoryName" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "IsDynamic" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "KeepLocalDir" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ProfileType" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "SizeInMBs" -Value 40000 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VolumeType" -Value "VHDX" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "AccessNetworkAsComputerObject" -Value 1 -Force
    } 
    else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "Enabled" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VHDLocations" -Value $ProfileShare -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ConcurrentUserSessions" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "DeleteLocalProfileWhenVHDShouldApply" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "FlipFlopProfileDirectoryName" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "IsDynamic" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "KeepLocalDir" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ProfileType" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "SizeInMBs" -Value 40000 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VolumeType" -Value "VHDX" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "AccessNetworkAsComputerObject" -Value 1 -Force
    }

    # Include credentials in the profile
    if (-not (Test-Path -Path "HKLM:\Software\Policies\Microsoft\AzureADAccount")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "AzureADAccount" -ErrorAction Ignore
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\AzureADAccount" -Name "LoadCredKeyFromProfile" -Value 1 -Force
    }
    else {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\AzureADAccount" -Name "LoadCredKeyFromProfile" -Value 1 -Force
    }

    # Store credentials to access the storage account
    cmdkey.exe /add:$FileServer /user:$($User) /pass:$($Secret)
    
    # Disable Windows Defender Credential Guard (only needed for Windows 11 22H2)
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -Force   
}

$path = ("{0}\System32\GroupPolicy\Machine\Scripts\Startup" -f $env:SystemRoot)
    if (-not (Test-Path $path)) {
        # path HAS to be available for this to work
        New-Item -path $path -itemType Directory
    }
(Get-Command Set-FsLogixProfile).ScriptBlock | Set-Content -Path ("{0}\System32\GroupPolicy\Machine\Scripts\Startup\Set-FsLogixProfile.ps1" -f $env:SystemRoot) -Force

# register the script
Register-EventScript -eventToRegister "Startup" -script "Set-FsLogixProfile.ps1" -scriptParameters "-StorageAccount <storage account name> -Share <share name> -Secret <storage account key>"