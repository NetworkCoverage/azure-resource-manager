# This script needs to be run by an admin account in your Azure tenant.
# This script will create an Microsoft Entra ID app in your organisation with permission
# to access resources in yours or customers' tenants.

Function Read-HostDefault($prompt, $default) {

    if (-not $default) {
        # $default is null or empty, ensure input is not empty
        do {
            $input = Read-Host "$prompt (An input is required): "
        } while ($input -eq [string]::empty)
    } else {
        # Display the prompt with the default value in yellow
        Write-Host -NoNewline "$prompt [Default: "
        Write-Host -NoNewline -ForegroundColor Yellow "$default"
        Write-Host -NoNewline "] (Use enter for the default value): "
        $input = Read-Host
        $input = if ($input -eq [string]::empty) {$default} else {$input}
    }
    
    Write-Host -ForegroundColor Green "$input `n"
    return $input
}



Function Test-CommandExists
{
Param ($command)

    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {Write-Host "$command does not exist"; RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExistsnd function test-CommandExists



Function Add-ResourcePermission {
    param (
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess]$requiredAccess,
        [System.Collections.Generic.List[Microsoft.Graph.PowerShell.Models.MicrosoftGraphResourceAccess]]$exposedPermissions,
        [string]$requiredAccesses,
        [string]$permissionType
    )

    foreach ($permission in $requiredAccesses.Trim().Split(" ")) {
        $reqPermission = $exposedPermissions | Where-Object { $_.Value -contains $permission }

        Write-Host "Collected information for $($reqPermission.Value) of type $permissionType" -ForegroundColor Green
        $resourceAccess = New-Object Microsoft.Graph.PowerShell.Models.MicrosoftGraphResourceAccess
        $resourceAccess.Type = $permissionType
        $resourceAccess.Id = $reqPermission.Id
        #$requiredAccess.ResourceAccess.Add($resourceAccess)
        $requiredAccess.ResourceAccess += $resourceAccess
    }
}


  Function New-AppKey ($fromDate, $durationInYears) {
      
      $key = @{
          #keyId = (New-Guid).ToString()
          endDateTime = $fromDate.AddYears($durationInYears)
          StartDateTime = $fromDate
       }
      return $key
  }



 Function Get-RequiredPermissions {
    
    $requiredApplicationPermissions = 'GroupMember.Read.All','User.Read.All' | Find-MgGraphPermission -ExactMatch -PermissionType Application

    $appPermissions = New-Object -TypeName System.Collections.Generic.List[Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess]
    $requiredResourceAccess = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess
    $requiredResourceAccess.ResourceAppId =  "00000003-0000-0000-c000-000000000000"

    foreach ($permission in $requiredApplicationPermissions) {
        $requiredResourceAccess.ResourceAccess+=@{ Id = $permission.Id; Type = "Role" }
    }

    $requiredApplicationPermissionDelegated= 'User.Read' | Find-MgGraphPermission -ExactMatch -PermissionType Delegated

    foreach ($permission in $requiredApplicationPermissionDelegated) {
        $requiredResourceAccess.ResourceAccess+=@{ Id = $permission.Id; Type = "Scope" }
    }

    $appPermissions.Add($requiredResourceAccess)

    return $appPermissions
}


  function Confirm-MicrosoftGraphServicePrincipal {

      $graphsp = Get-MgServicePrincipal -All | Where-Object {$_.displayname -eq "Microsoft Graph"}
      if (!$graphsp) {
          $graphsp = Get-MgServicePrincipal -SearchString "Microsoft.Azure.AgregatorService"
      }
      if (!$graphsp) {
         Connect-MgGraph  -TenantId $tenant_id -NoWelcome  
          New-MgServicePrincipal -ApplId "00000003-0000-0000-c000-000000000000"
          $graphsp = Get-MgServicePrincipal -All | Where-Object {$_.displayname -eq "Microsoft Graph"}
      }
      return $graphsp
}



$configFile = Join-Path -Path $PSScriptRoot -ChildPath "config.json"

# Check if the configuration file exists
if (Test-Path $configFile) {
    # If the file exists, read the content and convert it from JSON
    $config = Get-Content -Path $configFile | ConvertFrom-Json
} else {
    # If the file does not exist, set $config to $null
    $config = $null
}


# Define default values
$defaultUseMailsOnline = $false
$defaultOneTimePasswordServiceUri = "https://onetimepass.domaincrawler.com/"


# Load values from the configuration or use default values if the configuration is missing
$tenant_id = $config.tenantID
$appName = $config.appName
$hostname = $config.hostname
$useSCIM = $config.useSCIM
$useMailsOnline = if ($null -ne $config -and $config.PSObject.Properties.Name -contains 'useMailsOnline') { 
    $config.useMailsOnline 
} else { 
    $defaultUseMailsOnline 
}



$oneTimePasswordServiceUri = if ($null -ne $config -and $config.PSObject.Properties.Name -contains 'oneTimePasswordServiceUri' -and -not [string]::IsNullOrEmpty($config.oneTimePasswordServiceUri)) {
    $config.oneTimePasswordServiceUri
} else {
    $defaultOneTimePasswordServiceUri
}




# Set ErrorActionPreference to "Stop"
$ErrorActionPreference = "Stop"
try{
      
     try {
        $sessioninfo = Get-CloudDrive
        if ($sessioninfo) {
            $tenant_id =  (Get-AzSubscription)[0].TenantID
        
            If  (-Not(Test-CommandExists Connect-MgGraph)) {install-module Microsoft.Graph}

            import-module Microsoft.Graph
            Microsoft.Graph\Connect-MgGraph -TenantID $env:ACC_TID -NoWelcome -Scopes "Application.ReadWrite.All" "User.Read",  "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

        }   
     }
     catch {
        [regex] $match = '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$'
        $i = 0
        do {
                if ($i -gt 0) {
                Write-Host  "The TenantID is in wrong Format, it shoud be a GUID."
            }
    
            $i++;
            $tenant_id =  &  Read-HostDefault "Please enter your Microsoft Entra ID TenantID" $tenant_id 

            }until ($tenant_id -match $match)
     
    
          If  (-Not(Test-CommandExists Connect-MgGraph)) {
                    Install-Module Microsoft.Graph
        }

       
    }     

    Connect-MgGraph -TenantID $tenant_id -NoWelcome -Scopes "Application.ReadWrite.All", "User.Read",  "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

    $appName =  & Read-HostDefault "Please enter the wanted name for the App Regristration, e.G. 'empower'" $appName

    [regex] $match = '(https)(:\/\/)([^\s,]+)' #https URL
          $c=0;
          do {
             if ($c -gt 0) {
            Write-Host  "URL Wrong Format"
             }

            $c++;
            $appURI =  &  Read-HostDefault "Please enter the empower URL you received from your empower contact person. It should be start with 'https://' " $hostname
        }until ($appURI -match $match)

    $removeExistingAppWithSameName = $false
    if(!($myApp = Get-MgApplication -Filter "DisplayName eq '$($appName)'"  -ErrorAction SilentlyContinue))
    {
      # Check for the Microsoft Graph Service Principal. If it doesn't exist already, create it.
      $graphsp = Confirm-MicrosoftGraphServicePrincipal

      $existingapp = $null
      $SearchString = "DisplayName:" + $appName
      $existingapp = Get-MgApplication -Search  $SearchString -ConsistencyLevel eventual
      if ($existingapp -and $removeExistingAppWithSameName) {
          Remove-MgApplication -ApplicationId $existingApp.AppId
      }

      $rsps = @()
      if ($graphsp) {
        $rsps += $graphsp

        $tenantDetails = Get-MgOrganization -OrganizationId $tenant_id 
        $tenantName = $tenantDetails.DisplayName

        $fromDate = [System.DateTime]::Now
        $appKey = New-AppKey -fromDate $fromDate -durationInYears 100

        $additionalPaths = @(
        "/empower/identityservice/",
        "/empower/identityservice/grants",
        "/empower/identityservice/signin-oidc"
        )

        $redirectUris = foreach ($path in $additionalPaths) {
            $appURI.trim('/') + $path
        }

        $params = @{
            RedirectUris = $redirectUris
            ImplicitGrantSettings = @{ EnableIdTokenIssuance = $true }
        }

        If ($useSCIM) {
            $ResourceAccessPermissions = @()
        }
        else {
            $ResourceAccessPermissions =  Get-RequiredPermissions
        }

        Write-Host "Create AppRegristration with Permissions" -ForegroundColor Yellow

        New-MgApplication -DisplayName $appName  -RequiredResourceAccess $ResourceAccessPermissions   -Web $params 
        $myApp = Get-MgApplication -Filter "DisplayName eq '$appName'"


        #add secret
        $secret = Add-MgApplicationPassword -ApplicationId $myApp.Id -PasswordCredential $appKey 
        $client_id = $myApp.AppId 

        # Creating the Service Principal for the application
        $servicePrincipal = New-MgServicePrincipal -AppId $myApp.AppId

        # grant admin consent
        $graphSpId = $(Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'").Id

        $graphAppRoles = (Get-MgServicePrincipal -ServicePrincipalId $graphSpId).AppRoles

        foreach ($permission in $ResourceAccessPermissions.ResourceAccess  | Where-Object {$_.Type -eq "Role"} ) {

            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId  $servicePrincipal.Id -PrincipalId $servicePrincipal.Id  -AppRoleId $permission.Id -ResourceId $graphSpId | Out-Null

                $permissionName = ($graphAppRoles | Where-Object { $_.Id -eq $permission.Id }).Value

                 Write-Host "Assigned App Permission: $permissionName" -ForegroundColor Green
            }
            catch {
                Write-Host  "Error assigning App Permission: $permissionName - $_" -ForegroundColor Red
            }
        }

            # Permissions to grant consent to, space separated
            $scopes = "User.Read"

            $params = @{
                ClientId    =  $servicePrincipal.Id
                ConsentType = "AllPrincipals"
                ResourceId  =  $graphSpId
                Scope       =  $scopes
            }

            Try {
                New-MgOauth2PermissionGrant -BodyParameter $params | Out-Null

                Write-Host "Granted Delegated Permission: $scopes" -ForegroundColor Green
            }
            catch {
                Write-Host "Error granting Delegated Permission ($scopes) - $_" -ForegroundColor Red
            }
         
            $client_secret = $secret.SecretText;

            $RawPasswordLink = Invoke-WebRequest -Method POST -Body "password=$client_secret&ttl=week" -Uri $oneTimePasswordServiceUri -UseBasicParsing
            $Link = $RawPasswordLink.RawContent.Substring($RawPasswordLink.RawContent.IndexOf('value="') + 7)

            $Link = $Link.Substring(0, $link.IndexOf(' ') - 1)
            $appInfo = [pscustomobject][ordered]@{
                    AppName                = $appName
                    TenantName             = $tenantName
                    TenantId               = $tenant_id
                    clientId               = $client_id
                    clientSecret           = $Link
                    createDateClientSecret =  $appKey.StartDateTime.ToShortDateString()
                    expirationDateClientSecret = $appKey.endDateTime.ToShortDateString()
                }
         }
        else {
            Write-Host
            Write-Host "Microsoft Graph Service Principal could not be found or created" -ForegroundColor Red
            Write-Host
        }
    }
    else {
        Write-Host
        Write-Host -f Yellow Azure AD Application $appName already exists.
    }

    Write-Host
    Write-Host -f Green "Finished" 

    Write-Host
    Write-Host "Copy the details from here or find the needed Details in the File AppRegistrationInfo.json, in the current folder"
    $jsonPath =  Join-Path -Path $PSScriptRoot -ChildPath AppRegistrationInfo.json
    $appInfo | Select-Object -Property TenantId, clientId, clientSecret
    $appInfo | Select-Object -Property TenantId, clientId, clientSecret, createDateClientSecret, expirationDateClientSecret | ConvertTo-Json >> $jsonPath 
}
Catch  {
          Write-Host -foregroundcolor Red "An error occurred: $_"
}
 # Reset ErrorActionPreference to default "Continue"
 $ErrorActionPreference = "Continue"

if ($useMailsOnline) {
     .\EntraIdAppRegistration_MailsOnline.ps1 -tenant_id  $tenant_id -appName $appName
} 

# This script needs to be run by an admin account in your Azure tenant.
# This script will create an Microsoft Entra ID app in your organisation with permission
# to access resources in yours or customers' tenants.