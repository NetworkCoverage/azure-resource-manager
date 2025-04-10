param(
[string]$tenant_id = "",
[string]$appName = "")


Function Test-CommandExists
{
Param ($command)

 $oldPreference = $ErrorActionPreference
 $ErrorActionPreference = 'stop'
 try {if(Get-Command $command){RETURN $true}}
 Catch {Write-Host "$command does not exist"; RETURN $false}
 Finally {$ErrorActionPreference=$oldPreference}

} #end function test-CommandExistsnd function test-CommandExists


$ErrorActionPreference = "Stop"
Try{
      
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
            
           if ([string]::IsNullOrEmpty($tenant_id)) {
               $tenant_id = Read-Host "Please enter your Microsoft Entra ID TenantID" 
            }
            
            

            }until ($tenant_id -match $match)
     
    
          If  (-Not(Test-CommandExists Connect-MgGraph)) {
                    Install-Module Microsoft.Graph
        }

        Connect-MgGraph -TenantID $tenant_id -NoWelcome -Scopes "Application.ReadWrite.All"   #, "User.Read"    "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

    }
}     
Catch  {
          Write-Host -foregroundcolor Red "An error occurred: $_"
}
        
if ([string]::IsNullOrEmpty($appName)) {
    $appName = Read-Host "Please enter your Application Name"
}

$myApps = Get-MgApplication -Filter "DisplayName eq '$($appName)'" -ErrorAction SilentlyContinue


# Prüfe die Anzahl der gefundenen Anwendungen
if ($myApps.Count -ne 1) {
             $appID = Read-Host "No or more than one App Regrstration Found please add your ApplicationID"
             $myApp =  Get-MgApplicationByAppId -AppId $appID -ErrorAction SilentlyContinue
} else {
            $myApp = Get-MgApplication -Filter "DisplayName eq '$appName'"
}

if ($myApps.Count -eq 1) {
    $redirectUris = $myApp.Web.RedirectUris
    $firstRedirectUri = $redirectUris | Select-Object -First 1

    $uri = New-Object System.Uri($firstRedirectUri)
    $appURI  = $uri.Host

    $scope = @{
        adminConsentDescription = "Retrieve basic user information"
        adminConsentDisplayName = "Allow empower® to access basic information on behalf of the Office user to identify them in addins that support Single Sign-On."
        id = [guid]::NewGuid()
        isEnabled = $true
        type = "User"
        userConsentDescription = ""
        userConsentDisplayName = ""
        value = "access_as_user"
    }


    $api = @{
    Oauth2PermissionScopes = @(
            @{
                adminConsentDisplayName = "Retrieve basic user information"
                adminConsentDescription = "Allow empower® to access basic information on behalf of the Office user to identify them in addins that support Single Sign-On."
                id = [guid]::NewGuid()
                isEnabled = $true
                type = "User"
                userConsentDescription = ""
                userConsentDisplayName = ""
                value = "access_as_user"
            }
        )
        RequestedAccessTokenVersion = 2
    }

     $params = @{
        identifierUris = @(
            "api://$appURI/$($myApp.AppId)"
        )
        api =  $api
    }

    Update-MgApplicationByAppId  -AppId $myApp.AppId  -BodyParameter $params
    
    # Definieren der Client-Anwendungs-IDs
    $clientAppIds = @(
        "5e3ce6c0-2b1f-4285-8d4b-75ee78787346",
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "ea5a67f6-b6f3-4338-b240-c655ddc3cc8e"
    )

    $myApp = Get-MgApplication -Filter "DisplayName eq '$appName'"
    $oauthPermissions = $myApp.Api.Oauth2PermissionScopes | Where-Object { $_.Value -eq "access_as_user" }  

    $clientAppIds = @(
        @{
            AppId = "5e3ce6c0-2b1f-4285-8d4b-75ee78787346"
            DelegatedPermissionIds = @($oauthPermissions.Id)
        },
        @{
            AppId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
            DelegatedPermissionIds = @($oauthPermissions.Id)
        },
        @{
            AppId = "ea5a67f6-b6f3-4338-b240-c655ddc3cc8e"
            DelegatedPermissionIds = @($oauthPermissions.Id)
        }
    )


     $api = @{
        preAuthorizedApplications = $clientAppIds
    }

     $params = @{
             api =  $api
    }

    Update-MgApplicationByAppId  -AppId $myApp.AppId  -BodyParameter $params 

    Write-Host
    Write-Host -f Green "Finished" 


}
else {
    Write-Host
    Write-Host -f Yellow Entra Id Application does not exists.
}

