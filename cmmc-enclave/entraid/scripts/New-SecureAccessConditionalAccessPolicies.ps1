param(
    [Parameter()]
    [string[]]$ExcludedUserIds,

    [Parameter(Mandatory = $true)]
    [string]$AppgateOIDCApplicationId,

    [Parameter(Mandatory = $true)]
    [ValidateScript({
        foreach ($ip in $_) {
            $parsed = $null
            if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) {
                throw "'$ip' is not a valid IP address."
            }
            if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                throw "'$ip' is not a valid IPv4 address (IPv6 not allowed)."
            }
        }
        $true
    })]
    [string[]]$SecureEnclaveIp
)

'Microsoft.Graph.Users', 'Microsoft.Graph.Identity.SignIns' | ForEach-Object {
    Write-Host ('Installing module: {0}...' -f $_)
    Install-Module -Name $_ -Force -AllowClobber   
}

# Ensure proper Graph scopes are present
$RequiredScopes = @("Policy.ReadWrite.ConditionalAccess", "Directory.Read.All")
try {$Context = Get-MgContext} catch {$Context = $null}
$ExistingScopes = if ($Context) {$Context.Scopes} else {@()}
if (-not $Context -or ($RequiredScopes | Where-Object {$_ -notin $ExistingScopes})) {
    $Scopes = $ExistingScopes + $RequiredScopes | Select-Object -Unique
    Connect-MgGraph -NoWelcome -Scopes $Scopes -Environment 'USGov'
}

$MgSignedInUserId = (Get-MgUser -UserId (Get-MgContext).Account).Id
if ($ExcludedUserIds -notcontains $MgSignedInUserId) {
    $ExcludedUserIds += $MgSignedInUserId
}

$ExistingLocations = Get-MgIdentityConditionalAccessNamedLocation -All
if (-not ($ExistingLocations.DisplayName -contains "Secure Enclave")) {
    Write-Host 'Creating Secure Enclave location...'
    $Params = @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        DisplayName = "Secure Enclave"
        IsTrusted = $true
        IpRanges = @(
            foreach ($Ip in $SecureEnclaveIp) {
                @{
                    "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                    "cidrAddress" = "$Ip/32"
                }
            }
        )
    }        
    try {
        $SecureEnclaveLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $Params  -ErrorAction Stop
        Start-Sleep -Seconds 180 # give time for Azure to propagate the new location
    } 
    catch {
        throw "Failed to create Secure Enclave location: $_"
    }
}

$PolicyTemplates = @(
    @{
        DisplayName = "Block access outside Zero Trust Network"
        State = "enabledForReportingButNotEnforced"
        Conditions  = @{
            Applications = @{
                ExcludeApplications = @($AppgateOIDCApplicationId)
                IncludeApplications = @("All")
            }
            ClientAppTypes = @("all")
            Locations = @{
                ExcludeLocations = @($SecureEnclaveLocation.Id)
                IncludeLocations = @("All")
            }
            Users = @{
                ExcludeUsers = $ExcludedUserIds
                IncludeUsers = @("All")
            }
        }
        GrantControls = @{
            BuiltInControls = @("block")
            Operator = "OR"
        }
    },
    @{
        DisplayName = "Block non-AVD cloud apps on ZTNA unless using AVD"
        State = "enabledForReportingButNotEnforced"
        Conditions  = @{
            Applications = @{
                ExcludeApplications = @(
                    "a4a365df-50f1-4397-bc59-1a1564b8bb9c", # Microsoft Remote Desktop
                    "270efc09-cd0d-444b-a71f-39af4910ec45", # Windows Cloud Login
                    "9cdead84-a844-4324-93f2-b2e6bb768d07", # Azure Virtual Desktop
                    "a85cf173-4192-42f8-81fa-777a763e6e2c", # Azure Virtual Desktop Client
                    $AppgateOIDCApplicationId # Appgate OIDC Application
                )
                IncludeApplications = @("All")
            }
            ClientAppTypes = @("all")
            Devices = @{
                DeviceFilter = @{
                    Mode = "exclude"
                    Rule = 'device.displayName -startsWith "avd" -and device.manufacturer -eq "Microsoft Corporation" -and device.model -eq "Virtual Machine"'
                }
            }            
            Locations = @{
            }
            Users = @{
                ExcludeUsers = $ExcludedUserIds
                IncludeUsers = @("All")
            }            
        }
        GrantControls = @{
            BuiltInControls = @("block")
            Operator = "OR"
        }
    },
    @{
        DisplayName = "Enforce periodic reauthentication for AVD cloud apps"
        State= "enabledForReportingButNotEnforced"
        Conditions  = @{
            Applications = @{
                IncludeApplications = @(
                    "9cdead84-a844-4324-93f2-b2e6bb768d07", 
                    "a4a365df-50f1-4397-bc59-1a1564b8bb9c",
                    "270efc09-cd0d-444b-a71f-39af4910ec45"
                )
            }
            ClientAppTypes = @("all")
            Users = @{
                ExcludeUsers = $ExcludedUserIds
                IncludeUsers = @("All")
            }
        }
        GrantControls = @{
            BuiltInControls = @("mfa")
            Operator = "OR"
        }
        SessionControls = @{
            SignInFrequency = @{
                AuthenticationType = "primaryAndSecondaryAuthentication"
                FrequencyInterval = "timeBased"
                IsEnabled = $true
                Type = "hours"
                Value = 1
            }
        }
    }
)

$Policy = @()
foreach ($Template in $PolicyTemplates) {
    $Existing = Get-MgIdentityConditionalAccessPolicy -All | Where-Object {$_.DisplayName -eq $Template.DisplayName}
    if (-not $Existing) {
        Write-Host ('Creating Conditional Access Policy: {0}' -f $Template.DisplayName)
        $Policy += New-MgIdentityConditionalAccessPolicy @Template
    } else {
        Write-Host ('Policy already exists: {0}. Skipping.' -f $Template.DisplayName)
    }
}
$Policy