param(
    [Parameter(Mandatory = $true)]
    [string]$MFAExemptGroupId
)


'Microsoft.Graph.Identity.SignIns'  | ForEach-Object {
    if (-not (Get-Module -ListAvailable -Name $_)) {
        Write-Host ('Installing missing module: {0}...' -f $_)
        Install-Module -Name $_ -Scope CurrentUser -Force
    }
    Import-Module $_ -Force
}


# Ensure proper Graph scopes are present
$RequiredScopes = @("Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Directory.Read.All")
try {$Context = Get-MgContext} catch {$Context = $null}
$ExistingScopes = if ($Context) {$Context.Scopes} else {@()}
if (-not $Context -or ($RequiredScopes | Where-Object {$_ -notin $ExistingScopes})) {
    $Scopes = $ExistingScopes + $RequiredScopes | Select-Object -Unique
    Connect-MgGraph -NoWelcome -Scopes $Scopes -Environment 'USGov'
}

$ExistingLocations = Get-MgIdentityConditionalAccessNamedLocation -All
if (-not ($ExistingLocations.DisplayName -contains "United States")) {
    Write-Host 'Creating United States location...'
    $Params = @{
        "@odata.type" = "#microsoft.graph.countryNamedLocation"
        DisplayName = "United States"
        CountriesAndRegions = @("US")
        IncludeUnknownCountriesAndRegions = $false
        }
        
    try {$UnitedStatesLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $Params -ErrorAction Stop} catch {throw "Failed to create United States location: $_"}
} 
else {
    Write-Host 'United States location already exists. Skipping creation.'
    $UnitedStatesLocation = $ExistingLocations | Where-Object {$_.DisplayName -eq "United States"}
}

$PolicyTemplates = @(
    @{
        DisplayName = "Require MFA for all users"
        State = "enabled"
        Conditions = @{
            Applications = @{
                IncludeApplications = @("All")
            }
            ClientAppTypes = @("all")
            Users = @{
                ExcludeGroups = $MFAExemptGroupId
                IncludeUsers = @("All")
            }
            Locations = @{
                IncludeLocations = @($UnitedStatesLocation.Id)
            }
        }
        GrantControls = @{
            BuiltInControls = @("mfa")
            Operator = "OR"
        }
    },
    @{
        DisplayName = "Block sign-ins outside the United States"
        State       = "enabled"
        Conditions  = @{
            Applications = @{
                IncludeApplications = @("All")
            }
            ClientAppTypes = @("all")
            Locations = @{
                ExcludeLocations = @($UnitedStatesLocation.Id)
                IncludeLocations = @("All")
            }
            Users = @{
                IncludeUsers = @("All")
            }
        }
        GrantControls = @{
            BuiltInControls = @("block")
            Operator = "OR"
        }
    },
    @{
        DisplayName = "Block legacy authentication"
        State = "enabled"
        Conditions = @{
            Applications = @{
                IncludeApplications = @("All")
            }
            ClientAppTypes = @("exchangeActiveSync", "other")
            Users = @{
                IncludeUsers = @("All")
            }            
        }
        GrantControls = @{
            BuiltInControls = @("block")
            Operator = "OR"
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