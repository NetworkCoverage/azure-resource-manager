#https://petri.com/powershell-create-conditional-access-policies/
param (
    $TenantAdminUserPrincipalName, # this is the netcov admin user not your personal account
    $MFAExemptGroupName,
    $EgnyteEnterpriseAppId
)

#Install-Module Microsoft.Graph
Import-Module Microsoft.Graph -Verbose
$Permissions = @(
    "Policy.Read.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Application.Read.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Organization.Read.All",
    "RoleManagement.ReadWrite.Directory"
)
Connect-MgGraph -Scopes $Permissions -Environment USGov

$TenantAdminUserId = (Get-MgUser -UserId $TenantAdminUserPrincipalName).Id

New-MgGroup -DisplayName 'MFA Exempt' -MailEnabled:$false  -MailNickName 'mfaexempt' -SecurityEnabled
$MFAExemptGroupId = (Get-MgGroup -Filter "DisplayName eq `'$MFAExemptGroupName`'").Id

# Create named locations
$NamedLocations = @(
    @{
        "@odata.type" = "#microsoft.graph.countryNamedLocation"
        DisplayName = "US"
        CountriesAndRegions = @(
            "US"
        )
        IncludeUnknownCountriesAndRegions = $false
        CountryLookupMethod = "clientIpAddress"
    },
    @{
        "@odata.type" = "#microsoft.graph.ipNamedLocation"
        DisplayName = "Enclave Public IPs"
        IsTrusted = $true
        IpRanges = @(
            @{
                "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                CidrAddress = '' #"12.34.221.11/22"
            }
            @{
                "@odata.type" = "#microsoft.graph.iPv6CidrRange"
                CidrAddress = '' #"2001:0:9d38:90d6:0:0:0:0/63"
            }
        )
    }   
)
$NamedLocations | ForEach-Object -Process {
    Write-Host ('Creating named location - {0}' -f $_.DisplayName)
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $_
}

# Create conditional access policies
$PolicyTemplates = @(
    @{
        displayName = "Require multifactor authentication for all users"
        state = "enabled"
        conditions = @{
            clientAppTypes = "all"
            applications= @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
                excludeGroups = $MFAExemptGroupId
            }
            locations = @{
                includeLocations = @(
                    # "All"
                )
                excludeLocations = @(
                    # "AllTrusted"
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "mfa"
        }
    },
    @{
        displayName = "Block legacy authentication"
        state = "enabled"
        conditions = @{
            clientAppTypes = @(
                "exchangeActiveSync",
                "other"
            )
            applications = @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "block"
        }
    },
    @{
        displayName = "Block access for unknown or unsupported device platform"
        state = "enabled"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
            platforms = @{
                includePlatforms = "all"
                excludePlatforms = @(
                    "android",
                    "iOS",
                    "windows",
                    "linux"
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "block"
        }
    },
    @{
        displayName = "Require approved client apps and app protection policies"
        state = "enabled"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
            platforms = @{
                includePlatforms = @(
                    "android",
                    "iOS"
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = @(
                "approvedApplication",
                "compliantApplication"
            )
        }
    },
    @{
        displayName = "Require multifactor authentication for admins"
        state = "enabled"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                excludeUsers = $TenantAdminUserId
                includeRoles = @(
                    "62e90394-69f5-4237-9190-012177145e10",
                    "194ae4cb-b126-40b2-bd5b-6091b380977d",
                    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                    "29232cdf-9323-42fd-ade2-1d097af3e4de",
                    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                    "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                    "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                    "fe930be7-5e62-47db-91af-98c3a49a38b1",
                    "c4e39bd9-1100-46d3-8c65-fb160da0071f",
                    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                    "158c047a-c907-4556-b7ef-446551a6b5f7",
                    "966707d0-3269-4727-9be2-8c3a10f19b9d",
                    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                    "e8611ab8-c189-46e8-94e1-60213ab1f814"
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "mfa"
        }
    },
    @{
        displayName = "Use application enforced restrictions for unmanaged devices"
        state = "enabled"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                includeApplications = "Office365"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
        }
        sessionControls = @{
            applicationEnforcedRestrictions = @{
                isEnabled = $true
            }
        }
    },
    @{
        displayName = "Block browser access on mobile devices"
        state = "enabled"
        conditions = @{
            clientAppTypes = "browser"
            applications = @{
                includeApplications = "Office365"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
            platforms =@{
                includePlatforms = @(
                    "android",
                    "iOS"
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "block"
        }
    },
    @{
        displayName = "Require multifactor authentication for guest access"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "GuestsOrExternalUsers"
                excludeUsers = $TenantAdminUserId
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "mfa"
        }
    },
    @{
        displayName = "Require multifactor authentication for risky sign-ins"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            signInRiskLevels = @(
                "high",
                "medium"
            )
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "mfa"
        }
    },
    @{
        displayName = "Require password change for high-risk users"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            userRiskLevels = "high"
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
        }
        grantControls = @{
            operator = "AND"
            builtInControls = @(
                "mfa",
                "passwordChange"
            )
        }
    },
    @{
        displayName = "No persistent browser session"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
            devices = @{
                deviceFilter = @{
                    mode = "include"
                    rule = "device.trustType -ne `"ServerAD`" -or device.isCompliant -ne True"
                }
            }
        }
        sessionControls = @{
            signInFrequency = @{
                value = 1
                type = "hours"
                authenticationType = "primaryAndSecondaryAuthentication"
                frequencyInterval = "timeBased"
                isEnabled = $true
            }
            persistentBrowser = @{
                mode = "never"
                isEnabled = $true
            }
        }
    },
    # Require phishing-resistant multifactor authentication for admins - this policy is failing with error code 007: Incoming ConditionalAccessPolicy object is null or does not match the schema of ConditionalAccessPolicy type. For examples, please see API documentation at https://docs.microsoft.com/en-us/graph/api/conditionalaccessroot-post-policies?view=graph-rest-1.0.
    @{
        displayName = "Require phishing-resistant multifactor authentication for admins"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                includeApplications = "All"
            }
            users = @{
                excludeUsers = $TenantAdminUserId
                includeRoles = @(
                    "62e90394-69f5-4237-9190-012177145e10",
                    "194ae4cb-b126-40b2-bd5b-6091b380977d",
                    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                    "29232cdf-9323-42fd-ade2-1d097af3e4de",
                    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                    "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                    "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                    "fe930be7-5e62-47db-91af-98c3a49a38b1",
                    "c4e39bd9-1100-46d3-8c65-fb160da0071f",
                    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                    "158c047a-c907-4556-b7ef-446551a6b5f7",
                    "966707d0-3269-4727-9be2-8c3a10f19b9d",
                    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                    "e8611ab8-c189-46e8-94e1-60213ab1f814"
                )
            }
        }
        grantControls = @{
            authenticationStrength = New-MgPolicyAuthenticationStrengthPolicy -DisplayName "Phishing-resistant MFA" -Description "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key" -RequirementsSatisfied "mfa" -AllowedCombinations @("windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor")
            <# authenticationStrength = @{
                displayName = "Phishing-resistant MFA"
                description = "Phishing-resistant, Passwordless methods for the strongest authentication, such as a FIDO2 security key"
                requirementsSatisfied = "mfa"
	            allowedCombinations = @(
                    "windowsHelloForBusiness",
                    "fido2",
                    "x509CertificateMultiFactor"
                )
            }#>
        }
    },
    @{
        displayName = "Require devices to be marked as compliant"
        state = "enabledForReportingButNotEnforced"
        conditions = @{
            clientAppTypes = "all"
            applications = @{
                "includeApplications" = "Office365"
            }
            users = @{
                includeUsers = "All"
                excludeUsers = $TenantAdminUserId
            }
            platforms = @{
                includePlatforms = @(
                    "android",
                    "iOS",
                    "windows"
                )
                excludePlatforms = @(
                    "android",
                    "iOS",
                    "macOS",
                    "linux"
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "compliantDevice"
        }
    },
    @{
        displayName = "Block external access to Azure Virtual Desktop"
        state = "enabled"
        conditions = @{ 
            clientAppTypes = "all"
            applications = @{
                includeApplications = "9cdead84-a844-4324-93f2-b2e6bb768d07" # Azure Virtual Desktop
            }
            users = @{
                includeUsers = "All"
            }
            locations = @{
                includeLocations = @(
                    "All"
                )
                excludeLocations = @(
                    "AllTrusted" # AllTrusted is the default named location that includes all trusted locations.
                    # (Get-MgIdentityConditionalAccessNamedLocation).Id
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "block"
        }
    },
    @{
        displayName = "Block external access to Egnyte"
        state = "enabledForReportingButNotEnforced"
        conditions = @{ 
            clientAppTypes = "all"
            applications = @{
                includeApplications = $EgnyteEnterpriseAppId
            }
            users = @{
                includeUsers = "All"
            }
            locations = @{
                includeLocations = @(
                    "All"
                )
                excludeLocations = @(
                    "AllTrusted" # AllTrusted is the default named location that includes all trusted locations.
                    # (Get-MgIdentityConditionalAccessNamedLocation).Id
                )
            }
        }
        grantControls = @{
            operator = "OR"
            builtInControls = "block"
        }
    }
)

$PolicyTemplates | ForEach-Object -Process {
    Write-Host ('Creating conditional access policy - {0}' -f $_.displayName)
    $Params = @{
        DisplayName = $_.displayName
        State = $_.state
        Conditions = $_.conditions
        GrantControls = $_.grantcontrols
        SessionControls = $_.sessioncontrols
    }
    New-MgIdentityConditionalAccessPolicy @Params
}