param (
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter] $GpuVms,

    [Parameter(Mandatory = $false)]
    [ValidateSet("v1.0", "Beta")]
    [System.String]$ApiVersion = "Beta",

    [Parameter(Mandatory = $true)]
    [System.String]$TenantId
)

$SettingsCatalogPolicies = @(
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 7
        name = "Configure device and resource redirection"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = ""
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId  = "device_vendor_msft_policy_config_admx_terminalserver_ts_time_zone"
                    choiceSettingValue  = @{
                        settingValueTemplateReference  = $null
                        children  = @()
                        value  = "device_vendor_msft_policy_config_admx_terminalserver_ts_time_zone_1"
                    }
                }
            }
            @{
                id = "1"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_clipboard"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_clipboard_1"
                    }
                }
            }
            @{
                id = "2"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_com"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_com_1"
                    }
                }
            }
            @{
                id = "3"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_remotedesktopservices_donotallowdriveredirection"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_remotedesktopservices_donotallowdriveredirection_1"
                    }
                }
            }
            @{
                id = "4"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_lpt"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_lpt_1"
                    }
                }
            }
            @{
                id = "5"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_smart_card"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_smart_card_1"
                    }
                }
            }
            @{
                id = "6"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_pnp"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_client_pnp_1"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Azure Virtual Desktop Hosts"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 3
        name = "Configure GPU acceleration for Azure Virtual Desktop"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = "Azure Virtual Desktop supports graphics processing unit (GPU) acceleration in rendering and encoding for improved app performance and scalability. GPU acceleration is crucial for graphics-intensive apps and can be used with all supported operating systems for Azure Virtual Desktop."
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_server_avc_hw_encode_preferred"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_server_avc_hw_encode_preferred_1"
                    }
                }
            }
            @{
                id = "1"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_server_avc444_mode_preferred"
                        choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_server_avc444_mode_preferred_1"
                    }
                }
            }
            @{
                id = "2"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_terminalserver_ts_dx_use_full_hwgpu"
                        choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_admx_terminalserver_ts_dx_use_full_hwgpu_1"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "GPU-optimized Azure VMs"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 8
        name = "Configure OneDrive settings"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = ""
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_allowtenantlist"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @(
                            @{
                                simpleSettingCollectionValue = @(
                                    @{
                                        settingValueTemplateReference = $null
                                        "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                        value = $TenantId
                                    }
                                )
                                settingInstanceTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
                                settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_allowtenantlist_allowtenantlistbox"
                            }
                        )
                        value = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_allowtenantlist_1"
                    }
                }
            }
            @{
            id = "1"
            settingInstance = @{
                settingInstanceTemplateReference = $null
                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_enableodignorelistfromgpo"
                choiceSettingValue = @{
                    settingValueTemplateReference = $null
                    children = @(
                        @{
                            simpleSettingCollectionValue = @(
                                @{
                                    settingValueTemplateReference = $null
                                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    value = "*.mp3"
                                }
                                @{
                                    settingValueTemplateReference = $null
                                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    value = "*.pst"
                                }
                            )
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_enableodignorelistfromgpo_enableodignorelistfromgpolistbox"
                        }
                    )
                    value = "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_enableodignorelistfromgpo_1"
                }
            }
            }
            @{
                id = "2"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_blockexternalsync"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_blockexternalsync_1"
                    }
                }
            }
            @{
            id = "3"
            settingInstance = @{
                settingInstanceTemplateReference = $null
                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinwithwizard"
                choiceSettingValue = @{
                    settingValueTemplateReference = $null
                    children = @(
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinwithwizard_kfmoptinwithwizard_textbox"
                            simpleSettingValue = @{
                                settingValueTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                value = $TenantId
                            }
                        }
                    )
                    value = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinwithwizard_1"
                }
            }
            }
            @{
            id = "4"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv3~policy~onedrivengsc_localmassdeletefiledeletethreshold"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @(
                            @{
                                settingInstanceTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                                settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv3~policy~onedrivengsc_localmassdeletefiledeletethreshold_lmdfiledeletethresholdbox"
                                simpleSettingValue = @{
                                    settingValueTemplateReference = $null
                                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue"
                                    value = 25
                                }
                            }
                        )
                        value = "device_vendor_msft_policy_config_onedrivengscv3~policy~onedrivengsc_localmassdeletefiledeletethreshold_1"
                    }
                }
            }
            @{
                id = "5"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_forcedlocalmassdeletedetection"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_forcedlocalmassdeletedetection_1"
                    }
                }
            }
            @{
                id = "6"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @(
                            @{
                                settingInstanceTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_kfmoptinnowizard_dropdown"
                                choiceSettingValue = @{
                                    settingValueTemplateReference = $null
                                    children = @()
                                    value = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_kfmoptinnowizard_dropdown_0"
                                }
                            }
                            @{
                                settingInstanceTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                                settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_kfmoptinnowizard_textbox"
                                simpleSettingValue = @{
                                    settingValueTemplateReference = $null
                                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    value = $TenantId
                                }
                            }
                        )
                        value = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_1"
                    }
                }
            }
            @{
                id = "7"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig_1"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Azure Virtual Desktop Hosts"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 1
        name = "Configure Windows NTP client"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = ""
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient"
                    choiceSettingValue = @{
                    settingValueTemplateReference = $null
                    children = @(
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_crosssitesyncflags"
                            simpleSettingValue = @{
                                settingValueTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue"
                                value = 2
                            }
                        }
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_ntpclienteventlogflags"
                            simpleSettingValue = @{
                                settingValueTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue"
                                value = 0
                            }
                        }
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_ntpserver"
                            simpleSettingValue = @{
                                settingValueTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                value = "time.nist.gov0x01"
                            }
                        }
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_resolvepeerbackoffmaxtimes"
                            simpleSettingValue = @{
                                settingValueTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue"
                                value = 7
                            }
                        }
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_resolvepeerbackoffminutes"
                            simpleSettingValue = @{
                                settingValueTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue"
                                value = 15
                            }
                        }
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_specialpollinterval"
                            simpleSettingValue = @{
                                settingValueTemplateReference = $null
                                "@odata.type"= "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue"
                                value = 3600
                            }
                        }
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_type"
                            choiceSettingValue = @{
                                settingValueTemplateReference = $null
                                children = @()
                                value = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_w32time_type_ntp"
                            }
                        }
                    )
                    value = "device_vendor_msft_policy_config_admx_w32time_w32time_policy_configure_ntpclient_1"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Azure Virtual Desktop Hosts"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 1
        name = "Disable password reveal"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = "Disables the password reveal button"
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "user_vendor_msft_policy_config_credentialsui_disablepasswordreveal"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "user_vendor_msft_policy_config_credentialsui_disablepasswordreveal_1"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Users"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 2
        name = "Enable Azure Information Protection add-in for sensitivity labeling"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = "Enables the policy that ensures Azure Information Protection add-in for\nsensitivity labeling is present"
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "user_vendor_msft_policy_config_office16v13~policy~l_microsoftofficesystem~l_securitysettings_l_aipexception"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "user_vendor_msft_policy_config_office16v13~policy~l_microsoftofficesystem~l_securitysettings_l_aipexception_1"
                    }
                }
            }
            @{
                id = "1"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "user_vendor_msft_policy_config_office16v3~policy~l_microsoftofficesystem~l_securitysettings_l_useofficeforlabelling"
                    choiceSettingValue = @{
                        settingValueTemplateReference = $null
                        children = @()
                        value = "user_vendor_msft_policy_config_office16v3~policy~l_microsoftofficesystem~l_securitysettings_l_useofficeforlabelling_0"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Users"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 2
        name = "Enable interactive logon banner"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = "Displays interactive logon"
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    simpleSettingCollectionValue = @(
                        @{
                            settingValueTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                            value = "This system is the property of $CustomerName and is intended for authorized users only. Employees and users of $CustomerName’s Electronic Systems (including desktop computers laptop computers servers mobile devices email Internet access and business applications) should have no expectation of privacy with regard to use of these resources. All individuals’ activities while using $CustomerName’s Electronic Systems may be monitored and audited. By signing on and using any of these Electronic Systems users acknowledge that all data messages documents etc. sent received or reviewed while using these Electronic Systems are property of $CustomerName. Additionally this system contains federal contract information and/or Controlled Unclassified Information (CUI). By using this system (which includes any device attached to this system) you consent to abide by $CustomerName's policies regarding CUI. You further acknowledge that failure to abide by these terms and usage requirements may result in revoked or suspended access privileges."
                        }
                    )
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_messagetextforusersattemptingtologon"
                }
            }
            @{
                id = "1"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_messagetitleforusersattemptingtologon"
                    simpleSettingValue = @{
                        settingValueTemplateReference = $null
                        "@odata.type"= "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                        value = "$CustomerName Terms of Use"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Azure Virtual Desktop Hosts"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        platforms = "windows10"
        technologies = "mdm"
        settingCount = 1
        name = "Enable screen capture protection"
        templateReference = @{
            templateDisplayVersion = $null
            templateFamily = "none"
            templateDisplayName = $null
            templateId = ""
        }
        roleScopeTagIds = @(
            "0"
        )
        creationSource = $null
        description = "Prevents users from capturing the screen for sharing"
        priorityMetaData = $null
        settings = @(
            @{
                id = "0"
                settingInstance = @{
                    settingInstanceTemplateReference = $null
                    "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                    settingDefinitionId = "device_vendor_msft_policy_config_terminalserver-avdv1~policy~avd_gp_node_avd_server_screen_capture_protection"
                    choiceSettingValue = @{
                    settingValueTemplateReference = $null
                    children = @(
                        @{
                            settingInstanceTemplateReference = $null
                            "@odata.type"= "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                            settingDefinitionId = "device_vendor_msft_policy_config_terminalserver-avdv1~policy~avd_gp_node_avd_server_screen_capture_protection_avd_server_screen_capture_protection_level"
                            choiceSettingValue = @{
                                settingValueTemplateReference = $null
                                children = @()
                                value = "device_vendor_msft_policy_config_terminalserver-avdv1~policy~avd_gp_node_avd_server_screen_capture_protection_avd_server_screen_capture_protection_level_1"
                            }   
                        }
                    )
                    value = "device_vendor_msft_policy_config_terminalserver-avdv1~policy~avd_gp_node_avd_server_screen_capture_protection_1"
                    }
                }
            }
        )
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Azure Virtual Desktop Hosts"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
)
$TemplatePolicies = @(
    @{
        bitLockerEnableStorageCardEncryptionOnMobile = $false
        defenderDisableScanDownloads = $null
        localSecurityOptionsBlockMicrosoftAccounts = $false
        applicationGuardBlockClipboardSharing = "notConfigured"
        userRightsDelegation = $null
        defenderDisableRealTimeMonitoring = $null
        firewallMergeKeyingModuleSettings = $null
        defenderAllowIntrusionPreventionSystem = $null
        applicationGuardEnabled = $false
        userRightsLoadUnloadDrivers = $null
        localSecurityOptionsAllowUndockWithoutHavingToLogon = $false
        defenderProcessCreationType = "userDefined"
        localSecurityOptionsSmartCardRemovalBehavior = "noAction"
        bitLockerSystemDrivePolicy = @{
            prebootRecoveryUrl = $null
            startupAuthenticationTpmPinAndKeyUsage = "blocked"
            startupAuthenticationRequired = $false
            startupAuthenticationTpmPinUsage = "blocked"
            startupAuthenticationBlockWithoutTpmChip = $false
            startupAuthenticationTpmKeyUsage = "blocked"
            prebootRecoveryMessage = $null
            minimumPinLength = $null
            prebootRecoveryEnableMessageAndUrl = $false
            recoveryOptions = $null
            startupAuthenticationTpmUsage = "blocked"
            encryptionMethod = "xtsAes128"
        }
        firewallRules = @()
        defenderSecurityCenterDisableSecureBootUI = $null
        bitLockerEncryptDevice = $true
        applicationGuardAllowPrintToXPS = $false
        defenderDisableCloudProtection = $null
        userRightsGenerateSecurityAudits = $null
        localSecurityOptionsMachineInactivityLimit = $null
        localSecurityOptionsLogOnMessageText = $null
        firewallProfilePrivate = $null
        applicationGuardAllowVirtualGPU = $false
        defenderScriptDownloadedPayloadExecution = "userDefined"
        deviceManagementApplicabilityRuleOsEdition = $null
        userRightsAllowAccessFromNetwork = $null
        defenderGuardMyFoldersType = "userDefined"
        applicationGuardAllowCameraMicrophoneRedirection = $null
        userRightsActAsPartOfTheOperatingSystem = $null
        firewallIPSecExemptionsAllowICMP = $false
        applicationGuardCertificateThumbprints = @()
        defenderSecurityCenterDisableHealthUI = $null
        xboxServicesEnableXboxGameSaveTask = $false
        localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations = $false
        defenderEmailContentExecutionType = "userDefined"
        localSecurityOptionsBlockRemoteOpticalDriveAccess = $false
        userRightsAccessCredentialManagerAsTrustedCaller = $null
        localSecurityOptionsMachineInactivityLimitInMinutes = $null
        defenderAdobeReaderLaunchChildProcess = "notConfigured"
        localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager = $null
        userRightsLocalLogOn = $null
        defenderUntrustedUSBProcess = "userDefined"
        defenderSecurityCenterDisableNotificationAreaUI = $null
        userRightsManageAuditingAndSecurityLogs = $null
        localSecurityOptionsHideUsernameAtSignIn = $false
        userRightsChangeSystemTime = $null
        userRightsTakeOwnership = $null
        supportsScopeTags = $true
        defenderProcessCreation = "userDefined"
        defenderOfficeAppsOtherProcessInjectionType = "userDefined"
        defenderAllowOnAccessProtection = $null
        defenderScanDirection = $null
        defenderAllowBehaviorMonitoring = $null
        bitLockerFixedDrivePolicy = @{
            encryptionMethod = "xtsAes128"
            recoveryOptions = @{
            enableRecoveryInformationSaveToStore = $true
            recoveryKeyUsage = "allowed"
            recoveryInformationToStore = "passwordAndKey"
            enableBitLockerAfterRecoveryInformationToStore = $true
            blockDataRecoveryAgent = $false
            hideRecoveryOptions = $true
            recoveryPasswordUsage = "allowed"
        }
            requireEncryptionForWriteAccess = $false
        }
        defenderSecurityCenterDisableClearTpmUI = $null
        userRightsModifyObjectLabels = $null
        defenderSecurityCenterHelpEmail = $null
        dmaGuardDeviceEnumerationPolicy = "deviceDefault"
        firewallIPSecExemptionsNone = $false
        localSecurityOptionsBlockRemoteLogonWithBlankPassword = $false
        localSecurityOptionsDisableAdministratorAccount = $false
        defenderSecurityCenterBlockExploitProtectionOverride = $false
        applicationGuardForceAuditing = $false
        userRightsRemoteDesktopServicesLogOn = $null
        defenderDisableIntrusionPreventionSystem = $null
        defenderScheduledScanDay = $null
        applicationGuardAllowPersistence = $false
        defenderEnableScanMappedNetworkDrivesDuringFullScan = $null
        userRightsLockMemory = $null
        defenderOfficeAppsExecutableContentCreationOrLaunchType = "userDefined"
        defenderUntrustedExecutableType = "userDefined"
        localSecurityOptionsDisableServerDigitallySignCommunicationsAlways = $false
        defenderOfficeAppsLaunchChildProcess = "userDefined"
        defenderPotentiallyUnwantedAppAction = $null
        defenderSecurityCenterHelpURL = $null
        defenderSecurityCenterDisableAppBrowserUI = $null
        firewallBlockStatefulFTP = $null
        applicationGuardEnabledOptions = "notConfigured"
        localSecurityOptionsInformationDisplayedOnLockScreen = "notConfigured"
        smartScreenEnableInShell = $false
        defenderDisableScanScriptsLoadedInInternetExplorer = $null
        localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser = "notConfigured"
        localSecurityOptionsAllowUIAccessApplicationElevation = $false
        defenderAllowScanScriptsLoadedInInternetExplorer = $null
        localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn = $false
        localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees = $false
        xboxServicesLiveNetworkingServiceStartupMode = "manual"
        firewallPreSharedKeyEncodingMethod = "deviceDefault"
        defenderDisableCatchupQuickScan = $null
        defenderSecurityCenterDisableRansomwareUI = $null
        defenderEmailContentExecution = "userDefined"
        userRightsDenyLocalLogOn = $null
        defenderFilesAndFoldersToExclude = @()
        localSecurityOptionsClientDigitallySignCommunicationsAlways = $false
        applicationGuardAllowPrintToPDF = $false
        localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares = $false
        localSecurityOptionsGuestAccountName = $null
        localSecurityOptionsDoNotRequireCtrlAltDel = $false
        defenderDisableBehaviorMonitoring = $null
        defenderAdditionalGuardedFolders = @()
        defenderOfficeAppsExecutableContentCreationOrLaunch = "userDefined"
        deviceManagementApplicabilityRuleOsVersion = $null
        defenderAllowScanDownloads = $null
        "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
        defenderDisableCatchupFullScan = $null
        defenderAdvancedRansomewareProtectionType = "notConfigured"
        localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients = "none"
        deviceGuardSecureBootWithDMA = "notConfigured"
        defenderAllowEndUserAccess = $null
        defenderDaysBeforeDeletingQuarantinedMalware = $null
        defenderDisableScanArchiveFiles = $null
        description = $null
        defenderSecurityCenterOrganizationDisplayName = $null
        localSecurityOptionsStandardUserElevationPromptBehavior = "notConfigured"
        userRightsProfileSingleProcess = $null
        roleScopeTagIds = @(
            "0"
        )
        defenderEnableScanIncomingMail = $null
        deviceGuardLocalSystemAuthorityCredentialGuardSettings = "notConfigured"
        localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers = $false
        localSecurityOptionsAllowPKU2UAuthenticationRequests = $false
        applicationGuardBlockNonEnterpriseContent = $false
        defenderAllowScanArchiveFiles = $null
        defenderOfficeAppsLaunchChildProcessType = "userDefined"
        firewallCertificateRevocationListCheckMethod = "deviceDefault"
        defenderOfficeCommunicationAppsLaunchChildProcess = "notConfigured"
        bitLockerAllowStandardUserEncryption = $true
        deviceGuardLaunchSystemGuard = "notConfigured"
        defenderExploitProtectionXml = $null
        lanManagerWorkstationDisableInsecureGuestLogons = $false
        firewallIPSecExemptionsAllowNeighborDiscovery = $false
        userRightsCreatePageFile = $null
        defenderDisableOnAccessProtection = $null
        firewallPacketQueueingMethod = "deviceDefault"
        displayName = "Enable Bitlocker"
        localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation = $false
        applicationGuardAllowFileSaveOnHost = $false
        localSecurityOptionsHideLastSignedInUser = $false
        userRightsManageVolumes = $null
        defenderOfficeAppsOtherProcessInjection = "userDefined"
        smartScreenBlockOverrideForFiles = $false
        firewallProfilePublic = $null
        defenderDisableScanNetworkFiles = $null
        defenderSecurityCenterITContactDisplay = "notConfigured"
        defenderSecurityCenterDisableNetworkUI = $null
        lanManagerAuthenticationLevel = "lmAndNltm"
        localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers = "none"
        defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI = $null
        localSecurityOptionsClearVirtualMemoryPageFile = $false
        userRightsBlockAccessFromNetwork = $null
        defenderSecurityCenterDisableHardwareUI = $null
        firewallIPSecExemptionsAllowRouterDiscovery = $false
        defenderGuardedFoldersAllowedAppPaths = @()
        localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation = $false
        defenderScheduledScanTime = $null
        userRightsDebugPrograms = $null
        userRightsCreateToken = $null
        localSecurityOptionsDisableGuestAccount = $false
        defenderSecurityCenterDisableFamilyUI = $null
        xboxServicesLiveGameSaveServiceStartupMode = "manual"
        localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees = $false
        deviceGuardEnableVirtualizationBasedSecurity = $false
        defenderSecurityCenterDisableTroubleshootingUI = $null
        defenderAllowScanNetworkFiles = $null
        defenderExploitProtectionXmlFileName = $null
        defenderUntrustedExecutable = "userDefined"
        defenderDetectedMalwareActions = $null
        localSecurityOptionsOnlyElevateSignedExecutables = $false
        defenderEnableLowCpuPriority = $null
        defenderScanMaxCpuPercentage = $null
        firewallIdleTimeoutForSecurityAssociationInSeconds = $null
        defenderBlockPersistenceThroughWmiType = "userDefined"
        bitLockerDisableWarningForOtherDiskEncryption = $true
        localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts = $false
        userRightsCreateSymbolicLinks = $null
        applicationGuardAllowPrintToNetworkPrinters = $false
        defenderSubmitSamplesConsentType = $null
        localSecurityOptionsAdministratorElevationPromptBehavior = "notConfigured"
        defenderOfficeMacroCodeAllowWin32ImportsType = "userDefined"
        defenderNetworkProtectionType = "notConfigured"
        userRightsModifyFirmwareEnvironment = $null
        defenderSecurityCenterDisableAccountUI = $null
        defenderSignatureUpdateIntervalInHours = $null
        localSecurityOptionsUseAdminApprovalMode = $false
        xboxServicesLiveAuthManagerServiceStartupMode = "manual"
        defenderAllowScanRemovableDrivesDuringFullScan = $null
        firewallProfileDomain = $null
        defenderScriptDownloadedPayloadExecutionType = "userDefined"
        defenderAllowCloudProtection = $null
        defenderOfficeMacroCodeAllowWin32Imports = "userDefined"
        defenderPreventCredentialStealingType = "notConfigured"
        windowsDefenderTamperProtection = "notConfigured"
        defenderScheduledQuickScanTime = $null
        appLockerApplicationControl = "notConfigured"
        deviceManagementApplicabilityRuleDeviceMode = $null
        localSecurityOptionsInformationShownOnLockScreen = "notConfigured"
        userRightsCreateGlobalObjects = $null
        defenderAllowRealTimeMonitoring = $null
        defenderCheckForSignaturesBeforeRunningScan = $null
        defenderUntrustedUSBProcessType = "userDefined"
        localSecurityOptionsUseAdminApprovalModeForAdministrators = $false
        defenderSecurityCenterNotificationsFromApp = "notConfigured"
        defenderScriptObfuscatedMacroCode = "userDefined"
        defenderBlockEndUserAccess = $null
        localSecurityOptionsAdministratorAccountName = $null
        defenderSecurityCenterDisableVirusUI = $null
        firewallIPSecExemptionsAllowDHCP = $false
        bitLockerRemovableDrivePolicy = @{
            blockCrossOrganizationWriteAccess = $false
            encryptionMethod = "aesCbc128"
            requireEncryptionForWriteAccess = $false
        }
        defenderCloudExtendedTimeoutInSeconds = $null
        bitLockerRecoveryPasswordRotation = "notConfigured"
        xboxServicesAccessoryManagementServiceStartupMode = "manual"
        localSecurityOptionsBlockUsersInstallingPrinterDrivers = $false
        defenderDisableScanRemovableDrivesDuringFullScan = $null
        userRightsBackupData = $null
        applicationGuardAllowPrintToLocalPrinters = $false
        userRightsImpersonateClient = $null
        userRightsCreatePermanentSharedObjects = $null
        localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool = $false
        defenderScriptObfuscatedMacroCodeType = "userDefined"
        userRightsRemoteShutdown = $null
        defenderAttackSurfaceReductionExcludedPaths = @()
        applicationGuardBlockFileTransfer = "notConfigured"
        localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange = $false
        localSecurityOptionsAllowUIAccessApplicationsForSecureLocations = $false
        defenderFileExtensionsToExclude = @()
        userRightsIncreaseSchedulingPriority = $null
        defenderCloudBlockLevel = $null
        defenderScanType = $null
        userRightsRestoreData = $null
        defenderSecurityCenterHelpPhone = $null
        localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares = $false
        localSecurityOptionsLogOnMessageTitle = $null
        defenderProcessesToExclude = @()
        deviceGuardEnableSecureBootWithDMA = $false 
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Azure Virtual Desktop Hosts"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        bitLockerEnableStorageCardEncryptionOnMobile = $false
        defenderDisableScanDownloads = $null
        localSecurityOptionsBlockMicrosoftAccounts = $false
        applicationGuardBlockClipboardSharing = "notConfigured"
        userRightsDelegation = $null
        defenderDisableRealTimeMonitoring = $null
        firewallMergeKeyingModuleSettings = $null
        defenderAllowIntrusionPreventionSystem = $null
        applicationGuardEnabled = $false
        userRightsLoadUnloadDrivers = $null
        localSecurityOptionsAllowUndockWithoutHavingToLogon = $false
        defenderProcessCreationType = "userDefined"
        localSecurityOptionsSmartCardRemovalBehavior = "noAction"
        bitLockerSystemDrivePolicy = @{
            prebootRecoveryUrl = $null
            startupAuthenticationTpmPinAndKeyUsage = "blocked"
            startupAuthenticationRequired = $false
            startupAuthenticationTpmPinUsage = "blocked"
            startupAuthenticationBlockWithoutTpmChip = $false
            startupAuthenticationTpmKeyUsage = "blocked"
            prebootRecoveryMessage = $null
            minimumPinLength = $null
            prebootRecoveryEnableMessageAndUrl = $false
            recoveryOptions = $null
            startupAuthenticationTpmUsage = "blocked"
            encryptionMethod = $null
        }
        firewallRules = @()
        defenderSecurityCenterDisableSecureBootUI = $null
        bitLockerEncryptDevice = $false
        applicationGuardAllowPrintToXPS = $false
        defenderDisableCloudProtection = $null
        userRightsGenerateSecurityAudits = $null
        localSecurityOptionsMachineInactivityLimit = 15
        localSecurityOptionsLogOnMessageText = $null
        firewallProfilePrivate = $null
        applicationGuardAllowVirtualGPU = $false
        defenderScriptDownloadedPayloadExecution = "userDefined"
        deviceManagementApplicabilityRuleOsEdition = $null
        userRightsAllowAccessFromNetwork = $null
        defenderGuardMyFoldersType = "userDefined"
        applicationGuardAllowCameraMicrophoneRedirection = $null
        userRightsActAsPartOfTheOperatingSystem = $null
        firewallIPSecExemptionsAllowICMP = $false
        applicationGuardCertificateThumbprints = @()
        defenderSecurityCenterDisableHealthUI = $null
        xboxServicesEnableXboxGameSaveTask = $false
        localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations = $false
        defenderEmailContentExecutionType = "userDefined"
        localSecurityOptionsBlockRemoteOpticalDriveAccess = $false
        userRightsAccessCredentialManagerAsTrustedCaller = $null
        localSecurityOptionsMachineInactivityLimitInMinutes = 15
        defenderAdobeReaderLaunchChildProcess = "notConfigured"
        localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager = $null
        userRightsLocalLogOn = $null
        defenderUntrustedUSBProcess = "userDefined"
        defenderSecurityCenterDisableNotificationAreaUI = $null
        userRightsManageAuditingAndSecurityLogs = $null
        localSecurityOptionsHideUsernameAtSignIn = $false
        userRightsChangeSystemTime = $null
        userRightsTakeOwnership = $null
        supportsScopeTags = $true
        defenderProcessCreation = "userDefined"
        defenderOfficeAppsOtherProcessInjectionType = "userDefined"
        defenderAllowOnAccessProtection = $null
        defenderScanDirection = $null
        defenderAllowBehaviorMonitoring = $null
        bitLockerFixedDrivePolicy = @{
            encryptionMethod = $null
            recoveryOptions = $null
            requireEncryptionForWriteAccess = $false
        }
        defenderSecurityCenterDisableClearTpmUI = $null
        userRightsModifyObjectLabels = $null
        defenderSecurityCenterHelpEmail = $null
        dmaGuardDeviceEnumerationPolicy = "deviceDefault"
        firewallIPSecExemptionsNone = $false
        localSecurityOptionsBlockRemoteLogonWithBlankPassword = $false
        localSecurityOptionsDisableAdministratorAccount = $false
        defenderSecurityCenterBlockExploitProtectionOverride = $false
        applicationGuardForceAuditing = $false
        userRightsRemoteDesktopServicesLogOn = $null
        defenderDisableIntrusionPreventionSystem = $null
        defenderScheduledScanDay = $null
        applicationGuardAllowPersistence = $false
        defenderEnableScanMappedNetworkDrivesDuringFullScan = $null
        userRightsLockMemory = $null
        defenderOfficeAppsExecutableContentCreationOrLaunchType = "userDefined"
        defenderUntrustedExecutableType = "userDefined"
        localSecurityOptionsDisableServerDigitallySignCommunicationsAlways = $false
        defenderOfficeAppsLaunchChildProcess = "userDefined"
        defenderPotentiallyUnwantedAppAction = $null
        defenderSecurityCenterHelpURL = $null
        defenderSecurityCenterDisableAppBrowserUI = $null
        firewallBlockStatefulFTP = $null
        applicationGuardEnabledOptions = "notConfigured"
        localSecurityOptionsInformationDisplayedOnLockScreen = "notConfigured"
        smartScreenEnableInShell = $false
        defenderDisableScanScriptsLoadedInInternetExplorer = $null
        localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser = "notConfigured"
        localSecurityOptionsAllowUIAccessApplicationElevation = $false
        defenderAllowScanScriptsLoadedInInternetExplorer = $null
        localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn = $false
        localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees = $false
        xboxServicesLiveNetworkingServiceStartupMode = "manual"
        firewallPreSharedKeyEncodingMethod = "deviceDefault"
        defenderDisableCatchupQuickScan = $null
        defenderSecurityCenterDisableRansomwareUI = $null
        defenderEmailContentExecution = "userDefined"
        userRightsDenyLocalLogOn = $null
        defenderFilesAndFoldersToExclude = @()
        localSecurityOptionsClientDigitallySignCommunicationsAlways = $false
        applicationGuardAllowPrintToPDF = $false
        localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares = $false
        localSecurityOptionsGuestAccountName = $null
        localSecurityOptionsDoNotRequireCtrlAltDel = $false
        defenderDisableBehaviorMonitoring = $null
        defenderAdditionalGuardedFolders = @()
        defenderOfficeAppsExecutableContentCreationOrLaunch = "userDefined"
        deviceManagementApplicabilityRuleOsVersion = $null
        defenderAllowScanDownloads = $null
        "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
        defenderDisableCatchupFullScan = $null
        defenderAdvancedRansomewareProtectionType = "notConfigured"
        localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients = "none"
        deviceGuardSecureBootWithDMA = "notConfigured"
        defenderAllowEndUserAccess = $null
        defenderDaysBeforeDeletingQuarantinedMalware = $null
        defenderDisableScanArchiveFiles = $null
        description = $null
        defenderSecurityCenterOrganizationDisplayName = $null
        localSecurityOptionsStandardUserElevationPromptBehavior = "notConfigured"
        userRightsProfileSingleProcess = $null
        roleScopeTagIds = @(
            "0"
        )
        defenderEnableScanIncomingMail = $null
        deviceGuardLocalSystemAuthorityCredentialGuardSettings = "notConfigured"
        localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers = $false
        localSecurityOptionsAllowPKU2UAuthenticationRequests = $false
        applicationGuardBlockNonEnterpriseContent = $false
        defenderAllowScanArchiveFiles = $null
        defenderOfficeAppsLaunchChildProcessType = "userDefined"
        firewallCertificateRevocationListCheckMethod = "deviceDefault"
        defenderOfficeCommunicationAppsLaunchChildProcess = "notConfigured"
        bitLockerAllowStandardUserEncryption = $false
        deviceGuardLaunchSystemGuard = "notConfigured"
        defenderExploitProtectionXml = $null
        lanManagerWorkstationDisableInsecureGuestLogons = $false
        firewallIPSecExemptionsAllowNeighborDiscovery = $false
        userRightsCreatePageFile = $null
        defenderDisableOnAccessProtection = $null
        firewallPacketQueueingMethod = "deviceDefault"
        displayName = "Set lock screen inactivity timer"
        localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation = $false
        applicationGuardAllowFileSaveOnHost = $false
        localSecurityOptionsHideLastSignedInUser = $false
        userRightsManageVolumes = $null
        defenderOfficeAppsOtherProcessInjection = "userDefined"
        smartScreenBlockOverrideForFiles = $false
        firewallProfilePublic = $null
        defenderDisableScanNetworkFiles = $null
        defenderSecurityCenterITContactDisplay = "notConfigured"
        defenderSecurityCenterDisableNetworkUI = $null
        lanManagerAuthenticationLevel = "lmAndNltm"
        localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers = "none"
        defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI = $null
        localSecurityOptionsClearVirtualMemoryPageFile = $false
        userRightsBlockAccessFromNetwork = $null
        defenderSecurityCenterDisableHardwareUI = $null
        firewallIPSecExemptionsAllowRouterDiscovery = $false
        defenderGuardedFoldersAllowedAppPaths = @()
        localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation = $false
        defenderScheduledScanTime = $null
        userRightsDebugPrograms = $null
        userRightsCreateToken = $null
        localSecurityOptionsDisableGuestAccount = $false
        defenderSecurityCenterDisableFamilyUI = $null
        xboxServicesLiveGameSaveServiceStartupMode = "manual"
        localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees = $false
        deviceGuardEnableVirtualizationBasedSecurity = $false
        defenderSecurityCenterDisableTroubleshootingUI = $null
        defenderAllowScanNetworkFiles = $null
        defenderExploitProtectionXmlFileName = $null
        defenderUntrustedExecutable = "userDefined"
        defenderDetectedMalwareActions = $null
        localSecurityOptionsOnlyElevateSignedExecutables = $false
        defenderEnableLowCpuPriority = $null
        defenderScanMaxCpuPercentage = $null
        firewallIdleTimeoutForSecurityAssociationInSeconds = $null
        defenderBlockPersistenceThroughWmiType = "userDefined"
        bitLockerDisableWarningForOtherDiskEncryption = $false
        localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts = $false
        userRightsCreateSymbolicLinks = $null
        applicationGuardAllowPrintToNetworkPrinters = $false
        defenderSubmitSamplesConsentType = $null
        localSecurityOptionsAdministratorElevationPromptBehavior = "notConfigured"
        defenderOfficeMacroCodeAllowWin32ImportsType = "userDefined"
        defenderNetworkProtectionType = "notConfigured"
        userRightsModifyFirmwareEnvironment = $null
        defenderSecurityCenterDisableAccountUI = $null
        defenderSignatureUpdateIntervalInHours = $null
        localSecurityOptionsUseAdminApprovalMode = $false
        xboxServicesLiveAuthManagerServiceStartupMode = "manual"
        defenderAllowScanRemovableDrivesDuringFullScan = $null
        firewallProfileDomain = $null
        defenderScriptDownloadedPayloadExecutionType = "userDefined"
        defenderAllowCloudProtection = $null
        defenderOfficeMacroCodeAllowWin32Imports = "userDefined"
        defenderPreventCredentialStealingType = "notConfigured"
        windowsDefenderTamperProtection = "notConfigured"
        defenderScheduledQuickScanTime = $null
        appLockerApplicationControl = "notConfigured"
        deviceManagementApplicabilityRuleDeviceMode = $null
        localSecurityOptionsInformationShownOnLockScreen = "notConfigured"
        userRightsCreateGlobalObjects = $null
        defenderAllowRealTimeMonitoring = $null
        defenderCheckForSignaturesBeforeRunningScan = $null
        defenderUntrustedUSBProcessType = "userDefined"
        localSecurityOptionsUseAdminApprovalModeForAdministrators = $false
        defenderSecurityCenterNotificationsFromApp = "notConfigured"
        defenderScriptObfuscatedMacroCode = "userDefined"
        defenderBlockEndUserAccess = $null
        localSecurityOptionsAdministratorAccountName = $null
        defenderSecurityCenterDisableVirusUI = $null
        firewallIPSecExemptionsAllowDHCP = $false
        bitLockerRemovableDrivePolicy = @{
            blockCrossOrganizationWriteAccess = $false
            encryptionMethod = $null
            requireEncryptionForWriteAccess = $false
        }
        defenderCloudExtendedTimeoutInSeconds = $null
        bitLockerRecoveryPasswordRotation = "notConfigured"
        xboxServicesAccessoryManagementServiceStartupMode = "manual"
        localSecurityOptionsBlockUsersInstallingPrinterDrivers = $false
        defenderDisableScanRemovableDrivesDuringFullScan = $null
        userRightsBackupData = $null
        applicationGuardAllowPrintToLocalPrinters = $false
        userRightsImpersonateClient = $null
        userRightsCreatePermanentSharedObjects = $null
        localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool = $false
        defenderScriptObfuscatedMacroCodeType = "userDefined"
        userRightsRemoteShutdown = $null
        defenderAttackSurfaceReductionExcludedPaths = @()
        applicationGuardBlockFileTransfer = "notConfigured"
        localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange = $false
        localSecurityOptionsAllowUIAccessApplicationsForSecureLocations = $false
        defenderFileExtensionsToExclude = @()
        userRightsIncreaseSchedulingPriority = $null
        defenderCloudBlockLevel = $null
        defenderScanType = $null
        userRightsRestoreData = $null
        defenderSecurityCenterHelpPhone = $null
        localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares = $false
        localSecurityOptionsLogOnMessageTitle = $null
        defenderProcessesToExclude = @()
        deviceGuardEnableSecureBootWithDMA = $false
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Users"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }
    @{
        description = $null
        printerDefaultName = $null
        privacyDisableLaunchExperience = $false
        passwordRequired = $true
        settingsBlockUpdateSecurityPage = $false
        defenderScheduledQuickScanTime = $null
        startMenuPinnedFolderFileExplorer = "notConfigured"
        displayAppListWithGdiDPIScalingTurnedOff = @()
        wiFiBlockAutomaticConnectHotspots = $false
        startMenuPinnedFolderNetwork = "notConfigured"
        inkWorkspaceBlockSuggestedApps = $false
        appManagementPackageFamilyNamesToLaunchAfterLogOn = @()
        deviceManagementApplicabilityRuleDeviceMode = $null
        messagingBlockSync = $false
        appManagementMSIAlwaysInstallWithElevatedPrivileges = $false
        searchEnableRemoteQueries = $false
        appManagementMSIAllowUserControlOverInstall = $false
        smartScreenBlockPromptOverride = $false
        startMenuPinnedFolderPictures = "notConfigured"
        defenderSystemScanSchedule = "userDefined"
        defenderScanRemovableDrivesDuringFullScan = $false
        searchDisableIndexingRemovableDrive = $false
        securityBlockAzureADJoinedDevicesAutoEncryption = $false
        wiFiScanInterval = $null
        windowsSpotlightBlockThirdPartyNotifications = $false
        defenderRequireBehaviorMonitoring = $false
        powerButtonActionOnBattery = "notConfigured"
        enterpriseCloudPrintResourceIdentifier = $null
        passwordBlockSimple = $true
        defenderSubmitSamplesConsentType = $null
        privacyBlockInputPersonalization = $false
        cellularData = "allowed"
        messagingBlockMMS = $false
        passwordRequiredType = "alphanumeric"
        wiFiBlocked = $false
        searchDisableIndexingEncryptedItems = $false
        edgeBlockAutofill = $false
        enableAutomaticRedeployment = $false
        edgeBlockFullScreenMode = $false
        edgeBlockPasswordManager = $false
        gameDvrBlocked = $false
        experienceBlockTaskSwitcher = $false
        edgeHomeButtonConfigurationEnabled = $false
        defenderPotentiallyUnwantedAppAction = $null
        startMenuPinnedFolderPersonalFolder = "notConfigured"
        diagnosticsDataSubmissionMode = "userDefined"
        edgeBlockPrinting = $false
        systemTelemetryProxyServer = $null
        defenderDaysBeforeDeletingQuarantinedMalware = $null
        lockScreenAllowTimeoutConfiguration = $false
        defenderDisableCatchupFullScan = $false
        "@odata.type" = "#microsoft.graph.windows10GeneralConfiguration"
        edgeBlockSearchEngineCustomization = $false
        defenderRequireRealTimeMonitoring = $false
        microsoftAccountSignInAssistantSettings = "notConfigured"
        logonBlockFastUserSwitching = $false
        edgeBlockJavaScript = $false
        startMenuHideRestartOptions = $false
        settingsBlockSystemPage = $false
        enterpriseCloudPrintOAuthClientIdentifier = $null
        startMenuHideSignOut = $false
        configureTimeZone = $null
        defenderFileExtensionsToExclude = @()
        lockScreenBlockCortana = $false
        edgeBlockSendingIntranetTrafficToInternetExplorer = $false
        edgeHomepageUrls = @()
        defenderBlockOnAccessProtection = $false
        lockScreenTimeoutInSeconds = $null
        settingsBlockChangeLanguage = $false
        edgeBlockAddressBarDropdown = $false
        edgeEnterpriseModeSiteListLocation = $null
        networkProxyServer = $null
        cellularBlockDataWhenRoaming = $false
        edgeBlockSideloadingExtensions = $false
        powerSleepButtonActionPluggedIn = "notConfigured"
        usbBlocked = $false
        edgeBlockEditFavorites = $false
        searchDisableLocation = $false
        antiTheftModeBlocked = $false
        startMenuPinnedFolderSettings = "notConfigured"
        startMenuLayoutEdgeAssetsXml = $null
        bluetoothAllowedServices = @()
        safeSearchFilter = "userDefined"
        bluetoothBlockAdvertising = $false
        defenderSignatureUpdateIntervalInHours = $null
        enterpriseCloudPrintMopriaDiscoveryResourceIdentifier = $null
        roleScopeTagIds = @(
            "0"
        )
        searchDisableIndexerBackoff = $false
        sharedUserAppDataAllowed = $false
        searchBlockWebResults = $false
        edgeBlockSavingHistory = $false
        findMyFiles = "notConfigured"
        inkWorkspaceAccessState = "notConfigured"
        cameraBlocked = $false
        startMenuHidePowerButton = $false
        powerHybridSleepPluggedIn = "notConfigured"
        settingsBlockSettingsApp = $false
        edgeFavoritesBarVisibility = "notConfigured"
        edgeCookiePolicy = "userDefined"
        edgeOpensWith = "notConfigured"
        bluetoothBlockPrePairing = $false
        enterpriseCloudPrintDiscoveryEndPoint = $null
        cryptographyAllowFipsAlgorithmPolicy = $false
        personalizationLockScreenImageUrl = $null
        appsBlockWindowsStoreOriginatedApps = $false
        powerLidCloseActionOnBattery = "notConfigured"
        developerUnlockSetting = "notConfigured"
        energySaverPluggedInThresholdPercentage = $null
        microsoftAccountBlockSettingsSync = $false
        defenderScanType = "userDefined"
        edgeShowMessageWhenOpeningInternetExplorerSites = "notConfigured"
        edgeBlockInPrivateBrowsing = $false
        taskManagerBlockEndTask = $false
        passwordSignInFailureCountBeforeFactoryReset = 10
        edgeBlockDeveloperTools = $false
        cortanaBlocked = $false
        settingsBlockEditDeviceName = $false
        edgeBlockSendingDoNotTrackHeader = $false
        displayAppListWithGdiDPIScalingTurnedOn = @()
        defenderScanNetworkFiles = $false
        startMenuHideRecentlyAddedApps = $false
        uninstallBuiltInApps = $false
        storageRestrictAppInstallToSystemVolume = $false
        edgeAllowStartPagesModification = $false
        windowsSpotlightBlockWindowsTips = $false
        settingsBlockNetworkInternetPage = $false
        nfcBlocked = $false
        enterpriseCloudPrintDiscoveryMaxLimit = $null
        edgeSearchEngine = $null
        edgeBlockPopups = $false
        edgeBlockExtensions = $false
        defenderScanDownloads = $false
        settingsBlockPrivacyPage = $false
        powerHybridSleepOnBattery = "notConfigured"
        settingsBlockChangePowerSleep = $false
        powerLidCloseActionPluggedIn = "notConfigured"
        windowsSpotlightBlockOnActionCenter = $false
        edgeTelemetryForMicrosoft365Analytics = "notConfigured"
        edgeKioskModeRestriction = "notConfigured"
        powerButtonActionPluggedIn = "notConfigured"
        edgeBlockCompatibilityList = $false
        windowsSpotlightBlocked = $false
        bluetoothBlockPromptedProximalConnections = $false
        windowsSpotlightBlockWelcomeExperience = $false
        defenderPromptForSampleSubmission = "userDefined"
        startBlockUnpinningAppsFromTaskbar = $false
        startMenuLayoutXml = $null
        passwordMinimumLength = 10
        edgeBlockSearchSuggestions = $false
        edgeRequiredExtensionPackageFamilyNames = @()
        inkWorkspaceAccess = "notConfigured"
        startMenuHideHibernate = $false
        defenderScanMaxCpu = $null
        settingsBlockTimeLanguagePage = $false
        defenderScanMappedNetworkDrivesDuringFullScan = $false
        edgeFavoritesListLocation = $null
        edgeDisableFirstRunPage = $false
        printerNames = @()
        startMenuMode = "userDefined"
        enterpriseCloudPrintOAuthAuthority = $null
        locationServicesBlocked = $false
        windowsStoreBlockAutoUpdate = $false
        supportsScopeTags = $true
        experienceDoNotSyncBrowserSettings = "notConfigured"
        edgeBlockWebContentOnNewTabPage = $false
        passwordRequireWhenResumeFromIdleState = $true
        smartScreenBlockPromptOverrideForFiles = $false
        lockScreenBlockToastNotifications = $false
        experienceBlockDeviceDiscovery = $false
        settingsBlockAddProvisioningPackage = $false
        startMenuPinnedFolderDownloads = "notConfigured"
        edgeNewTabPageURL = $null
        storageRestrictAppDataToSystemVolume = $false
        passwordExpirationDays = 90
        edgeRequireSmartScreen = $false
        webRtcBlockLocalhostIpAddress = $false
        defenderFilesAndFoldersToExclude = @()
        windowsSpotlightConfigureOnLockScreen = "notConfigured"
        startMenuHideUserTile = $false
        windowsStoreBlocked = $false
        cellularBlockVpnWhenRoaming = $false
        startMenuHideRecentJumpLists = $false
        windowsSpotlightBlockTailoredExperiences = $false
        certificatesBlockManualRootCertificateInstallation = $false
        edgeHomeButtonConfiguration = $null
        startMenuHideSwitchAccount = $false
        lockScreenActivateAppsWithVoice = "notConfigured"
        defenderRequireCloudProtection = $false
        deviceManagementBlockManualUnenroll = $false
        wirelessDisplayBlockUserInputFromReceiver = $false
        deviceManagementBlockFactoryResetOnMobile = $false
        defenderBlockEndUserAccess = $false
        settingsBlockGamingPage = $false
        settingsBlockDevicesPage = $false
        personalizationDesktopImageUrl = $null
        authenticationWebSignIn = "notConfigured"
        edgeBlockPrelaunch = $false
        authenticationAllowSecondaryDevice = $false
        defenderDetectedMalwareActions = $null
        defenderMonitorFileActivity = "userDefined"
        smartScreenEnableAppInstallControl = $false
        displayName = "Set password policy"
        defenderCloudExtendedTimeout = $null
        printerBlockAddition = $false
        resetProtectionModeBlocked = $false
        tenantLockdownRequireNetworkDuringOutOfBoxExperience = $false
        authenticationPreferredAzureADTenantDomainName = $null
        wirelessDisplayRequirePinForPairing = $false
        smartScreenAppInstallControl = "notConfigured"
        privacyAutoAcceptPairingAndConsentPrompts = $false
        settingsBlockAccountsPage = $false
        windows10AppsForceUpdateSchedule = $null
        startMenuAppListVisibility = "userDefined"
        oneDriveDisableFileSync = $false
        storageBlockRemovableStorage = $false
        edgeKioskResetAfterIdleTimeInMinutes = $null
        energySaverOnBatteryThresholdPercentage = $null
        bluetoothBlocked = $false
        startMenuPinnedFolderHomeGroup = "notConfigured"
        voiceRecordingBlocked = $false
        edgePreventCertificateErrorOverride = $false
        searchBlockDiacritics = $false
        wirelessDisplayBlockProjectionToThisDevice = $false
        networkProxyDisableAutoDetect = $false
        settingsBlockAppsPage = $false
        passwordMinimumCharacterSetCount = 4
        accountsBlockAddingNonMicrosoftAccountEmail = $false
        passwordMinimumAgeInDays = $null
        settingsBlockChangeSystemTime = $false
        screenCaptureBlocked = $false
        internetSharingBlocked = $false
        privacyAdvertisingId = "notConfigured"
        windowsSpotlightBlockConsumerSpecificFeatures = $false
        deviceManagementApplicabilityRuleOsEdition = $null
        startMenuHideSleep = $false
        experienceBlockErrorDialogWhenNoSIM = $false
        startMenuHideLock = $false
        appsAllowTrustedAppsSideloading = "notConfigured"
        edgeSendIntranetTrafficToInternetExplorer = $false
        deviceManagementApplicabilityRuleOsVersion = $null
        edgeSyncFavoritesWithInternetExplorer = $false
        defenderScanArchiveFiles = $false
        startMenuHideChangeAccountSettings = $false
        defenderDisableCatchupQuickScan = $false
        defenderCloudExtendedTimeoutInSeconds = $null
        edgeBlockLiveTileDataCollection = $false
        edgeFirstRunUrl = $null
        settingsBlockRemoveProvisioningPackage = $false
        edgeBlockTabPreloading = $false
        wiFiBlockManualConfiguration = $false
        settingsBlockEaseOfAccessPage = $false
        edgeBlockAccessToAboutFlags = $false
        passwordPreviousPasswordBlockCount = 10
        startMenuHideFrequentlyUsedApps = $false
        bluetoothBlockDiscoverableMode = $false
        storageRequireMobileDeviceEncryption = $false
        powerSleepButtonActionOnBattery = "notConfigured"
        defenderScanScriptsLoadedInInternetExplorer = $false
        privacyBlockPublishUserActivities = $false
        searchEnableAutomaticIndexSizeManangement = $false
        copyPasteBlocked = $false
        searchDisableUseLocation = $false
        startMenuPinnedFolderVideos = "notConfigured"
        connectedDevicesServiceBlocked = $false
        edgeBlocked = $false
        cellularBlockVpn = $false
        activateAppsWithVoice = "notConfigured"
        startMenuPinnedFolderDocuments = "notConfigured"
        windowsStoreEnablePrivateStoreOnly = $false
        defenderScheduleScanEnableLowCpuPriority = $false
        searchDisableAutoLanguageDetection = $false
        defenderProcessesToExclude = @()
        startMenuPinnedFolderMusic = "notConfigured"
        networkProxyAutomaticConfigurationUrl = $null
        privacyBlockActivityFeed = $false
        networkProxyApplySettingsDeviceWide = $false
        defenderPotentiallyUnwantedAppActionSetting = "userDefined"
        settingsBlockChangeRegion = $false
        startMenuHideShutDown = $false
        microsoftAccountBlocked = $false
        messagingBlockRichCommunicationServices = $false
        defenderCloudBlockLevel = "notConfigured"
        edgeClearBrowsingDataOnExit = $false
        defenderRequireNetworkInspectionSystem = $false
        settingsBlockPersonalizationPage = $false
        lockScreenBlockActionCenterNotifications = $false
        passwordMinutesOfInactivityBeforeScreenTimeout = $null
        dataProtectionBlockDirectMemoryAccess = $null
        defenderScheduledScanTime = $null
        defenderScanIncomingMail = $false
        assignments = @(
            @{
                target= @{
                    deviceAndAppManagementAssignmentFilterId = $null
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget" 
                    groupId = "All Windows 10 and later Devices"
                    deviceAndAppManagementAssignmentFilterType = "none"
                }
            }
        )
    }  
)

Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, Group.ReadWrite.All" -Environment USGov

<# Group for the following settings catalog intune device configuration profiles
    - Configure device and resource redirection
    - Configure OneDrive settings
    - Configure Windows NTP client
    - Enable interactive logon banner
    - Enable screen capture 
   Group for Enable Bitlocker endpoint protection intune device configuration profile    
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
<# Group for the following settings catalog intune device configuration profiles
   - Disable password reveal
   - Enable Azure Information Protection add-in for sensitivity labeling
   Group for Set lock screen inactivity timer endpoint protection intune device configuration profile
#>
<#$AllUsersGroup = Get-MgGroup -ConsistencyLevel eventual -Count groupCount -Search '"DisplayName:All Users"'
if ($null -eq $AllUsersGroup) {
    $parameters = @{
        DisplayName = 'All Users'
        MailEnabled = $False 
        MailNickName = (New-Guid).ToString().Substring(0,10)
        SecurityEnabled = $true
        Description = 'This group is for all users'
        MembershipRule = "(user.accountEnabled -eq True)"
        MembershipRuleProcessingState = 'On'
        GroupTypes = 'DynamicMembership'
    }
    $AllUsersGroup = New-MgGroup @parameters
}
#>
$AllUsersGroup = Get-MgGroup -ConsistencyLevel eventual -CountVariable groupCount -Search '"displayName:All Users"' -Property Id,DisplayName

if (-not $AllUsersGroup) {

    $parameters = @{
        DisplayName     = 'All Users'
        Description     = 'This group is for all users'
        SecurityEnabled = $true
        MailEnabled     = $false
        MailNickname    = (New-Guid).ToString().Substring(0,10)
        GroupTypes      = @('DynamicMembership')
        MembershipRule  = '(user.accountEnabled -eq true)'
        MembershipRuleProcessingState = 'On'
    }

    $AllUsersGroup = New-MgGroup @parameters
}


# Group for Set password policy device restriction intune device configuration profile
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

function Get-ExistingDeviceConfiguration {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$DisplayName,

        [Parameter(Mandatory = $false)]
        [System.String]$ODataType
    )

    $LookupKey = Get-NormalizedPolicyName -Name $DisplayName
    if ([string]::IsNullOrWhiteSpace($LookupKey)) {
        return $null
    }

    if (-not $script:DeviceConfigurationByName.ContainsKey($LookupKey)) {
        return $null
    }

    $Candidates = @($script:DeviceConfigurationByName[$LookupKey])
    if (-not [string]::IsNullOrWhiteSpace($ODataType)) {
        $TypedMatch = $Candidates | Where-Object { $_.'@odata.type' -eq $ODataType } | Select-Object -First 1
        if ($null -ne $TypedMatch) {
            return $TypedMatch
        }
    }

    return $Candidates | Select-Object -First 1
}

function Get-ExistingSettingsCatalogPolicy {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Name
    )

    $LookupKey = Get-NormalizedPolicyName -Name $Name
    if ([string]::IsNullOrWhiteSpace($LookupKey)) {
        return $null
    }

    if ($script:SettingsCatalogPolicyByName.ContainsKey($LookupKey)) {
        return $script:SettingsCatalogPolicyByName[$LookupKey]
    }

    return $null
}

function Get-NormalizedPolicyName {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Name
    )

    return $Name.Trim().ToLowerInvariant()
}

function Get-AllGraphItems {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Uri
    )

    $Items = @()
    $NextPage = $Uri

    while (-not [string]::IsNullOrWhiteSpace($NextPage)) {
        $Response = Invoke-MgGraphRequest -Method GET -Uri $NextPage -ErrorAction Stop
        if ($null -ne $Response.value) {
            $Items += @($Response.value)
            $NextPage = $Response.'@odata.nextLink'
        }
        else {
            $Items += @($Response)
            $NextPage = $null
        }
    }

    return $Items
}

function Remove-NullProperties {
    param (
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    # Keep scalar values as-is; do not enumerate string/primitive members like ".Length".
    if (
        ($InputObject -is [string]) -or
        ($InputObject -is [ValueType]) -or
        ($InputObject -is [datetime]) -or
        ($InputObject -is [datetimeoffset]) -or
        ($InputObject -is [guid]) -or
        ($InputObject -is [uri]) -or
        ($InputObject -is [version]) -or
        ($InputObject -is [timespan])
    ) {
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $Result = [ordered]@{}
        foreach ($Key in $InputObject.Keys) {
            $CleanValue = Remove-NullProperties -InputObject $InputObject[$Key]
            if ($null -ne $CleanValue) {
                $Result[$Key] = $CleanValue
            }
        }
        return $Result
    }

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        $Result = @()
        foreach ($Item in $InputObject) {
            $CleanItem = Remove-NullProperties -InputObject $Item
            if ($null -ne $CleanItem) {
                $Result += ,$CleanItem
            }
        }
        return $Result
    }

    $Properties = $InputObject.PSObject.Properties
    if (($null -ne $Properties) -and ($Properties.Count -gt 0)) {
        $Result = [ordered]@{}
        foreach ($Property in $Properties) {
            $CleanValue = Remove-NullProperties -InputObject $Property.Value
            if ($null -ne $CleanValue) {
                $Result[$Property.Name] = $CleanValue
            }
        }
        return $Result
    }

    return $InputObject
}

function Remove-ArrayProperties {
    param (
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $Result = [ordered]@{}
        foreach ($Key in $InputObject.Keys) {
            $Value = $InputObject[$Key]
            if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string]) -and -not ($Value -is [System.Collections.IDictionary])) {
                continue
            }

            $CleanValue = Remove-ArrayProperties -InputObject $Value
            if ($null -ne $CleanValue) {
                $Result[$Key] = $CleanValue
            }
        }
        return $Result
    }

    $Properties = $InputObject.PSObject.Properties
    if (($null -ne $Properties) -and ($Properties.Count -gt 0)) {
        $Result = [ordered]@{}
        foreach ($Property in $Properties) {
            $Value = $Property.Value
            if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string]) -and -not ($Value -is [System.Collections.IDictionary])) {
                continue
            }

            $CleanValue = Remove-ArrayProperties -InputObject $Value
            if ($null -ne $CleanValue) {
                $Result[$Property.Name] = $CleanValue
            }
        }
        return $Result
    }

    return $InputObject
}

function Remove-PropertyRecursive {
    param (
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [System.String]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $Result = [ordered]@{}
        foreach ($Key in $InputObject.Keys) {
            if ($Key -eq $PropertyName) {
                continue
            }

            $CleanValue = Remove-PropertyRecursive -InputObject $InputObject[$Key] -PropertyName $PropertyName
            if ($null -ne $CleanValue) {
                $Result[$Key] = $CleanValue
            }
        }
        return $Result
    }

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        $Result = @()
        foreach ($Item in $InputObject) {
            $CleanItem = Remove-PropertyRecursive -InputObject $Item -PropertyName $PropertyName
            if ($null -ne $CleanItem) {
                $Result += ,$CleanItem
            }
        }
        return $Result
    }

    $Properties = $InputObject.PSObject.Properties
    if (($null -ne $Properties) -and ($Properties.Count -gt 0)) {
        $Result = [ordered]@{}
        foreach ($Property in $Properties) {
            if ($Property.Name -eq $PropertyName) {
                continue
            }

            $CleanValue = Remove-PropertyRecursive -InputObject $Property.Value -PropertyName $PropertyName
            if ($null -ne $CleanValue) {
                $Result[$Property.Name] = $CleanValue
            }
        }
        return $Result
    }

    return $InputObject
}

function Normalize-ODataTypeValues {
    param (
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $Result = [ordered]@{}
        foreach ($Key in $InputObject.Keys) {
            $Value = Normalize-ODataTypeValues -InputObject $InputObject[$Key]
            if ($Key -eq '@odata.type') {
                if ([string]::IsNullOrWhiteSpace([string]$Value)) {
                    continue
                }
                $Result[$Key] = [string]$Value
            }
            else {
                $Result[$Key] = $Value
            }
        }
        return $Result
    }

    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        $Result = @()
        foreach ($Item in $InputObject) {
            $Result += ,(Normalize-ODataTypeValues -InputObject $Item)
        }
        return $Result
    }

    $Properties = $InputObject.PSObject.Properties
    if (($null -ne $Properties) -and ($Properties.Count -gt 0)) {
        $Result = [ordered]@{}
        foreach ($Property in $Properties) {
            $Value = Normalize-ODataTypeValues -InputObject $Property.Value
            if ($Property.Name -eq '@odata.type') {
                if ([string]::IsNullOrWhiteSpace([string]$Value)) {
                    continue
                }
                $Result[$Property.Name] = [string]$Value
            }
            else {
                $Result[$Property.Name] = $Value
            }
        }
        return $Result
    }

    return $InputObject
}

function Initialize-ExistingPolicyCache {
    $script:DeviceConfigurationByName = @{}
    $script:SettingsCatalogPolicyByName = @{}

    $ExistingDeviceConfigurations = Get-AllGraphItems -Uri ("{0}/deviceManagement/deviceConfigurations?`$top=999" -f $ApiVersion)
    foreach ($Policy in $ExistingDeviceConfigurations) {
        if ([string]::IsNullOrWhiteSpace($Policy.displayName)) {
            continue
        }

        $Key = Get-NormalizedPolicyName -Name $Policy.displayName
        if (-not $script:DeviceConfigurationByName.ContainsKey($Key)) {
            $script:DeviceConfigurationByName[$Key] = @($Policy)
        }
        elseif (@($script:DeviceConfigurationByName[$Key]).id -notcontains $Policy.id) {
            $script:DeviceConfigurationByName[$Key] += @($Policy)
            Write-Warning ("Multiple device configuration policies found with the same name '{0}'. Updating the first match." -f $Policy.displayName)
        }
    }

    $ExistingSettingsCatalogPolicies = Get-AllGraphItems -Uri ("{0}/deviceManagement/configurationPolicies?`$select=id,name&`$top=999" -f $ApiVersion)
    foreach ($Policy in $ExistingSettingsCatalogPolicies) {
        if ([string]::IsNullOrWhiteSpace($Policy.name)) {
            continue
        }

        $Key = Get-NormalizedPolicyName -Name $Policy.name
        if (-not $script:SettingsCatalogPolicyByName.ContainsKey($Key)) {
            $script:SettingsCatalogPolicyByName[$Key] = $Policy
        }
        elseif ($script:SettingsCatalogPolicyByName[$Key].id -ne $Policy.id) {
            Write-Warning ("Multiple settings catalog policies found with the same name '{0}'. Updating the first match." -f $Policy.name)
        }
    }
}

function Resolve-GroupId {
    param (
        [AllowNull()]
        $GroupObject,

        [Parameter(Mandatory = $true)]
        [System.String]$GroupName
    )

    $Ids = @(
        $GroupObject |
        ForEach-Object { $_.id } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    )

    if ($Ids.Count -gt 1) {
        Write-Warning ("Multiple Entra groups found for '{0}'. Using the first id: {1}" -f $GroupName, $Ids[0])
    }

    if ($Ids.Count -eq 0) {
        return $null
    }

    return [string]$Ids[0]
}

$GroupIdByName = @{
    "All Azure Virtual Desktop Hosts" = Resolve-GroupId -GroupObject $AvdHostGroup -GroupName "All Azure Virtual Desktop Hosts"
    "All Users" = Resolve-GroupId -GroupObject $AllUsersGroup -GroupName "All Users"
    "All Windows 10 and later Devices" = Resolve-GroupId -GroupObject $AllWindows10Group -GroupName "All Windows 10 and later Devices"
}
if ($GpuVms) {
    $GroupIdByName["GPU-optimized Azure VMs"] = Resolve-GroupId -GroupObject $AvdGpuGroup -GroupName "GPU-optimized Azure VMs"
}

Initialize-ExistingPolicyCache

foreach ($TemplatePolicy in $TemplatePolicies) {
    Write-Host ("Reviewing Device Configuration Policy: {0}" -f $TemplatePolicy.DisplayName) -ForegroundColor Green

    $SkipPolicy = $false
    foreach ($Assignment in $TemplatePolicy.assignments) {
        if (($Assignment.target.groupId -eq "GPU-optimized Azure VMs") -and (-not $GpuVms)) {
            Write-Warning ("Skipping policy '{0}' because -GpuVms was not provided." -f $TemplatePolicy.DisplayName)
            $SkipPolicy = $true
            break
        }
    }
    if ($SkipPolicy) {
        continue
    }

    $DeviceConfigurationRequestBodyObject = $TemplatePolicy | Select-Object -Property * -ExcludeProperty assignments
    if ($DeviceConfigurationRequestBodyObject.supportsScopeTags) {
        $DeviceConfigurationRequestBodyObject.supportsScopeTags = $false
    }
    $DeviceConfigurationRequestBody = $DeviceConfigurationRequestBodyObject | ConvertTo-Json -Depth 100

    $DeviceConfigurationId = $null
    try {
        $ExistingDeviceConfiguration = Get-ExistingDeviceConfiguration -DisplayName $TemplatePolicy.DisplayName -ODataType $TemplatePolicy.'@odata.type'
        if ($null -ne $ExistingDeviceConfiguration) {
            # Some USGov Graph beta deviceConfiguration PATCH payloads fail schema validation.
            # Replace the policy to keep runs idempotent and avoid malformed PATCH errors.
            Write-Host ("Replacing Device Configuration Policy: {0}" -f $TemplatePolicy.DisplayName) -ForegroundColor Yellow
            Invoke-MgGraphRequest -Method DELETE -Uri ("{0}/deviceManagement/deviceConfigurations/{1}" -f $ApiVersion, $ExistingDeviceConfiguration.id) -ErrorAction Stop | Out-Null

            $DeviceConfiguration = Invoke-MgGraphRequest -Method POST -Body $DeviceConfigurationRequestBody.ToString() -Uri ("{0}/deviceManagement/deviceConfigurations" -f $ApiVersion) -ErrorAction Stop
            $DeviceConfigurationId = $DeviceConfiguration.id
            $script:DeviceConfigurationByName[(Get-NormalizedPolicyName -Name $TemplatePolicy.DisplayName)] = @([PSCustomObject]@{
                id = $DeviceConfigurationId
                displayName = $TemplatePolicy.DisplayName
                '@odata.type' = $TemplatePolicy.'@odata.type'
            })
        }
        else {
            Write-Host ("Creating Device Configuration Policy: {0}" -f $TemplatePolicy.DisplayName) -ForegroundColor Green
            $DeviceConfiguration = Invoke-MgGraphRequest -Method POST -Body $DeviceConfigurationRequestBody.ToString() -Uri ("{0}/deviceManagement/deviceConfigurations" -f $ApiVersion) -ErrorAction Stop
            $DeviceConfigurationId = $DeviceConfiguration.id
            $script:DeviceConfigurationByName[(Get-NormalizedPolicyName -Name $TemplatePolicy.DisplayName)] = @([PSCustomObject]@{
                id = $DeviceConfigurationId
                displayName = $TemplatePolicy.DisplayName
                '@odata.type' = $TemplatePolicy.'@odata.type'
            })
        }
    }
    catch {
        Write-Verbose ("{0} - Failed to create/update Device Configuration" -f $TemplatePolicy.DisplayName) -Verbose
        Write-Error $_ -ErrorAction Continue
        continue
    }

    Write-Host ("Creating Device Configuration Policy Assignments: {0}" -f $TemplatePolicy.DisplayName) -ForegroundColor Green
    $DeviceConfigurationAssignments = @()
    foreach ($Assignment in @($TemplatePolicy.assignments)) {
        $GroupName = $Assignment.target.groupId
        if ($GroupIdByName.ContainsKey($GroupName)) {
            $ResolvedGroupId = [string]$GroupIdByName[$GroupName]
            if ([string]::IsNullOrWhiteSpace($ResolvedGroupId)) {
                Write-Warning ("Skipping assignment for unresolved group '{0}' in policy '{1}'." -f $GroupName, $TemplatePolicy.DisplayName)
                $SkipPolicy = $true
                continue
            }

            $DeviceConfigurationAssignments += @(
                @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $ResolvedGroupId
                    }
                }
            )
        }
        else {
            Write-Warning ("Skipping assignment for unresolved group '{0}' in policy '{1}'." -f $GroupName, $TemplatePolicy.DisplayName)
            $SkipPolicy = $true
        }
    }
    if ($SkipPolicy) {
        continue
    }

    $DeviceConfigurationAssignmentsRequestBodyObject = @{
        assignments = @($DeviceConfigurationAssignments)
    }
    $DeviceConfigurationAssignmentsRequestBody = $DeviceConfigurationAssignmentsRequestBodyObject | ConvertTo-Json -Depth 100
    try {
        Invoke-MgGraphRequest -Method POST -Body $DeviceConfigurationAssignmentsRequestBody.ToString() -Uri ("{0}/deviceManagement/deviceConfigurations/{1}/assign" -f $ApiVersion, $DeviceConfigurationId) -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Verbose ("{0} - Failed to create Device Configuration Assignment(s)" -f $TemplatePolicy.DisplayName) -Verbose
        Write-Verbose ("Payload: {0}" -f $DeviceConfigurationAssignmentsRequestBody) -Verbose
        Write-Error $_ -ErrorAction Continue
    }
}

foreach ($SettingsPolicy in $SettingsCatalogPolicies) {
    Write-Host ("Reviewing Settings Catalog Policy: {0}" -f $SettingsPolicy.name) -ForegroundColor Green

    $SkipPolicy = $false
    foreach ($Assignment in $SettingsPolicy.assignments) {
        if (($Assignment.target.groupId -eq "GPU-optimized Azure VMs") -and (-not $GpuVms)) {
            Write-Warning ("Skipping policy '{0}' because -GpuVms was not provided." -f $SettingsPolicy.name)
            $SkipPolicy = $true
            break
        }
    }
    if ($SkipPolicy) {
        continue
    }

    $ConfigurationPolicyRequestBodyObject = $SettingsPolicy | Select-Object -Property * -ExcludeProperty assignments
    $ConfigurationPolicyRequestBody = $ConfigurationPolicyRequestBodyObject | ConvertTo-Json -Depth 100

    $ConfigurationPolicyId = $null
    try {
        $ExistingConfigurationPolicy = Get-ExistingSettingsCatalogPolicy -Name $SettingsPolicy.name
        if ($null -ne $ExistingConfigurationPolicy) {
            # Settings catalog PATCH with nested settings often fails validation in USGov beta.
            # Replace policy for consistent desired-state behavior.
            Write-Host ("Replacing Settings Catalog Policy: {0}" -f $SettingsPolicy.name) -ForegroundColor Yellow
            Invoke-MgGraphRequest -Method DELETE -Uri ("{0}/deviceManagement/configurationPolicies/{1}" -f $ApiVersion, $ExistingConfigurationPolicy.id) -ErrorAction Stop | Out-Null

            $ConfigurationPolicy = Invoke-MgGraphRequest -Method POST -Body $ConfigurationPolicyRequestBody.ToString() -Uri ("{0}/deviceManagement/configurationPolicies" -f $ApiVersion) -ErrorAction Stop
            $ConfigurationPolicyId = $ConfigurationPolicy.id
            $script:SettingsCatalogPolicyByName[(Get-NormalizedPolicyName -Name $SettingsPolicy.name)] = [PSCustomObject]@{
                id = $ConfigurationPolicyId
                name = $SettingsPolicy.name
            }
        }
        else {
            Write-Host ("Creating Settings Catalog Policy: {0}" -f $SettingsPolicy.name) -ForegroundColor Green
            $ConfigurationPolicy = Invoke-MgGraphRequest -Method POST -Body $ConfigurationPolicyRequestBody.ToString() -Uri ("{0}/deviceManagement/configurationPolicies" -f $ApiVersion) -ErrorAction Stop
            $ConfigurationPolicyId = $ConfigurationPolicy.id
            $script:SettingsCatalogPolicyByName[(Get-NormalizedPolicyName -Name $SettingsPolicy.name)] = [PSCustomObject]@{
                id = $ConfigurationPolicyId
                name = $SettingsPolicy.name
            }
        }
    }
    catch {
        Write-Verbose ("{0} - Failed to create/update Settings Catalog Policy" -f $SettingsPolicy.name) -Verbose
        Write-Error $_ -ErrorAction Continue
        continue
    }

    Write-Host ("Creating Settings Catalog Policy Assignments: {0}" -f $SettingsPolicy.name) -ForegroundColor Green
    $ConfigurationPolicyAssignments = @()
    foreach ($Assignment in @($SettingsPolicy.assignments)) {
        $GroupName = $Assignment.target.groupId
        if ($GroupIdByName.ContainsKey($GroupName)) {
            $ResolvedGroupId = [string]$GroupIdByName[$GroupName]
            if ([string]::IsNullOrWhiteSpace($ResolvedGroupId)) {
                Write-Warning ("Skipping assignment for unresolved group '{0}' in policy '{1}'." -f $GroupName, $SettingsPolicy.name)
                $SkipPolicy = $true
                continue
            }

            $ConfigurationPolicyAssignments += @(
                @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $ResolvedGroupId
                        deviceAndAppManagementAssignmentFilterType = [string]$Assignment.target.deviceAndAppManagementAssignmentFilterType
                    }
                }
            )
        }
        else {
            Write-Warning ("Skipping assignment for unresolved group '{0}' in policy '{1}'." -f $GroupName, $SettingsPolicy.name)
            $SkipPolicy = $true
        }
    }
    if ($SkipPolicy) {
        continue
    }

    $ConfigurationPolicyAssignmentsRequestBodyObject = @{
        assignments = @($ConfigurationPolicyAssignments)
    }
    $ConfigurationPolicyAssignmentsRequestBody = $ConfigurationPolicyAssignmentsRequestBodyObject | ConvertTo-Json -Depth 100
    try {
        Invoke-MgGraphRequest -Method POST -Body $ConfigurationPolicyAssignmentsRequestBody.ToString() -Uri ("{0}/deviceManagement/configurationPolicies/{1}/assign" -f $ApiVersion, $ConfigurationPolicyId) -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Verbose ("{0} - Failed to create Settings Catalog Assignment(s)" -f $SettingsPolicy.name) -Verbose
        Write-Verbose ("Payload: {0}" -f $ConfigurationPolicyAssignmentsRequestBody) -Verbose
        Write-Error $_ -ErrorAction Continue
    }
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph -ErrorAction SilentlyContinue
