<#

.SYNOPSIS
Verify a VM is setup correctly and registered to existing/new host pool.

.DESCRIPTION
This script verifies RD agent installed and the VM is registered successfully as session host to existing/new host pool.

#>
param(
    [Parameter(mandatory = $true)]
    [string]$HostPoolName
)

$ScriptPath = [system.io.path]::GetDirectoryName($PSCommandPath)

# Dot sourcing Functions.ps1 file
. (Join-Path $ScriptPath "Functions.ps1")
. (Join-Path $ScriptPath "AvdFunctions.ps1")

Write-Log -Message "Check if RD Infra registry exists"
$RegistryCheckObj = IsRDAgentRegistryValidForRegistration
if (!$RegistryCheckObj.result) {
    Write-Log -Err "RD agent registry check failed ($($RegistryCheckObj.msg))"
    return $false;
}

$SessionHostName = GetAvdSessionHostName
Write-Log -Message "SessionHost '$SessionHostName' is registered. $($SessionHost | Out-String)"
return $true;
# SIG # Begin signature block
# MIIoSwYJKoZIhvcNAQcCoIIoPDCCKDgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAG12jm1kvsQM2t
# 285BuoFPuwNGQjknUCKMGM172L+AvKCCDWowggY1MIIEHaADAgECAhMzAAAACWMn
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
# 8Qud9TGCGjcwghozAgEBMIGcMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1aWxkIFRvb2xz
# IFBDQSAyMDIwAhMzAAAACWMn7YqGMfm5AAAAAAAJMA0GCWCGSAFlAwQCAQUAoIHU
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCOcT0C6EB672QsQjgJzsG9/mMVSnUf
# 16LU4PaLs7jS9TBoBgorBgEEAYI3AgEMMVowWKA6gDgAVwBpAG4AZABvAHcAcwAg
# AEIAdQBpAGwAZAAgAFQAbwBvAGwAcwAgAEkAbgB0AGUAcgBuAGEAbKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAMHZQbwKjTSpq
# d1QBLe32YpJfWvoWfkF/HfEw69/ULndlhdQEJ4rQIBpofy0EnaqgudNHRHJdu6ee
# hJAoZbRR7xrOPtKugRhI1f4FMmkQiHpVVsNoLd+Co9Gjw9CwPcbOe1yRL9+KWLDN
# E/HDtWwMewnMv8QLpAxjBkSozHUGYD5Y6BHcZyVTdAzpVlMTR4dYf0i2uwki/Oni
# bnB5+CLejBja59qf3QoXTYqm9W500owZZ7PQVWd/IraZLcb752xLd2LwXM982Rd8
# 4C2OF6+eJOQxAMpsAmDs9CYcrHWQColKI0rySJklpT20Rr7OkoLqrVCMDpIIF1HK
# gHRNxYvCZ6GCF5QwgheQBgorBgEEAYI3AwMBMYIXgDCCF3wGCSqGSIb3DQEHAqCC
# F20wghdpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEE
# ggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAEzMWLvFxI
# fs5GDZzqwj57mMVEPRZmSysHxEx2pq1ciAIGZ1sNBeIeGBMyMDI1MDEwODA2NTE0
# Ni42NzdaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHqMIIHIDCCBQigAwIB
# AgITMwAAAebZQp7qAPh94QABAAAB5jANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1MTVaFw0yNTAzMDUxODQ1
# MTVaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hp
# ZWxkIFRTUyBFU046MzMwMy0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC9vph84tgluEzm/wpNKlAjcElGzflvKADZ1D+2d/ieYYEtF2HKMrKGFDOLpLWW
# G5DEyiKblYKrE2nt540OGu35Zx0gXJBE0zWanZEAjCjt4eGBi+uakZsk70zHTQHH
# yfP+B3m2BSSNFPhgsVIPp6vo/9t6OeNezIwX5E5+VwEG37nZgEexQF2fQZYbxQ1A
# auqDvRdXsSpK1dh1UBt9EaMszuucaR5nMwQN6sDjG99FzdK9Atzbn4SmlsoLUtRA
# h/768sKd0Y1hMmKVHwIX8/4JuURUBRZ0JWu0NYQBp8khku18Q8CAQ500tFB7VH3p
# D8zoA4lcA7JkxTGoPKrufm+lRZAA4iMgbcLZ2P/xSdnKFxU8vL31RoNlZJiGL5Mq
# TXvvyBLz+MRP4En9Nye1N8x/lJD1stdNo5wJG+mgXsE/zfzg2GaVqQczFHg0Nl8b
# pIqnNFUReQRq3C1jVYMCScegNzHeYtw5OmZ/7eVnRmjXlCsLvdsxOzc1YVn6nZLk
# QD5y31HYrB9iIHuswhaMv2hJNNjVndkpWy934PIZuWTMk360kjXPFwl2Wv1Tzm9t
# OrCq8+l408KIL6J+efoGNkR8YB3M+u1tYeVDO/TcObGHxaGFB6QZxAUpnfB5N/Mm
# BNxMOqzG1N8QiwW8gtjjMJiFBf6iYYrCjtRwF7IPdQLFtQIDAQABo4IBSTCCAUUw
# HQYDVR0OBBYEFOUEMXntN54+11ZM+Qu7Q5rg3Fc9MB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEB
# CwUAA4ICAQBhbuogTapRsuwSkaFMQ6dyu8ZCYUpWQ8iIrbi40tU2hK6pHgu0hj0z
# /9zFRRx5DfhukjvbjA/dS5VYfxz1EIbPlt897MJ2sBGO2YLYwYelfJpDwbB0XS9Z
# krqpzq6X/lmDQDn3G5vcYpYQCJ55LLvyFlJ195AVo4Wy8UX5p7g9W3MgNHQMpM+E
# V64+cszj4Ho5aQmeKGtKy7w72eRY/vWDuptrvzruFNmKCIt12UcA5BOsXp1Ptkjx
# 2yRsCj77DSml0zVYjqW/ISWkrGjyeVJ+khzctxaLkklVwCxigokD6fkWby0hCEKT
# OTPMzhugPIAcxcHsR2sx01YRa9pH2zvddsuBEfSFG6Cj0QSvEZ/M9mJ+h4miaQSR
# 7AEbVGDbyRKkYn80S+3AmRlh3ZOe+BFqJ57OXdeIDSHbvHzJ7oTqG896l3eUhPsZ
# g69fNgxTxlvRNmRE/+61Yj7Z1uB0XYQP60rsMLdTlVYEyZUl5MLTL5LvqFozZlS2
# Xoji4BEP6ddVTzmHJ4odOZMWTTeQ0IwnWG98vWv/roPegCr1G61FVrdXLE3AXIft
# 4ZN4ZkDTnoAhPw7DZNPRlSW4TbVj/Lw0XvnLYNwMUA9ouY/wx9teTaJ8vTkbgYya
# OYKFz6rNRXZ4af6e3IXwMCffCaspKUXC72YMu5W8L/zyTxsNUEgBbTCCB3EwggVZ
# oAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jv
# c29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4
# MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvX
# JHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa
# /rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AK
# OG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rbo
# YiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIck
# w+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbni
# jYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F
# 37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZ
# fD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIz
# GHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR
# /bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1
# Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUC
# AwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0O
# BBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yD
# fQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9
# /Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5
# bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvf
# am++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn
# 0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlS
# dYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0
# j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5
# JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakUR
# R6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4
# O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVn
# K+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoI
# Yn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNNMIICNQIBATCB+aGB0aSB
# zjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UE
# CxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjMzMDMtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDiWNBeFJ9jvaErN64D1G86
# eL0mu6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBCwUAAgUA6yh5yzAiGA8yMDI1MDEwODA0MTI1OVoYDzIwMjUwMTA5MDQx
# MjU5WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDrKHnLAgEAMAcCAQACAhQrMAcC
# AQACAhOmMAoCBQDrKctLAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkK
# AwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAAqw
# oTQ0I58USYgE4f6g2vKZKMlI/4M1b6ohGU23jtsIooozPsNgmbxEdQZWTyUIAgIU
# EbG/sv11HtVMaXaY3TYPqs3yGxMsiaG5SeRlU2fG7BmmdwsIVBFqfGM8REWCGDRt
# k/cYXu28ESan5YKvKeC4UdBmJDtdt8xGuuxR9VSpu4krpL821WI88LAwxLxMf/vT
# PbU06OTSYEKllzFwg9UxKXqUtOEU8eGwJXwJ55+miivKuCBIBbNP8EYL8v42VP8k
# lDMkRgP5Wez+dvhtm1AsBHInBFFNheUxzBPSPyyYYDZL4b45ygDePYQ/SApR+IHj
# K0mS8Cmizf5fdjLYjBYxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAebZQp7qAPh94QABAAAB5jANBglghkgBZQMEAgEFAKCC
# AUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCC/
# mSHZ+eTFPF/zuWs3srLeoGYUVE1aLrnFJAdOJ/TiLzCB+gYLKoZIhvcNAQkQAi8x
# geowgecwgeQwgb0EIM+7o4aoHrMJaG8gnLO1q16hIYcRnoy6FnOCbnSD0sZZMIGY
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHm2UKe6gD4
# feEAAQAAAeYwIgQgbp2v7gE4HXM/B8A1efQ1NxReJrmgmTdyYT7qPr4apj8wDQYJ
# KoZIhvcNAQELBQAEggIAW+kHqnb+2mOUaqEHCr3LGgP3nzf+lNQPlNQSOZbum04H
# GTw/MnsQRmqLrnnfJStHHRy3FjH0/dnqY1neODMjnVdMUdRaaEp9Qo1P26v5+6p1
# T0jMtsgsjI8HwEDf/LgSMZhGRR2440J0cLtIv76Uz8pjt24sWFD8HOUhSU7PL6BP
# sw9BnqFg7QeOL85/ENlvYwrV+fExZs2hQ2zI+XNhXGZSRHe5eSNVlIRoPxtLMvXG
# sLc2jzthz8hypGaFzT+Y3GXExekiV6BUeOQAxNgVciud4MJd4E134ELjK7z75bhQ
# beMh91NeczcVwHYyLu1lbvSA2Gok8Wg50NLdFLOC8jlF+B7ZQ0RnJ1RvZtOda3jC
# 6UKngcL+LtE2NHyqQQDWLkhmycniQkPpvF/kiD6zhsvAK5Ki0qSxou4GbvYk8jJX
# uekPuRO3gTQUSkWruBWRFrZ4BADXXnpBSH7YQ9U8IfaSR01oRs+O80LdAT7dwlTm
# 1uPXwNWniPv3Y4moTL8QmJjiGatssMyvCbCAgoqiX0DzJFoNIUj125dQSoForu9k
# pGTfbzvxSTcTtBEeol0AuyIzD8HSVhSqPatQFr9WV7cnMmENKrAE4sk4S9mD0XMr
# QaeHSyzSiXtQzEV7YQZ5QKFu+KswrSA7RHJh7Gk5m/VJ9NMhcWIqO7pi6cOT8yo=
# SIG # End signature block
