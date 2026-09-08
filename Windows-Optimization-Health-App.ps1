<#
.SYNOPSIS
    Windows Optimization Health App - GUI front end for the same checks used by
    Windows_Optimization_Health_Report.ps1. Shows the user only what is NOT in
    a good state (Fail/Warning), with an option to reveal all checks.

.DESCRIPTION
    Runs the same non-elevated detection logic (services, Defender health &
    policy sabotage, Windows Update policy, Microsoft Store, Edge/WebView2/
    Winget, SmartScreen, Firewall, UAC/VBS/Credential Guard/Memory Integrity/
    LSASS protection, critical scheduled tasks, RDP/NLA hardening) and
    presents the results in a WPF window:
      - Summary tiles (Total / Pass / Warning / Fail / High-severity)
      - A filtered grid showing only issues by default (toggle to show all)
      - Refresh button to re-run the scan
      - Export HTML Report button (reuses the same report format)

.NOTES
    Run as the logged-on user (not elevated) - matches the original script's
    design so results reflect what the signed-in user actually experiences.
    Requires PowerShell with WPF support (Windows PowerShell 5.1 / PowerShell
    7+ with -sta, on Windows Desktop).
#>

[CmdletBinding()]
param()

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# -------------------------------------------------------------------------
# Winget is a per-user app package and is not reliably resolvable when
# running as SYSTEM, so that individual check is skipped in that context.
# -------------------------------------------------------------------------
$IsRunningAsSystem = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM')

$IgnoreDisabledTasks = @(
    "\Microsoft\Windows\Servicing\OOBEFodSetup",
    "\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates",
    "\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates"
)

$ReportFileName = "WindowsOptimizationHealthReport.html"
$PreferredReportFolders = @(
    "$(Join-Path ([Environment]::GetFolderPath('Desktop')) 'WindowsOptimizationHealth')",
    "$env:LOCALAPPDATA\WindowsOptimizationHealth",
    "$env:TEMP\WindowsOptimizationHealth"
)

# -------------------------------------------------------------------------
# Helper functions (ported from Windows_Optimization_Health_Report.ps1)
# -------------------------------------------------------------------------

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $Item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $Item.$Name
    } catch { return $null }
}

function Get-ServiceStartupType {
    param([string]$ServiceName)
    try {
        $ServiceReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction Stop
        switch ($ServiceReg.Start) {
            0 { return "Boot" }; 1 { return "System" }; 2 { return "Automatic" }
            3 { return "Manual" }; 4 { return "Disabled" }; default { return "Unknown" }
        }
    } catch { return "Unknown" }
}

function Test-PathAny {
    param([string[]]$Paths)
    foreach ($Path in $Paths) { if (Test-Path $Path) { return $true } }
    return $false
}

function Test-EdgeUpdateClient {
    param([string]$ProductName)
    $ClientRoots = @(
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients"
    )
    foreach ($Root in $ClientRoots) {
        if (-not (Test-Path $Root)) { continue }
        try {
            foreach ($Client in (Get-ChildItem -Path $Root -ErrorAction Stop)) {
                $Props = Get-ItemProperty -Path $Client.PSPath -ErrorAction SilentlyContinue
                if ($Props.name -and $Props.name -like "*$ProductName*" -and $Props.pv) { return $true }
            }
        } catch { }
    }
    return $false
}

function ConvertTo-HtmlEncoded {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ReportPath {
    foreach ($Folder in $PreferredReportFolders) {
        try {
            if (-not (Test-Path $Folder)) { New-Item -Path $Folder -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            $TestFile = Join-Path $Folder "write-test.tmp"
            "test" | Out-File -FilePath $TestFile -Encoding utf8 -Force -ErrorAction Stop
            Remove-Item -Path $TestFile -Force -ErrorAction SilentlyContinue
            return (Join-Path $Folder $ReportFileName)
        } catch { }
    }
    return (Join-Path $env:TEMP $ReportFileName)
}

# -------------------------------------------------------------------------
# Core scan: returns an array of check result objects
# -------------------------------------------------------------------------

function Invoke-HealthScan {

    $Checks = New-Object System.Collections.Generic.List[psobject]

    function Add-Check {
        param(
            [string]$Category, [string]$Component, [string]$DisplayName,
            [ValidateSet("Pass","Fail","Warning","Info")][string]$State,
            [ValidateSet("High","Medium","Low","Info")][string]$Severity,
            [string]$Expected, [string]$CurrentValue, [string]$Details
        )
        $Checks.Add([pscustomobject]@{
            Category = $Category; Component = $Component; DisplayName = $DisplayName
            State = $State; Severity = $Severity; Expected = $Expected
            CurrentValue = $CurrentValue; Details = $Details
        })
    }

    # 1. Critical service startup checks
    $ExpectedServices = @(
        @{ Name = "wuauserv";              DisplayName = "Windows Update";                          Expected = @("Manual","Automatic"); Required = $true;  Severity = "High" }
        @{ Name = "BITS";                  DisplayName = "Background Intelligent Transfer Service";  Expected = @("Manual","Automatic"); Required = $true;  Severity = "High" }
        @{ Name = "UsoSvc";                DisplayName = "Update Orchestrator Service";              Expected = @("Manual","Automatic"); Required = $true;  Severity = "High" }
        @{ Name = "DoSvc";                 DisplayName = "Delivery Optimization";                    Expected = @("Manual","Automatic"); Required = $true;  Severity = "High" }
        @{ Name = "CryptSvc";              DisplayName = "Cryptographic Services";                   Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "TrustedInstaller";      DisplayName = "Windows Modules Installer";                Expected = @("Manual");              Required = $true;  Severity = "High" }
        @{ Name = "WinDefend";             DisplayName = "Microsoft Defender Antivirus";             Expected = @("Manual","Automatic"); Required = $true;  Severity = "High" }
        @{ Name = "SecurityHealthService"; DisplayName = "Windows Security Service";                 Expected = @("Manual","Automatic"); Required = $true;  Severity = "High" }
        @{ Name = "MpsSvc";                DisplayName = "Windows Defender Firewall";                Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "Sense";                 DisplayName = "Microsoft Defender for Endpoint";          Expected = @("Manual","Automatic"); Required = $false; Severity = "High" }
        @{ Name = "EventLog";              DisplayName = "Windows Event Log";                        Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "RpcSs";                 DisplayName = "Remote Procedure Call";                    Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "DcomLaunch";            DisplayName = "DCOM Server Process Launcher";             Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "RpcEptMapper";          DisplayName = "RPC Endpoint Mapper";                      Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "Schedule";              DisplayName = "Task Scheduler";                           Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "ProfSvc";               DisplayName = "User Profile Service";                     Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "Dhcp";                  DisplayName = "DHCP Client";                              Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "Dnscache";              DisplayName = "DNS Client";                               Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "LanmanWorkstation";     DisplayName = "Workstation";                              Expected = @("Automatic");           Required = $true;  Severity = "High" }
        @{ Name = "LanmanServer";          DisplayName = "Server";                                   Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
        @{ Name = "InstallService";        DisplayName = "Microsoft Store Install Service";          Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
        @{ Name = "AppXSvc";               DisplayName = "AppX Deployment Service";                  Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
        @{ Name = "ClipSVC";               DisplayName = "Client License Service";                   Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
        @{ Name = "dmwappushservice";      DisplayName = "Device Management WAP Push Routing";       Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
        @{ Name = "Appinfo";               DisplayName = "Application Information";                  Expected = @("Manual");              Required = $true;  Severity = "Medium" }
        @{ Name = "Themes";                DisplayName = "Themes";                                   Expected = @("Automatic");           Required = $true;  Severity = "Low" }
        @{ Name = "WpnService";            DisplayName = "Windows Push Notifications";               Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
        @{ Name = "WSearch";               DisplayName = "Windows Search";                           Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
        @{ Name = "edgeupdate";            DisplayName = "Microsoft Edge Update Service";            Expected = @("Manual","Automatic"); Required = $false; Severity = "Medium" }
        @{ Name = "edgeupdatem";           DisplayName = "Microsoft Edge Update Service Machine";    Expected = @("Manual","Automatic"); Required = $false; Severity = "Medium" }
        @{ Name = "TermService";           DisplayName = "Remote Desktop Services";                  Expected = @("Manual","Automatic"); Required = $true;  Severity = "Medium" }
    )

    foreach ($Svc in $ExpectedServices) {
        $Service = Get-Service -Name $Svc.Name -ErrorAction SilentlyContinue
        $ExpectedText = $Svc.Expected -join ", "

        if (-not $Service) {
            if ($Svc.Required) {
                Add-Check "Services" $Svc.Name $Svc.DisplayName "Fail" $Svc.Severity $ExpectedText "Missing" "Required service was not found."
            } else {
                Add-Check "Services" $Svc.Name $Svc.DisplayName "Warning" $Svc.Severity $ExpectedText "Missing" "Optional service was not found. Verify this is expected for this device."
            }
            continue
        }

        $StartupType = Get-ServiceStartupType -ServiceName $Svc.Name
        $CurrentValue = "$StartupType / $($Service.Status)"

        if ($StartupType -in $Svc.Expected) {
            Add-Check "Services" $Svc.Name $Svc.DisplayName "Pass" "Info" $ExpectedText $CurrentValue "Service startup type matches the expected baseline."
        } else {
            Add-Check "Services" $Svc.Name $Svc.DisplayName "Fail" $Svc.Severity $ExpectedText $CurrentValue "Unexpected service startup type. This is commonly caused by optimizer, debloater, privacy, or gaming tweak tools."
        }
    }

    # 2. Defender health checks
    try {
        $MpStatus = Get-MpComputerStatus -ErrorAction Stop

        if ($MpStatus.PSObject.Properties.Name -contains "AMRunningMode") {
            if ($MpStatus.AMRunningMode -match "Disabled") {
                Add-Check "Defender" "AMRunningMode" "Defender Running Mode" "Fail" "High" "Normal / Active" $MpStatus.AMRunningMode "Defender is disabled."
            } elseif ($MpStatus.AMRunningMode -match "Passive") {
                Add-Check "Defender" "AMRunningMode" "Defender Running Mode" "Warning" "Medium" "Normal / Active" $MpStatus.AMRunningMode "Defender is in passive mode. This may be expected with another antivirus, but should be verified."
            } else {
                Add-Check "Defender" "AMRunningMode" "Defender Running Mode" "Pass" "Info" "Normal / Active" $MpStatus.AMRunningMode "Defender running mode looks healthy."
            }
        }

        $DefenderBooleanChecks = @(
            @{ Name = "AntivirusEnabled";          DisplayName = "Defender Antivirus";           Severity = "High" }
            @{ Name = "RealTimeProtectionEnabled"; DisplayName = "Real-time Protection";          Severity = "High" }
            @{ Name = "AMServiceEnabled";          DisplayName = "Defender Antimalware Service";  Severity = "High" }
            @{ Name = "AntispywareEnabled";        DisplayName = "Defender Antispyware";          Severity = "High" }
            @{ Name = "BehaviorMonitorEnabled";    DisplayName = "Behavior Monitoring";           Severity = "High" }
            @{ Name = "IoavProtectionEnabled";     DisplayName = "Downloaded File Scanning";      Severity = "High" }
            @{ Name = "OnAccessProtectionEnabled"; DisplayName = "On-access Protection";          Severity = "High" }
            @{ Name = "NISEnabled";                DisplayName = "Network Inspection System";     Severity = "Medium" }
            @{ Name = "IsTamperProtected";         DisplayName = "Tamper Protection";             Severity = "High" }
        )

        foreach ($Check in $DefenderBooleanChecks) {
            if ($MpStatus.PSObject.Properties.Name -contains $Check.Name) {
                $Value = $MpStatus.($Check.Name)
                if ($Value -eq $true) {
                    Add-Check "Defender" $Check.Name $Check.DisplayName "Pass" "Info" "Enabled" "Enabled" "Defender setting is enabled."
                } elseif ($Value -eq $false) {
                    Add-Check "Defender" $Check.Name $Check.DisplayName "Fail" $Check.Severity "Enabled" "Disabled" "Defender setting is disabled."
                } else {
                    Add-Check "Defender" $Check.Name $Check.DisplayName "Info" "Info" "Enabled" $Value "Defender setting returned an unexpected value."
                }
            }
        }
    } catch {
        Add-Check "Defender" "Get-MpComputerStatus" "Defender Health" "Warning" "Medium" "Readable Defender status" "Unable to query" "Could not query Defender health. Defender may be removed, broken, disabled, or managed by another antivirus."
    }

    # 3. Defender policy sabotage checks
    $DefenderPolicyChecks = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; DisplayName = "Disable Defender Antispyware Policy"; Severity = "High" }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "DisableAntiVirus"; DisplayName = "Disable Defender Antivirus Policy"; Severity = "High" }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; DisplayName = "Disable Real-time Monitoring Policy"; Severity = "High" }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; DisplayName = "Disable Behavior Monitoring Policy"; Severity = "High" }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIOAVProtection"; DisplayName = "Disable Downloaded File Scanning Policy"; Severity = "High" }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScriptScanning"; DisplayName = "Disable Script Scanning Policy"; Severity = "High" }
    )
    foreach ($PolicyCheck in $DefenderPolicyChecks) {
        $Value = Get-RegValue -Path $PolicyCheck.Path -Name $PolicyCheck.Name
        if ($Value -eq 1) {
            Add-Check "Defender Policy" $PolicyCheck.Name $PolicyCheck.DisplayName "Fail" $PolicyCheck.Severity "Not configured or 0" $Value "Policy disables or weakens Defender protection."
        } elseif ($null -eq $Value) {
            Add-Check "Defender Policy" $PolicyCheck.Name $PolicyCheck.DisplayName "Pass" "Info" "Not configured or 0" "Not configured" "Policy is not configured."
        } else {
            Add-Check "Defender Policy" $PolicyCheck.Name $PolicyCheck.DisplayName "Pass" "Info" "Not configured or 0" $Value "Policy is not configured to disable protection."
        }
    }

    # 4. Windows Update policy checks
    $WindowsUpdatePolicyChecks = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; DisplayName = "Disable Windows Update Access"; Severity = "High" }
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"; DisplayName = "Disable Automatic Updates"; Severity = "High" }
    )
    foreach ($WUCheck in $WindowsUpdatePolicyChecks) {
        $Value = Get-RegValue -Path $WUCheck.Path -Name $WUCheck.Name
        if ($Value -eq 1) {
            Add-Check "Windows Update Policy" $WUCheck.Name $WUCheck.DisplayName "Fail" $WUCheck.Severity "Not configured or 0" $Value "Windows Update is disabled or restricted by policy."
        } elseif ($null -eq $Value) {
            Add-Check "Windows Update Policy" $WUCheck.Name $WUCheck.DisplayName "Pass" "Info" "Not configured or 0" "Not configured" "Policy is not configured."
        } else {
            Add-Check "Windows Update Policy" $WUCheck.Name $WUCheck.DisplayName "Pass" "Info" "Not configured or 0" $Value "Policy is not configured to block Windows Update."
        }
    }

    # 5. Microsoft Store checks
    $StorePolicyDisabled = $false
    foreach ($Path in @("HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore", "HKCU:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
        if ((Get-RegValue -Path $Path -Name "RemoveWindowsStore") -eq 1) { $StorePolicyDisabled = $true; break }
    }
    if ($StorePolicyDisabled) {
        Add-Check "Microsoft Store" "RemoveWindowsStore" "Microsoft Store Policy" "Warning" "Medium" "Not configured or 0" "Disabled by policy" "Microsoft Store is disabled by policy. Verify this matches the customer baseline."
    } else {
        Add-Check "Microsoft Store" "RemoveWindowsStore" "Microsoft Store Policy" "Pass" "Info" "Not configured or 0" "Not disabled by policy" "Microsoft Store is not blocked by policy."
    }
    try {
        Get-AppxPackage -Name "Microsoft.WindowsStore" -ErrorAction Stop | Out-Null
        Add-Check "Microsoft Store" "Microsoft.WindowsStore" "Microsoft Store Package" "Pass" "Info" "Present for current user" "Present" "Microsoft Store package is present for the current user."
    } catch {
        Add-Check "Microsoft Store" "Microsoft.WindowsStore" "Microsoft Store Package" "Fail" "High" "Present for current user" "Missing" "Microsoft Store package is missing for the current user."
    }

    # 6. Edge, WebView2, and Winget checks
    $EdgePaths = @("C:\Program Files (x86)\Microsoft\Edge\Application", "C:\Program Files\Microsoft\Edge\Application")
    $WebViewPaths = @("C:\Program Files (x86)\Microsoft\EdgeWebView\Application", "C:\Program Files\Microsoft\EdgeWebView\Application")

    if (Test-PathAny -Paths $EdgePaths) {
        Add-Check "Application Integrity" "MicrosoftEdgeFolder" "Microsoft Edge Application Folder" "Pass" "Info" "Present" "Present" "Microsoft Edge application folder was found."
    } else {
        Add-Check "Application Integrity" "MicrosoftEdgeFolder" "Microsoft Edge Application Folder" "Fail" "High" "Present" "Missing" "Microsoft Edge application folder was not found."
    }
    if (Test-PathAny -Paths $WebViewPaths) {
        Add-Check "Application Integrity" "WebView2Folder" "Microsoft Edge WebView2 Runtime Folder" "Pass" "Info" "Present" "Present" "WebView2 Runtime folder was found."
    } else {
        Add-Check "Application Integrity" "WebView2Folder" "Microsoft Edge WebView2 Runtime Folder" "Fail" "High" "Present" "Missing" "WebView2 Runtime folder was not found."
    }
    if (Test-EdgeUpdateClient -ProductName "Edge") {
        Add-Check "Application Integrity" "EdgeUpdateClient" "Edge Update Registry Client" "Pass" "Info" "Present" "Present" "Edge Update registry client was found."
    } else {
        Add-Check "Application Integrity" "EdgeUpdateClient" "Edge Update Registry Client" "Warning" "Medium" "Present" "Missing" "Edge Update registry client was not found. This may indicate a broken or partially removed Edge installation."
    }
    if (Test-EdgeUpdateClient -ProductName "WebView") {
        Add-Check "Application Integrity" "WebView2UpdateClient" "WebView2 Update Registry Client" "Pass" "Info" "Present" "Present" "WebView2 Update registry client was found."
    } else {
        Add-Check "Application Integrity" "WebView2UpdateClient" "WebView2 Update Registry Client" "Warning" "Medium" "Present" "Missing" "WebView2 Update registry client was not found. This may indicate a broken or partially removed WebView2 installation."
    }

    if ($IsRunningAsSystem) {
        Add-Check "Application Integrity" "Winget" "Windows Package Manager" "Info" "Info" "Present" "Skipped (SYSTEM context)" "Winget check skipped because the app is running as SYSTEM. Winget is a per-user app and its presence cannot be reliably determined in the SYSTEM context."
    } else {
        try {
            $WingetCommand = Get-Command winget.exe -ErrorAction Stop
            Add-Check "Application Integrity" "Winget" "Windows Package Manager" "Pass" "Info" "Present" $WingetCommand.Source "Winget executable was found."
        } catch {
            Add-Check "Application Integrity" "Winget" "Windows Package Manager" "Warning" "Medium" "Present" "Missing" "Winget was not found for the current user context."
        }
    }

    # 7. SmartScreen checks
    $ExplorerSmartScreen = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled"
    $PolicySmartScreen = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen"
    $EdgeSmartScreen = Get-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled"

    if ($ExplorerSmartScreen -eq "Off") {
        Add-Check "SmartScreen" "ExplorerSmartScreenEnabled" "Windows SmartScreen" "Fail" "High" "Warn or RequireAdmin" $ExplorerSmartScreen "Windows SmartScreen is disabled."
    } elseif ($null -eq $ExplorerSmartScreen) {
        Add-Check "SmartScreen" "ExplorerSmartScreenEnabled" "Windows SmartScreen" "Info" "Info" "Warn or RequireAdmin" "Not configured" "SmartScreen registry value was not found."
    } else {
        Add-Check "SmartScreen" "ExplorerSmartScreenEnabled" "Windows SmartScreen" "Pass" "Info" "Warn or RequireAdmin" $ExplorerSmartScreen "Windows SmartScreen is not disabled."
    }
    if ($PolicySmartScreen -eq 0) {
        Add-Check "SmartScreen" "EnableSmartScreen" "SmartScreen Policy" "Fail" "High" "Not configured or 1" $PolicySmartScreen "SmartScreen is disabled by policy."
    } elseif ($null -eq $PolicySmartScreen) {
        Add-Check "SmartScreen" "EnableSmartScreen" "SmartScreen Policy" "Pass" "Info" "Not configured or 1" "Not configured" "SmartScreen policy is not configured."
    } else {
        Add-Check "SmartScreen" "EnableSmartScreen" "SmartScreen Policy" "Pass" "Info" "Not configured or 1" $PolicySmartScreen "SmartScreen policy is not configured to disable protection."
    }
    if ($EdgeSmartScreen -eq 0) {
        Add-Check "SmartScreen" "EdgeSmartScreenEnabled" "Microsoft Edge SmartScreen" "Fail" "High" "Not configured or 1" $EdgeSmartScreen "Microsoft Edge SmartScreen is disabled by policy."
    } elseif ($null -eq $EdgeSmartScreen) {
        Add-Check "SmartScreen" "EdgeSmartScreenEnabled" "Microsoft Edge SmartScreen" "Pass" "Info" "Not configured or 1" "Not configured" "Microsoft Edge SmartScreen policy is not configured."
    } else {
        Add-Check "SmartScreen" "EdgeSmartScreenEnabled" "Microsoft Edge SmartScreen" "Pass" "Info" "Not configured or 1" $EdgeSmartScreen "Microsoft Edge SmartScreen policy is not configured to disable protection."
    }

    # 8. Firewall profile checks
    try {
        foreach ($Profile in (Get-NetFirewallProfile -ErrorAction Stop)) {
            if ($Profile.Enabled -eq $true) {
                Add-Check "Firewall" $Profile.Name "Windows Firewall $($Profile.Name) Profile" "Pass" "Info" "Enabled" "Enabled" "Firewall profile is enabled."
            } else {
                Add-Check "Firewall" $Profile.Name "Windows Firewall $($Profile.Name) Profile" "Fail" "High" "Enabled" "Disabled" "Firewall profile is disabled."
            }
        }
    } catch {
        Add-Check "Firewall" "Get-NetFirewallProfile" "Windows Firewall Profiles" "Warning" "Medium" "Readable firewall profile status" "Unable to query" "Could not query Windows Firewall profile state."
    }

    # 9. UAC, VBS, Credential Guard, Memory Integrity, LSASS protection
    $EnableLUA = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    if ($EnableLUA -eq 0) {
        Add-Check "Security Features" "EnableLUA" "User Account Control" "Fail" "High" "Enabled" "Disabled" "UAC is disabled."
    } elseif ($EnableLUA -eq 1) {
        Add-Check "Security Features" "EnableLUA" "User Account Control" "Pass" "Info" "Enabled" "Enabled" "UAC is enabled."
    } else {
        Add-Check "Security Features" "EnableLUA" "User Account Control" "Info" "Info" "Enabled" "Not configured or unknown" "Could not determine UAC state from registry."
    }

    $EnableVBS = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity"
    $RequirePlatformSecurityFeatures = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures"
    $LsaCfgFlags = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags"
    $HvciEnabled = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled"
    $RunAsPPL = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"

    if ($EnableVBS -eq 0) {
        Add-Check "Security Features" "EnableVirtualizationBasedSecurity" "Virtualization Based Security" "Warning" "Medium" "Enabled where required" "Disabled" "VBS is explicitly disabled."
    } elseif ($EnableVBS -eq 1) {
        Add-Check "Security Features" "EnableVirtualizationBasedSecurity" "Virtualization Based Security" "Pass" "Info" "Enabled where required" "Enabled" "VBS is enabled."
    } else {
        Add-Check "Security Features" "EnableVirtualizationBasedSecurity" "Virtualization Based Security" "Info" "Info" "Enabled where required" "Not configured" "VBS is not explicitly configured."
    }
    if ($LsaCfgFlags -eq 0) {
        Add-Check "Security Features" "LsaCfgFlags" "Credential Guard" "Warning" "Medium" "Enabled where required" "Disabled" "Credential Guard appears to be explicitly disabled."
    } elseif ($LsaCfgFlags -eq 1 -or $LsaCfgFlags -eq 2) {
        Add-Check "Security Features" "LsaCfgFlags" "Credential Guard" "Pass" "Info" "Enabled where required" $LsaCfgFlags "Credential Guard appears to be enabled or configured."
    } else {
        Add-Check "Security Features" "LsaCfgFlags" "Credential Guard" "Info" "Info" "Enabled where required" "Not configured" "Credential Guard is not explicitly configured."
    }
    if ($HvciEnabled -eq 0) {
        Add-Check "Security Features" "HVCI" "Memory Integrity" "Warning" "Medium" "Enabled where required" "Disabled" "Memory Integrity is explicitly disabled."
    } elseif ($HvciEnabled -eq 1) {
        Add-Check "Security Features" "HVCI" "Memory Integrity" "Pass" "Info" "Enabled where required" "Enabled" "Memory Integrity is enabled."
    } else {
        Add-Check "Security Features" "HVCI" "Memory Integrity" "Info" "Info" "Enabled where required" "Not configured" "Memory Integrity is not explicitly configured."
    }
    if ($RunAsPPL -eq 1 -or $RunAsPPL -eq 2) {
        Add-Check "Security Features" "RunAsPPL" "LSASS Protection" "Pass" "Info" "Enabled where required" $RunAsPPL "LSASS protection appears to be enabled."
    } elseif ($RunAsPPL -eq 0) {
        Add-Check "Security Features" "RunAsPPL" "LSASS Protection" "Warning" "Medium" "Enabled where required" "Disabled" "LSASS protection is explicitly disabled."
    } else {
        Add-Check "Security Features" "RunAsPPL" "LSASS Protection" "Info" "Info" "Enabled where required" "Not configured" "LSASS protection is not explicitly configured."
    }
    if ($RequirePlatformSecurityFeatures -eq 0) {
        Add-Check "Security Features" "RequirePlatformSecurityFeatures" "Platform Security Features" "Warning" "Low" "Configured according to baseline" "Not required" "Platform security requirements are explicitly relaxed."
    } elseif ($null -eq $RequirePlatformSecurityFeatures) {
        Add-Check "Security Features" "RequirePlatformSecurityFeatures" "Platform Security Features" "Info" "Info" "Configured according to baseline" "Not configured" "Platform security requirements are not explicitly configured."
    } else {
        Add-Check "Security Features" "RequirePlatformSecurityFeatures" "Platform Security Features" "Pass" "Info" "Configured according to baseline" $RequirePlatformSecurityFeatures "Platform security feature requirements are configured."
    }

    # 10. Critical scheduled task checks
    $CriticalTaskPaths = @(
        "\Microsoft\Windows\WindowsUpdate\", "\Microsoft\Windows\UpdateOrchestrator\",
        "\Microsoft\Windows\Application Experience\", "\Microsoft\Windows\InstallService\",
        "\Microsoft\Windows\PushToInstall\", "\Microsoft\Windows\Windows Defender\",
        "\Microsoft\Windows\ExploitGuard\", "\Microsoft\Windows\Device Information\",
        "\Microsoft\Windows\Shell\", "\Microsoft\Windows\Servicing\"
    )
    try {
        $ScheduledTasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($CriticalPath in $CriticalTaskPaths) {
            $TasksInPath = $ScheduledTasks | Where-Object { $_.TaskPath.StartsWith($CriticalPath, [System.StringComparison]::OrdinalIgnoreCase) }
            $DisabledTasksInPath = $TasksInPath | Where-Object { $_.State -eq "Disabled" }

            if ($DisabledTasksInPath.Count -eq 0) {
                Add-Check "Scheduled Tasks" $CriticalPath $CriticalPath "Pass" "Info" "No disabled critical tasks" "No disabled tasks found" "No disabled scheduled tasks were found in this critical path."
            } else {
                foreach ($Task in $DisabledTasksInPath) {
                    $TaskFullName = "$($Task.TaskPath)$($Task.TaskName)"
                    if ($TaskFullName -in $IgnoreDisabledTasks) { continue }
                    Add-Check "Scheduled Tasks" $TaskFullName $Task.TaskName "Warning" "Medium" "Enabled unless intentionally disabled" "Disabled" "Critical Microsoft scheduled task is disabled."
                }
            }
        }
    } catch {
        Add-Check "Scheduled Tasks" "Get-ScheduledTask" "Scheduled Task Query" "Warning" "Low" "Readable scheduled tasks" "Unable to query" "Could not query scheduled tasks."
    }

    # 11. RDP and NLA hardening checks
    $UserAuthentication = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
    $fDenyTSConnections = Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"

    if ($UserAuthentication -eq 0) {
        Add-Check "Remote Desktop" "UserAuthentication" "Remote Desktop Network Level Authentication" "Fail" "High" "Enabled" "Disabled" "Network Level Authentication is disabled for RDP."
    } elseif ($UserAuthentication -eq 1) {
        Add-Check "Remote Desktop" "UserAuthentication" "Remote Desktop Network Level Authentication" "Pass" "Info" "Enabled" "Enabled" "Network Level Authentication is enabled for RDP."
    } else {
        Add-Check "Remote Desktop" "UserAuthentication" "Remote Desktop Network Level Authentication" "Info" "Info" "Enabled" "Not configured or unknown" "Could not determine the NLA state."
    }
    if ($fDenyTSConnections -eq 0) {
        Add-Check "Remote Desktop" "fDenyTSConnections" "Remote Desktop Access" "Warning" "Low" "Disabled unless explicitly required" "Enabled" "Remote Desktop is enabled. Verify this is intentional."
    } elseif ($fDenyTSConnections -eq 1) {
        Add-Check "Remote Desktop" "fDenyTSConnections" "Remote Desktop Access" "Pass" "Info" "Disabled unless explicitly required" "Disabled" "Remote Desktop is disabled."
    } else {
        Add-Check "Remote Desktop" "fDenyTSConnections" "Remote Desktop Access" "Info" "Info" "Disabled unless explicitly required" "Not configured or unknown" "Could not determine Remote Desktop access state."
    }

    return $Checks
}

# -------------------------------------------------------------------------
# HTML export (same visual format as the original report)
# -------------------------------------------------------------------------

function Export-HealthHtmlReport {
    param(
        [System.Collections.Generic.List[psobject]]$Checks,
        [string]$ReportPath
    )

    if (-not $ReportPath) { $ReportPath = Get-ReportPath }
    $DeviceName = $env:COMPUTERNAME
    $UserName = "$env:USERDOMAIN\$env:USERNAME"
    $GeneratedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $PassCount = ($Checks | Where-Object { $_.State -eq "Pass" }).Count
    $FailCount = ($Checks | Where-Object { $_.State -eq "Fail" }).Count
    $WarningCount = ($Checks | Where-Object { $_.State -eq "Warning" }).Count
    $TotalCount = $Checks.Count
    $HighCount = ($Checks | Where-Object { $_.Severity -eq "High" -and $_.State -eq "Fail" }).Count

    $Rows = ($Checks | Sort-Object Category, DisplayName | ForEach-Object {
        "<tr><td>$(ConvertTo-HtmlEncoded $_.State)</td><td>$(ConvertTo-HtmlEncoded $_.Severity)</td><td>$(ConvertTo-HtmlEncoded $_.Category)</td><td>$(ConvertTo-HtmlEncoded $_.DisplayName)</td><td>$(ConvertTo-HtmlEncoded $_.Expected)</td><td>$(ConvertTo-HtmlEncoded $_.CurrentValue)</td><td>$(ConvertTo-HtmlEncoded $_.Details)</td></tr>"
    }) -join "`n"

    $Html = @"
<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Windows Optimization Health Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f5f7fb;color:#1f1f1f;margin:0;padding:0}
.header{background:linear-gradient(135deg,#005a9e,#0078d4);color:white;padding:28px 36px}
.container{padding:28px 36px}
table{border-collapse:collapse;width:100%;font-size:13px;background:white}
th{background:#fafafa;text-align:left;padding:10px;border-bottom:1px solid #d7dde5}
td{padding:10px;border-bottom:1px solid #eceff3;vertical-align:top}
</style></head><body>
<div class='header'><h1>Windows Optimization Health Report</h1>
<div>Device: $(ConvertTo-HtmlEncoded $DeviceName) | User: $(ConvertTo-HtmlEncoded $UserName) | Generated: $(ConvertTo-HtmlEncoded $GeneratedAt)</div></div>
<div class='container'>
<p>Total: $TotalCount | Passed: $PassCount | Warnings: $WarningCount | Failed: $FailCount | High severity failures: $HighCount</p>
<table><tr><th>State</th><th>Severity</th><th>Category</th><th>Display name</th><th>Expected</th><th>Current value</th><th>Details</th></tr>
$Rows
</table></div></body></html>
"@

    $Html | Out-File -FilePath $ReportPath -Encoding utf8 -Force
    return $ReportPath
}

# -------------------------------------------------------------------------
# WPF GUI
# -------------------------------------------------------------------------

[xml]$Xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows Optimization Health" Height="720" Width="1180"
        WindowStartupLocation="CenterScreen" Background="#F5F7FB">
    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0" Orientation="Vertical" Margin="0,0,0,12">
            <TextBlock Text="Windows Optimization Health" FontSize="26" FontWeight="Bold" Foreground="#0078D4"/>
            <TextBlock x:Name="SubtitleText" Text="Scanning..." FontSize="12" Foreground="#555" Margin="0,4,0,0"/>
        </StackPanel>

        <UniformGrid Grid.Row="1" Rows="1" Columns="5" Margin="0,0,0,12">
            <Border Background="White" CornerRadius="8" Margin="0,0,8,0" Padding="12" BorderBrush="#0078D4" BorderThickness="0,0,0,4">
                <StackPanel><TextBlock Text="Total Checks" FontSize="12" Foreground="#555"/><TextBlock x:Name="TotalText" Text="0" FontSize="24" FontWeight="Bold"/></StackPanel>
            </Border>
            <Border Background="White" CornerRadius="8" Margin="0,0,8,0" Padding="12" BorderBrush="#107C10" BorderThickness="0,0,0,4">
                <StackPanel><TextBlock Text="Passed" FontSize="12" Foreground="#555"/><TextBlock x:Name="PassText" Text="0" FontSize="24" FontWeight="Bold" Foreground="#107C10"/></StackPanel>
            </Border>
            <Border Background="White" CornerRadius="8" Margin="0,0,8,0" Padding="12" BorderBrush="#FF8C00" BorderThickness="0,0,0,4">
                <StackPanel><TextBlock Text="Warnings" FontSize="12" Foreground="#555"/><TextBlock x:Name="WarnText" Text="0" FontSize="24" FontWeight="Bold" Foreground="#9D5D00"/></StackPanel>
            </Border>
            <Border Background="White" CornerRadius="8" Margin="0,0,8,0" Padding="12" BorderBrush="#D13438" BorderThickness="0,0,0,4">
                <StackPanel><TextBlock Text="Failed" FontSize="12" Foreground="#555"/><TextBlock x:Name="FailText" Text="0" FontSize="24" FontWeight="Bold" Foreground="#D13438"/></StackPanel>
            </Border>
            <Border Background="White" CornerRadius="8" Padding="12" BorderBrush="#D13438" BorderThickness="0,0,0,4">
                <StackPanel><TextBlock Text="High Severity Issues" FontSize="12" Foreground="#555"/><TextBlock x:Name="HighText" Text="0" FontSize="24" FontWeight="Bold" Foreground="#D13438"/></StackPanel>
            </Border>
        </UniformGrid>

        <DockPanel Grid.Row="2" Margin="0,0,0,10">
            <CheckBox x:Name="ShowAllCheckBox" Content="Show all checks (including healthy items)" VerticalAlignment="Center" DockPanel.Dock="Left"/>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                <Button x:Name="RefreshButton" Content="Refresh Scan" Width="120" Margin="0,0,8,0" Padding="6"/>
                <Button x:Name="ExportButton" Content="Export HTML Report" Width="150" Padding="6"/>
            </StackPanel>
        </DockPanel>

        <DataGrid x:Name="ResultsGrid" Grid.Row="3" AutoGenerateColumns="False" IsReadOnly="True"
                  CanUserAddRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal"
                  RowBackground="White" AlternatingRowBackground="#FAFBFD" FontSize="12">
            <DataGrid.Columns>
                <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                <DataGridTextColumn Header="Severity" Binding="{Binding Severity}" Width="80"/>
                <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="150"/>
                <DataGridTextColumn Header="Item" Binding="{Binding DisplayName}" Width="220"/>
                <DataGridTextColumn Header="Expected" Binding="{Binding Expected}" Width="180"/>
                <DataGridTextColumn Header="Current Value" Binding="{Binding CurrentValue}" Width="160"/>
                <DataGridTextColumn Header="Details" Binding="{Binding Details}" Width="*"/>
            </DataGrid.Columns>
            <DataGrid.RowStyle>
                <Style TargetType="DataGridRow">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding State}" Value="Fail">
                            <Setter Property="Background" Value="#FDE7E9"/>
                        </DataTrigger>
                        <DataTrigger Binding="{Binding State}" Value="Warning">
                            <Setter Property="Background" Value="#FFF4CE"/>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </DataGrid.RowStyle>
        </DataGrid>

        <TextBlock x:Name="StatusText" Grid.Row="4" Margin="0,10,0,0" FontSize="11" Foreground="#666"/>
    </Grid>
</Window>
"@

$Reader = New-Object System.Xml.XmlNodeReader $Xaml
$Window = [System.Windows.Markup.XamlReader]::Load($Reader)

$SubtitleText   = $Window.FindName("SubtitleText")
$TotalText      = $Window.FindName("TotalText")
$PassText       = $Window.FindName("PassText")
$WarnText       = $Window.FindName("WarnText")
$FailText       = $Window.FindName("FailText")
$HighText       = $Window.FindName("HighText")
$ShowAllCheckBox = $Window.FindName("ShowAllCheckBox")
$RefreshButton  = $Window.FindName("RefreshButton")
$ExportButton   = $Window.FindName("ExportButton")
$ResultsGrid    = $Window.FindName("ResultsGrid")
$StatusText     = $Window.FindName("StatusText")

$script:AllChecks = $null

function Update-Grid {
    if (-not $script:AllChecks) { return }

    if ($ShowAllCheckBox.IsChecked) {
        $Filtered = $script:AllChecks
    } else {
        $Filtered = $script:AllChecks | Where-Object { $_.State -in @("Fail","Warning") }
    }

    $SeverityOrder = @{ High = 1; Medium = 2; Low = 3; Info = 4 }
    $StateOrder = @{ Fail = 1; Warning = 2; Info = 3; Pass = 4 }

    $Sorted = $Filtered | Sort-Object `
        @{ Expression = { $StateOrder[$_.State] } },
        @{ Expression = { $SeverityOrder[$_.Severity] } },
        Category, DisplayName

    $ResultsGrid.ItemsSource = @($Sorted)

    if (-not $ShowAllCheckBox.IsChecked -and $Filtered.Count -eq 0) {
        $StatusText.Text = "No issues found. Toggle 'Show all checks' to see every passed check."
    } else {
        $StatusText.Text = "Showing $($Filtered.Count) of $($script:AllChecks.Count) checks."
    }
}

function Run-Scan {
    $RefreshButton.IsEnabled = $false
    $ExportButton.IsEnabled = $false
    $SubtitleText.Text = "Scanning device for unsupported optimization/debloater/privacy/gaming tweak damage..."
    $Window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    $script:AllChecks = Invoke-HealthScan

    $Total = $script:AllChecks.Count
    $Pass  = ($script:AllChecks | Where-Object { $_.State -eq "Pass" }).Count
    $Warn  = ($script:AllChecks | Where-Object { $_.State -eq "Warning" }).Count
    $Fail  = ($script:AllChecks | Where-Object { $_.State -eq "Fail" }).Count
    $High  = ($script:AllChecks | Where-Object { $_.Severity -eq "High" -and $_.State -eq "Fail" }).Count

    $TotalText.Text = $Total
    $PassText.Text  = $Pass
    $WarnText.Text  = $Warn
    $FailText.Text  = $Fail
    $HighText.Text  = $High

    $DeviceName = $env:COMPUTERNAME
    $GeneratedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $SubtitleText.Text = "Device: $DeviceName | Last scanned: $GeneratedAt"

    Update-Grid

    $RefreshButton.IsEnabled = $true
    $ExportButton.IsEnabled = $true
}

$ShowAllCheckBox.Add_Click({ Update-Grid })
$RefreshButton.Add_Click({ Run-Scan })
$ExportButton.Add_Click({
    if (-not $script:AllChecks) { return }

    $SaveDialog = New-Object Microsoft.Win32.SaveFileDialog
    $SaveDialog.Title = "Save Windows Optimization Health Report"
    $SaveDialog.Filter = "HTML Report (*.html)|*.html|All Files (*.*)|*.*"
    $SaveDialog.DefaultExt = ".html"
    $SaveDialog.FileName = "WindowsOptimizationHealthReport_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $SaveDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

    $DialogResult = $SaveDialog.ShowDialog($Window)
    if ($DialogResult -ne $true) { return }

    $Checks = New-Object System.Collections.Generic.List[psobject]
    $script:AllChecks | ForEach-Object { $Checks.Add($_) }

    try {
        $Path = Export-HealthHtmlReport -Checks $Checks -ReportPath $SaveDialog.FileName
        [System.Windows.MessageBox]::Show("Report exported to:`n$Path", "Export Complete", "OK", "Information") | Out-Null
    } catch {
        [System.Windows.MessageBox]::Show("Failed to export report:`n$($_.Exception.Message)", "Export Failed", "OK", "Error") | Out-Null
    }
})

$Window.Add_Loaded({ Run-Scan })

$Window.ShowDialog() | Out-Null

# SIG # Begin signature block
# MIIcFAYJKoZIhvcNAQcCoIIcBTCCHAECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCeCEgi68Pm6EJQ
# lPdj/ljvlPy9paPidbLJJ4LYkzcN3KCCFlYwggMYMIICAKADAgECAhASyhUD+luh
# k0G2G5BtRuM2MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMMGUF1cmVsaXVtIElu
# dGVybmFsIFNjcmlwdHMwHhcNMjYwOTA4MTYzMDM0WhcNMzEwOTA4MTY0MDMzWjAk
# MSIwIAYDVQQDDBlBdXJlbGl1bSBJbnRlcm5hbCBTY3JpcHRzMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnybFa2HOo4yqyhAgcHvOnlmDqrn3Rlamz7HY
# eCKaw+tFnCNHhU1Fd26OlBDC8ZZwutG5hI/Lh8Zp5fmSDmCSBHK5o60du4kNQ69G
# +350D2ZBpZ+9wNHrvl9L3+uiek7tHUdwRzvX18JmDS5n2wPG6jqQiu6ca8ol+/Vi
# c0ENMioqw1L9+MllHqYmea88H2pUASQgD0O5VqF8kVJQPwnzZlAHup2QgyHD6hCV
# DIE/oPhvLw95Vq5ORX+I9qlfYeO+BH0xczdExvkq984ZzY1kcOWk1laoSwCn7a4c
# Rjx+9x80Do8ofo/NVUrTPYwFm5IKgYxeKyri0f9fANJ0v3TdvQIDAQABo0YwRDAO
# BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFO3V
# 1ItaHNsMau7mP+5DchIKdIm0MA0GCSqGSIb3DQEBCwUAA4IBAQCBvsYWCyPBsuPw
# zwOlkm0SYasDPIhOKYMuAGxfVYH0EGIpRtgiYcKDXyZXmAfmUjZOumAtip2Rn7Nr
# igAiys66K1bhVMe6rj2ww3FOPUXDqwiL7tIXHCqJJSoINGonCfLELw67a5jPvuxS
# NCmFbxrd1aarG/H8ahP6tSTFWimZUNJywqdNrA2OUVqi8O0kBNHPW04/uBzPuBkm
# tOLeTriFLGr2nJl0t0J2COrNEvOlfzlAobSgiM4Cmfhow2KTCEQR9lV46fHXLfp5
# Ib37BjPVY5tYt4rfiu+mjo+b6JGqy72uYg8GdNsyQ/5cqc0f8vb7zerlR8tzE1tT
# +rO9J5oBMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGtDCCBJyg
# AwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUw
# NTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2N
# DZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qft
# JYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0t
# rj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX
# 0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEp
# NVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coW
# J+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdk
# DjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0Xb
# Qcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sf
# uZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7v
# QTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwb
# tmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/n
# upiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3Bggr
# BgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAX
# zvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQ
# a8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd
# 6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FH
# aoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOc
# zgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFb
# qrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z
# 4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT
# 70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43es
# aUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif
# /sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+
# VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAhP
# 3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNjA4
# MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQw
# OTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04xjD4fAkOkbnGQi7+Wpx81iYx
# fzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZdw5uaAhuWevQKhDdZIB4Nnqc
# fpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4yyYQSPqomT92osQAv6hBi47A
# TZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqMv9AfGZvp8ygYElhudpQjtcPp
# woOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d3z9lcSIHkdvGPdGUrXdxfVbg
# OUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ27k3oHKEXBRGfRTqjOU+jE3b
# a/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pBNY4r3uD7hEmk/M81XhVgwDA7
# aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmVZeqTVDgsmzHP5MQuhAJkiWNu
# C9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71fHeu1qMLlLNB3WOB/ADCxr3S
# /1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4tMZae9FvqMOt/9PvmAxF9TNIs
# IFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X+eVtczhCgHCVQCF6XDAlPQID
# AQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUFMljijAu1Er7bpTz
# 5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0P
# AQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSB
# iDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsG
# AQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0f
# BFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1Ud
# IAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEA
# jcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDaMiqsaxWyW5cwlT/6ZF5sFzna
# zqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+OReFreFhnTXSG0Vrd2E2CZqUf
# m+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R79ZsfRFYe9UiXpXBDf6DkUo18
# 3Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp1w9Z2CyOyI5or/sSwomAuNQ0
# hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylcheWkMlj+CoVRlFE55pv0ZWCaF
# t04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ3dw9K2x1xLtu6PkPKeLBFjzK
# igwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6QHnPXrRNeIzkAMyylnRN8P0w
# mirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc1P/sV+zWxHXKH8tFt1ncHdVz
# qrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDDW15jERFE4LvjnGu2O9zD1nLJ
# SMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbevGH4punIxM1Uoi0nmX3ZK+Xb
# RT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0/YMxggUUMIIFEAIBATA4MCQx
# IjAgBgNVBAMMGUF1cmVsaXVtIEludGVybmFsIFNjcmlwdHMCEBLKFQP6W6GTQbYb
# kG1G4zYwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKA
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgtjLhR0lM7evUeuM+DBWWgWSh2lBu
# ohv/MY26mmL/PYEwDQYJKoZIhvcNAQEBBQAEggEAbjwaXcCrlF7PkMLG6ztPF5FX
# aSiVqzWQbKIghwLhjkujsP8acY4dMIy65ryGGRjBskPwHuVqxg1eBPwaUEaadt/u
# bHjAXtiSN+9Yg7qqvzjNUiBwYeqAcg87cksFRxBob9iVjJiV1wJEyRPQy7LUMaOV
# 1AXZ0J3mmfx/cLsYr2KrIx+YJz7TPlzQ51pOAdcMpZb6DEHZW3UEklaMucWnwDrW
# sGrMSC2LVJ9XTLmuG/xH4gNSLsjirbG+RvhB2y3IiE9hl99JgbFHnBCH6KCp75K6
# JfVCyfaCAap+uHgq8XbDba8UljQriXAcUXkD3oS7pEZcxsjHiQujGDsylLCZ4KGC
# AyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNP
# fkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZI
# hvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MDgxNjQxMDdaMC8GCSqGSIb3DQEJ
# BDEiBCCvhFuGLUXJQuno6Wi6ja9/DyR8Tu7t/ynEB3v2w461BjANBgkqhkiG9w0B
# AQEFAASCAgBZI1Qv3+Jn4aumKYm6S1i4Vr/kmd9b5lBOA/zMkTtRbRkQvvUSxDft
# GJgrYuaQgmw8w3zSlR/ysHtBDXex5Psac70DPFhYDN2Qqmo2+PF4aGXmchARRIN5
# bMnF1sDdyK36Y3P2NE3GfFQ+pvIC2P3A66/6xMfoIY+uxNdvKN3Qgeb3SWa3zCm7
# vMRF7FE9nxKRfF0Kt60W6dCgjv/2nd3jsALd1Kp5Y4DIJAfm9i4c/cx9aZpowB+A
# YpXKXoANNumEHOwnq2C3LqEa8LdvpAaU1i/Z1zkPRw9ZSYGpXLXKGphzAMBjBJ5M
# xMMULiRAOe2qajEIMQZR3QFERA4CjqW1Zgwu9Zr7rWjcuwH5e1GtJ7KV8ttLth5r
# mK9IRYne4hmEK/C3t5KwfG3/zvXkNNLS6fHB1y/jb21LY9gkDt1lALlC+BTQnTDP
# hsAqbJVVotcdEMo53ZFsxYDkewOl49pwynoj6W+lYEMbw/XIu9ZrlWJiC+a3BVL3
# x9k4Ovr3b0DCxGIxNGay1DxbpKVkyqD+0TRpjftpa5nnCxdTGoPSg6VglllNLzKp
# aMba31RYCPuhmD2D5bP/Mags2CS75L2aFPOzWv11B7bOV/SxHPtob+uCT91cwd6R
# HtMMGJo7/Qc9IyozKwfXsYDYKsnLOkBT5y6ZOkwjzMcUhSSaFU20Tg==
# SIG # End signature block
