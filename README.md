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
