```markdown name=README.md
# Windows Optimization Health App

A PowerShell WPF GUI that scans a Windows PC for signs of “optimization,” debloating, privacy-hardening, or gaming-tweak changes that may have weakened core system functionality or security.

This script is the GUI companion to the same health-check logic used by the Windows Optimization Health Report script. It highlights only the items that are in a warning or failed state by default, while still letting you reveal all checks.

## What it checks

The app evaluates a broad set of Windows health and integrity areas, including:

- Core Windows services
- Microsoft Defender health and sabotage-related policy settings
- Windows Update policy settings
- Microsoft Store availability and policy state
- Microsoft Edge, WebView2, and Winget presence
- SmartScreen settings
- Firewall profile status
- UAC, Virtualization-Based Security, Credential Guard, Memory Integrity, and LSASS protection
- Critical scheduled tasks
- Remote Desktop and Network Level Authentication hardening

## Features

- **WPF graphical interface**
- **Summary tiles** for:
  - Total checks
  - Passed
  - Warnings
  - Failed
  - High-severity issues
- **Issue-focused view** that hides healthy checks by default
- **Show all checks** toggle
- **Refresh Scan** button
- **Export HTML Report** button
- Runs **non-elevated** so results match the logged-in user’s real experience

## Requirements

- Windows
- PowerShell 5.1, or PowerShell 7+ running with `-STA`
- WPF support (`PresentationFramework`, `PresentationCore`, `WindowsBase`)
- A standard desktop session
- Run as the signed-in user, not as SYSTEM or an elevated admin session, for best results

## Usage

Run the script from PowerShell:

```powershell
.\Windows-Optimization-Health-App.ps1
```

If using PowerShell 7+, launch it with STA mode enabled:

```powershell
pwsh -sta -File .\Windows-Optimization-Health-App.ps1
```

## What to expect

When launched, the app:

1. Scans the system for health and hardening issues
2. Displays summary counts at the top
3. Lists only warnings and failures by default
4. Lets you expand the view to show all checks
5. Allows exporting an HTML report to disk

## Exported report

The exported HTML report includes the same check results in a clean, readable format and is saved to a user-writable folder when possible.

Default save locations include:

- Desktop
- `%LOCALAPPDATA%\WindowsOptimizationHealth`
- `%TEMP%\WindowsOptimizationHealth`

## Notes

- The script is designed to be read-only and does not change system settings.
- Some checks may be informational depending on your device configuration.
- Certain items, such as Winget, may be skipped when the script is running in `SYSTEM` context.
- Some checks may vary by Windows edition, installed components, or enterprise policy.

## Safety

This tool is for auditing and diagnostics only. It does not optimize or modify Windows settings.

## License

Add your project’s license here if desired.

## Related scripts

This GUI is intended to pair with the corresponding HTML report script used for the same set of Windows health checks.
```
