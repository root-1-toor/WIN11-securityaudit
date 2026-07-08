# WIN11-securityaudit

**PC-Security-Audit.ps1** — A deep diagnostic and security sweep for Windows 11, in a single PowerShell script.

One run gives you a full hardware inventory, drive health report, malware and corruption checks, a remote-access and persistence audit, a suspicious-file sweep, and a Win11Debloat-inspired bloat/telemetry audit — followed by an interactive review where **you** decide what happens to every finding.

> 🛡️ **Nothing is deleted automatically.** Every removal requires your explicit confirmation, and quarantined files can always be restored.

---

## Features

### 1. Hardware Inventory
CPU (with live clock speeds), RAM, GPU, motherboard, BIOS, and network adapters.

### 2. Drive Health
SMART / reliability counters, SSD wear level, and drive temperatures.

### 3. Malware Check
Windows Defender status, threat history, and an optional on-demand scan.

### 4. Corrupt-Data Checks
System File Checker (SFC), DISM component-store health, and volume scan.

### 5. Remote-Access Audit
- RDP configuration and status
- Installed remote-access tools
- Live network connections
- RDP logon history
- Suspicious user accounts
- Firewall rule review

### 6. Suspicious File Sweep
- Executables in Temp / AppData
- Unsigned binaries
- Double-extension files (`invoice.pdf.exe`)
- Startup entries

### 7. Task Scheduler Deep Scan
Inspects **every** scheduled task, including hidden ones:
- Tasks pointing at user-writable binaries
- Encoded / obfuscated commands
- COM handler DLLs
- Elevated persistence
- Orphaned task XML
- Full logon/boot persistence inventory

### 8. Driver Audit
Flags outdated drivers and devices reporting errors.

### 9. Windows 11 Bloat Audit *(Win11Debloat-inspired)*
- Preinstalled apps
- Telemetry & CEIP scheduled tasks
- Ads and suggestions
- AI features: **Copilot, Recall, Click to Do**
- Edge news feed
- OneDrive

Plus optional quality-of-life customizations: taskbar tweaks, Explorer settings, classic context menu, mouse acceleration, dark mode.

### 10. Interactive Review
At the end of the sweep, walk through each finding and choose:

| Action | What it does |
|---|---|
| **Remove** | Deletes / disables the item (with confirmation) |
| **Quarantine** | Moves files to a dated folder on your Desktop — fully restorable |
| **Keep** | Leaves it untouched |

Bulk one-shot options are available for the **Bloat** and **Customize** categories.

---

## Usage

1. Right-click PowerShell and select **Run as Administrator**
2. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\PC-Security-Audit.ps1
```

---

## Output

- ✅ Interactive prompts for every actionable finding
- 📄 A full text report saved next to the script
- 🗂️ Quarantined items go to a dated folder on your Desktop for easy restore

---

## Requirements

- Windows 11
- PowerShell (run as Administrator)
- No external dependencies — 100% built-in cmdlets

---

## Safety Notes

- **Nothing is deleted automatically.** Every removal requires your confirmation.
- **Quarantine over delete.** Quarantine moves files to a dated Desktop folder instead of deleting, so anything can be restored.
- The script is read-only until the interactive review phase — the entire audit runs without modifying your system.

---

## Disclaimer

This script is provided as-is. Review the code before running it, as you should with any script that requires administrator privileges. The author is not responsible for any unintended changes to your system.

## License

MIT
