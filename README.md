# WIN11-securityaudit
================================================================================
  PC-Security-Audit.ps1  Windows 11 Deep Diagnostic & Security Sweep
================================================================================
  WHAT IT DOES
    1. Hardware inventory (CPU w/ live clocks, RAM, GPU, board, BIOS, network)
    2. Drive health (SMART / reliability counters, wear, temperature)
    3. Malware check (Windows Defender status, threat history, optional scan)
    4. Corrupt-data checks (SFC, DISM, volume scan)
    5. Remote-access audit (RDP, remote tools, live connections, RDP logons,
       suspicious accounts, firewall rules)
    6. Suspicious file sweep (temp/appdata executables, unsigned binaries,
       double extensions, startup entries)
    7. Task Scheduler DEEP scan (every task incl. hidden: user-writable
       binaries, encoded commands, COM handler DLLs, elevated persistence,
       orphaned task XML, logon/boot persistence inventory)
    8. Driver audit (old drivers, devices reporting errors)
    9. Windows 11 bloat audit - Win11Debloat-inspired (preinstalled apps,
       telemetry, ads, AI features incl. Copilot/Recall/Click to Do,
       Edge feed, OneDrive, CEIP tasks) plus optional customizations
       (taskbar, Explorer, context menu, mouse accel, dark mode)
   10. Interactive review at the end: Remove / Quarantine / Keep each finding,
       with one-shot bulk options for Bloat and Customize categories

  USAGE
    Right-click PowerShell -> Run as Administrator, then:
      Set-ExecutionPolicy -Scope Process Bypass
      .\PC-Security-Audit.ps1

  NOTES
    - Nothing is deleted automatically. Every removal requires your confirmation.
    - "Quarantine" moves files to a dated folder on your Desktop instead of
      deleting them, so anything can be restored.
    - A full text report is saved next to the script.
