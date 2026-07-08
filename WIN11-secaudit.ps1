#Requires -Version 5.1
<#
================================================================================
  PC-Security-Audit.ps1  —  Windows 11 Deep Diagnostic & Security Sweep
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
================================================================================
#>

# ------------------------------------------------------------------ elevation
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "Not running as Administrator - attempting to relaunch elevated..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# ------------------------------------------------------------------ globals
$Script:StartTime   = Get-Date
$Script:BaseDir     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Script:ReportPath  = Join-Path $BaseDir ("PC-Audit-Report_{0:yyyy-MM-dd_HH-mm}.txt" -f $StartTime)
$Script:Quarantine  = Join-Path ([Environment]::GetFolderPath('Desktop')) ("Quarantine_{0:yyyy-MM-dd_HH-mm}" -f $StartTime)
$Script:Findings    = [System.Collections.Generic.List[object]]::new()
$Script:Report      = [System.Text.StringBuilder]::new()

function Write-Section {
    param([string]$Title)
    $bar = "=" * 78
    Write-Host "`n$bar" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
    [void]$Report.AppendLine("`r`n$bar`r`n  $Title`r`n$bar")
}

function Write-Line {
    param([string]$Text, [ConsoleColor]$Color = 'Gray')
    Write-Host $Text -ForegroundColor $Color
    [void]$Report.AppendLine($Text)
}

function Add-Finding {
    <# Registers something the user can act on at the end.
       Type controls what "Remove" means:
         File          -> quarantine/delete the file
         RegistryValue -> delete a Run-key value          (Data = @{Key;Name})
         ScheduledTask -> disable the task                (Data = task path\name)
         Service       -> stop + disable the service      (Data = service name)
         Program       -> show/run its uninstall string   (Data = uninstall cmd)
         Driver        -> pnputil /delete-driver          (Data = oemXX.inf)
         Threat        -> Remove-MpThreat                 (Data = ThreatID)
         Info          -> not removable, informational only
    #>
    param(
        [string]$Category, [string]$Severity, [string]$Description,
        [string]$Type = 'Info', [object]$Data = $null
    )
    $Findings.Add([pscustomobject]@{
        Id = $Findings.Count + 1; Category = $Category; Severity = $Severity
        Description = $Description; Type = $Type; Data = $Data
    })
    $color = switch ($Severity) { 'HIGH' {'Red'} 'MEDIUM' {'Yellow'} 'LOW' {'DarkYellow'} default {'Gray'} }
    Write-Line ("  [{0}] {1}: {2}" -f $Severity, $Category, $Description) $color
}

# ==============================================================================
# 1. HARDWARE INVENTORY
# ==============================================================================
function Show-Hardware {
    Write-Section "1. HARDWARE INVENTORY"

    $cs   = Get-CimInstance Win32_ComputerSystem
    $os   = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    $bb   = Get-CimInstance Win32_BaseBoard
    Write-Line ("  System      : {0} {1}" -f $cs.Manufacturer, $cs.Model)
    Write-Line ("  OS          : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
    Write-Line ("  Motherboard : {0} {1}" -f $bb.Manufacturer, $bb.Product)
    Write-Line ("  BIOS/UEFI   : {0}  v{1}  ({2:d})" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion, $bios.ReleaseDate)
    Write-Line ("  Uptime      : {0:g}" -f ((Get-Date) - $os.LastBootUpTime))

    # --- CPU with live clock ---
    foreach ($cpu in Get-CimInstance Win32_Processor) {
        Write-Line ""
        Write-Line ("  CPU         : {0}" -f $cpu.Name.Trim()) White
        Write-Line ("    Cores/Threads   : {0} / {1}" -f $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors)
        Write-Line ("    Base Clock      : {0} MHz" -f $cpu.MaxClockSpeed)
        try {
            $perf = Get-Counter '\Processor Information(_Total)\% Processor Performance' -ErrorAction Stop
            $live = [math]::Round($cpu.MaxClockSpeed * ($perf.CounterSamples[0].CookedValue / 100))
            Write-Line ("    Current Clock   : ~{0} MHz" -f $live) Green
        } catch {
            Write-Line ("    Current Clock   : {0} MHz (reported)" -f $cpu.CurrentClockSpeed)
        }
        Write-Line ("    Load            : {0}%" -f $cpu.LoadPercentage)
        Write-Line ("    L2 / L3 Cache   : {0} KB / {1} KB" -f $cpu.L2CacheSize, $cpu.L3CacheSize)
    }

    # --- RAM ---
    Write-Line ""
    $totalGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $freeGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    Write-Line ("  RAM         : {0} GB total, {1} GB free" -f $totalGB, $freeGB) White
    foreach ($m in Get-CimInstance Win32_PhysicalMemory) {
        $mhz = if ($m.ConfiguredClockSpeed) { $m.ConfiguredClockSpeed } else { $m.Speed }
        Write-Line ("    {0}  {1} GB @ {2} MHz  {3} {4}" -f $m.DeviceLocator,
            [math]::Round($m.Capacity/1GB), $mhz, $m.Manufacturer, "$($m.PartNumber)".Trim())
    }

    # --- GPU ---
    Write-Line ""
    foreach ($gpu in Get-CimInstance Win32_VideoController) {
        Write-Line ("  GPU         : {0}" -f $gpu.Name) White
        if ($gpu.AdapterRAM -gt 0) { Write-Line ("    VRAM (reported) : {0} GB" -f [math]::Round($gpu.AdapterRAM/1GB,1)) }
        Write-Line ("    Driver          : {0}  ({1:d})" -f $gpu.DriverVersion, $gpu.DriverDate)
        Write-Line ("    Resolution      : {0}x{1} @ {2} Hz" -f $gpu.CurrentHorizontalResolution, $gpu.CurrentVerticalResolution, $gpu.CurrentRefreshRate)
    }

    # --- Network adapters ---
    Write-Line ""
    Write-Line "  Network Adapters (up):" White
    Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
        Write-Line ("    {0}  [{1}]  {2}" -f $_.Name, $_.LinkSpeed, $_.InterfaceDescription)
    }

    # --- Battery (laptops) ---
    $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if ($bat) { Write-Line ("  Battery     : {0}% remaining" -f $bat.EstimatedChargeRemaining) White }
}

# ==============================================================================
# 2. DRIVE HEALTH
# ==============================================================================
function Show-DriveHealth {
    Write-Section "2. DRIVE HEALTH (SMART / Reliability)"

    foreach ($disk in Get-PhysicalDisk) {
        $healthColor = if ($disk.HealthStatus -eq 'Healthy') {'Green'} else {'Red'}
        Write-Line ""
        Write-Line ("  {0}  [{1}, {2} GB, Bus: {3}]" -f $disk.FriendlyName, $disk.MediaType,
            [math]::Round($disk.Size/1GB), $disk.BusType) White
        Write-Line ("    Health Status   : {0}" -f $disk.HealthStatus) $healthColor
        Write-Line ("    Operational     : {0}" -f ($disk.OperationalStatus -join ', '))

        $r = $disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
        if ($r) {
            if ($null -ne $r.Temperature -and $r.Temperature -gt 0) {
                $tColor = if ($r.Temperature -ge 60) {'Red'} elseif ($r.Temperature -ge 50) {'Yellow'} else {'Green'}
                Write-Line ("    Temperature     : {0} C  (max recorded {1} C)" -f $r.Temperature, $r.TemperatureMax) $tColor
            }
            if ($null -ne $r.Wear)              { Write-Line ("    SSD Wear        : {0}% used" -f $r.Wear) }
            if ($null -ne $r.PowerOnHours)      { Write-Line ("    Power-On Hours  : {0}" -f $r.PowerOnHours) }
            if ($null -ne $r.StartStopCycleCount){Write-Line ("    Start/Stop Count: {0}" -f $r.StartStopCycleCount) }
            if ($r.ReadErrorsUncorrected -gt 0 -or $r.WriteErrorsUncorrected -gt 0) {
                Add-Finding -Category 'Drive Health' -Severity 'HIGH' -Type 'Info' -Description (
                    "{0}: uncorrected errors (read {1} / write {2}) - BACK UP THIS DRIVE" -f
                    $disk.FriendlyName, $r.ReadErrorsUncorrected, $r.WriteErrorsUncorrected)
            }
        }
        if ($disk.HealthStatus -ne 'Healthy') {
            Add-Finding -Category 'Drive Health' -Severity 'HIGH' -Type 'Info' -Description (
                "{0} reports health status '{1}' - back up immediately" -f $disk.FriendlyName, $disk.HealthStatus)
        }
    }

    Write-Line ""
    Write-Line "  Volume usage:" White
    Get-Volume | Where-Object DriveLetter | Sort-Object DriveLetter | ForEach-Object {
        $pct = if ($_.Size -gt 0) { [math]::Round(100 * ($_.Size - $_.SizeRemaining) / $_.Size) } else { 0 }
        Write-Line ("    {0}:  {1}  {2}/{3} GB used ({4}%)  Health: {5}" -f $_.DriveLetter, $_.FileSystem,
            [math]::Round(($_.Size-$_.SizeRemaining)/1GB), [math]::Round($_.Size/1GB), $pct, $_.HealthStatus)
    }
}

# ==============================================================================
# 3. MALWARE CHECK (Windows Defender)
# ==============================================================================
function Invoke-MalwareCheck {
    Write-Section "3. MALWARE CHECK (Windows Defender)"

    try { $mp = Get-MpComputerStatus -ErrorAction Stop }
    catch {
        Write-Line "  Windows Defender is unavailable (another AV may be primary)." Yellow
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Line ("    Installed AV: {0}" -f $_.displayName) }
        return
    }

    Write-Line ("  Real-time protection : {0}" -f $mp.RealTimeProtectionEnabled) ($(if($mp.RealTimeProtectionEnabled){'Green'}else{'Red'}))
    Write-Line ("  Antivirus enabled    : {0}" -f $mp.AntivirusEnabled)
    Write-Line ("  Definitions age      : {0} day(s)  (v{1})" -f $mp.AntivirusSignatureAge, $mp.AntivirusSignatureVersion)
    Write-Line ("  Last quick scan      : {0}" -f $mp.QuickScanEndTime)
    Write-Line ("  Last full scan       : {0}" -f $mp.FullScanEndTime)
    Write-Line ("  Tamper protection    : {0}" -f $mp.IsTamperProtected)

    if (-not $mp.RealTimeProtectionEnabled) {
        Add-Finding -Category 'Malware' -Severity 'HIGH' -Type 'Info' -Description 'Real-time protection is OFF'
    }
    if ($mp.AntivirusSignatureAge -gt 7) {
        Add-Finding -Category 'Malware' -Severity 'MEDIUM' -Type 'Info' -Description "Definitions are $($mp.AntivirusSignatureAge) days old - run Windows Update"
    }

    # Existing / historical threats
    $threats = Get-MpThreat -ErrorAction SilentlyContinue
    if ($threats) {
        foreach ($t in $threats) {
            Add-Finding -Category 'Malware' -Severity 'HIGH' -Type 'Threat' -Data $t.ThreatID -Description (
                "Defender threat: {0} ({1})  Active: {2}" -f $t.ThreatName, $t.SeverityID, ($t.IsActive))
        }
    } else { Write-Line "  No threats in Defender's current threat list." Green }

    $det = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5
    if ($det) {
        Write-Line "`n  Recent detections:" White
        $det | ForEach-Object { Write-Line ("    {0:g}  {1}" -f $_.InitialDetectionTime, ($_.Resources -join '; ')) }
    }

    # Defender exclusions can hide malware
    $pref = Get-MpPreference
    foreach ($ex in @($pref.ExclusionPath) + @($pref.ExclusionProcess) | Where-Object { $_ }) {
        Add-Finding -Category 'Malware' -Severity 'MEDIUM' -Type 'Info' -Description "Defender exclusion present: $ex (verify you added this yourself)"
    }

    Write-Host ""
    $choice = Read-Host "  Run a Defender scan now? [Q]uick / [F]ull (slow) / [S]kip"
    switch ($choice.ToUpper()) {
        'Q' { Write-Line "  Running quick scan (a few minutes)..." Yellow; Start-MpScan -ScanType QuickScan; Write-Line "  Quick scan complete." Green }
        'F' { Write-Line "  Running FULL scan (this can take hours)..." Yellow; Start-MpScan -ScanType FullScan; Write-Line "  Full scan complete." Green }
        default { Write-Line "  Scan skipped." }
    }
    # Re-check threats after scan
    Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.ThreatID -notin ($Findings | Where-Object Type -eq 'Threat').Data } |
        ForEach-Object {
            Add-Finding -Category 'Malware' -Severity 'HIGH' -Type 'Threat' -Data $_.ThreatID -Description ("Defender threat: {0}" -f $_.ThreatName)
        }
}

# ==============================================================================
# 4. CORRUPT DATA / SYSTEM FILE INTEGRITY
# ==============================================================================
function Invoke-IntegrityChecks {
    Write-Section "4. CORRUPT DATA & SYSTEM FILE INTEGRITY"

    Write-Line "  Volume dirty-bit / file-system scan:" White
    Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystem -eq 'NTFS' } | ForEach-Object {
        try {
            $result = Repair-Volume -DriveLetter $_.DriveLetter -Scan -ErrorAction Stop
            $color = if ($result -eq 'NoErrorsFound') {'Green'} else {'Red'}
            Write-Line ("    {0}:  {1}" -f $_.DriveLetter, $result) $color
            if ($result -ne 'NoErrorsFound') {
                Add-Finding -Category 'Corruption' -Severity 'HIGH' -Type 'Info' -Description (
                    "Volume {0}: reported '{1}' - run: Repair-Volume -DriveLetter {0} -OfflineScanAndFix" -f $_.DriveLetter, $result)
            }
        } catch { Write-Line ("    {0}:  scan failed ({1})" -f $_.DriveLetter, $_.Exception.Message) Yellow }
    }

    Write-Host ""
    $choice = Read-Host "  Run DISM component-store check + SFC system file check? Takes 10-30 min. [Y/N]"
    if ($choice -match '^[Yy]') {
        Write-Line "`n  DISM /Online /Cleanup-Image /ScanHealth ..." Yellow
        $dism = & dism.exe /Online /Cleanup-Image /ScanHealth
        $dismLine = ($dism | Select-String -Pattern 'component store|repairable|No component').Line -join ' | '
        Write-Line ("    DISM: {0}" -f $dismLine)
        if ($dism -match 'repairable') {
            Add-Finding -Category 'Corruption' -Severity 'MEDIUM' -Type 'Info' -Description 'Component store is repairable - run: DISM /Online /Cleanup-Image /RestoreHealth'
        }

        Write-Line "`n  SFC /scannow ..." Yellow
        $sfc = & sfc.exe /scannow
        $sfcText = ($sfc -join ' ') -replace '\x00',''
        if     ($sfcText -match 'did not find any integrity violations') { Write-Line '    SFC: no integrity violations.' Green }
        elseif ($sfcText -match 'successfully repaired')                 { Write-Line '    SFC: corrupt files found and repaired.' Yellow
            Add-Finding -Category 'Corruption' -Severity 'LOW' -Type 'Info' -Description 'SFC repaired corrupt system files (see CBS.log)' }
        elseif ($sfcText -match 'unable to fix')                         { Write-Line '    SFC: corrupt files it could NOT fix.' Red
            Add-Finding -Category 'Corruption' -Severity 'HIGH' -Type 'Info' -Description 'SFC found unfixable corruption - run DISM /RestoreHealth then SFC again' }
        else { Write-Line '    SFC finished - review output above.' }
    } else { Write-Line "  DISM/SFC skipped." }
}

# ==============================================================================
# 5. REMOTE ACCESS AUDIT
# ==============================================================================
function Invoke-RemoteAccessAudit {
    Write-Section "5. REMOTE ACCESS AUDIT"

    # --- RDP ---
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($rdp -eq 0) {
        Add-Finding -Category 'Remote Access' -Severity 'MEDIUM' -Type 'Info' -Description 'Remote Desktop (RDP) is ENABLED. Disable in Settings > System > Remote Desktop if you do not use it.'
    } else { Write-Line "  RDP: disabled." Green }

    # --- Known remote-access software ---
    $remoteTools = 'TeamViewer','AnyDesk','VNC','TightVNC','UltraVNC','RealVNC','Chrome Remote','LogMeIn','Splashtop','GoToMyPC','Ammyy','Remote Utilities','RustDesk','Parsec','DWService','ConnectWise','ScreenConnect','Atera','SupRemo','ZohoAssist','Zoho Assist','NoMachine','Radmin'
    $uninstKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $installed = Get-ItemProperty $uninstKeys -ErrorAction SilentlyContinue | Where-Object DisplayName
    $foundTool = $false
    foreach ($app in $installed) {
        foreach ($tool in $remoteTools) {
            if ($app.DisplayName -like "*$tool*") {
                $foundTool = $true
                Add-Finding -Category 'Remote Access' -Severity 'MEDIUM' -Type 'Program' -Data $app.UninstallString -Description (
                    "Remote-access software installed: {0} {1} (keep only if YOU installed it)" -f $app.DisplayName, $app.DisplayVersion)
            }
        }
    }
    if (-not $foundTool) { Write-Line "  No known remote-access software found installed." Green }

    # --- Remote-tool processes currently running ---
    $procNames = 'TeamViewer','AnyDesk','vncserver','winvnc','tvnserver','LogMeIn','RustDesk','ScreenConnect','Ammyy','remoting_host','mstsc'
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $n = $_.Name; $procNames | Where-Object { $n -like "*$_*" } } |
        Select-Object -Unique Name | ForEach-Object {
            Add-Finding -Category 'Remote Access' -Severity 'HIGH' -Type 'Info' -Description "Remote-access process RUNNING right now: $($_.Name)"
        }

    # --- Listening ports associated with remote access ---
    $riskyPorts = @{ 3389='RDP'; 5900='VNC'; 5901='VNC'; 5938='TeamViewer'; 7070='AnyDesk'; 5800='VNC-web'; 4899='Radmin'; 6568='AnyDesk'; 21115='RustDesk'; 21116='RustDesk'; 22='SSH'; 23='Telnet' }
    Write-Line "`n  Listening ports of interest:" White
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    $flagged = $false
    foreach ($l in $listeners) {
        if ($riskyPorts.ContainsKey([int]$l.LocalPort)) {
            $flagged = $true
            $p = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            Add-Finding -Category 'Remote Access' -Severity 'MEDIUM' -Type 'Info' -Description (
                "Port {0} ({1}) is LISTENING - process: {2} (PID {3})" -f $l.LocalPort, $riskyPorts[[int]$l.LocalPort], $p.Name, $l.OwningProcess)
        }
    }
    if (-not $flagged) { Write-Line "    None of the common remote-access ports are listening." Green }

    # --- Established external connections ---
    Write-Line "`n  Established outbound/inbound connections (non-local):" White
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fe80)' } |
        Sort-Object RemoteAddress -Unique | Select-Object -First 25 | ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            Write-Line ("    {0,-21} -> {1}:{2}  [{3}]" -f "$($_.LocalAddress):$($_.LocalPort)", $_.RemoteAddress, $_.RemotePort, $p.Name)
        }

    # --- Recent remote logons (Event ID 4624, LogonType 10 = RDP, 3 = network) ---
    Write-Line "`n  Recent interactive-remote logons (Event 4624 type 10):" White
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-14)} -MaxEvents 800 -ErrorAction Stop
        $rdpLogons = $events | Where-Object { $_.Properties[8].Value -eq 10 }
        if ($rdpLogons) {
            $rdpLogons | Select-Object -First 10 | ForEach-Object {
                $u = $_.Properties[5].Value; $ip = $_.Properties[18].Value
                Add-Finding -Category 'Remote Access' -Severity 'HIGH' -Type 'Info' -Description (
                    "RDP logon on {0:g} - user '{1}' from {2} (verify this was you)" -f $_.TimeCreated, $u, $ip)
            }
        } else { Write-Line "    No RDP logons in the last 14 days." Green }
    } catch { Write-Line "    Could not read Security log: $($_.Exception.Message)" Yellow }

    # --- Local accounts / hidden admins ---
    Write-Line "`n  Local user accounts:" White
    Get-LocalUser | ForEach-Object {
        Write-Line ("    {0,-20} Enabled:{1,-6} LastLogon:{2}" -f $_.Name, $_.Enabled, $_.LastLogon)
    }
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    Write-Line ("  Administrators group : {0}" -f (($admins.Name | ForEach-Object { $_.Split('\')[-1] }) -join ', '))
    Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -in 'Guest','DefaultAccount','WDAGUtilityAccount' } | ForEach-Object {
        Add-Finding -Category 'Remote Access' -Severity 'HIGH' -Type 'Info' -Description "Built-in account '$($_.Name)' is ENABLED (normally disabled)"
    }

    # --- Firewall inbound allow rules to any address ---
    $fwProfiles = Get-NetFirewallProfile
    $fwProfiles | ForEach-Object {
        $c = if ($_.Enabled) {'Green'} else {'Red'}
        Write-Line ("  Firewall [{0}] : {1}" -f $_.Name, $(if($_.Enabled){'ON'}else{'OFF'})) $c
        if (-not $_.Enabled) {
            Add-Finding -Category 'Remote Access' -Severity 'HIGH' -Type 'Info' -Description "Firewall profile '$($_.Name)' is DISABLED"
        }
    }
}

# ==============================================================================
# 6. SUSPICIOUS FILE SWEEP
# ==============================================================================
function Invoke-SuspiciousFileSweep {
    Write-Section "6. SUSPICIOUS FILE SWEEP"
    Write-Line "  Scanning high-risk locations (this may take a few minutes)..." Yellow

    $execExt = '.exe','.scr','.bat','.cmd','.vbs','.js','.ps1','.hta','.pif','.com','.jar'
    $hotDirs = @(
        $env:TEMP, "$env:SystemRoot\Temp", "$env:PUBLIC",
        "$env:APPDATA", "$env:LOCALAPPDATA\Temp", "$env:ProgramData",
        "$env:USERPROFILE\Downloads"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $suspects = [System.Collections.Generic.List[object]]::new()
    foreach ($dir in $hotDirs) {
        Get-ChildItem $dir -File -Recurse -Force -ErrorAction SilentlyContinue -Depth 3 |
            Where-Object { $_.Extension -in $execExt } | ForEach-Object { $suspects.Add($_) }
    }
    Write-Line ("  Executables found in temp/appdata/public locations: {0}" -f $suspects.Count)

    foreach ($f in $suspects) {
        $reasons = [System.Collections.Generic.List[string]]::new()

        # Double extension (invoice.pdf.exe)
        if ($f.BaseName -match '\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp3|mp4|zip)$') { $reasons.Add('double extension') }

        # Hidden or system attributes in user space
        if ($f.Attributes -band [IO.FileAttributes]::Hidden) { $reasons.Add('hidden attribute') }

        # Unsigned exe in temp-type location
        if ($f.Extension -in '.exe','.scr','.com') {
            $sig = Get-AuthenticodeSignature $f.FullName -ErrorAction SilentlyContinue
            if ($sig.Status -ne 'Valid') { $reasons.Add("unsigned/invalid signature ($($sig.Status))") }
        }

        # Freshly dropped executables in Temp specifically
        if ($f.DirectoryName -like "*\Temp*" -and $f.CreationTime -gt (Get-Date).AddDays(-7) -and $f.Extension -in '.exe','.scr','.bat','.vbs','.hta') {
            $reasons.Add('created in Temp within last 7 days')
        }

        if ($reasons.Count -ge 2 -or ($reasons -contains 'double extension')) {
            $sev = if ($reasons -contains 'double extension') {'HIGH'} else {'MEDIUM'}
            Add-Finding -Category 'Suspicious File' -Severity $sev -Type 'File' -Data $f.FullName -Description (
                "{0}  [{1}]  ({2:g}, {3} KB)" -f $f.FullName, ($reasons -join '; '), $f.LastWriteTime, [math]::Round($f.Length/1KB))
        }
    }

    # --- Startup entries (Run keys + startup folders) ---
    Write-Line "`n  Startup entries:" White
    $runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
               'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = Get-ItemProperty $key
        foreach ($p in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            Write-Line ("    [{0}] {1} = {2}" -f ($key -replace '.*(HKLM|HKCU).*','$1'), $p.Name, $p.Value)
            if ($p.Value -match 'Temp\\|AppData\\Local\\Temp|ProgramData\\[^\\]+\.(exe|vbs|bat|js)|powershell.*-enc|wscript|mshta|-w hidden') {
                Add-Finding -Category 'Suspicious File' -Severity 'HIGH' -Type 'RegistryValue' -Data @{Key=$key; Name=$p.Name} -Description (
                    "Startup entry launching from suspicious location: '{0}' -> {1}" -f $p.Name, $p.Value)
            }
        }
    }
    foreach ($sf in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
        Get-ChildItem $sf -File -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Line ("    [StartupFolder] {0}" -f $_.Name)
            if ($_.Extension -in '.vbs','.bat','.js','.hta','.ps1') {
                Add-Finding -Category 'Suspicious File' -Severity 'MEDIUM' -Type 'File' -Data $_.FullName -Description "Script in Startup folder: $($_.FullName)"
            }
        }
    }

    # --- Scheduled tasks are covered in depth by Section 7 ---

    # --- Non-Microsoft services running from user-writable paths ---
    Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -match 'Temp\\|AppData\\|Users\\Public' -and $_.State -eq 'Running'
    } | ForEach-Object {
        Add-Finding -Category 'Suspicious File' -Severity 'HIGH' -Type 'Service' -Data $_.Name -Description (
            "Service '{0}' running from user-writable path: {1}" -f $_.DisplayName, $_.PathName)
    }

    # --- Hosts file tampering ---
    $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
             Where-Object { $_ -match '^\s*\d' -and $_ -notmatch '^\s*127\.0\.0\.1\s+localhost|^\s*::1' }
    if ($hosts) {
        Add-Finding -Category 'Suspicious File' -Severity 'MEDIUM' -Type 'Info' -Description (
            "hosts file contains {0} custom redirect entrie(s) - verify: notepad C:\Windows\System32\drivers\etc\hosts" -f $hosts.Count)
    }
}

# ==============================================================================
# 7. TASK SCHEDULER DEEP SCAN
# ==============================================================================
function Invoke-TaskSchedulerDeepScan {
    Write-Section "7. TASK SCHEDULER DEEP SCAN"
    Write-Line "  Enumerating every task (including hidden), inspecting authors, principals," Yellow
    Write-Line "  triggers, actions, COM handlers, and on-disk binaries..." Yellow

    $userWritable = 'Temp\\|\\AppData\\|\\Users\\Public\\|\\ProgramData\\[^\\]+\.(exe|bat|vbs|js|ps1|cmd|scr)|\\Downloads\\|\$Recycle\.Bin'
    $lolbinArgs   = '-enc\s|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|invoke-webrequest.*iex|iex\s*\(|-w(indowstyle)?\s+hidden|bitsadmin|certutil.*-urlcache|mshta\s+http|regsvr32.*\/i:http|rundll32.*javascript'
    $safeAuthors  = 'Microsoft|SYSTEM|^\s*$'

    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $stats = [ordered]@{ Total=$allTasks.Count; Enabled=0; Hidden=0; NonMicrosoftPath=0; Flagged=0 }
    $flaggedIds = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($t in $allTasks) {
        $full = "$($t.TaskPath)$($t.TaskName)"
        if ($t.State -ne 'Disabled') { $stats.Enabled++ }
        $isHidden = $false
        try { $isHidden = [bool]$t.Settings.Hidden } catch {}
        if ($isHidden) { $stats.Hidden++ }
        $isMsPath = $t.TaskPath -like '\Microsoft\*'
        if (-not $isMsPath) { $stats.NonMicrosoftPath++ }
        $author   = "$($t.Author)"
        $runAs    = "$($t.Principal.UserId)"
        $runLevel = "$($t.Principal.RunLevel)"

        $reasons = [System.Collections.Generic.List[string]]::new()
        $detail  = ''

        foreach ($a in $t.Actions) {
            # ---- Exec actions ----
            if ($a.CimClass.CimClassName -eq 'MSFT_TaskExecAction' -and $a.Execute) {
                $exe    = [Environment]::ExpandEnvironmentVariables($a.Execute.Trim('"'))
                $argStr = if ($a.Arguments) { [Environment]::ExpandEnvironmentVariables($a.Arguments) } else { '' }
                $detail = "runs: $exe $argStr"

                # a) executable lives in a user-writable location
                if ("$exe $argStr" -match $userWritable) { $reasons.Add('action in user-writable path') }

                # b) encoded / hidden / download-cradle arguments (LOLBin patterns)
                if ($argStr -match $lolbinArgs) { $reasons.Add('encoded/hidden/download-style arguments') }

                # c) SYSTEM or Highest privileges + user-writable binary = classic persistence
                if (($runAs -match 'SYSTEM' -or $runLevel -eq 'Highest') -and ("$exe" -match $userWritable)) {
                    $reasons.Add("elevated ($runAs/$runLevel) from user-writable path")
                }

                # d) resolve the binary on disk: missing, or unsigned outside trusted dirs
                $exePath = $exe
                if ($exePath -and -not [IO.Path]::IsPathRooted($exePath)) {
                    $cmd = Get-Command $exePath -ErrorAction SilentlyContinue
                    if ($cmd) { $exePath = $cmd.Source }
                }
                if ($exePath -and [IO.Path]::IsPathRooted($exePath)) {
                    if (-not (Test-Path -LiteralPath $exePath)) {
                        if ($t.State -ne 'Disabled') { $reasons.Add('target binary MISSING (broken/leftover task)') }
                    }
                    elseif ($exePath -notmatch '^[A-Z]:\\Windows\\|^[A-Z]:\\Program Files') {
                        $sig = Get-AuthenticodeSignature -LiteralPath $exePath -ErrorAction SilentlyContinue
                        if ($sig -and $sig.Status -ne 'Valid') { $reasons.Add("unsigned binary outside trusted dirs ($($sig.Status))") }
                    }
                }
            }
            # ---- COM handler actions: resolve CLSID -> DLL and inspect it ----
            elseif ($a.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction' -and $a.ClassId) {
                $dll = $null
                foreach ($hive in "HKLM:\SOFTWARE\Classes\CLSID\$($a.ClassId)\InprocServer32",
                                  "HKLM:\SOFTWARE\Classes\WOW6432Node\CLSID\$($a.ClassId)\InprocServer32") {
                    $v = (Get-ItemProperty $hive -ErrorAction SilentlyContinue).'(default)'
                    if ($v) { $dll = [Environment]::ExpandEnvironmentVariables($v.Trim('"')); break }
                }
                if ($dll) {
                    $detail = "COM handler $($a.ClassId) -> $dll"
                    if ($dll -match $userWritable) { $reasons.Add('COM handler DLL in user-writable path') }
                    elseif ($dll -notmatch '^[A-Z]:\\Windows\\|^[A-Z]:\\Program Files' -and (Test-Path -LiteralPath $dll)) {
                        $sig = Get-AuthenticodeSignature -LiteralPath $dll -ErrorAction SilentlyContinue
                        if ($sig -and $sig.Status -ne 'Valid') { $reasons.Add("unsigned COM handler DLL ($($sig.Status))") }
                    }
                } elseif (-not $isMsPath) { $detail = "COM handler $($a.ClassId) (CLSID not resolvable)" }
            }
        }

        # e) hidden task outside \Microsoft\ - a favorite malware trick
        if ($isHidden -and -not $isMsPath) { $reasons.Add('HIDDEN task outside \Microsoft\') }

        # f) task registered directly in the root folder "\" by a non-Microsoft author
        if ($t.TaskPath -eq '\' -and $author -notmatch $safeAuthors -and $reasons.Count -gt 0) {
            $reasons.Add('registered in scheduler root')
        }

        # g) recently created non-Microsoft task (last 30 days)
        if (-not $isMsPath -and $t.Date) {
            try {
                $regDate = [datetime]$t.Date
                if ($regDate -gt (Get-Date).AddDays(-30)) { $reasons.Add(("registered recently ({0:yyyy-MM-dd})" -f $regDate)) }
            } catch {}
        }

        if ($reasons.Count -gt 0) {
            $stats.Flagged++
            [void]$flaggedIds.Add($full)
            # Severity: HIGH if any strong indicator, else MEDIUM; broken/recent-only = LOW
            $strong = $reasons | Where-Object { $_ -match 'user-writable|encoded|HIDDEN|elevated|COM handler DLL' }
            $weakOnly = -not $strong
            $sev = if ($strong) {'HIGH'} elseif ($reasons -match 'MISSING|recently') {'LOW'} else {'MEDIUM'}
            if ($weakOnly -and $reasons.Count -eq 1 -and $reasons[0] -match 'recently') { $sev = 'LOW' }
            Add-Finding -Category 'Task Scheduler' -Severity $sev -Type 'ScheduledTask' -Data $full -Description (
                "{0}  [{1}]  ({2})  {3}  | Author: {4} | RunAs: {5}/{6}" -f $full, ($reasons -join '; '), $t.State, $detail, $author, $runAs, $runLevel)
        }
    }

    # --- Inventory of all enabled non-Microsoft tasks (context, informational) ---
    Write-Line "`n  Enabled non-Microsoft tasks (review that you recognize each):" White
    $allTasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object {
        $full = "$($_.TaskPath)$($_.TaskName)"
        $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
        $mark = if ($flaggedIds.Contains($full)) { ' <-- FLAGGED' } else { '' }
        Write-Line ("    {0}  ->  {1}{2}" -f $full, $act.Trim(), $mark)
    }

    # --- Logon & boot triggered tasks (persistence surface) ---
    Write-Line "`n  Non-Microsoft tasks that fire at LOGON or BOOT:" White
    $persist = $allTasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | Where-Object {
        $_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'LogonTrigger|BootTrigger' }
    }
    if ($persist) { $persist | ForEach-Object { Write-Line ("    {0}{1}" -f $_.TaskPath, $_.TaskName) } }
    else { Write-Line "    None." Green }

    # --- Orphan check: task XML files on disk without a registered task ---
    Write-Line "`n  Cross-checking task store on disk vs registered tasks..." White
    $registered = @($allTasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
    $orphans = 0
    Get-ChildItem "$env:SystemRoot\System32\Tasks" -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = '\' + $_.FullName.Substring("$env:SystemRoot\System32\Tasks\".Length).Replace('\','\')
        if ($rel -notin $registered) {
            $orphans++
            if ($orphans -le 10) {
                Add-Finding -Category 'Task Scheduler' -Severity 'MEDIUM' -Type 'File' -Data $_.FullName -Description (
                    "Task XML on disk with NO registered task (possible tampering/leftover): {0}" -f $rel)
            }
        }
    }
    if ($orphans -eq 0) { Write-Line "    Task store and registry are consistent." Green }
    elseif ($orphans -gt 10) { Write-Line ("    ...plus {0} more orphaned task files (see report)." -f ($orphans-10)) Yellow }

    Write-Line ""
    Write-Line ("  Task totals: {0} tasks | {1} enabled | {2} hidden | {3} outside \Microsoft\ | {4} FLAGGED" -f
        $stats.Total, $stats.Enabled, $stats.Hidden, $stats.NonMicrosoftPath, $stats.Flagged) White
    Write-Line "  NOTE: many legitimate apps (browsers, GPU tools, updaters) live outside" DarkYellow
    Write-Line "  \Microsoft\ and may trip 'recently registered'. Flags are leads, not verdicts." DarkYellow
}

# ==============================================================================
# 8. DRIVER AUDIT
# ==============================================================================
function Invoke-DriverAudit {
    Write-Section "8. DRIVER AUDIT"
    Write-Line "  Enumerating signed drivers (this takes a moment)..." Yellow

    # Devices reporting problems
    $problemDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Error' -or $_.Problem -ne 0 -and $_.Present }
    if ($problemDevices) {
        Write-Line "`n  Devices reporting problems:" White
        foreach ($d in $problemDevices) {
            Add-Finding -Category 'Driver' -Severity 'MEDIUM' -Type 'Info' -Description (
                "Device error: {0}  (status {1}, problem code {2})" -f $d.FriendlyName, $d.Status, $d.Problem)
        }
    } else { Write-Line "  No devices reporting driver errors." Green }

    # Old third-party drivers
    $cutoff = (Get-Date).AddYears(-4)
    $drivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.DriverProviderName -and $_.DriverProviderName -ne 'Microsoft' -and $_.DriverDate -and $_.DeviceName }

    Write-Line ("`n  Third-party drivers installed: {0}" -f ($drivers | Select-Object -Unique InfName).Count)
    Write-Line "  Third-party drivers older than 4 years:" White

    $old = $drivers | Where-Object { $_.DriverDate -lt $cutoff } |
           Sort-Object DriverDate | Select-Object -Unique DeviceName, DriverProviderName, DriverVersion, DriverDate, InfName
    if ($old) {
        foreach ($d in $old | Select-Object -First 40) {
            # Only offer removal for drivers backed by an oem*.inf third-party package
            $type = if ($d.InfName -like 'oem*.inf') { 'Driver' } else { 'Info' }
            Add-Finding -Category 'Driver' -Severity 'LOW' -Type $type -Data $d.InfName -Description (
                "{0}  |  {1} v{2}  |  dated {3:yyyy-MM-dd}  |  {4}" -f $d.DeviceName, $d.DriverProviderName, $d.DriverVersion, $d.DriverDate, $d.InfName)
        }
        Write-Line "`n  NOTE: 'Old' does not always mean 'broken'. Prefer updating via Windows" DarkYellow
        Write-Line "  Update or the manufacturer's site. Only remove drivers for hardware you" DarkYellow
        Write-Line "  no longer own. Removing an in-use driver can disable the device." DarkYellow
    } else { Write-Line "  None found - drivers are reasonably current." Green }

    # Pending Windows Update driver updates
    Write-Line "`n  Checking Windows Update for available driver updates..." White
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and Type='Driver'")
        if ($result.Updates.Count -gt 0) {
            foreach ($u in $result.Updates) {
                Add-Finding -Category 'Driver' -Severity 'LOW' -Type 'Info' -Description "Driver update available via Windows Update: $($u.Title)"
            }
        } else { Write-Line "    No driver updates pending in Windows Update." Green }
    } catch { Write-Line "    Windows Update query failed: $($_.Exception.Message)" Yellow }
}

# ==============================================================================
# 9. WINDOWS 11 BLOAT AUDIT
# ==============================================================================
function Invoke-BloatAudit {
    Write-Section "9. WINDOWS 11 BLOAT AUDIT"
    Write-Line "  Enumerating preinstalled apps, telemetry settings, and UI clutter..." Yellow

    # --------------------------------------------------------- 8a. AppX bloat
    # Pattern -> friendly label. Only flagged if actually installed.
    $bloatApps = [ordered]@{
        'Microsoft.549981C3F5F10'            = 'Cortana'
        'Microsoft.Copilot'                  = 'Copilot app'
        'Microsoft.Windows.Ai.Copilot*'      = 'Copilot provider'
        'Microsoft.BingNews'                 = 'Bing News'
        'Microsoft.BingWeather'              = 'Bing Weather'
        'Microsoft.BingSearch'               = 'Bing Search'
        'Microsoft.GamingApp'                = 'Xbox app'
        'Microsoft.Xbox.TCUI'                = 'Xbox TCUI'
        'Microsoft.XboxGameOverlay'          = 'Xbox Game Overlay'
        'Microsoft.XboxGamingOverlay'        = 'Xbox Game Bar'
        'Microsoft.XboxIdentityProvider'     = 'Xbox Identity Provider'
        'Microsoft.XboxSpeechToTextOverlay'  = 'Xbox Speech Overlay'
        'Microsoft.GetHelp'                  = 'Get Help'
        'Microsoft.Getstarted'               = 'Tips / Get Started'
        'Microsoft.WindowsFeedbackHub'       = 'Feedback Hub'
        'Microsoft.Microsoft3DViewer'        = '3D Viewer'
        'Microsoft.MicrosoftOfficeHub'       = 'Office Hub promo app'
        'Microsoft.MicrosoftSolitaireCollection' = 'Solitaire Collection'
        'Microsoft.MixedReality.Portal'      = 'Mixed Reality Portal'
        'Microsoft.People'                   = 'People'
        'Microsoft.PowerAutomateDesktop'     = 'Power Automate'
        'Microsoft.Todos'                    = 'Microsoft To Do'
        'Microsoft.WindowsAlarms'            = 'Alarms & Clock'
        'Microsoft.WindowsMaps'              = 'Maps'
        'Microsoft.WindowsSoundRecorder'     = 'Sound Recorder'
        'Microsoft.YourPhone'                = 'Phone Link'
        'MicrosoftWindows.CrossDevice'       = 'Cross Device Experience'
        'Microsoft.ZuneMusic'                = 'Media Player (Zune Music)'
        'Microsoft.ZuneVideo'                = 'Movies & TV'
        'Microsoft.OutlookForWindows'        = 'New Outlook (preinstalled)'
        'Microsoft.Windows.DevHome'          = 'Dev Home'
        'MicrosoftTeams'                     = 'Teams (consumer)'
        'MSTeams'                            = 'Teams (consumer)'
        'Clipchamp.Clipchamp'                = 'Clipchamp'
        'MicrosoftCorporationII.QuickAssist' = 'Quick Assist (also a remote-access vector)'
        'MicrosoftCorporationII.MicrosoftFamily' = 'Family Safety'
        'Microsoft.OneConnect'               = 'Mobile Plans'
        'Microsoft.SkypeApp'                 = 'Skype'
        'Microsoft.Wallet'                   = 'Wallet'
        'Microsoft.Messaging'                = 'Messaging'
        'Microsoft.Print3D'                  = 'Print 3D'
        'Microsoft.OneDriveSync'             = 'OneDrive sync (Store version)'
        # Third-party sponsored preinstalls
        'king.com.*'                         = 'Candy Crush / King games'
        'SpotifyAB.SpotifyMusic'             = 'Spotify (preinstalled)'
        'Disney.*'                           = 'Disney+'
        'BytedancePte.Ltd.TikTok'            = 'TikTok'
        'Facebook.Facebook*'                 = 'Facebook'
        'Facebook.Instagram*'                = 'Instagram'
        '*Netflix*'                          = 'Netflix'
        'AmazonVideo.PrimeVideo'             = 'Prime Video'
        '*Twitter*'                          = 'Twitter/X'
        '*LinkedIn*'                         = 'LinkedIn (preinstalled)'
        '*McAfee*'                           = 'McAfee trial'
        '*Norton*'                           = 'Norton trial'
        '*ESPN*'                             = 'ESPN'
        '*Duolingo*'                         = 'Duolingo (preinstalled)'
        '*HiddenCity*'                       = 'Hidden City game'
        '*AdobeSystemsIncorporated.AdobePhotoshopExpress*' = 'Photoshop Express (preinstalled)'
        '*Dolby*'                            = 'Dolby promo app'
        '*.WhatsAppDesktop'                  = 'WhatsApp (preinstalled)'
        '*Booking*'                          = 'Booking.com'
    }

    $installedAppx = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    $provisioned   = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    $foundBloat = 0
    foreach ($entry in $bloatApps.GetEnumerator()) {
        $hit = $installedAppx | Where-Object { $_.Name -like $entry.Key } | Select-Object -First 1
        $prov = $provisioned | Where-Object { $_.DisplayName -like $entry.Key } | Select-Object -First 1
        if ($hit -or $prov) {
            $foundBloat++
            Add-Finding -Category 'Bloat' -Severity 'LOW' -Type 'Appx' -Data $entry.Key -Description (
                "{0}  [{1}]" -f $entry.Value, $(if ($hit) { $hit.Name } else { $prov.DisplayName }))
        }
    }
    Write-Line ("  Removable preinstalled apps found: {0}" -f $foundBloat) White

    # --------------------------------------------------- 8b. OneDrive (win32)
    $odSetup = @("$env:SystemRoot\System32\OneDriveSetup.exe", "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ((Get-Process OneDrive -ErrorAction SilentlyContinue) -or (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe")) {
        Add-Finding -Category 'Bloat' -Severity 'LOW' -Type 'OneDrive' -Data $odSetup -Description (
            'OneDrive is installed. Remove ONLY if you do not sync files with it - local copies of already-synced files remain on disk.')
    }

    # ------------------------------------------------ 8c. Optional capabilities
    $bloatCaps = @{
        'Browser.InternetExplorer*' = 'Internet Explorer mode files'
        'MathRecognizer*'           = 'Math Recognizer'
        'Microsoft.Windows.WordPad*'= 'WordPad'
        'App.StepsRecorder*'        = 'Steps Recorder'
        'Media.WindowsMediaPlayer*' = 'Windows Media Player (legacy)'
        'Hello.Face*'               = 'Windows Hello Face (only if you never use face login)'
    }
    $caps = Get-WindowsCapability -Online -ErrorAction SilentlyContinue | Where-Object State -eq 'Installed'
    foreach ($entry in $bloatCaps.GetEnumerator()) {
        $cap = $caps | Where-Object { $_.Name -like $entry.Key } | Select-Object -First 1
        if ($cap) {
            Add-Finding -Category 'Bloat' -Severity 'LOW' -Type 'Capability' -Data $cap.Name -Description ("Optional capability: {0}" -f $entry.Value)
        }
    }

    # ---------------------------------------------- 8d. Telemetry & ad tweaks
    # Each is a self-contained set of registry writes, applied only if you pick Remove.
    $tweaks = @(
        @{ Desc = 'Telemetry: set diagnostic data to minimum + disable DiagTrack service'
           Reg  = @(
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Value=0}
             @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'; Name='AllowTelemetry'; Value=0})
           Svc  = @('DiagTrack','dmwappushservice') }
        @{ Desc = 'Advertising ID: disable personalized ads'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name='Enabled'; Value=0}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name='DisabledByGroupPolicy'; Value=1}) }
        @{ Desc = 'Start menu & Settings ads: disable suggestions, promoted apps, tips'
           Reg  = @(
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-338388Enabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-338389Enabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-353694Enabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-353696Enabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SilentInstalledAppsEnabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SystemPaneSuggestionsEnabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SoftLandingEnabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='Start_IrisRecommendations'; Value=0}) }
        @{ Desc = 'Lock screen: disable Spotlight fun facts & tips'
           Reg  = @(
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='RotatingLockScreenOverlayEnabled'; Value=0}
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContent-338387Enabled'; Value=0}) }
        @{ Desc = 'Taskbar: remove Widgets button'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='TaskbarDa'; Value=0}) }
        @{ Desc = 'Taskbar: remove Chat/Teams button'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='TaskbarMn'; Value=0}) }
        @{ Desc = 'Taskbar: remove Copilot button + disable Copilot via policy'
           Reg  = @(
             @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='ShowCopilotButton'; Value=0}
             @{Path='HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot'; Name='TurnOffWindowsCopilot'; Value=1}
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Name='TurnOffWindowsCopilot'; Value=1}) }
        @{ Desc = 'Start menu search: disable Bing web results'
           Reg  = @(@{Path='HKCU:\Software\Policies\Microsoft\Windows\Explorer'; Name='DisableSearchBoxSuggestions'; Value=1}) }
        @{ Desc = 'Windows Recall / AI data analysis: disable (24H2+)'
           Reg  = @(@{Path='HKCU:\Software\Policies\Microsoft\Windows\WindowsAI'; Name='DisableAIDataAnalysis'; Value=1}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name='DisableAIDataAnalysis'; Value=1}) }
        @{ Desc = 'Tailored experiences: stop diagnostic data being used for ads/tips'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Name='TailoredExperiencesWithDiagnosticDataEnabled'; Value=0}) }
        @{ Desc = 'Activity history / Timeline: stop publishing & uploading activities'
           Reg  = @(
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableActivityFeed'; Value=0}
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='PublishUserActivities'; Value=0}
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='UploadUserActivities'; Value=0}) }
        @{ Desc = '"Finish setting up your device" nag screen: disable'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'; Name='ScoobeSystemSettingEnabled'; Value=0}) }
        @{ Desc = 'Game Bar / Game DVR background recording: disable'
           Reg  = @(
             @{Path='HKCU:\System\GameConfigStore'; Name='GameDVR_Enabled'; Value=0}
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name='AllowGameDVR'; Value=0}) }
        @{ Desc = 'Edge: disable startup boost & background preloading'
           Reg  = @(
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='StartupBoostEnabled'; Value=0}
             @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='BackgroundModeEnabled'; Value=0}) }
        @{ Desc = 'Feedback nags: never ask for feedback'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Siuf\Rules'; Name='NumberOfSIUFInPeriod'; Value=0}
                   @{Path='HKCU:\Software\Microsoft\Siuf\Rules'; Name='PeriodInNanoSeconds'; Value=0}) }
        # ---- Win11Debloat-inspired additions ----
        @{ Desc = 'Click to Do (AI text/image analysis): disable + stop WSAIFabricSvc auto-start'
           Reg  = @(@{Path='HKCU:\Software\Policies\Microsoft\Windows\WindowsAI'; Name='DisableClickToDo'; Value=1}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name='DisableClickToDo'; Value=1})
           Svc  = @('WSAIFabricSvc') }
        @{ Desc = 'Paint AI features (Cocreator, Image Creator, Generative Fill): disable'
           Reg  = @(@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Paint'; Name='DisableCocreator'; Value=1}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Paint'; Name='DisableImageCreator'; Value=1}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Paint'; Name='DisableGenerativeFill'; Value=1}) }
        @{ Desc = 'Notepad AI features (Rewrite): disable'
           Reg  = @(@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Notepad'; Name='DisableAIFeatures'; Value=1}) }
        @{ Desc = 'Edge: disable Copilot sidebar + MSN news feed on new tab page'
           Reg  = @(@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='HubsSidebarEnabled'; Value=0}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='NewTabPageContentEnabled'; Value=0}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ShowRecommendationsEnabled'; Value=0}) }
        @{ Desc = 'Settings app: hide the "Home" page with its Microsoft 365/OneDrive ads'
           Reg  = @(@{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='SettingsPageVisibility'; Value='hide:home'; Kind='String'}) }
        @{ Desc = 'Taskbar search box: disable Search Highlights (dynamic/branded content)'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name='IsDynamicSearchBoxEnabled'; Value=0}
                   @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='EnableDynamicContentInWSB'; Value=0}) }
        @{ Desc = 'Windows search: disable local device search history'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name='IsDeviceSearchHistoryEnabled'; Value=0}) }
        @{ Desc = 'App-launch tracking (used for Start menu suggestions): disable'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='Start_TrackProgs'; Value=0}) }
    )
    foreach ($t in $tweaks) {
        Add-Finding -Category 'Bloat' -Severity 'LOW' -Type 'RegTweak' -Data $t -Description $t.Desc
    }

    # ------------------------------------------- 8e. Telemetry scheduled tasks
    $ceipTasks = '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
                 '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
                 '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
                 '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
                 '\Microsoft\Windows\Autochk\Proxy',
                 '\Microsoft\Windows\Feedback\Siuf\DmClient',
                 '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
    foreach ($tp in $ceipTasks) {
        $name = Split-Path $tp -Leaf; $path = (Split-Path $tp) + '\'
        $task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Disabled') {
            Add-Finding -Category 'Bloat' -Severity 'LOW' -Type 'ScheduledTask' -Data $tp -Description "Telemetry/CEIP scheduled task active: $tp"
        }
    }

    # -------------------------------- 9f. Customizations (Win11Debloat-style)
    # These are preference tweaks, not bloat - kept in their own category so the
    # bulk "remove all bloat" option never touches them.
    $customize = @(
        @{ Desc = 'Taskbar: align icons to the LEFT (classic style)'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='TaskbarAl'; Value=0}) }
        @{ Desc = 'Taskbar: hide the Task View button'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='ShowTaskViewButton'; Value=0}) }
        @{ Desc = 'Taskbar: shrink search box to icon only'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Name='SearchboxTaskbarMode'; Value=1}) }
        @{ Desc = 'Taskbar: enable "End Task" in app right-click menu'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'; Name='TaskbarEndTask'; Value=1}) }
        @{ Desc = 'Context menu: restore the full Windows 10 style right-click menu'
           Reg  = @(@{Path='HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32'; Name='(default)'; Value=''; Kind='String'}) }
        @{ Desc = 'File Explorer: show file extensions for known types (helps spot fake .pdf.exe files!)'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='HideFileExt'; Value=0}) }
        @{ Desc = 'File Explorer: show hidden files, folders and drives'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='Hidden'; Value=1}) }
        @{ Desc = 'Start menu: hide the Recommended section (policy; full effect on some editions)'
           Reg  = @(@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='HideRecommendedSection'; Value=1}) }
        @{ Desc = 'Mouse: turn OFF Enhance Pointer Precision (mouse acceleration)'
           Reg  = @(@{Path='HKCU:\Control Panel\Mouse'; Name='MouseSpeed'; Value='0'; Kind='String'}
                   @{Path='HKCU:\Control Panel\Mouse'; Name='MouseThreshold1'; Value='0'; Kind='String'}
                   @{Path='HKCU:\Control Panel\Mouse'; Name='MouseThreshold2'; Value='0'; Kind='String'}) }
        @{ Desc = 'Keyboard: disable the Sticky Keys shortcut (5x Shift popup)'
           Reg  = @(@{Path='HKCU:\Control Panel\Accessibility\StickyKeys'; Name='Flags'; Value='506'; Kind='String'}) }
        @{ Desc = 'Storage Sense: disable automatic disk cleanup'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'; Name='01'; Value=0}) }
        @{ Desc = 'Theme: enable dark mode for system and apps'
           Reg  = @(@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name='AppsUseLightTheme'; Value=0}
                   @{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name='SystemUsesLightTheme'; Value=0}) }
    )
    foreach ($t in $customize) {
        Add-Finding -Category 'Customize' -Severity 'LOW' -Type 'RegTweak' -Data $t -Description $t.Desc
    }

    Write-Line "`n  NOTE: Removed Store apps can be reinstalled any time from Microsoft Store." DarkYellow
    Write-Line "  Taskbar/Start tweaks take effect after signing out or restarting Explorer." DarkYellow
}

# ==============================================================================
# 10. INTERACTIVE REVIEW  (Remove / Quarantine / Keep)
# ==============================================================================
function Invoke-FindingAction {
    param($f, [string]$ans)
    try {
        switch ($f.Type) {
            'File' {
                if ($ans -eq 'Q') {
                    if (-not (Test-Path $Quarantine)) { New-Item $Quarantine -ItemType Directory -Force | Out-Null }
                    $dest = Join-Path $Quarantine ([IO.Path]::GetFileName($f.Data) + '.quarantined')
                    Move-Item -LiteralPath $f.Data -Destination $dest -Force
                    Write-Host "      Quarantined to $dest`n" -ForegroundColor Green
                } else {
                    $sure = Read-Host "      PERMANENTLY delete '$($f.Data)'? Type YES to confirm"
                    if ($sure -ceq 'YES') { Remove-Item -LiteralPath $f.Data -Force; Write-Host "      Deleted.`n" -ForegroundColor Green }
                    else { Write-Host "      Skipped (not confirmed).`n" -ForegroundColor Gray }
                }
            }
            'RegistryValue' {
                Remove-ItemProperty -Path $f.Data.Key -Name $f.Data.Name -Force
                Write-Host "      Startup entry removed.`n" -ForegroundColor Green
            }
            'ScheduledTask' {
                $tp = Split-Path $f.Data; $tn = Split-Path $f.Data -Leaf
                Disable-ScheduledTask -TaskPath "$tp\" -TaskName $tn | Out-Null
                Write-Host "      Task disabled (not deleted, so it can be re-enabled if legitimate).`n" -ForegroundColor Green
            }
            'Service' {
                Stop-Service -Name $f.Data -Force -ErrorAction SilentlyContinue
                Set-Service  -Name $f.Data -StartupType Disabled
                Write-Host "      Service stopped and disabled.`n" -ForegroundColor Green
            }
            'Program' {
                Write-Host "      Uninstall command: $($f.Data)" -ForegroundColor White
                $run = Read-Host "      Launch the uninstaller now? [Y/N]"
                if ($run -match '^[Yy]') { Start-Process cmd.exe -ArgumentList "/c", $f.Data; Write-Host "      Uninstaller launched.`n" -ForegroundColor Green }
                else { Write-Host "      Skipped.`n" -ForegroundColor Gray }
            }
            'Driver' {
                Write-Host "      WARNING: removing a driver package can disable the device that uses it." -ForegroundColor Red
                $sure = Read-Host "      Remove driver package '$($f.Data)' via pnputil? Type YES to confirm"
                if ($sure -ceq 'YES') {
                    & pnputil.exe /delete-driver $f.Data /uninstall
                    Write-Host "      pnputil executed (see output above).`n" -ForegroundColor Green
                } else { Write-Host "      Skipped (not confirmed).`n" -ForegroundColor Gray }
            }
            'Threat' {
                Remove-MpThreat -ThreatID $f.Data -ErrorAction Stop
                Write-Host "      Defender remediation triggered for threat.`n" -ForegroundColor Green
            }
            'Appx' {
                Get-AppxPackage -AllUsers -Name $f.Data -ErrorAction SilentlyContinue |
                    ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }
                Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like $f.Data } |
                    ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null }
                Write-Host "      App removed (deprovisioned for new users too). Reinstallable from Store.`n" -ForegroundColor Green
            }
            'Capability' {
                Remove-WindowsCapability -Online -Name $f.Data -ErrorAction Stop | Out-Null
                Write-Host "      Capability removed (re-addable via Settings > Optional features).`n" -ForegroundColor Green
            }
            'RegTweak' {
                foreach ($r in $f.Data.Reg) {
                    if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
                    $kind = if ($r.Kind) { $r.Kind } else { 'DWord' }
                    if ($r.Name -eq '(default)') {
                        Set-Item -Path $r.Path -Value $r.Value | Out-Null
                    } else {
                        New-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -PropertyType $kind -Force | Out-Null
                    }
                }
                if ($f.Data.Svc) {
                    foreach ($s in $f.Data.Svc) {
                        Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                        Set-Service  -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
                    }
                }
                Write-Host "      Tweak applied.`n" -ForegroundColor Green
            }
            'OneDrive' {
                $sure = Read-Host "      Uninstall OneDrive? Synced files stay in the cloud + local copies remain. Type YES to confirm"
                if ($sure -ceq 'YES') {
                    Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
                    if ($f.Data) { Start-Process $f.Data -ArgumentList '/uninstall' -Wait }
                    else { & winget uninstall --id Microsoft.OneDrive --silent }
                    Write-Host "      OneDrive uninstall executed.`n" -ForegroundColor Green
                } else { Write-Host "      Skipped (not confirmed).`n" -ForegroundColor Gray }
            }
        }
        return $true
    } catch {
        Write-Host "      FAILED: $($_.Exception.Message)`n" -ForegroundColor Red
        [void]$Report.AppendLine("      Action FAILED: $($_.Exception.Message)")
        return $false
    }
}

function Invoke-Review {
    Write-Section "10. REVIEW & CLEANUP"

    if ($Findings.Count -eq 0) {
        Write-Line "  Nothing was flagged. Your system looks clean." Green
        return
    }

    Write-Line ("  Total findings: {0}   (HIGH: {1}, MEDIUM: {2}, LOW: {3})" -f $Findings.Count,
        ($Findings | Where-Object Severity -eq 'HIGH').Count,
        ($Findings | Where-Object Severity -eq 'MEDIUM').Count,
        ($Findings | Where-Object Severity -eq 'LOW').Count) White

    $actionable = @($Findings | Where-Object Type -ne 'Info')
    $infoOnly   = @($Findings | Where-Object Type -eq 'Info')

    if ($infoOnly) {
        Write-Line "`n  Informational findings (manual follow-up, no automated action):" White
        $infoOnly | ForEach-Object { Write-Line ("    [{0}] {1}" -f $_.Severity, $_.Description) }
    }

    if (-not $actionable) { Write-Line "`n  No findings support automated removal."; return }

    # ---- Bulk handling for Bloat and Customize categories ----
    foreach ($cat in 'Bloat','Customize') {
        $group = @($actionable | Where-Object Category -eq $cat)
        if ($group.Count -le 3) { continue }
        $label = if ($cat -eq 'Bloat') { 'bloat items (preinstalled apps, telemetry, ads, AI features)' } else { 'optional customizations (taskbar, Explorer, mouse, theme)' }
        Write-Host ""
        Write-Host ("  {0} {1} were found." -f $group.Count, $label) -ForegroundColor White
        $group | ForEach-Object { Write-Host ("    #{0}  {1}" -f $_.Id, $_.Description) -ForegroundColor DarkGray }
        do { $bulk = (Read-Host "`n  ${cat}: [A]pply/remove ALL of the above / [I]ndividual prompts / [K]eep all as-is").ToUpper() } until ($bulk -in 'A','I','K')
        if ($bulk -eq 'A') {
            foreach ($f in $group) {
                Write-Host ("  Applying #{0}: {1}" -f $f.Id, $f.Description) -ForegroundColor Yellow
                [void](Invoke-FindingAction $f 'R')
                [void]$Report.AppendLine("  #$($f.Id) -> bulk applied ($($f.Description))")
            }
            $actionable = @($actionable | Where-Object Category -ne $cat)
        } elseif ($bulk -eq 'K') {
            Write-Host "  All $cat items kept as-is." -ForegroundColor Gray
            $actionable = @($actionable | Where-Object Category -ne $cat)
        }
        # 'I' falls through: items stay in the per-item loop below
    }

    if (-not $actionable) { return }

    Write-Line "`n  --- Actionable findings ---" White
    Write-Line "  For each item choose: [R]emove  [Q]uarantine (files only)  [K]eep`n"

    foreach ($f in $actionable) {
        Write-Host ("  #{0} [{1}] [{2}] {3}" -f $f.Id, $f.Severity, $f.Category, $f.Description) -ForegroundColor $(if($f.Severity -eq 'HIGH'){'Red'}elseif($f.Severity -eq 'MEDIUM'){'Yellow'}else{'Gray'})
        $valid = if ($f.Type -eq 'File') {'R','Q','K'} else {'R','K'}
        do { $ans = (Read-Host ("      Action [{0}]" -f ($valid -join '/'))).ToUpper() } until ($ans -in $valid)
        [void]$Report.AppendLine("  #$($f.Id) -> user chose: $ans  ($($f.Description))")

        if ($ans -eq 'K') { Write-Host "      Kept.`n" -ForegroundColor Gray; continue }
        [void](Invoke-FindingAction $f $ans)
    }

    # Offer Explorer restart so taskbar/Start tweaks show immediately
    if ($Findings | Where-Object { $_.Type -eq 'RegTweak' }) {
        $re = Read-Host "`n  Restart Explorer now so taskbar/Start changes take effect? [Y/N]"
        if ($re -match '^[Yy]') { Stop-Process -Name explorer -Force; Write-Host "  Explorer restarted." -ForegroundColor Green }
    }
}

# ==============================================================================
# MAIN
# ==============================================================================
Clear-Host
Write-Host @"
================================================================================
   WINDOWS 11 DEEP DIAGNOSTIC & SECURITY SWEEP
   Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm')
   Report  : $ReportPath
================================================================================
"@ -ForegroundColor Cyan
[void]$Report.AppendLine("PC Security Audit - $(Get-Date)")
[void]$Report.AppendLine("Machine: $env:COMPUTERNAME  User: $env:USERNAME")

Show-Hardware
Show-DriveHealth
Invoke-MalwareCheck
Invoke-IntegrityChecks
Invoke-RemoteAccessAudit
Invoke-SuspiciousFileSweep
Invoke-TaskSchedulerDeepScan
Invoke-DriverAudit
Invoke-BloatAudit
Invoke-Review

# ------------------------------------------------------------------ wrap up
Write-Section "DONE"
$elapsed = (Get-Date) - $StartTime
Write-Line ("  Completed in {0:mm} min {0:ss} sec." -f $elapsed)
Write-Line ("  Full report saved to: {0}" -f $ReportPath) White
if (Test-Path $Quarantine) { Write-Line ("  Quarantined files are in: {0}" -f $Quarantine) White }
$Report.ToString() | Out-File -FilePath $ReportPath -Encoding UTF8
Read-Host "`nPress Enter to exit"
