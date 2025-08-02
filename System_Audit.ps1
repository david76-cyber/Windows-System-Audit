# System_Audit.ps1 - Modular System Inventory and Security Audit Tool

# =========================
# 🚨 ADMIN PRIVILEGE CHECK
# =========================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "⚠️ Please run this script as Administrator for full results."
}

# =========================
# 📁 Set Report Path
# =========================
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = "$PSScriptRoot\System_Audit_Report_$timestamp.txt"

# =========================
# 📦 Utility: Write Section
# =========================
function Write-Section($title) {
    Add-Content -Path $reportPath -Value "`n=== $title ===`n"
}

# =========================
# 🧠 System Info
# =========================
function Get-SystemInfo {
    Write-Section "System Info"
    Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory | Out-String | Add-Content $reportPath
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime | Out-String | Add-Content $reportPath
}

# =========================
# 💽 Storage Info
# =========================
function Get-StorageInfo {
    Write-Section "Storage Info"
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $sizeGB = $_.Size / 1GB
        $freeGB = $_.FreeSpace / 1GB
        Add-Content $reportPath ("Drive {0}: {1} | {2:N2} GB free of {3:N2} GB" -f $_.DeviceID, $_.VolumeName, $freeGB, $sizeGB)
    }
}

# =========================
# 🌐 Network Config
# =========================
function Get-NetworkInfo {
    Write-Section "Network Info"
    Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, AddressFamily | Out-String | Add-Content $reportPath
    ipconfig /all | Out-String | Add-Content $reportPath
}

# =========================
# 🦠 Antivirus Status
# =========================
function Get-AntivirusStatus {
    Write-Section "Antivirus Status"
    Try {
        Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled | Out-String | Add-Content $reportPath
    } Catch {
        Add-Content $reportPath "Defender not available or access denied."
    }
    Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct | Select displayName, productState | Out-String | Add-Content $reportPath
}

# =========================
# 🔐 BitLocker Status
# =========================
function Get-BitLockerStatus {
    Write-Section "BitLocker Status"
    Try {
        Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod | Out-String | Add-Content $reportPath
    } Catch {
        Add-Content $reportPath "BitLocker check failed or not available."
    }
}

# =========================
# 📦 Installed Software (Top 10)
# =========================
function Get-InstalledApps {
    Write-Section "Installed Software (Top 10)"
    Try {
        $apps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\Uninstall\* | 
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
            Sort-Object InstallDate -Descending | Select-Object -First 10
        $apps | Format-Table -AutoSize | Out-String | Add-Content $reportPath
    } Catch {
        Add-Content $reportPath "Unable to access installed applications."
    }
}

# =========================
# ⏱️ Uptime
# =========================
function Get-Uptime {
    Write-Section "System Uptime"
    $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    Add-Content $reportPath "Last boot time: $lastBoot"
    Add-Content $reportPath "System uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
}

# =========================
# 🚀 Run All Sections
# =========================
Write-Output "Running system audit..."
Get-SystemInfo
Get-StorageInfo
Get-NetworkInfo
Get-AntivirusStatus
Get-BitLockerStatus
Get-InstalledApps
Get-Uptime

Write-Output "✅ System audit complete. Report saved to: $reportPath"
