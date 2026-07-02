<#
  Zero-Trust Vault — automatic backup task installer.

  Creates a Windows Scheduled Task that runs backup-vault.ps1 automatically:
    • Daily at 3 AM (catches up if the PC was off, runs when it wakes)
    • At every user logon (if the last backup is >12 hours old)

  This gives you "always-backed-up" behaviour similar to Bitwarden's cloud
  sync — except the backup stays on YOUR machine and USB drives, not a server.

  Usage:
    Install (run once after setup):
      powershell -ExecutionPolicy Bypass -File install-backup-task.ps1

    Check task status:
      powershell -ExecutionPolicy Bypass -File install-backup-task.ps1 -Status

    Uninstall:
      powershell -ExecutionPolicy Bypass -File install-backup-task.ps1 -Uninstall
#>
param(
  [switch]$Uninstall,
  [switch]$Status
)

$ErrorActionPreference = "Stop"
$taskName   = "ZeroTrustVault-AutoBackup"
$backupScript = Join-Path $PSScriptRoot "backup-vault.ps1"

if (-not (Test-Path $backupScript)) {
  throw "backup-vault.ps1 not found at: $backupScript"
}

# ---- Status mode -------------------------------------------------------------

if ($Status) {
  $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if (-not $task) {
    Write-Host "Task '$taskName' is NOT registered." -ForegroundColor Yellow
    Write-Host "Run install-backup-task.ps1 (without flags) to install it."
  } else {
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    Write-Host "Task       : $taskName" -ForegroundColor Green
    Write-Host "State      : $($task.State)"
    Write-Host "Last run   : $($info.LastRunTime)"
    Write-Host "Last result: $($info.LastTaskResult) $(if ($info.LastTaskResult -eq 0) { '(success)' } else { '(non-zero exit)' })"
    Write-Host "Next run   : $($info.NextRunTime)"
  }
  exit 0
}

# ---- Uninstall mode ----------------------------------------------------------

if ($Uninstall) {
  $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if ($task) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Task '$taskName' removed." -ForegroundColor Green
  } else {
    Write-Host "Task '$taskName' was not registered — nothing to remove."
  }
  exit 0
}

# ---- Install -----------------------------------------------------------------

# The wrapper script: only runs backup if >12h since last run (for logon trigger).
# Avoids repeated backups if user logs off and on frequently.
$wrapperScript = @"
`$lastMarker = Join-Path `$env:LOCALAPPDATA "ZeroTrustVault\last_backup.txt"
`$doBackup   = `$true
if (Test-Path `$lastMarker) {
  `$last = [datetime]::ParseExact((Get-Content `$lastMarker).Trim(), "yyyy-MM-dd HH:mm:ss", `$null)
  if (([datetime]::UtcNow - `$last).TotalHours -lt 12) { `$doBackup = `$false }
}
if (`$doBackup) {
  & powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "$($backupScript -replace "'", "''")"
  [datetime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss") | Out-File -Encoding ASCII `$lastMarker -NoNewline
}
"@

$wrapperPath = Join-Path $env:LOCALAPPDATA "ZeroTrustVault\backup_runner.ps1"
New-Item -ItemType Directory -Force -Path (Split-Path $wrapperPath) | Out-Null
[System.IO.File]::WriteAllText($wrapperPath, $wrapperScript, [System.Text.UTF8Encoding]::new($false))

# Build scheduled task components
$action = New-ScheduledTaskAction `
  -Execute  "powershell.exe" `
  -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -File `"$wrapperPath`""

$triggers = @(
  # Daily at 3 AM — runs even if PC was asleep (StartWhenAvailable)
  (New-ScheduledTaskTrigger -Daily -At "03:00"),
  # At logon — catches the case where PC was off at 3 AM
  (New-ScheduledTaskTrigger -AtLogon)
)

$settings = New-ScheduledTaskSettingsSet `
  -ExecutionTimeLimit    (New-TimeSpan -Minutes 10) `
  -StartWhenAvailable                               `
  -RunOnlyIfNetworkAvailable:$false                 `
  -WakeToRun:$false                                 `
  -MultipleInstances     IgnoreNew

# Remove existing task before re-registering
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask `
  -TaskName   $taskName `
  -Action     $action `
  -Trigger    $triggers `
  -Settings   $settings `
  -RunLevel   Limited `
  -Description "Automatically backs up the Zero-Trust Vault encrypted vault file."

Write-Host ""
Write-Host "Backup task installed." -ForegroundColor Green
Write-Host "  Task name  : $taskName"
Write-Host "  Triggers   : Daily at 03:00 + at each logon (if backup >12h old)"
Write-Host "  Script     : $backupScript"
Write-Host "  Backups to : Documents\ZeroTrustVault\Backups\ + any connected USB drives"
Write-Host ""
Write-Host "Commands:" -ForegroundColor Cyan
Write-Host "  Check status : powershell -File install-backup-task.ps1 -Status"
Write-Host "  Remove task  : powershell -File install-backup-task.ps1 -Uninstall"
Write-Host "  Manual run   : powershell -File backup-vault.ps1"
Write-Host ""
Write-Host "Run backup once now to verify it works:"
$run = Read-Host "Run backup now? [Y/n]"
if ($run -ne 'n' -and $run -ne 'N') {
  & powershell.exe -ExecutionPolicy Bypass -File $backupScript
}
