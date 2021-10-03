$action = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory (Get-Location) -Argument '-NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass -File Tailscale-Updater-Windows.ps1'
$trigger = New-ScheduledTaskTrigger -Daily -At 12:00
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Tailscale Updater" -Description "Daily Tailscale update" -User "NT AUTHORITY\SYSTEM"
