# installer script v0.1.4
[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $unstable = $false,
    [Parameter()]
    [string]
    $path = "$env:ALLUSERSPROFILE\Tailscale-updater"
)

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}

if(-not (Test-Path -LiteralPath $path)){
    Write-Host "Creating directory: $path"
    $target = New-Item -Path $path -ItemType Directory
}

Try {
    $target = Get-Item -LiteralPath $path
    Write-Host "Installation target: $target"
    Get-ChildItem "Tailscale-Updater-Windows.ps1" | Copy-Item -Destination $target -Force
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $target.FullName -Argument ('-NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass -File Tailscale-Updater-Windows.ps1'+$(if($unstable){' -Track unstable'}))
    $trigger = New-ScheduledTaskTrigger -Daily -At 12:00
    # remove an existing task to allow for repeat usage/upgrades
    Get-ScheduledTask | Where-Object TaskName -like "Tailscale Updater" | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Tailscale Updater" -Description "Daily Tailscale update" -User "NT AUTHORITY\SYSTEM" | Out-Null
    Write-Host "Successfully installed scheduled task"
} Catch {
    $_ | Write-Error
}
