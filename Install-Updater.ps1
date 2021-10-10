# installer script v0.1.4
[CmdletBinding()]
param (
    [Parameter()] [switch] $unstable = $false,
    [Parameter()] [string] $path = "$env:ALLUSERSPROFILE\Tailscale-updater"
)

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch as an elevated process:
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" '-File',('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
    exit
}

if(-not (Test-Path -LiteralPath $path)){
    Write-Host "Creating directory: $path"
    $target = New-Item -Path $path -ItemType Directory -Force
}

Try {
    $target = Get-Item -LiteralPath $path
    Write-Host "Installation target: $target"
    Get-ChildItem 'Tailscale-Updater-Windows.ps1' | Copy-Item -Destination $target -Force
    [System.Object[]]$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -WorkingDirectory $target.FullName -Argument ('-NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass -File Tailscale-Updater-Windows.ps1'+$(if($unstable){' -Track unstable'}))
    [System.Object[]]$trigger = New-ScheduledTaskTrigger -Daily -At '12:00:00Z' -RandomDelay (New-TimeSpan -Hours 1)
    $trigger += New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 15)
    [System.Object]$principal = New-ScheduledTaskPrincipal -RunLevel Highest -LogonType ServiceAccount -UserId 'SYSTEM'
    [System.Object]$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -Compatibility Win8 -ExecutionTimeLimit (New-TimeSpan -Hours 1) -StartWhenAvailable
    # remove an existing task to allow for repeat usage/upgrades
    Get-ScheduledTask | Where-Object TaskName -like "Tailscale Updater" | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -TaskName 'Tailscale Updater' -Description 'This task runs at start-up and at midday to attempt to update the Tailscale service' | Out-Null
    if(Get-ScheduledTask | Where-Object TaskName -like "Tailscale Updater"){
        Write-Host "Successfully installed scheduled task: Tailscale Updater"
    } else {
        Write-Error "Task not installed correctly: Tailscale Updater"
    }
    
} Catch {
    $_ | Write-Error
}