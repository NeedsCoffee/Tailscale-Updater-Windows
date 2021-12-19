# Tailscale-Updater-Windows

This is a little project to develop an updater & release collector for Tailscale on Windows.

The script requires PowerShell 5 or 7 and has been tested in both.
To use as an updater the script should be launched as an administrator from a scheduled task.

The script can be provided a number of switches which alter its behaviour.

## Available switches
\-Track [string, optional] \<stable (default)>\\\<unstable> - choose release to get (stable/unstable)

\-DownloadOnly [switch, optional] \<true>\\\<false (default)> - if specified just download then exit

\-SiloPath [string, optional] \<local or full path to release storage folder> - where to store release files

\-Verbose [switch, optional] \<true>\\\<false> (default)>

\-TaskMode [switch, optional] \<true>\\\<false> (default)> - reserved

## Installation

You can download and install the job using the following PowerShell one-liner (as admin preferably) to do the whole thing:
```
Set-ExecutionPolicy -ExecutionPolicy:RemoteSigned -Scope:LocalMachine -Force -Confirm:$False -ea:silentlycontinue; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (irm 'https://api.github.com/repos/needscoffee/tailscale-updater-windows/releases/latest').assets|%{irm $_.url -h:@{Accept="application/octet-stream"} -o:$_.name}; Start-Process 'powershell.exe' -ArgumentList:"-ExecutionPolicy:Bypass -Command:`"& {Set-Location $((Get-Location).Path);.\Install-Updater.ps1}`"" -Wait -Verb:RunAs; Remove-Item Install-Updater.ps1,Tailscale-Updater-Windows.ps1;
```

Manually this would be:
- Download the .ps1 files from the latest release
- Run powershell as admin
- Change to folder where you downloaded the files
- Run .\Install-Updater.ps1
-- Tailscale-Updater-Windows.ps1 will be copied to C:\ProgramData\Tailscale-updater\
-- Then a scheduled task will be created to run the script on a daily basis at midday, storing files in a silo sub-folder.

## Usage

Search for current stable release. Install if newer than an installed version
```plaintext
.\Tailscale-Updater-Windows.ps1
```

Search for current unstable release. Install if newer
```plaintext
.\Tailscale-Updater-Windows.ps1 -Track unstable
```

Search for current unstable release. Download, then exit without installing
```plaintext
.\Tailscale-Updater-Windows.ps1 -Track unstable -DownloadOnly
```

Search for current unstable release. Download to .\releases then exit without installing
```plaintext
.\Tailscale-Updater-Windows.ps1 -SiloPath .\releases -Track unstable -DownloadOnly
```

When run from PowerShell manually you can use -Verbose to monitor the progress
```plaintext
.\Tailscale-Updater-Windows.ps1 -Track stable -DownloadOnly -Verbose
```

## To-Do
- ~~Automatic release pruning - 3 previous versions perhaps~~ done
- ~~Auto-elevate and install as a scheduled task when run interactively~~ done with installer script
- Logging to a file or windows application log
- ~~Self-auto-update
- Auto-repair if node falls out of tailnet (store tskey in a secure keystore)
- Take a tskey as an interactive run switch to setup the node if needed
- ~~Determine alternative means of detecting new releases (API doesn't seem to do it - must be something!)
- Notification service support
