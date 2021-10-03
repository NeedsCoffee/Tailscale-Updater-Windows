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

Download the .ps1 files, as admin use powershell, change to folder where you downloaded the files, run .\Install-Updater.ps1
Scheduled task will be created and run the script on a daily basis at midday from the location where you ran the installer.

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

When run from the PowerShell manually you can use -Verbose to monitor the progress
```plaintext
.\Tailscale-Updater-Windows.ps1 -Track stable -DownloadOnly -Verbose
```

## To-Do
- Auto-elevate and install as a scheduled task when run interactively
- Logging to a file or windows application log
- Self-auto-update
- Auto-repair if node falls out of tailnet (store tskey in a secure keystore)
- Take a tskey as an interactive run switch to setup the node if needed
- Determine alternative means of detecting new releases (API doesn't seem to do it - must be something!)
- Notification service support