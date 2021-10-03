# Tailscale-Updater-Windows

This is a little project to develop an updater & release collector for Tailscale on Windows.

To use as an updater the script should be launched as an administrator from a scheduled task.

The script can be provided a number of switches which alter its behaviour.

## Available switches
\-Track [string, optional] \<stable (default)>\\\<unstable>

\-DownloadOnly [switch, optional] \<true>\\\<false (default)>

\-SiloPath [string, optional] \<local or full path to release storage folder>

\-Verbose [switch, optional] \<true>\\\<false> (default)>

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
