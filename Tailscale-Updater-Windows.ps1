[CmdletBinding()]
param (
    [Parameter()] [ValidateSet('stable','unstable')] [string]$Track = 'stable',
    [Parameter()] [switch]$DownloadOnly = $false,
    [Parameter()] [string]$SiloPath = (Join-Path -Path (Get-Location) -ChildPath 'tailscale_silo'),
    [Parameter()] [switch]$Force = $false,
    [Parameter()] [switch]$TaskMode = $false
)

function Get-TailscaleLatestReleaseInfo {
    # scrape Tailscale release pages and parse latest version info
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage='Specify which release track is of interest, stable (default) or unstable')]
        [ValidateSet('stable','unstable')]
        [string]$Track = 'stable'
    )
    Write-Verbose -Message "Release track: $Track"
    [string]$domain = 'pkgs.tailscale.com'
    [string]$release_prefix = 'tailscale-ipn-setup-'
    [string]$release_suffix = '.exe'
    [string]$uri = "https://$domain/$Track/"
    [string]$release_file_name = $null
    [string]$release_uri = $null

    Try {
        if(([System.Net.ServicePointManager]::SecurityProtocol -eq "SystemDefault") -and ([enum]::GetNames([System.Net.SecurityProtocolType]) -contains "Tls12")) {
            Write-Verbose -Message "Setting connection security: TLS 1.2"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        [Microsoft.PowerShell.Commands.WebResponseObject]$response = Invoke-WebRequest -Uri $uri -Method Get -UseBasicParsing   
        Write-Verbose -Message "Content retrieved: $($response.RawContentLength) bytes"
        [System.Object]$release_link = $response.Links | Where-Object -Property href -Match -Value "\$release_suffix`$"
        Write-Verbose -Message "Filtered link: $($release_link.OuterHTML)"
        $release_file_name = $release_link.href
        Write-Verbose -Message "Release file: $release_file_name"
        if(-not $release_file_name.Length -gt 4) {Throw "No release found!"}
        $release_uri = $uri + $release_file_name
        Write-Verbose -Message "Release url: $release_uri"
        [version]$release_version = $release_file_name -replace($release_prefix) -replace($release_suffix)
        Write-Verbose -Message "Parsed release version: $release_version"
    } Catch {
        $_ | Write-Error
    }

    [PSCustomObject]$release_object = @{
        name = $release_file_name
        version = $release_version
        track = $Track
        uri = $release_uri
    }
    return $release_object
}

function Get-TailscaleInstalledVersion {
    # find Tailscale on local device using service information and parse the version in use
    # this has the nice result that if the service isn't running, or isn't found then the version
    # returned is 0.0.0.0 which will in turn cause tailscale to install or re-install
    [CmdletBinding()] param()

    [string]$tailscale_app = 'tailscale-ipn.exe'
    [string]$tailscale_daemon = 'tailscaled'
    [version]$tailscale_version = $null
    [System.ComponentModel.Component]$tailscale_service = Get-Service -Name Tailscale -WarningAction:SilentlyContinue -ErrorAction:SilentlyContinue
    if($tailscale_service){
        Write-Verbose "Tailscale status: $($tailscale_service.Status)"
        [string]$tailscale_parent = (Get-Item -LiteralPath (Get-Process -Name $tailscale_daemon | Select-Object -ExpandProperty Path -First 1)).Directory
        Write-Verbose "Tailscale directory: $tailscale_parent"
        $tailscale_app_path = Join-Path -Path $tailscale_parent -ChildPath $tailscale_app
        if(Test-Path -LiteralPath $tailscale_app_path){
            $tailscale_version = (Get-Item -LiteralPath $tailscale_app_path).VersionInfo.ProductVersionRaw
            Write-Verbose "Tailscale version: $tailscale_version"
        } else {
            Throw "Can't reach Tailscale app [$tailscale_app_path]"
        }
    } else {
        Write-Verbose "Tailscale not installed"
    }
    return $tailscale_version
}

function Get-TailscaleRelease {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] [PSCustomObject]$Release,
        [Parameter(Mandatory=$true)] [string]$Destination
    )
    [string]$outpath = Join-Path -Path $Destination -ChildPath $Release.track
    [string]$outfile = Join-Path -Path $outpath -ChildPath $Release.name
    Write-Verbose "Download version: $($Release.version)"
    Write-Verbose "Download from: $($Release.uri)"
    Try {
        If(-not (Test-Path -LiteralPath $outpath)){
            Write-Host "Creating directory: $outpath"
            New-Item -Path $outpath -ItemType Directory | Out-Null
        }
        Write-Verbose "Download to: $outfile"
        Invoke-WebRequest -Uri $Release.uri -OutFile $outfile
    } Catch {
        $_ | Write-Error
    }
    $downloadedFile = Get-Item -LiteralPath $outfile
    return $downloadedFile
}

function Invoke-TailscaleInstall {
    [CmdletBinding()]
    param (
        [Parameter()] [System.IO.FileSystemInfo] $Release
    )
    Write-Verbose "Testing for admin rights"
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Not running as Admin"
        break
    } else {
        Write-Verbose "Admin rights available"
    }

    if(Test-Path -Path $Release){
        Write-Host "Starting installation: '$Release' /S"
        Try {
            Start-Process -FilePath $Release -ArgumentList '/S' -NoNewWindow -Wait
        } Catch {
            $_ | Write-Error
        }
    } else {
        Write-Error "Can't find installer"
    }
}

[PSCustomObject]$available_release = Get-TailscaleLatestReleaseInfo -Track $Track
[version]$installed_release = Get-TailscaleInstalledVersion

if($force -or $available_release.version -gt $installed_release){
    Write-Host "Tailscale release: $($available_release.version)"
    $file = Get-TailscaleRelease -Release $available_release -Destination $SiloPath
    if(Test-Path $file){
        Write-Host "Release downloaded: $($file.FullName)"
        if(-not $DownloadOnly){
            Invoke-TailscaleInstall -Release $file
        }
    } else {
        Write-Error "Release not downloaded."
    }
} else {
    Write-Host "No new release found."
}
