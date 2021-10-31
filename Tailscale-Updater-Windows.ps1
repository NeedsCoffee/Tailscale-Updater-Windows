# tailscale-updater script v0.3.0
[CmdletBinding()]
param (
    [Parameter()] [ValidateSet('stable','unstable')] [string]$Track = 'stable',
    [Parameter()] [switch]$DownloadOnly = $false,
    [Parameter()] [string]$SiloPath = (Join-Path -Path (Get-Location) -ChildPath 'tailscale_silo'),
    [Parameter()] [switch]$Force = $false,
    [Parameter()] [switch]$TaskMode = $false
)
function Invoke-SiloMaintenance {
    [CmdletBinding()]
    param ([string]$Path = $SiloPath)
    if(-Not (Test-Path -LiteralPath $SiloPath)){
        Write-Host "Silo Maintenance: SiloPath not found [$Path]"
    } else {
        [array]$silos = Get-ChildItem -LiteralPath $Path -Directory
        foreach($silo in $silos){
            Write-Verbose "Silo Maintenace: $($silo.FullName)"
            [array]$files = Get-ChildItem -LiteralPath $silo -File -Filter '*.exe' | Sort-Object -Property BaseName -Descending
            $files | Select-Object -Skip 2 | Remove-Item -Force -Verbose
        }
    }
}

function Get-TailscaleLatestReleaseInfo {
    # scrape Tailscale release pages and parse latest version info
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage='Specify which release track is of interest, stable (default) or unstable')]
        [ValidateSet('stable','unstable')]
        [string]$Track = 'stable'
    )
    Write-Verbose -Message "Release track: $Track"
    [string]$uri_base = "https://pkgs.tailscale.com/$Track/"
    [string]$release_os = 'windows'
    [string]$rest_uri = $uri_base+'?mode=json&os='+$release_os
    [string]$release_arch = 'amd64.exe'
    [string]$release_uri = $null
    [string]$release_file_name = $null

    Try {
        if(([System.Net.ServicePointManager]::SecurityProtocol -eq "SystemDefault") -and ([enum]::GetNames([System.Net.SecurityProtocolType]) -contains "Tls12")) {
            Write-Verbose -Message "Setting connection security: TLS 1.2"
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        [PSCustomObject]$response = Invoke-RestMethod -uri $rest_uri
        $release_file_name = $response.Installer.$release_arch
        Write-Verbose -Message "Release file: $release_file_name"

        $release_uri = $uri_base + $release_file_name
        Write-Verbose -Message "Release uri: $release_uri"

        [version]$release_version = $response.Version
        Write-Verbose -Message "Release version: $release_version"

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
function Install-CodeSigningCert {
    [string]$cert = @'
-----BEGIN CERTIFICATE-----
MIIFejCCBGKgAwIBAgIQDgWKFmZMJdpSyB2/I6zXXzANBgkqhkiG9w0BAQUFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBFViBDb2RlIFNpZ25p
bmcgQ0EwHhcNMjAwMzExMDAwMDAwWhcNMjEwNTE4MTIwMDAwWjCBqzETMBEGCysG
AQQBgjc8AgEDEwJDQTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQ
BgNVBAUTCTExMzE1NTktNTELMAkGA1UEBhMCQ0ExEDAOBgNVBAgTB09udGFyaW8x
EDAOBgNVBAcTB1Rvcm9udG8xFzAVBgNVBAoTDlRhaWxzY2FsZSBJbmMuMRcwFQYD
VQQDEw5UYWlsc2NhbGUgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKuYV//Z2aso7r/fCXKQ/jWuarqIHrbXiEweubhcAlNXf/+WQhwH2qVXy4im
vWC8N1cdiqsd/5BMc7TtxL9iPYjV4xSG/RczHI/e4iCW2rKU39eKUtU8cOxudULg
7jEA0nipZ95WYYqifIFeQmK8UpMiffuOzpHlwcWgbj4+iB6kQbmGgASC5FmKg08V
ZnuvEC/ZShealxfS/bFrRnzCB/YtDGemSu54yDy9t6LGip0gXJe2xgF72AQg3f9h
5XrcFVu7GXv1F30agS4lQ15fbEXiN7PMmO7pbv+Dn1MsZn/4BZOO0Lj3ibtBDGzk
aIsa178RHu8tRPjeDLxIs9SoJlkCAwEAAaOCAd0wggHZMB8GA1UdIwQYMBaAFK1p
BnD8gBsWs6kYlGuUAoZe9yeMMB0GA1UdDgQWBBTyXOOiRbrg0CfZklw63OESvzlo
GTAnBgNVHREEIDAeoBwGCCsGAQUFBwgDoBAwDgwMQ0EtMTEzMTU1OS01MA4GA1Ud
DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzBzBgNVHR8EbDBqMDOgMaAv
hi1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRVZDb2RlU2lnbmluZy1nMS5jcmww
M6AxoC+GLWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9FVkNvZGVTaWduaW5nLWcx
LmNybDBLBgNVHSAERDBCMDcGCWCGSAGG/WwDAjAqMCgGCCsGAQUFBwIBFhxodHRw
czovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAcGBWeBDAEDMHkGCCsGAQUFBwEBBG0w
azAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUF
BzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVkNvZGVT
aWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEFBQADggEBALXY
RiNFm7pWqUc8IgiR4EZ+UQUxp7HoVZ48Jlz3F/WvBdvEqp3uKJrlkfJdbDgdQgqu
tdxEEIORqeVI2PeFkUgQ79LikEM4yi35WCuUhfKX6D3RvseL4L5YesdB+l3+ol3P
F1JDS7h2EUumNnjGxAzteBf0amG338bO4w4PRGWWihzVwdi8OmeeWATjz4042mo4
I/Gd+m64dbasAyv8imdnNnKpwksJe191NjS8//KTdQQt128MgoJMA/E9zTKhqmHB
cKwXLuWV4cbBkvkGTz/qzluOFQVtHl2wPHpObmUkVvKyi5iXxqNZ0+0wvgt5yHGA
B6h0CYn/lGb/nMBUiVU=
-----END CERTIFICATE-----    
'@
}
function Invoke-TailscaleUpdate {
    [CmdletBinding()]
    param (
        [Parameter()] [PSCustomObject]$available,
        [Parameter()] [version]$installed
    )
    if($force -or $available.version -gt $installed){
        Write-Host "Tailscale release: $($available.version)"
        $file = Get-TailscaleRelease -Release $available -Destination $script:SiloPath
        if(Test-Path $file){
            Write-Host "Release downloaded: $($file.FullName)"
            if(-not $script:DownloadOnly){
                Invoke-TailscaleInstall -Release $file
            }
        } else {
            Write-Error "Release not downloaded."
        }
    } else {
        Write-Host "No new release found."
    }    
}
#Start
[PSCustomObject]$available_release = Get-TailscaleLatestReleaseInfo -Track $Track
[version]$installed_release = Get-TailscaleInstalledVersion
Invoke-TailscaleUpdate -available $available_release -installed $installed_release
Invoke-SiloMaintenance -Path $SiloPath
#End