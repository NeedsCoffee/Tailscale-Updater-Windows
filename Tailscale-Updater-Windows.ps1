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
    # make sure all silos contain no more than 2 releases
    [CmdletBinding()]
    param ([string]$Path = $SiloPath)
    if(-Not (Test-Path -LiteralPath $Path)){
        Write-Host "Silo Maintenance: SiloPath not found [$Path]"
    } else {
        [array]$silos = Get-ChildItem -LiteralPath $Path -Directory
        foreach($silo in $silos){
            Write-Verbose "Silo Maintenace: $($silo.FullName)"
            [array]$files = Get-ChildItem -LiteralPath $silo.FullName -File -Filter '*.exe' | Sort-Object -Property BaseName -Descending
            $files | Select-Object -Skip 2 | Remove-Item -Force -Verbose
        }
    }
}

function Get-TailscaleLatestReleaseInfo {
    # query Tailscale release page for latest Windows version
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
    # download a release
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
    # install a given release
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
function Invoke-ProcessAsInteractiveUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ApplicationPath
    )
    # PowerShell source: https://rzander.azurewebsites.net/create-a-process-as-loggedon-user/
    $source = @'
// C# source: https://github.com/murrayju/CreateProcessAsUser
using System;
using System.Runtime.InteropServices;

namespace murrayju.ProcessExtensions {
	public static class ProcessExtensions {

		private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
		private const int CREATE_NO_WINDOW = 0x08000000;

		private const int CREATE_NEW_CONSOLE = 0x00000010;

		private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
		private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

		[DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
		private static extern bool CreateProcessAsUser(
		IntPtr hToken, String lpApplicationName, String lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandle, uint dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

		[DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
		private static extern bool DuplicateTokenEx(
		IntPtr ExistingTokenHandle, uint dwDesiredAccess, IntPtr lpThreadAttributes, int TokenType, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

		[DllImport("userenv.dll", SetLastError = true)]
		private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

		[DllImport("userenv.dll", SetLastError = true)][
		return: MarshalAs(UnmanagedType.Bool)]
		private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool CloseHandle(IntPtr hSnapshot);

		[DllImport("kernel32.dll")]
		private static extern uint WTSGetActiveConsoleSessionId();

		[DllImport("Wtsapi32.dll")]
		private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

		[DllImport("wtsapi32.dll", SetLastError = true)]
		private static extern int WTSEnumerateSessions(
		IntPtr hServer, int Reserved, int Version, ref IntPtr ppSessionInfo, ref int pCount);

		private enum SW {
			SW_HIDE = 0,
			SW_SHOWNORMAL = 1,
			SW_NORMAL = 1,
			SW_SHOWMINIMIZED = 2,
			SW_SHOWMAXIMIZED = 3,
			SW_MAXIMIZE = 3,
			SW_SHOWNOACTIVATE = 4,
			SW_SHOW = 5,
			SW_MINIMIZE = 6,
			SW_SHOWMINNOACTIVE = 7,
			SW_SHOWNA = 8,
			SW_RESTORE = 9,
			SW_SHOWDEFAULT = 10,
			SW_MAX = 10
		}

		private enum WTS_CONNECTSTATE_CLASS {
			WTSActive,
			WTSConnected,
			WTSConnectQuery,
			WTSShadow,
			WTSDisconnected,
			WTSIdle,
			WTSListen,
			WTSReset,
			WTSDown,
			WTSInit
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct PROCESS_INFORMATION {
			public IntPtr hProcess;
			public IntPtr hThread;
			public uint dwProcessId;
			public uint dwThreadId;
		}

		private enum SECURITY_IMPERSONATION_LEVEL {
			SecurityAnonymous = 0,
			SecurityIdentification = 1,
			SecurityImpersonation = 2,
			SecurityDelegation = 3,
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct STARTUPINFO {
			public int cb;
			public String lpReserved;
			public String lpDesktop;
			public String lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}

		private enum TOKEN_TYPE {
			TokenPrimary = 1,
			TokenImpersonation = 2
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct WTS_SESSION_INFO {
			public readonly UInt32 SessionID;

			[MarshalAs(UnmanagedType.LPStr)]
			public readonly String pWinStationName;

			public readonly WTS_CONNECTSTATE_CLASS State;
		}

		private static bool GetSessionUserToken(ref IntPtr phUserToken) {
			var bResult = false;
			var hImpersonationToken = IntPtr.Zero;
			var activeSessionId = INVALID_SESSION_ID;
			var pSessionInfo = IntPtr.Zero;
			var sessionCount = 0;

			if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0) {
				var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
				var current = pSessionInfo;

				for (var i = 0; i < sessionCount; i++) {
					var si = (WTS_SESSION_INFO) Marshal.PtrToStructure((IntPtr) current, typeof(WTS_SESSION_INFO));
					current += arrayElementSize;

					if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive) {
						activeSessionId = si.SessionID;
					}
				}
			}

			if (activeSessionId == INVALID_SESSION_ID) {
				activeSessionId = WTSGetActiveConsoleSessionId();
			}

			if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0) {
				bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero, (int) SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int) TOKEN_TYPE.TokenPrimary, ref phUserToken);

				CloseHandle(hImpersonationToken);
			}

			return bResult;
		}

		public static bool StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true) {
			var hUserToken = IntPtr.Zero;
			var startInfo = new STARTUPINFO();
			var procInfo = new PROCESS_INFORMATION();
			var pEnv = IntPtr.Zero;
			int iResultOfCreateProcessAsUser;

			startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

			try {
				if (!GetSessionUserToken(ref hUserToken)) {
					throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
				}

				uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE: CREATE_NO_WINDOW);
				startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW: SW.SW_HIDE);
				startInfo.lpDesktop = "winsta0\\default";

				if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false)) {
					throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
				}

				if (!CreateProcessAsUser(hUserToken, appPath, // Application Name
				cmdLine, // Command Line
				IntPtr.Zero, IntPtr.Zero, false, dwCreationFlags, pEnv, workDir, // Working directory
				ref startInfo, out procInfo)) {
					throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
				}

				iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
			}
			finally {
				CloseHandle(hUserToken);
				if (pEnv != IntPtr.Zero) {
					DestroyEnvironmentBlock(pEnv);
				}
				CloseHandle(procInfo.hThread);
				CloseHandle(procInfo.hProcess);
			}
			return true;
		}
	}
}
'@
    Add-Type -ReferencedAssemblies 'System', 'System.Runtime.InteropServices' -TypeDefinition $source -Language CSharp
    [boolean]$result = $false
    if(Test-Path $ApplicationPath){
        [boolean]$result = [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser($ApplicationPath)
    } else {
        Write-Error "[$ApplicationPath] not found"
    }
    return $result
}
function Invoke-TailscaleUpdate {
    # test for installed release vs latest downloaded and install if newer available
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