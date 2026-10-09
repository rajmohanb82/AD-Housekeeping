<#
.SYNOPSIS
  Deploy Directory Keep onto a Windows member server with Apache Tomcat 10.1.

.DESCRIPTION
  Stage writes the Tomcat webapp under .\dist and does not touch Active Directory.
  Install downloads Temurin is left to the operator, downloads Apache Tomcat 10.1.60,
  registers the Python console and Tomcat as Windows services, and prints the
  delegation you would apply afterwards.

  The script never grants directory rights. Run delegation yourself, scoped to
  the people OU, after you have read the printed commands.

.PARAMETER Mode
  Stage or Install. Default is Stage.

.PARAMETER InstallRoot
  Program files location used by Install mode.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("Stage", "Install")]
    [string]$Mode = "Stage",
    [string]$InstallRoot = "$env:ProgramFiles\DirectoryKeep",
    [int]$AppPort = 8765,
    [int]$TomcatPort = 8080
)

$ErrorActionPreference = "Stop"
$TomcatVersion = "10.1.60"
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Test-DomainMember {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    [pscustomobject]@{
        Joined = [bool]$cs.PartOfDomain
        Domain = [string]$cs.Domain
        Name   = [string]$cs.Name
    }
}

function Invoke-Stage {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        throw "Python 3 is not on PATH. Install it, then rerun Stage."
    }
    Push-Location $RepoRoot
    try {
        if (-not (Test-Path .venv)) {
            & python -m venv .venv
        }
        & .\.venv\Scripts\python.exe -m pip install --upgrade pip
        & .\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
        & .\.venv\Scripts\python.exe -c "from ad_housekeeping.web import stage_bundle; print(stage_bundle())"
    }
    finally {
        Pop-Location
    }
    Write-Host "Staged: $RepoRoot\dist\tomcat\webapps\ad-housekeeping"
}

function Install-TomcatBits {
    $cache = Join-Path $InstallRoot "cache"
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    $zipName = "apache-tomcat-$TomcatVersion-windows-x64.zip"
    $zip = Join-Path $cache $zipName
    $url = "https://downloads.apache.org/tomcat/tomcat-10/v$TomcatVersion/bin/$zipName"
    Invoke-WebRequest -Uri $url -OutFile $zip
    Invoke-WebRequest -Uri "$url.sha512" -OutFile "$zip.sha512"
    $expected = (Get-Content "$zip.sha512" -Raw).Split(" ")[0].Trim()
    $actual = (Get-FileHash -Algorithm SHA512 -Path $zip).Hash.ToLower()
    if ($expected.ToLower() -ne $actual) {
        throw "Tomcat checksum did not match the Apache SHA-512 file."
    }
    $dest = Join-Path $InstallRoot "tomcat"
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Expand-Archive -Path $zip -DestinationPath $cache -Force
    Move-Item (Join-Path $cache "apache-tomcat-$TomcatVersion") $dest
    $webapp = Join-Path $dest "webapps\ad-housekeeping"
    Copy-Item -Recurse -Force (Join-Path $RepoRoot "dist\tomcat\webapps\ad-housekeeping") $webapp
    return $dest
}

Write-Host "Directory Keep — $Mode"
if ($Mode -eq "Stage") {
    Invoke-Stage
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Install mode must run in an elevated PowerShell."
}

$member = Test-DomainMember
if (-not $member.Joined) {
    throw "This computer is not domain-joined. Directory Keep installs on a member server, not on a workgroup laptop."
}
Write-Host "Domain: $($member.Domain)  Computer: $($member.Name)"

Invoke-Stage
$tomcatHome = Install-TomcatBits

$appHome = Join-Path $InstallRoot "app"
if (Test-Path $appHome) { Remove-Item -Recurse -Force $appHome }
New-Item -ItemType Directory -Force -Path $appHome | Out-Null
Copy-Item -Recurse -Force (Join-Path $RepoRoot "ad_housekeeping") (Join-Path $appHome "ad_housekeeping")
Copy-Item (Join-Path $RepoRoot "requirements.txt") $appHome
& python -m venv (Join-Path $appHome ".venv")
& (Join-Path $appHome ".venv\Scripts\python.exe") -m pip install -r (Join-Path $appHome "requirements.txt")

$secret = -join ((1..48) | ForEach-Object { "{0:x}" -f (Get-Random -Max 16) })
$envFile = Join-Path $appHome "service-env.cmd"
@"
set ADHK_PORT=$AppPort
set ADHK_SECRET=$secret
"@ | Set-Content -Path $envFile -Encoding ASCII

$pythonExe = Join-Path $appHome ".venv\Scripts\python.exe"
# The console binds to localhost. Tomcat on $TomcatPort is the front door.
New-Service -Name "DirectoryKeep" -BinaryPathName "`"$pythonExe`" -m ad_housekeeping" -DisplayName "Directory Keep" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Write-Warning "New-Service cannot set the working directory. Prefer NSSM or a scheduled task at startup:"
Write-Host "nssm install DirectoryKeep `"$pythonExe`" -m ad_housekeeping"
Write-Host "nssm set DirectoryKeep AppDirectory `"$appHome`""
Write-Host "nssm set DirectoryKeep AppEnvironmentExtra ADHK_PORT=$AppPort ADHK_SECRET=$secret"

Push-Location (Join-Path $tomcatHome "bin")
try {
    & .\service.bat install DirectoryKeepTomcat
}
finally {
    Pop-Location
}

New-NetFirewallRule -DisplayName "Directory Keep Tomcat" -Direction Inbound -Protocol TCP -LocalPort $TomcatPort -Action Allow -ErrorAction SilentlyContinue | Out-Null

Write-Host ""
Write-Host "Installed under $InstallRoot"
Write-Host "Tomcat front door: http://$($member.Name):$TomcatPort/ad-housekeeping/"
Write-Host "Python console (localhost): http://127.0.0.1:$AppPort/"
Write-Host ""
Write-Host "Next, create a gMSA and delegate only the people OU. These commands are NOT run by this installer:"
Write-Host @'

# From a domain controller, after the KDS root key already exists:
New-ADServiceAccount -Name svc-adhk -DNSHostName fab-mgmt01.fabrikam.corp -PrincipalsAllowedToRetrieveManagedPassword FAB-MGMT01$
Install-ADServiceAccount -Identity svc-adhk

# Reset and unlock on the people OU only. Do not use Domain Admins.
$ou = "OU=People,OU=Fabrikam,DC=fabrikam,DC=corp"
dsacls $ou /I:S /G "FABRIKAM\svc-adhk$:CA;Reset Password;user"
dsacls $ou /I:S /G "FABRIKAM\svc-adhk$:WP;lockoutTime;user"
dsacls $ou /I:S /G "FABRIKAM\svc-adhk$:RPWP;pwdLastSet;user"

'@
Write-Host "Run Tomcat and the Python service as FABRIKAM\svc-adhk$. Do not use a Domain Admin."
