param(
    [string]$Python = 'python.exe',
    [string]$DeploymentFile = (Join-Path $PSScriptRoot 'deployment.json'),
    [string]$TokenFile = (Join-Path $PSScriptRoot 'enrollment.token'),
    [string]$CaFile = (Join-Path $PSScriptRoot 'ca.pem'),
    [string]$TrustedKeysFile = $env:SERA_AGENT_TRUSTED_KEYS_FILE,
    [switch]$ResumeEnrollment
)
$ErrorActionPreference = 'Stop'
$admin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in Administrator PowerShell' }
$runtime = (Get-Command -Name $Python -CommandType Application -ErrorAction Stop).Source
$trustedRuntimeSids = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
# A LocalSystem service must never execute a runtime an ordinary user can replace.
# Reject links and writable executable/library descendants before launching Python.
function Assert-ProtectedRuntimeEntry([string]$Path, [bool]$Content = $true) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Runtime reparse paths are forbidden' }
    $rights = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    if ($Content) { $rights = $rights -bor [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trustedRuntimeSids) { throw 'Python runtime must be owned by SYSTEM, Administrators, TrustedInstaller or the elevated installing administrator' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        # CREATOR OWNER is an inheritance-only placeholder. Every concrete
        # descendant owner is checked separately before Python is invoked.
        if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $rights) -and $rule.IdentityReference.Value -notin $trustedRuntimeSids) { throw 'Python runtime is writable by an unprivileged account' }
    }
}
$runtimeRoot = Split-Path -Parent $runtime
$runtimeRoots = @($runtimeRoot)
$venvConfig = Join-Path (Split-Path -Parent $runtimeRoot) 'pyvenv.cfg'
if (Test-Path -LiteralPath $venvConfig -PathType Leaf) {
    Assert-ProtectedRuntimeEntry $venvConfig
    Assert-ProtectedRuntimeEntry (Split-Path -Parent $venvConfig)
    $runtimeRoots += Split-Path -Parent $venvConfig
    $homeLine = Get-Content -LiteralPath $venvConfig | Where-Object { $_ -match '^home\s*=\s*' } | Select-Object -First 1
    if (-not $homeLine) { throw 'Virtual runtime has no trusted base Python path' }
    $runtimeRoots += ($homeLine -replace '^home\s*=\s*','').Trim()
}
$ancestor = $runtimeRoot
while ($ancestor) { Assert-ProtectedRuntimeEntry $ancestor ($ancestor -eq $runtimeRoot); $parent = Split-Path -Parent $ancestor; if ($parent -eq $ancestor) { break }; $ancestor = $parent }
$scan = New-Object 'Collections.Generic.Queue[IO.DirectoryInfo]'
$scan.Enqueue((New-Object IO.DirectoryInfo($runtimeRoot)))
foreach ($root in ($runtimeRoots | Select-Object -Unique)) { Assert-ProtectedRuntimeEntry $root; if ($root -ne $runtimeRoot) { $scan.Enqueue((New-Object IO.DirectoryInfo($root))) } }
$entries = 0
while ($scan.Count) {
    foreach ($item in $scan.Dequeue().GetFileSystemInfos()) {
        $entries++
        if ($entries -gt 100000) { throw 'Runtime validation bound reached; choose a dedicated protected Python install' }
        Assert-ProtectedRuntimeEntry $item.FullName
        if ($item -is [IO.DirectoryInfo]) { $scan.Enqueue($item) }
    }
}
& $runtime -I -B -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ is required; runtime is not bundled' }
if ($env:SERA_AGENT_REQUIRE_SIGNED_PACKAGE -and $env:SERA_AGENT_REQUIRE_SIGNED_PACKAGE -ne '1') { throw 'Production installation cannot disable package signatures' }
if (-not $TrustedKeysFile -or -not [IO.Path]::IsPathRooted($TrustedKeysFile) -or -not (Test-Path -LiteralPath $TrustedKeysFile -PathType Leaf)) { throw 'An externally provisioned absolute public trust file is required' }
Assert-ProtectedRuntimeEntry $TrustedKeysFile
Assert-ProtectedRuntimeEntry (Split-Path -Parent $TrustedKeysFile)
$env:SERA_AGENT_TRUSTED_KEYS_FILE = [IO.Path]::GetFullPath($TrustedKeysFile)
$env:SERA_AGENT_REQUIRE_SIGNED_PACKAGE = '1'
& $runtime -I -B -c 'import cryptography, defusedxml; from importlib.metadata import version; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey; assert version("cryptography") == "50.0.2" and version("defusedxml") == "0.7.1", "Pinned production prerequisites required: Agent/requirements.txt"'
if ($LASTEXITCODE -ne 0) { throw 'Production requires the protected Python runtime with exact dependencies from Agent/requirements.txt' }
& $runtime -I -B (Join-Path $PSScriptRoot 'verify_package.py')
if ($LASTEXITCODE -ne 0) { throw 'Package verification failed' }
foreach ($file in @($DeploymentFile,$TokenFile,$CaFile)) { if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Scoped deployment JSON, one-time token file and public CA are required; generic ZIP contains none' } }
$target = Join-Path $env:ProgramData 'Vatex\LUMINA\xSERA\Agent'
$ancestor = Split-Path -Parent $target
while (Test-Path -LiteralPath $ancestor) { Assert-ProtectedRuntimeEntry $ancestor $false; $parent = Split-Path -Parent $ancestor; if (-not $parent -or $parent -eq $ancestor) { break }; $ancestor = $parent }
if (Get-Service -Name VatexLuminaXseraAgent -ErrorAction SilentlyContinue) { throw 'Existing service preserved; explicit upgrade/uninstall required' }
if ((Test-Path -LiteralPath $target) -and (-not $ResumeEnrollment -or (Test-Path -LiteralPath (Join-Path $target 'config.json')))) { throw 'Existing installation preserved; use -ResumeEnrollment only for an incomplete enrollment' }
if (Test-Path -LiteralPath $target) { if ((Get-Item -LiteralPath $target -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation reparse path rejected' } }
New-Item -ItemType Directory -Path $target -Force | Out-Null
& icacls.exe $target /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to protect installation directory' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Agent') -Destination $target -Recurse
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Destination $target
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'configure.py') -Destination $target
$config = Join-Path $target 'config.json'
& $runtime -I -B (Join-Path $target 'configure.py') --directory $target --deployment $DeploymentFile --token-file $TokenFile --ca-file $CaFile
if ($LASTEXITCODE -ne 0) { throw 'Endpoint enrollment failed; service was not registered' }
$entry = Join-Path $target 'Agent\Windows\main.py'
$binaryPath = '"' + $runtime + '" -I -B "' + $entry + '" service --config "' + $config + '"'
& sc.exe create VatexLuminaXseraAgent binPath= $binaryPath start= auto obj= LocalSystem DisplayName= 'Vatex LUMINA xSERA Endpoint Agent'
if ($LASTEXITCODE -ne 0) { throw 'Service registration failed' }
& sc.exe failure VatexLuminaXseraAgent reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service recovery configuration failed' }
& sc.exe failureflag VatexLuminaXseraAgent 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Non-crash service failure recovery configuration failed' }
& sc.exe start VatexLuminaXseraAgent
if ($LASTEXITCODE -ne 0) { throw 'Service start failed; inspect Windows service logs' }
Remove-Item -LiteralPath $TokenFile -Force
Write-Output 'Installed VatexLuminaXseraAgent. No remote shell/host isolation is supported. Runtime Python must remain installed and SYSTEM-accessible.'
