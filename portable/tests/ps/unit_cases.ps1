# Evaluates envscan library functions on fixed inputs and prints one JSON object
# (case name -> result) for tests/test_ps_unit.py. Runs in FullLanguage and in
# ConstrainedLanguage, so it may only use what the scanner itself may use.
param([string]$Lib, [string]$Scratch)

. $Lib
Initialize-EsRedaction
$script:ES_NETWORK_DRIVES = @()
$cases = @{}

function Get-AsciiBytes([string]$Text) {
    return @($Text.ToCharArray() | ForEach-Object { [int]$_ })
}

# ---- JSON writer
$tricky = @{
    __order = @('s', 'u')
    s = 'quote" back\ slash'; u = ('caf' + [char]0xE9 + ' ' + [char]0x65E5); c = ("tab`tnl`ncr`r" + [char]1)
    n = $null; b = $true; f = $false; i = 42; l = [long]1234567890123; d = 1.5; e = @(); h = @{}
    nested = @(@{ a = 1 }, @(1, 2), 'x'); single = @('only')
}
$cases.json_tricky = ConvertTo-EsJson $tricky
$cases.json_order = ConvertTo-EsJson @{ __order = @('z', 'a'); a = 1; z = 2; m = 3; b = 4 }
$cases.json_scalar_string = ConvertTo-EsJson 'plain'
$cases.json_long_array = ConvertTo-EsJson @{ list = @(1..40) }

# ---- secret names
$names = @('GITHUB_TOKEN', 'MY_API_KEY', 'PASSWORD', 'npm_config__authToken', 'AWS_SECRET_ACCESS_KEY', 'DB_PASSWORD_FILE',
    'PATH', 'PWD', 'SSH_AUTH_SOCK', 'JAVA_HOME', 'KEYBOARD_LAYOUT', 'credential.helper', 'GH_PAT_VALUE', 'PSModulePath')
$secretNames = @{}
foreach ($name in $names) { $secretNames[$name] = Test-EsSecretName $name }
$cases.secret_names = $secretNames

# ---- value and line redaction
$cases.value_url = Protect-EsValue 'https://user:hunter2@repo.corp.example/simple'
$cases.value_token = Protect-EsValue 'token is ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok'
$cases.value_bearer = Protect-EsValue 'Authorization: Bearer abcdefghijklmnop'
$cases.value_key = Protect-EsValue ('-----BEGIN RSA PRIVATE KEY-----' + "`n" + 'MIIE')
$cases.value_plain = Protect-EsValue 'C:\Program Files\nodejs\node.exe'
$cases.line_password = Protect-EsLine 'password = hunter2'
$cases.line_npm_token = Protect-EsLine '//npm.corp.example/:_authToken=npm_abcdefghijklmnopqrstuvwx'
$cases.line_registry = Protect-EsLine 'registry=https://npm.corp.example/repository/npm/'
$cases.line_xml = Protect-EsLine '<password>s3cret</password>'
$cases.line_nuget = Protect-EsLine '<add key="ClearTextPassword" value="s3cret" />'
$cases.cmdline = Protect-EsCommandLine 'app.exe --password hunter2 --user bob --api-key=xyz "Server=db;Password=abc;"'
$protected = Protect-EsData @{ a = @('https://u:p4ss@h.example/x', @{ b = 'ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }); n = 5 }
$cases.data_nested = $protected
$script:ES_OPT.redact = $false
$cases.value_redact_off = Protect-EsValue 'https://user:hunter2@repo.corp.example/simple'
$script:ES_OPT.redact = $true

# ---- arguments
$cases.arg_string = ConvertTo-EsArgString @('a', 'b c', '', 'x"y', 'trail\')
$script:ES_OPT.only = @()
$cases.args_unknown = @(Read-EsArguments @('--bogus'))
$cases.args_timeout = @(Read-EsArguments @('--timeout', '0'))
$cases.args_missing = @(Read-EsArguments @('--out'))
$cases.args_only_errors = @(Read-EsArguments @('--only=os.*,hw.cpu', '-deep'))
$cases.args_only = @($script:ES_OPT.only)
$cases.args_deep = $script:ES_OPT.deep

# ---- proxy blob, endpoints, versions
$proxy = 'proxy.corp:8080'
$exclusions = '<local>'
$blob = @(40, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, $proxy.Length, 0, 0, 0) + (Get-AsciiBytes $proxy) + @($exclusions.Length, 0, 0, 0) + (Get-AsciiBytes $exclusions)
$cases.proxy_blob = ConvertFrom-EsProxyBlob ([byte[]]$blob)
$cases.proxy_blob_direct = ConvertFrom-EsProxyBlob ([byte[]]@(24, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
$endpoints = @{}
foreach ($value in @('http://user:pw@proxy.corp:3128', 'https://repo.corp/maven', 'proxy:8080', 'http://169.254.169.254/latest', 'http://[fd00::1]:8080/x', 'metadata.google.internal', 'http://metadata.google.internal./x', 'http://proxy.corp.:3128', 'http://10.0.0.1.:3128')) {
    $endpoints[$value] = ConvertTo-EsEndpoint $value 'test'
}
$cases.endpoints = $endpoints
$versions = @{}
foreach ($text in @('git version 2.47.1.windows.1', 'openjdk version "21.0.1" 2023-10-17', 'go version go1.22.0 windows/amd64', "`nThis is perl 5, version 36, subversion 0 (v5.36.0)", 'v20.11.0', 'no version here')) {
    $versions[$text.Trim()] = (Get-EsVersionToken $text).version
}
$cases.versions = $versions

# ---- SDDL rights
$rights = @{}
foreach ($pair in @(@('0x1200a9', 2), @('0x1301bf', 2), @('FA', 2), @('LC', 4), @('LC', 2), @('DC', 2), @('GR', 2), @('0x10000000', 4), @('SDGXGWGR', 2))) {
    $rights[$pair[0] + '/' + $pair[1]] = Test-EsSddlRight $pair[0] $pair[1]
}
$cases.sddl_rights = $rights
$cases.sddl_scratch = Get-EsSddlAccess $Scratch
$cases.sddl_windows = Get-EsSddlAccess $env:SystemRoot
$cases.is_admin = (Get-EsTokenInfo).is_admin

# ---- dates, policies, findings, markdown
$cases.cim_date = Format-EsUtc (ConvertFrom-EsCimDate '20261030023208.500000+540')
$cases.policy_user = Get-EsPersistentPolicy @{ MachinePolicy = 'Undefined'; UserPolicy = 'Undefined'; CurrentUser = 'RemoteSigned'; LocalMachine = 'Restricted' }
$cases.policy_gpo = Get-EsPersistentPolicy @{ MachinePolicy = 'AllSigned'; UserPolicy = 'Undefined'; CurrentUser = 'RemoteSigned'; LocalMachine = 'Unrestricted' }
$cases.finding_known = New-EsFinding 'fs.low_disk' 'C:\ 10 MB free' @('hw.storage')
$cases.finding_unknown = (New-EsFinding 'no.such.finding' 'x' @()) -eq $null
$cases.md_text = Format-EsMdText 'a<b>_c'
$cases.md_plain = Format-EsMdText 'plain text'
$big = @{ big = ('x' * 70000) }
$cases.raw_limit = Limit-EsRaw $big
$cases.raw_limit_length = ([string]$cases.raw_limit.raw['big']).Length
$cases.raw_limit.raw = @{}

# ---- PATH lookup and the never-run rules
$a = Join-Path $Scratch 'a'
$b = Join-Path $Scratch 'b'
$null = New-Item -ItemType Directory -Path $a, $b -Force
foreach ($file in @((Join-Path $a 'tool.cmd'), (Join-Path $b 'tool.exe'), (Join-Path $b 'tool3.exe'), (Join-Path $b 'only.ps1'))) { Set-Content -LiteralPath $file -Value 'x' }
$script:ES_ENV_SNAPSHOT = @{ Path = ($a + ';' + $b + ';relative\dir;\\server\share'); PATHEXT = '.EXE;.CMD' }
$script:ES_PATH_DIRS = $null
$script:ES_PATH_INDEX = $null
$script:ES_PATHEXT = $null
$cases.path_dirs = @(Get-EsPathDirs | ForEach-Object { Split-Path -Leaf $_ })
$cases.find_order = @(Find-EsExecutable @('tool3', 'tool') @() | ForEach-Object { (Split-Path -Leaf (Split-Path -Parent $_.path)) + '/' + (Split-Path -Leaf $_.path) })
$cases.find_ps1 = @(Find-EsExecutable @('only') @() | ForEach-Object { Split-Path -Leaf $_.path })
$tool = @{ id = 'node'; mode = 'version' }
$presence = @{ id = 'sbt'; mode = 'presence' }
$cargo = Join-Path $Scratch '.cargo\bin'
$null = New-Item -ItemType Directory -Path $cargo -Force
Set-Content -LiteralPath (Join-Path $cargo 'rustup.exe') -Value 'x'
$cases.no_run = @{
    presence = Get-EsNoRunReason $presence 'C:\x\sbt.exe'
    ps1 = Get-EsNoRunReason $tool 'C:\x\node.ps1'
    alias = Get-EsNoRunReason $tool 'C:\Users\u\AppData\Local\Microsoft\WindowsApps\python.exe'
    winget = Get-EsNoRunReason @{ id = 'winget'; mode = 'version' } 'C:\Users\u\AppData\Local\Microsoft\WindowsApps\winget.exe'
    wsl = Get-EsNoRunReason @{ id = 'bash'; mode = 'version' } 'C:\Windows\System32\bash.exe'
    shim = Get-EsNoRunReason @{ id = 'cargo'; mode = 'version' } (Join-Path $cargo 'cargo.exe')
    js = Get-EsNoRunReason $tool 'C:\x\node.js'
    plain = Get-EsNoRunReason $tool 'C:\Program Files\nodejs\node.exe'
}

# ---- external command timeout: the child and its own child are both stopped
$script:ES_TMP = Join-Path $Scratch 'exec'
$null = New-Item -ItemType Directory -Path $script:ES_TMP
$script:ES_EMPTY_IN = Join-Path $script:ES_TMP 'stdin.empty'
$null = New-Item -ItemType File -Path $script:ES_EMPTY_IN
$script:ES_CHILD_CWD = $env:SystemDrive + '\'
# No snapshot: the child environment comes from the live one (the PATH case above left a fake
# snapshot without SystemRoot, which powershell.exe needs to start).
$script:ES_ENV_SNAPSHOT = @{}
$pidFile = Join-Path $script:ES_TMP 'grandchild.pid'
$inner = "Set-Content -LiteralPath '" + $pidFile + "' -Value `$PID; Start-Sleep -Seconds 60"
$cmdArgs = @('/d', '/c', (Join-Path $PSHOME 'powershell.exe'), '-NoProfile', '-NonInteractive', '-Command', $inner)
$run = Invoke-EsCommand -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -Arguments $cmdArgs -TimeoutSec 6
$grandchild = $null
if (Test-Path -LiteralPath $pidFile) { $grandchild = [int](@(Get-Content -LiteralPath $pidFile)[0]) }
$alive = $false
if ($grandchild) {
    for ($i = 0; $i -lt 30 -and (Get-Process -Id $grandchild -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 100 }
    $alive = [bool](Get-Process -Id $grandchild -ErrorAction SilentlyContinue)
    if ($alive) { Stop-Process -Id $grandchild -Force -ErrorAction SilentlyContinue }
}
$cases.exec_timeout = @{ timed_out = $run.timed_out; grandchild_seen = ($null -ne $grandchild); grandchild_alive = $alive }

# ---- default output folder: never a OneDrive (synced) folder
$oneDrive = Join-Path $Scratch 'OneDrive - Corp'
$work = Join-Path $oneDrive 'work'
$null = New-Item -ItemType Directory -Path $work
$script:ES_ENV_SNAPSHOT = @{ OneDrive = $oneDrive; USERPROFILE = [string]$env:USERPROFILE }
Push-Location -LiteralPath $work
$parents = @(Get-EsDefaultOutputParents)
Pop-Location
$cases.output_parents = @{ synced_cwd_listed = ($parents -contains $work); count = $parents.Count }

# ---- helpers split out of long probes
$cases.vm_products = @(@('VMware, Inc. VMware7,1', 'innotek GmbH VirtualBox', 'Google Google Compute Engine', '', 'Dell Inc. OptiPlex') |
        ForEach-Object { [string](Get-EsVmProduct $_) })
$cases.arch_facts = @{ none = (Get-EsArchFacts $null); arm = (Get-EsArchFacts @{ Architecture = 12 }) }
$cases.domain_facts = @{
    none = (Get-EsDomainFacts $null)
    joined = (Get-EsDomainFacts @{ PartOfDomain = $true; Domain = 'corp.example'; DNSHostName = 'PC1' })
    workgroup = (Get-EsDomainFacts @{ PartOfDomain = $false; Workgroup = 'WORKGROUP' })
}
$pathEntry = @{ path = 'C:\x'; exists = $false; duplicate = $false; relative = $false; network = $false; writable = $true; position = 1 }
$cases.path_issues = @{ empty = (Get-EsPathIssues @() $null); one = (Get-EsPathIssues @($pathEntry) 3) }
$cases.brief_findings = @{ clean = @(Get-EsBriefFindings @() 0); incomplete = @(Get-EsBriefFindings @() 4) }
$cases.java_cacerts_unc = Get-EsJavaCacerts '\\server\share\jdk'
$major = $script:ES_PS_MAJOR
$script:ES_PS_MAJOR = 7
$appxResult = New-EsResult
$appx = Get-EsAppxEntries $appxResult
$script:ES_PS_MAJOR = $major
$cases.appx_ps7 = @{ listed = $appx.listed; count = @($appx.items).Count; status = $appxResult.status }

$cases.language_mode = $script:ES_LANGUAGE_MODE
Write-Output (ConvertTo-EsJson $cases)
