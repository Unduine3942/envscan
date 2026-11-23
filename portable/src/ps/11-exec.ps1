# ---------------------------------------------------------------------------
# 11-exec: external commands, CIM/WMI, registry, files and path patterns.
# ---------------------------------------------------------------------------

function Get-EsErrorStatus([string]$Message) {
    if (-not $Message) { return 'error' }
    if ($Message -match '(?i)access (is )?denied|unauthorized|requires elevat|administrator privilege|0x80070005|0x80041003') { return 'denied' }
    if ($Message -match '(?i)invalid (class|namespace)|not found|cannot find|does not exist|0x80041010|0x8004100e') { return 'not_found' }
    if ($Message -match '(?i)timed? ?out|timeout') { return 'timeout' }
    return 'error'
}

# ------------------------------------------------------------------ external commands

function ConvertTo-EsArgString([string[]]$Arguments) {
    $quoted = foreach ($arg in @($Arguments)) {
        if ($null -eq $arg -or $arg -eq '') { '""' }
        elseif ($arg -match '[\s"]') {
            $escaped = $arg -replace '(\\*)"', '$1$1\"'
            $escaped = $escaped -replace '(\\+)$', '$1$1'
            '"' + $escaped + '"'
        }
        else { $arg }
    }
    return (@($quoted) -join ' ')
}

function Select-EsDescendants([int]$ProcessId, [object[]]$Snapshot) {
    # $ProcessId and its descendants in a Win32_Process snapshot. A process counts as a child only
    # when it was created no earlier than its parent: a ParentProcessId may name a PID that was
    # reused since (the children of a long-gone process, e.g. explorer's). Without a creation
    # time a process is never treated as a descendant.
    $created = @{}
    $children = @{}
    foreach ($item in @($Snapshot)) {
        $created[[string]$item.ProcessId] = ConvertFrom-EsCimDate $item.CreationDate
        $parent = [string]$item.ParentProcessId
        if (-not $children.ContainsKey($parent)) { $children[$parent] = @() }
        $children[$parent] += [int]$item.ProcessId
    }
    $ids = @($ProcessId)
    for ($index = 0; $index -lt $ids.Count -and $index -lt 500; $index++) {
        $parentTime = $created[[string]$ids[$index]]
        if ($null -eq $parentTime) { continue }
        foreach ($child in @($children[[string]$ids[$index]])) {
            if ($null -eq $child -or $ids -contains $child) { continue }
            $childTime = $created[[string]$child]
            if ($null -ne $childTime -and $childTime -ge $parentTime) { $ids += $child }
        }
    }
    return $ids
}

function Get-EsProcessTree([int]$ProcessId) {
    # $ProcessId and its descendants from one Win32_Process snapshot (one WMI job on PS 2.0,
    # instead of one query per process).
    $snapshot = @()
    try { $snapshot = @(Get-EsCim -Class 'Win32_Process' -TimeoutSec 10) }
    catch { Write-EsLog ('process snapshot failed; only the timed-out process is stopped: ' + $_.Exception.Message) }
    return @(Select-EsDescendants $ProcessId $snapshot)
}

function Stop-EsProcessTree([int]$ProcessId) {
    foreach ($id in @(Get-EsProcessTree $ProcessId)) {
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
}

$script:ES_OEM_ENCODING = $null

function Read-EsOemText([string]$Path, [int]$MaxLines) {
    # PowerShell 2.0 only: its file cmdlets cannot decode the OEM code page. PowerShell 2.0
    # has no ConstrainedLanguage mode, so .NET decodes the file in the system OEM code page
    # (OEMCP, the code page PowerShell 3+ uses for the Oem encoding).
    if ($null -eq $script:ES_OEM_ENCODING) {
        $script:ES_OEM_ENCODING = [Console]::OutputEncoding
        $codePage = [string](Get-EsRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' 'OEMCP')
        try { if ($codePage -match '\A[0-9]{1,5}\z') { $script:ES_OEM_ENCODING = [Text.Encoding]::GetEncoding([int]$codePage) } }  # lint-allow: static-method
        catch { Write-EsLog ('OEM code page ' + $codePage + ' unavailable; console encoding used: ' + $_.Exception.Message) }
    }
    $text = [IO.File]::ReadAllText($Path, $script:ES_OEM_ENCODING)  # lint-allow: static-method
    $lines = @(($text -replace '\r?\n\z', '') -split '\r?\n' | Select-Object -First $MaxLines)
    return ($lines -join "`n")
}

function Read-EsCommandOutput([string]$Path, [string]$Encoding, [int]$MaxLines) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    try {
        if ($Encoding -eq 'Oem' -and $script:ES_PS_MAJOR -lt 3) { return (Read-EsOemText $Path $MaxLines) }
        $lines = @(Get-Content -LiteralPath $Path -Encoding $Encoding -TotalCount $MaxLines -ErrorAction Stop)
        return ($lines -join "`n")
    } catch { return '' }
}

function Get-EsLaunch([string]$FilePath, [string]$ArgString) {
    # What Start-Process runs. A .cmd or .bat runs through System32 cmd.exe with /d, so the
    # Command Processor AutoRun commands do not run, and /v:off; /s /c "<line>" runs the line
    # as it is. cmd.exe expands % even inside quotes and treats & | < > ^ as operators outside
    # them, so a batch line holding one of those is not run. Everything else starts directly.
    $launch = @{ file = $FilePath; args = $ArgString; error = $null }
    # A program that is (or is below) a link that is not followed would load from behind it.
    $link = Get-EsPathLinkReason $FilePath
    if ($link) { $launch.error = 'not run: ' + $link; return $launch }
    $ext = Get-EsExtension $FilePath
    if ($ext -ne '.cmd' -and $ext -ne '.bat') { return $launch }
    if ($FilePath.Contains('%') -or $ArgString -match '[%&|<>^\r\n]') {
        $launch.error = 'not run: the batch file command line holds a cmd.exe special character'
        return $launch
    }
    $launch.file = Get-EsSystemTool 'cmd.exe'
    if (-not $launch.file) { $launch.error = 'not run: the Windows folder is not a trusted local path (no cmd.exe)'; return $launch }
    $launch.args = '/d /v:off /s /c "' + ('"' + $FilePath + '" ' + $ArgString).Trim() + '"'
    return $launch
}

function Start-EsChild([hashtable]$Parameters, [hashtable]$Environment) {
    # Start-Process with this process environment set to the child table (Get-EsChildEnvTable:
    # allowlist, [child_env], $Environment) for the start only. Start-Process has no environment
    # parameter before PowerShell 7.4, and ProcessStartInfo needs New-Object, which
    # ConstrainedLanguage refuses. The table is set inside the try whose finally restores the
    # environment captured before it (Set-EsProcessEnv fails closed: no child starts when it
    # cannot be set). The handle is taken before the restore: without it a child that has
    # already exited reports no exit code.
    $saved = Get-EsProcessEnv
    try {
        $null = Set-EsProcessEnv (Get-EsChildEnvTable $Environment) $saved
        $process = Start-Process @Parameters
        $null = $process.Handle
    } finally { $null = Restore-EsProcessEnv $saved }
    return $process
}

function Invoke-EsCommand {
    # Runs one external command: empty stdin, child cwd = system drive root, timeout,
    # whole process tree killed on timeout. Never throws.
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSec = 0,
        [string]$Encoding = 'Oem',
        [int]$MaxLines = 4000,
        [string]$WorkingDirectory = '',
        [hashtable]$Environment = @{}
    )
    if ($TimeoutSec -le 0) { $TimeoutSec = [int]$script:ES_OPT.timeout }
    $script:ES_CMD_SEQ++
    $base = Join-Path $script:ES_TMP ('c' + $script:ES_CMD_SEQ)
    $launch = Get-EsLaunch $FilePath (ConvertTo-EsArgString $Arguments)
    $result = @{
        command = (@($launch.file, $launch.args) -join ' ').Trim(); exit_code = $null; stdout = ''; stderr = ''
        timed_out = $false; error = $launch.error; duration_ms = 0
    }
    if ($launch.error) { return $result }
    $start = Get-EsUtc
    $parameters = @{
        FilePath = $launch.file; NoNewWindow = $true; PassThru = $true; ErrorAction = 'Stop'
        RedirectStandardOutput = ($base + '.out'); RedirectStandardError = ($base + '.err')
        RedirectStandardInput = $script:ES_EMPTY_IN; WorkingDirectory = $script:ES_CHILD_CWD
    }
    if ($WorkingDirectory) { $parameters['WorkingDirectory'] = $WorkingDirectory }
    if ($launch.args) { $parameters['ArgumentList'] = $launch.args }
    try {
        $process = Start-EsChild $parameters $Environment
        $exited = $false
        try { Wait-Process -Id $process.Id -Timeout $TimeoutSec -ErrorAction Stop; $exited = $true }
        catch { $exited = [bool]$process.HasExited }
        if ($exited) { $result.exit_code = $process.ExitCode }
        else {
            $result.timed_out = $true
            Stop-EsProcessTree $process.Id
            Write-EsLog ('timeout after ' + $TimeoutSec + 's: ' + $result.command)
        }
    } catch { $result.error = $_.Exception.Message }
    $result.stdout = Read-EsCommandOutput ($base + '.out') $Encoding $MaxLines
    $result.stderr = Read-EsCommandOutput ($base + '.err') $Encoding $MaxLines
    Remove-Item -LiteralPath ($base + '.out'), ($base + '.err') -Force -ErrorAction SilentlyContinue
    $result.duration_ms = Get-EsElapsedMs $start
    return $result
}

function Get-EsCommandText([hashtable]$Result) {
    # stdout and stderr together (many tools print versions on stderr).
    $parts = @()
    if ($Result.stdout) { $parts += $Result.stdout }
    if ($Result.stderr) { $parts += $Result.stderr }
    return ($parts -join "`n").Trim()
}

# ------------------------------------------------------------------ CIM / WMI

function Get-EsCim {
    # The only place that queries CIM/WMI: timeouts on PS 3+, a job with a timeout on PS 2.0.
    param([string]$Class, [string]$Namespace = 'root/cimv2', [string]$Filter = '', [int]$TimeoutSec = 30)
    if ($script:ES_HAS_CIM) {
        $parameters = @{ ClassName = $Class; Namespace = $Namespace; OperationTimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
        if ($Filter) { $parameters['Filter'] = $Filter }
        return @(Get-CimInstance @parameters)  # lint-allow: cim-cmdlet
    }
    # The job's powershell.exe gets the child environment too (Get-EsChildEnvTable); set inside
    # the try whose finally restores it, failing closed like Start-EsChild.
    $saved = Get-EsProcessEnv
    try {
        $null = Set-EsProcessEnv (Get-EsChildEnvTable @{}) $saved
        $job = Start-Job -ScriptBlock { param($c, $n, $f) if ($f) { Get-WmiObject -Class $c -Namespace $n -Filter $f -ErrorAction Stop } else { Get-WmiObject -Class $c -Namespace $n -ErrorAction Stop } } -ArgumentList $Class, ($Namespace -replace '/', '\'), $Filter  # lint-allow: start-job, wmi-cmdlet
    } finally { $null = Restore-EsProcessEnv $saved }
    if (Wait-Job -Job $job -Timeout $TimeoutSec) {
        try { return @(Receive-Job -Job $job -ErrorAction Stop) }
        finally { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
    }
    Stop-Job -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    throw ('WMI query timed out: ' + $Class)
}

# Probe queries by namespace, class and filter, kept for the scan (reset by Invoke-EnvScan):
# several probes read the same classes (Win32_Processor alone takes about a second, and a
# timed-out query is not waited for twice). Get-EsProcessTree always queries afresh.
$script:ES_CIM_CACHE = @{}

function Get-EsCimSafe {
    # Like Get-EsCim but returns @{ items; status; error } instead of throwing. Callers must
    # not change the result (it is shared through the cache).
    param([string]$Class, [string]$Namespace = 'root/cimv2', [string]$Filter = '', [int]$TimeoutSec = 30)
    $key = $Namespace + ':' + $Class + '|' + $Filter
    if ($script:ES_CIM_CACHE.ContainsKey($key)) { return $script:ES_CIM_CACHE[$key] }
    try {
        $items = @(Get-EsCim -Class $Class -Namespace $Namespace -Filter $Filter -TimeoutSec $TimeoutSec)
        $result = @{ items = $items; status = 'ok'; error = $null }
    } catch {
        $message = $_.Exception.Message
        $result = @{ items = @(); status = (Get-EsErrorStatus $message); error = ($Class + ': ' + $message) }
    }
    $script:ES_CIM_CACHE[$key] = $result
    return $result
}

# ------------------------------------------------------------------ registry

function ConvertTo-EsRegValue($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) {
        $count = $Value.Length
        if ($count -gt 256) { $count = 256 }
        $hex = @(for ($i = 0; $i -lt $count; $i++) { ([int]$Value[$i]).ToString('x2') }) -join ''
        return $hex
    }
    if ($Value -is [array]) { return @($Value | ForEach-Object { [string]$_ }) }
    # REG_DWORD arrives as a signed Int32; report the unsigned value (masks such as MitigationOptions).
    if ($Value -is [int]) { if ($Value -lt 0) { return ([long]$Value + 4294967296) } return $Value }
    if ($Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64]) { return $Value }
    return [string]$Value
}

function Test-EsRegKey([string]$Path) {
    return [bool](Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)
}

# Registry keys the running probe was denied (reset by Invoke-EsProbe): a denied read makes
# the probe partial, because "absent" needs a completed read. Missing keys and values are
# not recorded.
$script:ES_DENIED_READS = @()

function Add-EsDeniedRead([string]$Path, $ErrorRecord) {
    $category = ''
    try { $category = [string]$ErrorRecord.CategoryInfo.Category } catch { }
    if ($category -ne 'PermissionDenied') { return }
    if ($script:ES_DENIED_READS -notcontains $Path) { $script:ES_DENIED_READS += $Path }
}

function Get-EsRegValues([string]$Path, [string]$SkipValuePattern = '') {
    # Values of one key as name -> value, or $null when the key is missing or unreadable.
    # Value names matching $SkipValuePattern are never read.
    try { $key = Get-Item -LiteralPath $Path -ErrorAction Stop } catch { Add-EsDeniedRead $Path $_; return $null }
    $names = @(@($key.Property) | Where-Object { $_ -and $_ -ne '(default)' -and -not ($SkipValuePattern -and $_ -match $SkipValuePattern) })
    $values = @{}
    if ($names.Count -eq 0) { return $values }
    try { $item = Get-ItemProperty -LiteralPath $Path -Name $names -ErrorAction Stop } catch { Add-EsDeniedRead $Path $_; return $null }
    foreach ($name in $names) { $values[[string]$name] = ConvertTo-EsRegValue $item.$name }
    return $values
}

function Get-EsRegValue([string]$Path, [string]$Name) {
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return (ConvertTo-EsRegValue $item.$Name)
    } catch { Add-EsDeniedRead $Path $_; return $null }
}

function Get-EsRegSubkeys([string]$Path) {
    # Subkey names. -Name lists them without opening each subkey, so one unreadable subkey
    # does not hide the others; a key this user may not list is recorded as a denied read.
    $failures = $null
    $names = @(Get-ChildItem -LiteralPath $Path -Name -ErrorAction SilentlyContinue -ErrorVariable failures)
    foreach ($failure in @($failures)) { Add-EsDeniedRead $Path $failure }
    return @($names | Where-Object { $_ } | ForEach-Object { [string]$_ })
}

function Get-EsRegTree([string]$Path, [int]$MaxKeys = 400, [string]$SkipPattern = '', [string]$SkipValuePattern = '') {
    # Every value under a key, flattened as "subkey\name" -> value (capped). Subkeys whose
    # path below $Path matches $SkipPattern are never opened; values whose name matches
    # $SkipValuePattern are never read.
    $out = @{}
    $queue = @($Path)
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt $MaxKeys) {
        $current = $queue[0]
        $queue = @($queue | Select-Object -Skip 1)
        $visited++
        $values = Get-EsRegValues $current $SkipValuePattern
        if ($null -eq $values) { continue }
        $relative = $current.Substring($Path.Length).TrimStart('\')
        foreach ($name in @($values.PSBase.Keys)) {
            $label = $name
            if ($relative) { $label = $relative + '\' + $name }
            $out[$label] = $values[$name]
        }
        foreach ($sub in @(Get-EsRegSubkeys $current)) {
            $child = $current + '\' + $sub
            if ($SkipPattern -and $child.Substring($Path.Length) -match $SkipPattern) { continue }
            $queue += $child
        }
    }
    return $out
}

# ------------------------------------------------------------------ files and paths

function Test-EsNetworkPath([string]$Path) {
    if (-not $Path) { return $false }
    if ($Path.StartsWith('\\')) { return $true }
    if ($Path -match '^([A-Za-z]):') {
        $drive = $matches[1].ToUpperInvariant() + ':'
        return ($script:ES_NETWORK_DRIVES -contains $drive)
    }
    return $false
}

function Initialize-EsDrives {
    # Network drive letters and their targets, found without contacting them: PowerShell's
    # drive list (DisplayRoot is the UNC path of a mapped drive) and the persistent mappings
    # under HKCU:\Network. Never WMI: Win32_LogicalDisk asks the file server for its size.
    $targets = @{}
    try {
        foreach ($drive in @(Get-PSDrive -PSProvider FileSystem -ErrorAction Stop)) {
            $display = $null
            try { $display = [string]$drive.DisplayRoot } catch { }
            if ($display -and $display.StartsWith('\') -and ([string]$drive.Name).Length -eq 1) {
                $targets[([string]$drive.Name).ToUpperInvariant() + ':'] = $display
            }
        }
    } catch { Write-EsLog ('drive list failed: ' + $_.Exception.Message) }
    foreach ($letter in @(Get-EsRegSubkeys 'HKCU:\Network')) {
        if ($letter.Length -ne 1) { continue }
        $drive = $letter.ToUpperInvariant() + ':'
        if (-not $targets.ContainsKey($drive)) { $targets[$drive] = Get-EsRegValue ('HKCU:\Network\' + $letter) 'RemotePath' }
    }
    $script:ES_NETWORK_DRIVE_TARGETS = $targets
    $script:ES_NETWORK_DRIVES = @($targets.PSBase.Keys | Sort-Object)
}

function Test-EsLocalPath([string]$Path) {
    # An absolute path on a local drive (X:\...). Relative, root-relative (\x), drive-relative
    # (C:x), device and UNC paths and mapped network drives are never touched: they resolve
    # against the current location or reach the network.
    if (-not $Path -or $Path -notmatch '\A[A-Za-z]:\\') { return $false }
    return (-not (Test-EsNetworkPath $Path))
}

function ConvertTo-EsFlatPath([string]$Path, [bool]$DropDots = $false) {
    # Text normalisation of a path (nothing is looked up): "/" becomes "\", doubled separators,
    # "." components and a trailing separator go, ".." folds into its parent (never above the
    # drive or the share). A "\\?\", "\\.\", "\??\" or UNC prefix stays. $DropDots: trailing dots
    # and spaces of each component are dropped too (Windows ignores them), and a component that
    # is only dots and spaces disappears.
    $p = $Path.Replace('/', '\')
    $prefix = ''
    if ($p -match '\A(\\\\[?.]\\|\\\?\?\\|\\\\)') { $prefix = $matches[1]; $p = $p.Substring($prefix.Length) }
    $floor = $(if ($prefix -eq '\\') { 2 } else { 1 })
    $parts = @()
    foreach ($part in $p.Split('\')) {
        if ($part -eq '' -or $part -eq '.') { continue }
        if ($part -eq '..') {
            if ($parts.Count -gt $floor) { $parts = @($parts | Select-Object -First ($parts.Count - 1)) }
            continue
        }
        if ($DropDots) { $part = $part -replace '[. ]+\z', ''; if ($part -eq '') { continue } }
        $parts += $part
    }
    $flat = $parts -join '\'
    if ($parts.Count -eq 1 -and $prefix -eq '' -and $parts[0] -match '\A[A-Za-z]:\z') { $flat += '\' }
    return ($prefix + $flat)
}

function Test-EsCredentialPath([string]$Path) {
    # A credential store, which the scanner never opens and never tests for existence
    # (spec/configs.toml): a path with a credential folder component (ES_CRED_FOLDER_RE), ending
    # in a credential file (ES_CRED_FILE_RE: .netrc, shell history, cloud and package-registry
    # tokens, SSH private keys) or a key file extension (.pem, .key, .p12, .pfx, .jks,
    # .keystore; not a trust store, ES_TRUST_STORE_NAMES). Text only, any case,
    # either separator. The same rule as es_cred_path in src/sh/11-policy.sh: keep the two in step.
    # Windows only: trailing dots and spaces of a component are dropped (.ssh. is .ssh), and a
    # path naming a stream (a ":" after the drive) or a possible 8.3 short name of a store
    # (Test-EsShortNameRisk) counts as one: the long name is not looked up.
    if (-not $Path) { return $false }
    # Flat form: one separator, no empty or "." component, ".." folded, trailing dots and spaces
    # of every component dropped, no trailing separator.
    $p = '\' + ((ConvertTo-EsFlatPath $Path $true).ToLowerInvariant() -replace '\A(\\\\[?.]\\|\\\?\?\\)', '')
    if (($p -replace '\A\\[a-z]:', '').Contains(':')) { return $true }
    if (Test-EsShortNameRisk $p) { return $true }
    if (($p + '\') -match $script:ES_CRED_FOLDER_RE) { return $true }
    if ($p -match $script:ES_CRED_FILE_RE) { return $true }
    # Key and keystore files by extension; the trust stores the scanner reads on purpose
    # (cacerts, the spec ca_bundles names) are certificates, not keys.
    $leaf = $p.Substring($p.LastIndexOf('\') + 1)
    return ($p -match $script:ES_CRED_KEY_RE -and $script:ES_TRUST_STORE_NAMES -notcontains $leaf)
}

# Credential folders (any component), files (the end of the path), history suffixes and key
# extensions for Test-EsCredentialPath: the names are generated from spec/policy.toml
# ($script:ES_TRUST_STORE_NAMES, $script:ES_CRED_FOLDERS, _FILES, _SUFFIXES, _KEY_EXTENSIONS, "\" separators, lower case) and
# become regular expressions here. The same data feeds es_cred_path in src/sh/11-policy.sh.
function Join-EsAlternation([object[]]$Names) {
    $parts = @()
    foreach ($name in @($Names)) { $parts += [regex]::Escape([string]$name) }
    return ($parts -join '|')
}
$script:ES_CRED_FOLDER_RE = '\\(' + (Join-EsAlternation $script:ES_CRED_FOLDERS) + ')\\'
$script:ES_CRED_FILE_RE = '(\\(' + (Join-EsAlternation $script:ES_CRED_FILES) + ')|(' +
    (Join-EsAlternation $script:ES_CRED_SUFFIXES) + '))$'
$script:ES_CRED_KEY_RE = '\.(' + (Join-EsAlternation $script:ES_CRED_KEY_EXTENSIONS) + ')$'

function Get-EsShortNamePrefixes {
    # The first two letters of every component of every credential folder and file name, without
    # the leading dot (a short name drops it: .terraform.d is TERRAF~1.D, .gem is GEM~1, .m2 is
    # M2~1; from the fifth collision on only two letters are kept). Generated from the same spec
    # data as the folder and file lists, so a new store needs no second edit.
    $seen = @{}
    foreach ($name in (@($script:ES_CRED_FOLDERS) + @($script:ES_CRED_FILES))) {
        foreach ($component in ([string]$name).ToLowerInvariant().Split('\')) {
            $short = $component.TrimStart('.')
            if ($short.Length -gt 2) { $short = $short.Substring(0, 2) }
            if ($short.Length -gt 0) { $seen[$short] = $true }
        }
    }
    return @($seen.PSBase.Keys | Sort-Object)
}
$script:ES_SHORT_PREFIX_RE = '\A(?:' + (Join-EsAlternation (Get-EsShortNamePrefixes)) + ')'

function Test-EsShortNameRisk([string]$Path) {
    # A "~<digit>" component that may be the 8.3 name of a credential store: as the last
    # component any (a *_history file may have any short name), as a folder one that starts like
    # a component of a spec credential folder or file (ES_SHORT_PREFIX_RE; over-cautious on
    # purpose: the long name is never looked up, so an unknown short name must count as a risk).
    $parts = @($Path.Split('\') | Where-Object { $_ })
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -notmatch '~[0-9]') { continue }
        if ($i -eq $parts.Count - 1 -or $parts[$i].TrimStart('.') -match $script:ES_SHORT_PREFIX_RE) { return $true }
    }
    return $false
}

function Test-EsDeviceName([string]$Path) {
    # A reserved device name as the last component (CON, PRN, AUX, NUL, COM1-9, LPT1-9, CONIN$,
    # CONOUT$; any case, with or without an extension): opening it opens a device, not a file.
    $leaf = $Path.Substring($Path.LastIndexOfAny([char[]]'\/') + 1)
    $dot = $leaf.IndexOf('.')
    if ($dot -ge 0) { $leaf = $leaf.Substring(0, $dot) }
    return ($leaf.TrimEnd(' ') -match '\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$)\z')
}

function Expand-EsPathPattern([string]$Pattern, [hashtable]$Result = $null) {
    # ~ = profile, {env:NAME} = variable (pattern skipped when unset), * and ? = glob.
    # Returns existing absolute local paths only (Test-EsLocalPath): a pattern that expands to
    # anything else, e.g. because a variable is empty or relative, is never touched. A path that
    # names a credential store (PIP_CONFIG_FILE=~/.netrc) or a reserved device (CON, NUL.txt:
    # opening it opens the device) is dropped before it is tested, and so is a path below a
    # folder that is a link not followed ($Result notes "<folder> not read: <reason>"). The path
    # itself may be such a link: its reader checks it (Get-EsPathLinkReason, Read-EsTextFile).
    $path = $Pattern
    if ($path.StartsWith('~')) { $path = [string]$env:USERPROFILE + $path.Substring(1) }
    for ($round = 0; $path -match '\{env:([A-Za-z0-9_()]+)\}'; $round++) {
        $value = Get-EsEnv $matches[1]
        if (-not $value -or $round -ge 8) { return @() }
        $path = $path.Replace('{env:' + $matches[1] + '}', $value.TrimEnd('\'))
    }
    $path = $path.Replace('/', '\')
    if (-not (Test-EsLocalPath $path) -or (Test-EsCredentialPath $path) -or (Test-EsDeviceName $path)) { return @() }
    $refused = Get-EsRefusedFolder $path
    if ($refused) { Add-EsReadNote $Result $refused.path $refused.reason; return @() }
    if ($path.IndexOfAny([char[]]'*?') -ge 0) { return @(Expand-EsGlob $path $Result) }
    if (Test-Path -LiteralPath $path) { return @($path) }
    return @()
}

function Expand-EsGlob([string]$Path, [hashtable]$Result) {
    # The existing matches of a path with * or ? in one or more components, expanded one
    # component at a time: a folder is listed only after its own path passed the checks (no
    # credential store, no device name, no link that is not followed), so neither a "*" nor a
    # {env:} value lists a credential folder or a share behind a link.
    $parts = $Path.Split('\')
    $current = @($parts[0])
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $part = $parts[$i]
        $next = @()
        foreach ($base in $current) {
            if ($part.IndexOfAny([char[]]'*?') -lt 0) { $next += ($base + '\' + $part); continue }
            $link = Get-EsPathLinkReason $base
            if ($link) { Add-EsReadNote $Result $base $link; continue }
            $next += @(Get-ChildItem -LiteralPath ($base + '\') -Name -Force -ErrorAction SilentlyContinue |
                    Where-Object { ([string]$_) -like $part } | ForEach-Object { $base + '\' + [string]$_ })
        }
        $current = @($next | Where-Object { -not (Test-EsCredentialPath $_) -and -not (Test-EsDeviceName $_) })
    }
    $found = @()
    foreach ($candidate in $current) {
        $refused = Get-EsRefusedFolder $candidate
        if ($refused) { Add-EsReadNote $Result $refused.path $refused.reason; continue }
        if (Test-Path -LiteralPath $candidate) { $found += $candidate }
    }
    return $found
}

function Test-EsPlaceholderFile($Item) {
    # OneDrive/cloud placeholders download when read: OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS.
    $attributes = [int]$Item.Attributes
    return (($attributes -band 0x1000) -ne 0 -or ($attributes -band 0x40000) -ne 0 -or ($attributes -band 0x400000) -ne 0)
}

# Why a file or folder that is a link is not read or listed (Get-EsLinkReason), and why a path
# that is not local is not looked at (Get-EsNonLocalReason).
$script:ES_LINK_REASONS = @('link to a network path', 'link to a credential store', 'link target unknown',
    'network path', 'not a local path', 'credential store')

function Get-EsNonLocalReason([string]$Path) {
    # Why a path is never looked at, not even with Get-Item: 'network path' (UNC, device UNC or a
    # mapped network drive) or 'not a local path' (relative, root- or drive-relative, a device
    # path); $null for an absolute path on a local drive (Test-EsLocalPath), a drive (C:) too.
    $p = ([string]$Path).Replace('/', '\')
    if ($p -match '\A[A-Za-z]:\z') { $p += '\' }
    if (Test-EsLocalPath $p) { return $null }
    if ($p -match '\A\\\\[?.]\\(?!UNC\\)') { return 'not a local path' }
    if (Test-EsNetworkPath $p) { return 'network path' }
    return 'not a local path'
}

function Test-EsLinkItem($Item) {
    # A file or folder whose content is elsewhere: a symbolic link or a junction. Before
    # PowerShell 5 (no LinkType) any reparse point counts, as a link with an unknown target.
    if (([int]$Item.Attributes -band 0x400) -eq 0) { return $false }
    if ($script:ES_PS_MAJOR -lt 5) { return $true }
    return (@('SymbolicLink', 'Junction') -contains [string]$Item.LinkType)
}

function Get-EsLinkTarget($Item, [string]$Path) {
    # The full path the link $Item at $Path points to (a relative target is relative to the
    # link's folder); $null when unknown: no Target before PowerShell 5, or a volume or
    # root-relative target.
    if ($script:ES_PS_MAJOR -lt 5) { return $null }
    $target = ''
    try { $target = [string](@($Item.Target) | Where-Object { $_ } | Select-Object -First 1) } catch { }
    $target = $target -replace '\A\\(\?\?|\\\?)\\', ''
    if ($target -match '\AUNC\\') { return (ConvertTo-EsFlatPath ('\' + $target.Substring(3))) }
    if ($target -match '\A([A-Za-z]:\\|\\\\)') { return (ConvertTo-EsFlatPath $target) }
    if (-not $target -or $target -match '\A(\\|[A-Za-z]:|Volume\{)') { return $null }
    return (ConvertTo-EsFlatPath ((Get-EsParentDir $Path) + '\' + $target))
}

function Get-EsLinkReason($Item, [string]$Path) {
    # Why the item at $Path is not read or listed: a link (Test-EsLinkItem) is followed only to a
    # local path that is no credential store, and a link there to another link is checked again.
    # $null: no link (a cloud file on disk, a deduplicated file), or a link that may be followed.
    # Only the link and local link targets are looked at, never a network or credential path.
    $current = $Item
    $at = $Path
    for ($hop = 0; $hop -lt 8; $hop++) {
        if (-not (Test-EsLinkItem $current)) { return $null }
        $target = Get-EsLinkTarget $current $at
        if (-not $target) { return 'link target unknown' }
        if (Test-EsCredentialPath $target) { return 'link to a credential store' }
        if (Test-EsNetworkPath $target) { return 'link to a network path' }
        if (-not (Test-EsLocalPath $target) -or (Test-EsDeviceName $target)) { return 'link target unknown' }
        $above = Get-EsRefusedFolder $target
        if ($above) { return $above.reason }
        $current = Get-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
        if ($null -eq $current) { return $null }
        $at = $target
    }
    return 'link target unknown'
}

# Link reasons of the paths looked at in this scan (lower-case path -> reason, '' for none).
$script:ES_LINK_CACHE = @{}

function Get-EsCachedLinkReason([string]$Path) {
    # Get-EsLinkReason of one path whose folders above passed, once per scan ('' when there is
    # none or the path is gone). While it is checked it counts as 'link target unknown', which
    # ends a loop of links through the folders above their targets.
    $nonLocal = Get-EsNonLocalReason $Path
    if ($nonLocal) { return $nonLocal }
    $key = $Path.ToLowerInvariant()
    if ($script:ES_LINK_CACHE.ContainsKey($key)) { return $script:ES_LINK_CACHE[$key] }
    $script:ES_LINK_CACHE[$key] = 'link target unknown'
    $reason = ''
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -ne $item) { $reason = [string](Get-EsLinkReason $item $Path) }
    $script:ES_LINK_CACHE[$key] = $reason
    return $reason
}

function Get-EsCredentialFolder([string]$Path) {
    # The shortest part of $Path (a folder above it, or $Path itself) that is a credential store
    # (Test-EsCredentialPath), or $null. Text only: nothing is looked at. The folders above are
    # tested as folders (an 8.3 "~1" name is a risk there only when it may abbreviate a
    # credential folder); $Path itself also as a file.
    $parts = $Path.Replace('/', '\').TrimEnd('\').Split('\')
    $folder = $parts[0]
    for ($i = 1; $i -lt $parts.Count - 1; $i++) {
        $folder += '\' + $parts[$i]
        if (Test-EsCredentialPath ($folder + '\_')) { return $folder }
    }
    if (Test-EsCredentialPath $Path) { return $Path }
    return $null
}

function Get-EsRefusedFolder([string]$Path) {
    # The first folder above $Path, from the volume root down (to a * or ? component), that is
    # a link not followed (Get-EsLinkReason) as @{ path; reason }, else $null. A file or folder
    # below such a link is never tested, listed, read or run: Windows would follow the link.
    # One Get-Item per folder per scan; no folder below a refused one is looked at. A path that
    # is not local is refused as a whole (Get-EsNonLocalReason), before any Get-Item, and so is a
    # path in or below a credential store (Get-EsCredentialFolder: reason 'credential store').
    $nonLocal = Get-EsNonLocalReason $Path
    if ($nonLocal) { return @{ path = $Path; reason = $nonLocal } }
    $store = Get-EsCredentialFolder $Path
    if ($store) { return @{ path = $store; reason = 'credential store' } }
    $parts = $Path.Replace('/', '\').TrimEnd('\').Split('\')
    $folder = $parts[0]
    for ($i = 1; $i -lt $parts.Count - 1; $i++) {
        if ($parts[$i].IndexOfAny([char[]]'*?') -ge 0) { break }
        $folder += '\' + $parts[$i]
        $reason = Get-EsCachedLinkReason $folder
        if ($reason) { return @{ path = $folder; reason = $reason } }
    }
    return $null
}

function Get-EsPathLinkReason([string]$Path) {
    # Why a path is not touched (tested, listed, read or run): a folder above it or the path
    # itself is a link that is not followed (Get-EsLinkReason). $null when it may be (or is gone).
    $refused = Get-EsRefusedFolder $Path
    if ($refused) { return $refused.reason }
    $p = $Path.Replace('/', '\').TrimEnd('\')
    if ($p.IndexOf('\') -lt 0) { return $null }
    $reason = Get-EsCachedLinkReason $p
    if ($reason) { return $reason }
    return $null
}

function Test-EsSafePath([string]$Path, [string]$PathType = 'Any') {
    # Test-Path for a path that may be touched; $false, without looking behind the link, when
    # the path or a folder above it is a link that is not followed (Get-EsPathLinkReason).
    if (Get-EsPathLinkReason $Path) { return $false }
    return [bool](Test-Path -LiteralPath $Path -PathType $PathType)
}

function Test-EsListableFolder([hashtable]$Result, [string]$Path) {
    # An existing folder that may be listed (a package or install root). When it or a folder
    # above it is a link that is not followed, $Result notes "<that folder> not read: <reason>".
    $refused = Get-EsRefusedFolder $Path
    if (-not $refused) {
        $reason = Get-EsPathLinkReason $Path
        if ($reason) { $refused = @{ path = $Path; reason = $reason } }
    }
    if ($refused) { Add-EsReadNote $Result $refused.path $refused.reason; return $false }
    return [bool](Test-Path -LiteralPath $Path -PathType Container)
}

function Add-EsReadNote([hashtable]$Result, [string]$Path, [string]$Problem, [string]$Label = '') {
    # A file or folder that was not read makes the probe partial: "<path> not read: <reason>"
    # (once) for a link (ES_LINK_REASONS), otherwise "<label>: <problem>" (no label: links only).
    if ($null -eq $Result -or -not $Problem) { return }
    if ($script:ES_LINK_REASONS -contains $Problem) {
        $note = $Path + ' not read: ' + $Problem
        if (@($Result.notes) -notcontains $note) { Add-EsNote $Result $note 'partial' }
    } elseif ($Label) { Add-EsNote $Result ($Label + ': ' + $Problem) 'partial' }
}

function Read-EsTextFile([string]$Path, [int]$MaxBytes = 16384) {
    # The text of a file, capped. Never opened: a folder, a cloud placeholder (it would
    # download), a link that does not end on a local path and a file below a folder that is
    # such a link (error: Get-EsLinkReason, Get-EsRefusedFolder).
    $result = @{ path = $Path; text = $null; size = $null; truncated = $false; error = $null }
    $refused = Get-EsRefusedFolder $Path
    if ($refused) { $result.error = $refused.reason; return $result }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer) { $result.error = 'is a directory'; return $result }
        $result.size = [long]$item.Length
        if (Test-EsPlaceholderFile $item) { $result.error = 'cloud placeholder (not downloaded)'; return $result }
        $result.error = Get-EsLinkReason $item $Path
        if ($result.error) { return $result }
        $lines = @(Get-Content -LiteralPath $Path -TotalCount 4000 -ErrorAction Stop)
        $text = $lines -join "`n"
        if ($text.Length -gt $MaxBytes -or $result.size -gt $MaxBytes) {
            $result.truncated = $true
            if ($text.Length -gt $MaxBytes) { $text = $text.Substring(0, $MaxBytes) }
        }
        $result.text = $text
    } catch {
        $result.error = $_.Exception.Message
    }
    return $result
}

function Read-EsBytes([string]$Path, [int]$Count = 4096) {
    if ($script:ES_PS_MAJOR -ge 6) { return @(Get-Content -LiteralPath $Path -AsByteStream -TotalCount $Count -ErrorAction Stop) }  # lint-allow: byte-encoding
    return @(Get-Content -LiteralPath $Path -Encoding Byte -TotalCount $Count -ErrorAction Stop)  # lint-allow: byte-encoding
}

function Get-EsDirEntries([string]$Path, [int]$Max = 5000) {
    # The entries of a folder; none when it or a folder above it is a link that is not followed.
    if (Get-EsPathLinkReason $Path) { return @() }
    try { return @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Select-Object -First $Max) }
    catch { return @() }
}

function Test-EsWritableDir([string]$Path) {
    # Creates and deletes one new file (never an existing one: no -Force).
    # Returns $true, $false or $null (directory missing, or not an absolute local path).
    if (-not (Test-EsLocalPath $Path) -or -not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    $probe = Join-Path $Path ('.envscan-write-' + $PID + '-' + (Get-Random) + '.tmp')
    try { $null = New-Item -ItemType File -Path $probe -ErrorAction Stop }
    catch { return $false }
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    return $true
}

function Get-EsPeMachine([string]$Path) {
    # Machine type from the PE header: x86, x86_64, arm64, arm; 'script' or $null otherwise.
    try {
        $bytes = Read-EsBytes $Path 4096
        if ($bytes.Count -lt 64) { return $null }
        if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
            if ($bytes[0] -eq 0x23 -and $bytes[1] -eq 0x21) { return 'script' }
            return $null
        }
        $offset = [int]$bytes[60] + 256 * [int]$bytes[61] + 65536 * [int]$bytes[62]
        if ($offset + 6 -ge $bytes.Count) { return $null }
        $machine = [int]$bytes[$offset + 4] + 256 * [int]$bytes[$offset + 5]
        switch ($machine) {
            0x014c { return 'x86' }
            0x8664 { return 'x86_64' }
            0xAA64 { return 'arm64' }
            0x01c4 { return 'arm' }
            0x0200 { return 'ia64' }
        }
        return ('0x' + $machine.ToString('x4'))
    } catch { return $null }
}
