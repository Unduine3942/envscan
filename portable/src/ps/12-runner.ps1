# ---------------------------------------------------------------------------
# 12-runner: arguments, probe results, probe runner, output folder, report.
# ---------------------------------------------------------------------------

$script:ES_USAGE = @(
    'Usage: envscan.ps1 [options]   (normally started through envscan.cmd)',
    '',
    '  --deep          also run probes that security tooling may flag (whoami /all, gpresult, exec tests)',
    '  --net           also check reachability of proxies and mirrors found in local configuration',
    '  --out DIR       parent directory for the output folder',
    '  --only IDS      comma-separated probe ids or area wildcards (net.*) to run',
    '  --skip IDS      comma-separated probe ids or area wildcards to skip',
    '  --timeout SEC   timeout per external command (default 15)',
    '  --budget SEC    time budget for the whole scan (default 600)',
    '  --no-redact     write secret values unredacted',
    '  --list-probes   list every probe and exactly what it reads or runs, then exit',
    '  --version       print the version and exit',
    '  --help          this text'
)

$script:ES_FLAG_OPTIONS = @('deep', 'net', 'no-redact', 'list-probes', 'version', 'help', 'h')
$script:ES_VALUE_OPTIONS = @('out', 'only', 'skip', 'timeout', 'budget')

function Split-EsIdList([string]$Value) {
    return @($Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-EsIdPatterns([string]$Option, [object[]]$Patterns) {
    # Error messages for --only / --skip: at least one pattern ("", "," and " , " hold none); a
    # pattern holds letters, digits, . _ - and * only, and selects at least one probe (a typo
    # must not silently run or skip everything).
    if (@($Patterns).Count -eq 0) { return @('--' + $Option + ' needs probe ids') }
    $errors = @()
    foreach ($pattern in @($Patterns)) {
        $text = [string]$pattern
        if ($text -notmatch '\A[A-Za-z0-9._*-]+\z') {
            $errors += ('--' + $Option + ": invalid pattern '" + $text + "' (allowed: letters, digits, . _ - *)")
        } elseif (@($script:ES_PROBES | Where-Object { [string]$_.id -like $text }).Count -eq 0) {
            $errors += ('--' + $Option + ": pattern '" + $text + "' matches no probe")
        }
    }
    return $errors
}

function Read-EsNumberOption([string]$Value, [int]$Min, [int]$Max) {
    # The value as an int when it is a plain decimal number in range, else $null.
    if ($Value -notmatch '\A[0-9]{1,9}\z') { return $null }
    $number = [int]$Value
    if ($number -lt $Min -or $number -gt $Max) { return $null }
    return $number
}

function Read-EsArguments([object[]]$Arguments) {
    $errors = @()
    $list = @($Arguments)
    $i = 0
    while ($i -lt $list.Count) {
        $raw = [string]$list[$i]
        $value = $null
        $name = $raw
        if ($raw -match '\A(-{1,2}[A-Za-z-]+)=([\s\S]*)\z') { $name = $matches[1]; $value = $matches[2] }
        if (-not $name.StartsWith('-')) { $errors += ('unexpected argument: ' + $raw); $i++; continue }
        $key = $name.TrimStart('-').ToLowerInvariant()
        if ($script:ES_FLAG_OPTIONS -contains $key -and $null -ne $value) { $errors += ('option --' + $key + ' takes no value'); $i++; continue }
        if ($script:ES_VALUE_OPTIONS -contains $key -and $null -eq $value) {
            $i++
            if ($i -ge $list.Count) { $errors += ('missing value for ' + $raw); break }
            $value = [string]$list[$i]
        }
        switch ($key) {
            'deep' { $script:ES_OPT.deep = $true }
            'net' { $script:ES_OPT.net = $true }
            'no-redact' { $script:ES_OPT.redact = $false }
            'list-probes' { $script:ES_OPT.list = $true }
            'version' { $script:ES_OPT.version = $true }
            'help' { $script:ES_OPT.help = $true }
            'h' { $script:ES_OPT.help = $true }
            'out' { $script:ES_OPT.out = $value }
            'only' { $script:ES_OPT.only = @(Split-EsIdList $value); $errors += @(Test-EsIdPatterns 'only' $script:ES_OPT.only) }
            'skip' { $script:ES_OPT.skip = @(Split-EsIdList $value); $errors += @(Test-EsIdPatterns 'skip' $script:ES_OPT.skip) }
            'timeout' {
                $number = Read-EsNumberOption $value 1 3600
                if ($null -ne $number) { $script:ES_OPT.timeout = $number } else { $errors += ('--timeout must be 1-3600 seconds: ' + $value) }
            }
            'budget' {
                $number = Read-EsNumberOption $value 10 86400
                if ($null -ne $number) { $script:ES_OPT.budget = $number } else { $errors += ('--budget must be 10-86400 seconds: ' + $value) }
            }
            default { $errors += ('unknown option: ' + $raw) }
        }
        $i++
    }
    return $errors
}

# ------------------------------------------------------------------ probe results

function New-EsResult([string]$Status = 'ok') {
    return @{ status = $Status; data = @{}; raw = @{}; sources = @(); notes = @(); error = $null; truncated = $false }
}

function Add-EsNote([hashtable]$Result, [string]$Note, [string]$Status = 'partial') {
    $Result.notes += $Note
    if ($Status -and $Result.status -eq 'ok') { $Result.status = $Status }
}

function Add-EsCimItems([hashtable]$Result, [string]$Class, [string]$Namespace = 'root/cimv2', [string]$Filter = '') {
    # Queries CIM, records the source, and notes failures. Returns the items (possibly empty).
    $label = 'CIM ' + $Class
    if ($Namespace -ne 'root/cimv2') { $label = 'CIM ' + $Namespace + ':' + $Class }
    $Result.sources += $label
    $query = Get-EsCimSafe -Class $Class -Namespace $Namespace -Filter $Filter
    if ($query.status -ne 'ok') { Add-EsNote $Result $query.error 'partial' }
    return @($query.items)
}

function Invoke-EsTool {
    # Runs a tool for a probe: records the source and raw output, and marks the probe
    # partial when the tool timed out, could not start, exited non-zero or printed nothing
    # (its data is then incomplete, not "none"). -AllowFailure skips the exit/output check.
    param([hashtable]$Result, [string]$Label, [string]$FilePath, [string[]]$Arguments = @(),
        [int]$TimeoutSec = 0, [string]$Encoding = 'Oem', [switch]$AllowFailure)
    $run = Invoke-EsCommand -FilePath $FilePath -Arguments $Arguments -TimeoutSec $TimeoutSec -Encoding $Encoding
    $Result.sources += ('run ' + $run.command)
    $text = Get-EsCommandText $run
    if ($text) { $Result.raw[$Label] = $text }
    if ($run.timed_out) { Add-EsNote $Result ($Label + ': timed out') 'partial' }
    elseif ($run.error) { Add-EsNote $Result ($Label + ': ' + $run.error) 'partial' }
    elseif (-not $AllowFailure) {
        if ($null -ne $run.exit_code -and $run.exit_code -ne 0) { Add-EsNote $Result ($Label + ': exit code ' + $run.exit_code) 'partial' }
        elseif (-not $text) { Add-EsNote $Result ($Label + ': no output') 'partial' }
    }
    return $run
}

# The Windows folder as Windows reports it: the parent of [Environment]::SystemDirectory
# (GetSystemDirectory; a static property, so ConstrainedLanguage and PS 2.0 allow it). Never
# $env:SystemRoot, SystemDrive or windir: a SystemRoot of \\host\share would make every batch
# file run that share's cmd.exe. Read once; tests may set it to a fake value.
$script:ES_WINDOWS_DIR = $null

function Test-EsSystemFolder([string]$Path) {
    # A plain local folder X:\name[\name...] (no device, UNC, mapped network drive, % or 8.3 name)
    # that is not, and is not below, a link or a credential store.
    if ($Path -notmatch '\A[A-Za-z]:\\[^\\/:*?"<>|%~]+(\\[^\\/:*?"<>|%~]+)*\z') { return $false }
    if (-not (Test-EsLocalPath $Path)) { return $false }
    return (-not (Get-EsPathLinkReason $Path))
}

function Get-EsWindowsDir {
    # The trusted Windows folder, or $null when it is not Test-EsSystemFolder.
    if ($null -eq $script:ES_WINDOWS_DIR) {
        $system = ''
        try { $system = [string][Environment]::SystemDirectory } catch { $system = '' }
        $script:ES_WINDOWS_DIR = ($system -replace '\\+\z', '') -replace '\\[^\\]*\z', ''
    }
    if (Test-EsSystemFolder $script:ES_WINDOWS_DIR) { return $script:ES_WINDOWS_DIR }
    return $null
}

function Get-EsSystemTool([string]$Name) {
    # Absolute System32 path (never PATH, never $env:SystemRoot); Sysnative from a 32-bit process
    # on 64-bit Windows. $null when the Windows folder is not trusted (the command is then refused).
    $root = Get-EsWindowsDir
    if (-not $root) { return $null }
    if ($env:PROCESSOR_ARCHITEW6432) {
        $native = Join-Path $root ('Sysnative\' + $Name)
        if (Test-Path -LiteralPath $native) { return $native }
    }
    return (Join-Path $root ('System32\' + $Name))
}

# ------------------------------------------------------------------ runner

function Test-EsIdMatch([string]$Id, [object[]]$Patterns) {
    foreach ($pattern in @($Patterns)) { if ($Id -like [string]$pattern) { return $true } }
    return $false
}

function Get-EsSkipReason([hashtable]$Meta) {
    if ($Meta.tier -eq 'deep' -and -not $script:ES_OPT.deep) { return 'requires --deep' }
    if ($Meta.tier -eq 'net' -and -not $script:ES_OPT.net) { return 'requires --net' }
    if (@($script:ES_OPT.only).Count -gt 0 -and -not (Test-EsIdMatch $Meta.id $script:ES_OPT.only)) { return 'not selected by --only' }
    if (Test-EsIdMatch $Meta.id $script:ES_OPT.skip) { return 'excluded by --skip' }
    if (((Get-EsUtc) - $script:ES_STARTED).TotalSeconds -gt $script:ES_OPT.budget) {
        $script:ES_BUDGET_SKIPS++
        return 'scan budget exhausted'
    }
    return $null
}

function Limit-EsRaw([hashtable]$Raw) {
    # Redacts raw text and caps it at ES_RAW_CAP characters per probe.
    $out = @{}
    $truncated = $false
    $left = $script:ES_RAW_CAP
    foreach ($label in @($Raw.PSBase.Keys | Sort-Object)) {
        $text = Protect-EsText ([string]$Raw[$label])
        if ($null -eq $text -or $text.Length -eq 0) { continue }
        if ($left -le 0) { $truncated = $true; continue }
        if ($text.Length -gt $left) { $text = $text.Substring(0, $left) + "`n[truncated]"; $truncated = $true }
        $left -= $text.Length
        $out[[string]$label] = $text
    }
    return @{ raw = $out; truncated = $truncated }
}

function Complete-EsEnvelope([hashtable]$Meta, [hashtable]$Result, [int]$DurationMs) {
    $status = [string]$Result.status
    if ($script:ES_STATUSES -notcontains $status) { $status = 'error' }
    $rawTable = $Result.raw
    if (-not ($rawTable -is [hashtable])) { $rawTable = @{} }
    $limited = Limit-EsRaw $rawTable
    $raw = $limited.raw
    $truncated = ([bool]$Result.truncated -or [bool]$limited.truncated)
    $data = $Result.data
    if (-not ($data -is [hashtable])) { $data = @{} }
    $envelope = @{
        __order = @('status', 'tier', 'scope', 'title', 'sources', 'duration_ms', 'data', 'raw', 'truncated', 'error', 'notes')
        status = $status; tier = [string]$Meta.tier; scope = [string]$Meta.scope; title = [string]$Meta.title
        sources = @(@($Result.sources) | Where-Object { $_ } | ForEach-Object { Protect-EsCommandLine ([string]$_) })
        duration_ms = $DurationMs; data = (Protect-EsData $data); truncated = $truncated; error = $null
    }
    if ($Result.error) { $envelope.error = Protect-EsValue ([string]$Result.error) }
    if ($raw.Count -gt 0) { $envelope.raw = $raw }
    $notes = @(@($Result.notes) | Where-Object { $_ } | ForEach-Object { Protect-EsValue ([string]$_) })
    if ($notes.Count -gt 0) { $envelope.notes = $notes }
    return $envelope
}

function Add-EsDeniedNote([hashtable]$Result) {
    # Registry keys the probe was denied (Add-EsDeniedRead): its data is incomplete, so an ok
    # or not_found result becomes partial, with the keys in a note.
    $denied = @($script:ES_DENIED_READS)
    $script:ES_DENIED_READS = @()
    if ($denied.Count -eq 0) { return }
    $shown = (@($denied | Select-Object -First 5) -join ', ')
    if ($denied.Count -gt 5) { $shown += (' (+' + ($denied.Count - 5) + ' more)') }
    $Result.notes = @($Result.notes) + @('access denied to ' + $denied.Count + ' registry key(s): ' + $shown)
    if (@('ok', 'not_found') -contains [string]$Result.status) { $Result.status = 'partial' }
}

function Invoke-EsProbe([hashtable]$Meta) {
    $start = Get-EsUtc
    $reason = Get-EsSkipReason $Meta
    if ($reason) {
        $result = New-EsResult 'skipped'
        $result.notes = @($reason)
    } else {
        $function = 'probe_' + $Meta.id.Replace('.', '_')
        $script:ES_DENIED_READS = @()
        try {
            $output = @(& $function)
            $result = $output | Where-Object { $_ -is [hashtable] -and $_.ContainsKey('status') } | Select-Object -Last 1
            if (-not $result) { $result = New-EsResult 'error'; $result.error = 'probe returned no result' }
        } catch {
            $result = New-EsResult 'error'
            $result.error = $_.Exception.Message
        }
        Add-EsDeniedNote $result
    }
    $probeMs = Get-EsElapsedMs $start
    try { $envelope = Complete-EsEnvelope $Meta $result $probeMs }
    catch {
        # A malformed probe result must not end the scan: record it as an error instead.
        $failed = New-EsResult 'error'
        $failed.error = 'could not complete the probe result: ' + $_.Exception.Message
        $envelope = Complete-EsEnvelope $Meta $failed $probeMs
    }
    $script:ES_RESULTS[$Meta.id] = $envelope
    $redactMs = (Get-EsElapsedMs $start) - $probeMs
    Write-EsLog ($Meta.id + ' ' + $envelope.status + ' ' + $envelope.duration_ms + 'ms (redaction ' + $redactMs + 'ms)' + $(if ($envelope.error) { ' ' + $envelope.error } else { '' }))
    return $envelope
}

function Test-EsDependency([hashtable]$Result, [string]$Id) {
    # A probe built on another probe's data: when that probe did not complete, mark this one
    # as an error instead of concluding "not found" from missing data.
    $status = Get-EsStatus $Id
    if (@('ok', 'partial', 'not_found', 'not_applicable') -contains $status) { return $true }
    if (-not $status) { $status = 'not run' }
    $Result.status = 'error'
    $Result.error = 'depends on ' + $Id + ', which is ' + $status
    return $false
}

function Test-EsInputComplete([hashtable]$Result, [string]$Id) {
    # A probe that adds another probe's data to its own (net.proxy, net.reachability): when that
    # probe did not complete (skipped, failed, not run), its part is missing, so this probe is
    # partial with a note instead of ok or not_found. $true when the data is complete.
    $status = Get-EsStatus $Id
    if (@('ok', 'partial', 'not_found', 'not_applicable') -contains $status) { return $true }
    if (-not $status) { $status = 'not run' }
    $Result.notes += ($Id + ' is ' + $status + ': what it would have added is missing')
    if (@('ok', 'not_found') -contains $Result.status) { $Result.status = 'partial' }
    return $false
}

function Get-EsData([string]$Id) {
    # Data of an earlier probe, or an empty table.
    $envelope = $script:ES_RESULTS[$Id]
    if ($envelope -and $envelope.data -is [hashtable]) { return $envelope.data }
    return @{}
}

function Get-EsStatus([string]$Id) {
    $envelope = $script:ES_RESULTS[$Id]
    if ($envelope) { return [string]$envelope.status }
    return $null
}

# ------------------------------------------------------------------ output folder

function Get-EsSafeHostName {
    $name = [string]$env:COMPUTERNAME
    if (-not $name) { $name = 'host' }
    return ($name -replace '[^A-Za-z0-9._-]', '_')
}

function Get-EsDefaultOutputParents {
    # The current directory, the profile, then TEMP. Never a network, OneDrive, Desktop or
    # Documents folder, from where the report could leave the machine; --out is used as given.
    Initialize-EsDrives
    $candidates = @()
    $location = Get-Location
    if ($location.Provider.Name -eq 'FileSystem') { $candidates += [string]$location.ProviderPath }
    $candidates += @($env:USERPROFILE, $env:TEMP)
    $personal = @(Get-EsPersonalFolders)
    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        if ((Test-EsNetworkPath $candidate) -or (Test-EsUnderFolder $candidate $personal)) {
            Write-EsLog ('output: skipped ' + $candidate + ' (network, OneDrive, Desktop or Documents folder)')
            continue
        }
        if (Get-EsCredentialFolder $candidate) {
            Write-EsLog ('output: skipped ' + $candidate + ' (credential store)')
            continue
        }
        $candidate
    }
}

function New-EsOutputFolder {
    $name = 'envscan-' + (Get-EsSafeHostName) + '-' + (Format-EsStamp $script:ES_STARTED)
    $parents = @()
    if ($script:ES_OPT.out) { $parents = @([string]$script:ES_OPT.out) }
    else { $parents = @(Get-EsDefaultOutputParents) }
    foreach ($parent in $parents) {
        if (-not $parent) { continue }
        try {
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                if (-not $script:ES_OPT.out) { continue }
                $null = New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop
            }
            $folder = Join-Path $parent $name
            $null = New-Item -ItemType Directory -Path $folder -ErrorAction Stop
            return $folder
        } catch {
            Write-EsLog ('cannot write output under ' + $parent + ': ' + $_.Exception.Message)
        }
    }
    return $null
}

function Initialize-EsTemp {
    # A new, randomly named folder (never an existing one: TEMP may be shared). Call
    # Initialize-EsDrives first: a TEMP on a mapped network drive is refused (Test-EsLocalPath).
    # Children run from the root of the drive of the trusted Windows folder (never SystemDrive).
    $base = $env:TEMP
    if (-not $base) { $base = $env:USERPROFILE }
    if (-not $base -or -not (Test-EsLocalPath $base) -or $base.Contains('%')) { throw ('no usable TEMP folder: ' + $base) }
    if (Get-EsCredentialFolder $base) { throw ('no usable TEMP folder: ' + $base + ' (credential store)') }
    $windows = Get-EsWindowsDir
    if (-not $windows) { throw 'the Windows folder is not a trusted local path' }
    $folder = $null
    for ($attempt = 0; $attempt -lt 5 -and -not $folder; $attempt++) {
        $candidate = Join-Path $base ('envscan-' + $PID + '-' + (Get-Random))
        try { $null = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop; $folder = $candidate } catch { }
    }
    if (-not $folder) { throw ('cannot create a temporary folder under ' + $base) }
    $script:ES_TMP = $folder
    $script:ES_EMPTY_IN = Join-Path $folder 'stdin.empty'
    $null = New-Item -ItemType File -Path $script:ES_EMPTY_IN -ErrorAction Stop
    $script:ES_CHILD_CWD = $windows.Substring(0, 2) + '\'
}

function Remove-EsTemp {
    if ($script:ES_TMP -and (Test-Path -LiteralPath $script:ES_TMP)) {
        Remove-Item -LiteralPath $script:ES_TMP -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-EsTextFile([string]$Path, [string]$Text, [string]$Encoding) {
    Set-Content -LiteralPath $Path -Value $Text -Encoding $Encoding -ErrorAction Stop
}
