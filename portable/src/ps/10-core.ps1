# ---------------------------------------------------------------------------
# 10-core: state, time, environment, logging (redacted), JSON writer.
# Everything here must work in PowerShell 2.0 and in ConstrainedLanguage mode.
# ---------------------------------------------------------------------------

$script:ES_IMPL = 'powershell'
$script:ES_STATUSES = @('ok', 'partial', 'not_found', 'not_applicable', 'denied', 'timeout', 'error', 'skipped')
$script:ES_RAW_CAP = 65536
$script:ES_OPT = @{
    deep = $false; net = $false; out = $null; only = @(); skip = @()
    timeout = 15; budget = 600; redact = $true; list = $false; version = $false; help = $false
}
$script:ES_RESULTS = @{}
$script:ES_LOG = @()
$script:ES_TMP = $null
$script:ES_EMPTY_IN = $null
$script:ES_CHILD_CWD = $null
$script:ES_CMD_SEQ = 0
$script:ES_BUDGET_SKIPS = 0
$script:ES_NETWORK_DRIVES = @()
$script:ES_NETWORK_DRIVE_TARGETS = @{}
$script:ES_ENV_SNAPSHOT = @{}
$script:ES_CHILD_ENV_SAVED = @{}
$script:ES_STARTED = [DateTime]::UtcNow
$script:ES_PS_MAJOR = 2
if ($PSVersionTable -and $PSVersionTable.PSVersion) { $script:ES_PS_MAJOR = [int]$PSVersionTable.PSVersion.Major }
$script:ES_LANGUAGE_MODE = [string]$ExecutionContext.SessionState.LanguageMode
$script:ES_FULL_LANGUAGE = ($script:ES_LANGUAGE_MODE -eq 'FullLanguage')
$script:ES_HAS_CIM = ($script:ES_PS_MAJOR -ge 3)
$script:ES_PLACEHOLDER = '<redacted>'

# ------------------------------------------------------------------ time

function Get-EsUtc { return [DateTime]::UtcNow }

function Format-EsUtc($Value) {
    # ISO 8601; formatted from the numeric parts so the culture's calendar never applies.
    if ($null -eq $Value) { return $null }
    return ('{0:D4}-{1:D2}-{2:D2}T{3:D2}:{4:D2}:{5:D2}Z' -f $Value.Year, $Value.Month, $Value.Day, $Value.Hour, $Value.Minute, $Value.Second)
}

function Format-EsStamp($Value) {
    # Compact UTC stamp for folder names: 20261110T164048Z.
    return ('{0:D4}{1:D2}{2:D2}T{3:D2}{4:D2}{5:D2}Z' -f $Value.Year, $Value.Month, $Value.Day, $Value.Hour, $Value.Minute, $Value.Second)
}

function Get-EsElapsedMs($Start) {
    $ms = [int](([DateTime]::UtcNow - $Start).TotalMilliseconds)
    if ($ms -lt 0) { return 0 }
    return $ms
}

function ConvertFrom-EsCimDate($Value) {
    # CIM returns DateTime; WMI (PS 2.0) returns DMTF strings such as 20261030023208.500000+540.
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $text = [string]$Value
    if ($text -match '^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.\d+([+-]\d+)$') {
        # A PowerShell [datetime] cast parses with the invariant culture.
        $local = [datetime]('{0}-{1}-{2}T{3}:{4}:{5}' -f $matches[1], $matches[2], $matches[3], $matches[4], $matches[5], $matches[6])
        return $local.AddMinutes(-1 * [int]$matches[7])
    }
    return $null
}

# ------------------------------------------------------------------ environment

function Get-EsEnv([string]$Name) {
    if (-not $Name) { return $null }
    $item = Get-Item -LiteralPath ('env:' + $Name) -ErrorAction SilentlyContinue
    if ($item) { return [string]$item.Value }
    return $null
}

function Get-EsProcessEnv {
    # This process environment as a (case-insensitive) name -> value table.
    $table = @{}
    foreach ($item in @(Get-ChildItem -Path 'env:' -ErrorAction SilentlyContinue)) {
        $table[[string]$item.Name] = [string]$item.Value
    }
    return $table
}

function Save-EsEnvSnapshot {
    $script:ES_ENV_SNAPSHOT = Get-EsProcessEnv
}

function Test-EsChildEnvKept([string]$Name) {
    # spec/child_env.toml [child_env_keep]: a listed name or a name with a listed prefix (case
    # is ignored, as Windows does).
    if (-not $Name) { return $false }
    if ($script:ES_CHILD_ENV_KEEP_NAMES -contains $Name) { return $true }
    foreach ($prefix in @($script:ES_CHILD_ENV_KEEP_PREFIXES)) {
        if ($Name.Length -ge $prefix.Length -and $Name.Substring(0, $prefix.Length) -eq $prefix) { return $true }
    }
    return $false
}

function Enter-EsChildEnv {
    # Children inherit this process environment; restored by Exit-EsChildEnv.
    $saved = @{}
    foreach ($name in @($script:ES_CHILD_ENV.PSBase.Keys)) {
        $saved[$name] = Get-EsEnv $name
        $value = [string]$script:ES_CHILD_ENV[$name]
        if ($value) { Set-Item -LiteralPath ('env:' + $name) -Value $value }
        else { Remove-Item -LiteralPath ('env:' + $name) -ErrorAction SilentlyContinue }
    }
    $script:ES_CHILD_ENV_SAVED = $saved
}

function Exit-EsChildEnv {
    foreach ($name in @($script:ES_CHILD_ENV_SAVED.PSBase.Keys)) {
        $old = $script:ES_CHILD_ENV_SAVED[$name]
        if ($null -eq $old) { Remove-Item -LiteralPath ('env:' + $name) -ErrorAction SilentlyContinue }
        else { Set-Item -LiteralPath ('env:' + $name) -Value $old }
    }
    $script:ES_CHILD_ENV_SAVED = @{}
}

# ------------------------------------------------------------------ logging

function Write-EsLog([string]$Message) {
    # Log lines carry commands, paths and error messages: redacted like command lines.
    $text = $Message
    if ($script:ES_REDACT_READY -and $script:ES_OPT.redact) { $text = Protect-EsCommandLine $Message }
    $script:ES_LOG += ((Format-EsUtc (Get-EsUtc)) + ' ' + $text)
}

# stdout is the console window (not a pipe or file): only then may the host print progress.
# A static property, so it works in ConstrainedLanguage; $null (unknown) before .NET 4.5.
$script:ES_STDOUT_IS_CONSOLE = $false
try { $script:ES_STDOUT_IS_CONSOLE = ([Console]::IsOutputRedirected -eq $false) } catch { }

function Write-EsProgress([string]$Message) {
    # Never stdout: it carries only the output folder path. FullLanguage writes to stderr.
    # ConstrainedLanguage cannot call a method on the console streams (nor $Host.UI), and
    # Write-Host goes to stdout when stdout is redirected: it is used only for a console
    # window, and otherwise the line is left out (envscan.log has it).
    if ($script:ES_FULL_LANGUAGE) {
        try { [Console]::Error.WriteLine($Message); return } catch { }
    }
    if ($script:ES_STDOUT_IS_CONSOLE) { Write-Host $Message }
}

function Write-EsFatal([string[]]$Lines) {
    # The message of an exit-2 end (bad arguments, no temp or output folder, internal error)
    # must reach the caller. Where Write-EsProgress has no stream (ConstrainedLanguage, stdout
    # not a console window), the lines go to stderr as one error record. -ErrorAction Continue:
    # the caller's $ErrorActionPreference neither hides it nor makes it a terminating error.
    if ($script:ES_FULL_LANGUAGE -or $script:ES_STDOUT_IS_CONSOLE) {
        foreach ($line in @($Lines)) { Write-EsProgress $line }
        return
    }
    Write-Error -Message (@($Lines) -join "`n") -ErrorAction Continue
}

# ------------------------------------------------------------------ JSON writer

function ConvertTo-EsJsonString($Text) {
    if ($null -eq $Text) { return 'null' }
    $s = [string]$Text
    if ($s -notmatch '[^\x20-\x7E]') {
        if ($s.IndexOf('\') -lt 0 -and $s.IndexOf('"') -lt 0) { return '"' + $s + '"' }
        return '"' + $s.Replace('\', '\\').Replace('"', '\"') + '"'
    }
    $parts = foreach ($ch in $s.ToCharArray()) {
        $code = [int]$ch
        if ($code -eq 34) { '\"' }
        elseif ($code -eq 92) { '\\' }
        elseif ($code -ge 32 -and $code -le 126) { [string]$ch }
        elseif ($code -eq 10) { '\n' }
        elseif ($code -eq 13) { '\r' }
        elseif ($code -eq 9) { '\t' }
        else { '\u' + $code.ToString('x4') }
    }
    return '"' + ($parts -join '') + '"'
}

function Test-EsJsonScalar($Value) {
    return ($null -eq $Value -or $Value -is [string] -or $Value -is [char] -or $Value -is [bool] -or
        $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or
        $Value -is [single] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [datetime])
}

function ConvertTo-EsJsonScalar($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string] -or $Value -is [char]) { return (ConvertTo-EsJsonString ([string]$Value)) }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return (ConvertTo-EsJsonString (Format-EsUtc $Value.ToUniversalTime())) }
    if ($Value -is [double] -or $Value -is [single]) {
        if ([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value)) { return 'null' }
    }
    if (Test-EsJsonScalar $Value) { return [string]$Value }
    return (ConvertTo-EsJsonString ([string]$Value))
}

function Get-EsOrderedKeys([hashtable]$Table) {
    # Keys listed in __order first, then the rest sorted (no pipeline: this runs for every table).
    # .PSBase.Keys: $Table.Keys would return the value of an entry named "Keys" (a registry
    # value or variable can have that name).
    $order = @()
    if ($Table.ContainsKey('__order')) { foreach ($key in $Table['__order']) { if ($Table.ContainsKey($key)) { $order += $key } } }
    $rest = @()
    foreach ($key in $Table.PSBase.Keys) { if ($key -ne '__order' -and $order -notcontains $key) { $rest += [string]$key } }
    if ($rest.Count -gt 1) {
        $sorted = [string[]]$rest
        [Array]::Sort($sorted)
        $rest = $sorted
    }
    return @($order + $rest)
}

# Printable ASCII without '"' and '\': such strings need no escaping (the common case).
# \A and \z, not ^ and $: in .NET, $ also matches before a final newline, which would let
# "text`n" through unescaped.
$script:ES_JSON_PLAIN_RE = '\A[ !#-\[\]-~]*\z'

function Write-EsJsonParts($Value, [int]$Level) {
    # Writes JSON fragments to the pipeline; ConvertTo-EsJson joins them. Plain strings and
    # numbers are written inline: a PowerShell function call costs more than the formatting.
    $pad = '  ' * ($Level + 1)
    if ($Value -is [hashtable]) {
        $keys = @(Get-EsOrderedKeys $Value)
        if ($keys.Count -eq 0) { '{}'; return }
        "{`n"
        $i = 0
        foreach ($key in $keys) {
            $i++
            $name = [string]$key
            if ($name -cmatch $script:ES_JSON_PLAIN_RE) { $name = '"' + $name + '"' } else { $name = ConvertTo-EsJsonString $name }
            $item = $Value[$key]
            if ($item -is [string] -and $item -cmatch $script:ES_JSON_PLAIN_RE) { $pad + $name + ': "' + $item + '"' }
            elseif ($item -is [int] -or $item -is [long]) { $pad + $name + ': ' + $item }
            elseif ($item -is [hashtable] -or $item -is [array]) { $pad + $name + ': '; Write-EsJsonParts $item ($Level + 1) }
            else { $pad + $name + ': ' + (ConvertTo-EsJsonScalar $item) }
            if ($i -lt $keys.Count) { ",`n" } else { "`n" }
        }
        ('  ' * $Level) + '}'
        return
    }
    if ($Value -is [array]) {
        $items = @($Value)
        if ($items.Count -eq 0) { '[]'; return }
        if ($items.Count -le 12) {
            $allScalar = $true
            foreach ($item in $items) { if ($item -is [hashtable] -or $item -is [array]) { $allScalar = $false; break } }
            if ($allScalar) {
                $inline = '[' + ((@($items | ForEach-Object { ConvertTo-EsJsonScalar $_ })) -join ', ') + ']'
                if ($inline.Length -le 100) { $inline; return }
            }
        }
        "[`n"
        $i = 0
        foreach ($item in $items) {
            $i++
            if ($item -is [string] -and $item -cmatch $script:ES_JSON_PLAIN_RE) { $pad + '"' + $item + '"' }
            elseif ($item -is [hashtable] -or $item -is [array]) { $pad; Write-EsJsonParts $item ($Level + 1) }
            else { $pad + (ConvertTo-EsJsonScalar $item) }
            if ($i -lt $items.Count) { ",`n" } else { "`n" }
        }
        ('  ' * $Level) + ']'
        return
    }
    ConvertTo-EsJsonScalar $Value
}

function ConvertTo-EsJson($Value) {
    return ((@(Write-EsJsonParts $Value 0)) -join '')
}
