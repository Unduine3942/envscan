# ---------------------------------------------------------------------------
# 05-unix-shim: PowerShell 6+ on Linux/macOS hands the scan to envscan.sh.
#
# Nothing here runs at load time; Invoke-EnvScan calls Invoke-EsUnixShim right after the
# options are validated and before any Windows-only work (temp folder, drives, CIM).
# The report then comes from sh, so it says impl posix-sh.
#
# Test-only hooks (ENVSCAN_TEST_*), read only when ENVSCAN_TEST_PLATFORM=unix:
#   ENVSCAN_TEST_PLATFORM=unix  forces this branch on any platform.
#   ENVSCAN_TEST_SH=<path>      replaces /bin/sh. Required when the real platform is not Unix.
#     It must be an absolute local path whose file name is sh, dash or bash (.exe too), and
#     never a network path or a credential store: a hook must not run an arbitrary program.
# An active hook is announced on stderr. The sh report does not record it.
# ---------------------------------------------------------------------------

function Test-EsRealUnix {
    return ($PSVersionTable.PSVersion.Major -ge 6 -and $PSVersionTable.Platform -eq 'Unix')
}

function Test-EsUnixShim {
    if ($env:ENVSCAN_TEST_PLATFORM -eq 'unix') { return $true }
    return (Test-EsRealUnix)
}

function Write-EsShimNotice([string]$Message) {
    # A notice that survives ConstrainedLanguage with redirected output: stderr through
    # Write-EsProgress in FullLanguage, else one error record (no policy words in it).
    if ($script:ES_FULL_LANGUAGE) { Write-EsProgress $Message; return }
    Write-Error -Message $Message -ErrorAction Continue
}

function Get-EsShimSh {
    # The sh to run, or $null after a fatal message. /bin/sh unless the test hook replaces it.
    $realUnix = Test-EsRealUnix
    $hook = [string]$env:ENVSCAN_TEST_SH
    if ($env:ENVSCAN_TEST_PLATFORM -ne 'unix') { return '/bin/sh' }
    if (-not $hook) {
        if ($realUnix) { return '/bin/sh' }
        Write-EsFatal 'envscan: ENVSCAN_TEST_PLATFORM=unix on a non-Unix host needs ENVSCAN_TEST_SH (a local sh, dash or bash)'
        return $null
    }
    $reason = ''
    if ($realUnix) { if (-not $hook.StartsWith('/')) { $reason = 'an absolute path' } }
    else {
        try { Initialize-EsDrives } catch { }
        if (-not (Test-EsLocalPath $hook)) { $reason = 'an absolute local path (no UNC or network drive)' }
    }
    if (-not $reason -and (Test-EsCredentialPath $hook)) { $reason = 'not a credential store' }
    if (-not $reason) {
        $leaf = Split-Path -Leaf $hook.Replace('\', '/')
        if ($leaf -notmatch '\A(sh|dash|bash)(\.exe)?\z') { $reason = 'a file named sh, dash or bash' }
    }
    if ($reason) {
        Write-EsFatal ('envscan: ENVSCAN_TEST_SH must be ' + $reason + ': ' + $hook)
        return $null
    }
    return $hook
}

function ConvertTo-EsShimArguments([object[]]$Arguments) {
    # PowerShell reads option names in any case and as -x or --x; sh only in lower case.
    # Option names are forwarded as --lowercase (-h as --help); values are never touched.
    $result = @()
    $list = @($Arguments)
    $i = 0
    while ($i -lt $list.Count) {
        $raw = [string]$list[$i]
        $i++
        if ($raw -notmatch '\A(-{1,2}[A-Za-z-]+)(=[\s\S]*)?\z') { $result += $raw; continue }
        $key = $matches[1].TrimStart('-').ToLowerInvariant()
        $suffix = [string]$matches[2]
        if ($key -eq 'h') { $key = 'help' }
        if (@($script:ES_FLAG_OPTIONS) + @($script:ES_VALUE_OPTIONS) -notcontains $key) { $result += $raw; continue }
        $result += ('--' + $key + $suffix)
        if ($script:ES_VALUE_OPTIONS -contains $key -and -not $suffix -and $i -lt $list.Count) {
            $result += [string]$list[$i]
            $i++
        }
    }
    return $result
}

function Test-EsNativeArgumentsExact {
    # pwsh 7.3+ passes native arguments as exact argv entries; 5.1 and 6.x to 7.2 drop empty
    # strings and strip embedded double quotes.
    $v = $PSVersionTable.PSVersion
    return ($v.Major -gt 7 -or ($v.Major -eq 7 -and $v.Minor -ge 3))
}

function Invoke-EsUnixShim([object[]]$Arguments) {
    # Runs "sh envscan.sh <arguments>" with the arguments as argv entries (no joining, no
    # re-parsing), empty stdin and the caller's directory. Sets the exit code from sh's.
    $script:ES_EXIT_CODE = 2
    $forward = @(ConvertTo-EsShimArguments $Arguments)
    if (-not (Test-EsNativeArgumentsExact)) {
        foreach ($item in $forward) {
            if ($item -eq '' -or $item.IndexOf('"') -ge 0) {
                Write-EsFatal 'envscan: an empty argument or one with a double quote needs pwsh 7.3 or later here; use sh envscan.sh'
                return
            }
        }
    }
    $dir = ''
    if ($script:ES_SCRIPT_PATH) { $dir = Split-Path -Parent $script:ES_SCRIPT_PATH }
    $target = Join-Path $dir 'envscan.sh'
    if (-not $dir -or -not (Test-Path -LiteralPath $target -PathType Leaf)) {
        Write-EsFatal 'envscan: envscan.sh must be next to envscan.ps1 on Linux/macOS'
        return
    }
    $sh = Get-EsShimSh
    if (-not $sh) { return }
    if (-not (Test-Path -LiteralPath $sh -PathType Leaf)) {
        Write-EsFatal ('envscan: sh not found: ' + $sh)
        return
    }
    if ($env:ENVSCAN_TEST_PLATFORM -eq 'unix') {
        Write-EsShimNotice ('envscan: test hook ENVSCAN_TEST_PLATFORM=unix is active; sh: ' + $sh)
    }
    $global:LASTEXITCODE = $null
    # An empty pipeline closes sh's stdin at once: the scanner never prompts.
    @() | & $sh $target @forward
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 2 }
    $script:ES_EXIT_CODE = [int]$code
}
