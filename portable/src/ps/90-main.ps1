# ---------------------------------------------------------------------------
# 90-main: entry point (excluded from build/lib/envscan-lib.ps1).
# ---------------------------------------------------------------------------

$script:ES_EXIT_CODE = 2

function Show-EsProbeList {
    foreach ($probe in @($script:ES_PROBES)) {
        Write-Output ($probe.id + '  [' + $probe.tier + ']  ' + $probe.title)
        foreach ($line in @($probe.footprint)) { Write-Output ('    - ' + $line) }
    }
}

function Get-EsCounts {
    $counts = @{ __order = $script:ES_STATUSES }
    foreach ($status in $script:ES_STATUSES) { $counts[$status] = 0 }
    foreach ($envelope in @($script:ES_RESULTS.Values)) { $counts[$envelope.status] = $counts[$envelope.status] + 1 }
    return $counts
}

function Get-EsExitCode {
    foreach ($envelope in @($script:ES_RESULTS.Values)) {
        if (@('partial', 'denied', 'timeout', 'error') -contains $envelope.status) { return 1 }
    }
    if ($script:ES_BUDGET_SKIPS -gt 0) { return 1 }
    return 0
}

function New-EsHostBlock {
    $os = Get-EsData 'os.identity'
    $name = [string]$os['name']
    if (-not $name) { $name = 'Windows' }
    $version = [string]$os['version']
    if ($os['build']) { $version = ($version + ' build ' + $os['build']).Trim() }
    $arch = [string]$os['arch']
    if (@('x86_64', 'x86', 'arm64', 'arm', 'ia64') -notcontains $arch) { $arch = 'other' }
    $hostName = [string]$os['hostname']
    if (-not $hostName) { $hostName = [string]$env:COMPUTERNAME }
    return @{
        __order = @('os_family', 'os_name', 'os_version', 'arch', 'hostname')
        os_family = 'windows'; os_name = $name; os_version = $version; arch = $arch; hostname = $hostName
    }
}

function New-EsReport([string]$Folder, [string[]]$Tiers, [object[]]$Findings, [int]$ExitCode) {
    $finished = Get-EsUtc
    $probes = @{ __order = @($script:ES_PROBES | ForEach-Object { $_.id }) }
    foreach ($id in @($script:ES_RESULTS.PSBase.Keys)) { $probes[$id] = $script:ES_RESULTS[$id] }
    $location = Get-Location
    $shellVersion = ([string]$PSVersionTable.PSVersion) + ' ' + [string]$PSVersionTable.PSEdition + ' (' + $script:ES_LANGUAGE_MODE + ')'
    $run = @{
        __order = @('started_utc', 'finished_utc', 'duration_ms', 'tiers', 'flags', 'cwd', 'out_dir', 'exit_code', 'redaction', 'counts')
        started_utc = (Format-EsUtc $script:ES_STARTED); finished_utc = (Format-EsUtc $finished)
        duration_ms = (Get-EsElapsedMs $script:ES_STARTED); tiers = @($Tiers)
        flags = @($script:ES_ARGS | ForEach-Object { Protect-EsValue ([string]$_) })
        cwd = [string]$location.ProviderPath; out_dir = $Folder; exit_code = $ExitCode
        redaction = [bool]$script:ES_OPT.redact; counts = (Get-EsCounts)
    }
    return @{
        __order = @('schema', 'scanner', 'run', 'host', 'findings', 'probes')
        schema = $script:ES_SCHEMA
        scanner = @{
            __order = @('name', 'version', 'impl', 'shell_version')
            name = $script:ES_NAME; version = $script:ES_VERSION; impl = $script:ES_IMPL; shell_version = ($shellVersion -replace '\s+', ' ').Trim()
        }
        run = $run
        host = (New-EsHostBlock)
        findings = @($Findings)
        probes = $probes
    }
}

function Format-EsProgressLine([int]$Index, [int]$Total, [string]$Id, [hashtable]$Envelope) {
    $counter = '[' + ([string]$Index).PadLeft(([string]$Total).Length) + '/' + $Total + ']'
    return ($counter + ' ' + ($Id + ' ').PadRight(36, '.') + ' ' + ([string]$Envelope.status).PadRight(14) + ([string]$Envelope.duration_ms).PadLeft(7) + ' ms')
}

function Invoke-EnvScan([object[]]$Arguments) {
    $errors = @(Read-EsArguments $Arguments)
    if ($errors.Count -gt 0) {
        Write-EsFatal (@($errors | ForEach-Object { 'envscan: ' + $_ }) + @($script:ES_USAGE))
        $script:ES_EXIT_CODE = 2
        return
    }
    if (Test-EsUnixShim) { Invoke-EsUnixShim $script:ES_ARGS; return }
    if ($script:ES_OPT.help) { foreach ($line in $script:ES_USAGE) { Write-Output $line }; $script:ES_EXIT_CODE = 0; return }
    if ($script:ES_OPT.version) { Write-Output ('envscan ' + $script:ES_VERSION + ' (powershell)'); $script:ES_EXIT_CODE = 0; return }
    if ($script:ES_OPT.list) { Show-EsProbeList; $script:ES_EXIT_CODE = 0; return }

    $script:ES_STARTED = Get-EsUtc
    $script:ES_CIM_CACHE = @{}
    Initialize-EsRedaction
    Save-EsEnvSnapshot
    # Network drives first: Initialize-EsTemp refuses a TEMP on a mapped network drive.
    try { Initialize-EsDrives } catch { Write-EsLog ('network drive detection failed: ' + $_.Exception.Message) }
    try { Initialize-EsTemp }
    catch { Write-EsFatal ('envscan: cannot create a temporary folder: ' + $_.Exception.Message); $script:ES_EXIT_CODE = 2; return }
    $folder = New-EsOutputFolder
    if (-not $folder) {
        Write-EsFatal 'envscan: cannot create an output folder; use --out DIR'
        Remove-EsTemp
        $script:ES_EXIT_CODE = 2
        return
    }
    $tiers = @('default')
    if ($script:ES_OPT.deep) { $tiers += 'deep' }
    if ($script:ES_OPT.net) { $tiers += 'net' }
    $probes = @($script:ES_PROBES)
    Write-EsProgress ('envscan ' + $script:ES_VERSION + ' (powershell, ' + $script:ES_LANGUAGE_MODE + '): ' + $probes.Count + ' probes, tiers ' + ($tiers -join ',') + ' -> ' + $folder)
    Invoke-EsProbeLoop $probes
    $mark = Get-EsUtc
    $findings = @()
    try { $findings = @(Get-EsFindings) } catch { Write-EsLog ('findings failed: ' + $_.Exception.Message) }
    Write-EsLog ('findings: ' + $findings.Count + ' in ' + (Get-EsElapsedMs $mark) + ' ms')
    $exitCode = Get-EsExitCode
    $report = New-EsReport $folder $tiers $findings $exitCode
    try { Write-EsTextFile (Join-Path $folder 'envscan.json') (ConvertTo-EsJson $report) 'ascii' }
    catch {
        Write-EsFatal ('envscan: cannot write envscan.json: ' + $_.Exception.Message)
        $script:ES_EXIT_CODE = 2
        return
    }
    if (-not (Write-EsSecondaryOutputs $folder $report)) { $exitCode = 1 }
    Write-EsProgress ('envscan: done in ' + [int]((Get-EsElapsedMs $script:ES_STARTED) / 1000) + ' s, exit code ' + $exitCode)
    Write-Output $folder
    $script:ES_EXIT_CODE = $exitCode
}

function Invoke-EsProbeLoop([object[]]$Probes) {
    # Error records are kept off stderr: envscan.cmd reads an exit code of 1 together with
    # an "UnauthorizedAccess" error on stderr as "PowerShell refused to run the script".
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        try { Enter-EsChildEnv } catch { Write-EsLog ('child environment: ' + $_.Exception.Message) }
        try { Initialize-EsDrives } catch { Write-EsLog ('network drive detection failed: ' + $_.Exception.Message) }
        $index = 0
        foreach ($meta in $Probes) {
            $index++
            try {
                $envelope = Invoke-EsProbe $meta
                Write-EsProgress (Format-EsProgressLine $index $Probes.Count $meta.id $envelope)
            } catch { Write-EsLog ($meta.id + ' failed outside the probe: ' + $_.Exception.Message) }
        }
    } finally {
        Exit-EsChildEnv
        Remove-EsTemp
        $ErrorActionPreference = $previous
    }
}

function Write-EsSecondaryOutputs([string]$Folder, [hashtable]$Report) {
    # envscan.md, AGENT_BRIEF.md and envscan.log; one failing does not stop the others.
    $ok = $true
    foreach ($item in @(@('envscan.md', 'ConvertTo-EsMarkdownReport'), @('AGENT_BRIEF.md', 'ConvertTo-EsBrief'))) {
        $mark = Get-EsUtc
        try {
            Write-EsTextFile (Join-Path $Folder $item[0]) (& $item[1] $Report) 'UTF8'
            Write-EsLog ($item[0] + ' written in ' + (Get-EsElapsedMs $mark) + ' ms')
        } catch {
            Write-EsLog ('cannot write ' + $item[0] + ': ' + $_.Exception.Message)
            Write-EsProgress ('envscan: cannot write ' + $item[0] + ': ' + $_.Exception.Message)
            $ok = $false
        }
    }
    try { Write-EsTextFile (Join-Path $Folder 'envscan.log') ($script:ES_LOG -join "`r`n") 'UTF8' }
    catch { $ok = $false }
    return $ok
}

try { Invoke-EnvScan $script:ES_ARGS }
catch {
    # Never exit 1 here: the launcher would mistake it for an execution policy refusal.
    Write-EsFatal ('envscan: internal error: ' + $_.Exception.Message)
    $script:ES_EXIT_CODE = 2
}
exit $script:ES_EXIT_CODE
