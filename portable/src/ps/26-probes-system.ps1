# ---------------------------------------------------------------------------
# 26-probes-system: writable locations, file system semantics, execution test
# (deep), processes, services, scheduled tasks.
# ---------------------------------------------------------------------------

$script:ES_MAX_PROCESSES = 600
$script:ES_MAX_SERVICES = 800
$script:ES_MAX_TASKS = 300
$script:ES_INSTALL_LOCATION_IDS = @('local_programs', 'local_appdata', 'programdata', 'home', 'system_drive_root')
# The deep exec test writes and runs scripts only where no other user can write.
$script:ES_EXEC_TEST_IDS = @('temp', 'local_appdata', 'local_programs', 'appdata', 'home')
$script:ES_CMD_META_RE = '[&|<>^%!()"]'

function Join-EsPathSafe([string]$Parent, [string]$Child) {
    if (-not $Parent) { return $null }
    return (Join-Path $Parent $Child)
}

function Get-EsCandidateDirs {
    $cwd = $null
    $location = Get-Location
    if ($location.Provider.Name -eq 'FileSystem') { $cwd = [string]$location.ProviderPath }
    $scriptDir = $null
    if ($script:ES_SCRIPT_PATH) { $scriptDir = Split-Path -Parent $script:ES_SCRIPT_PATH }
    $drive = [string](Get-EsOrigEnv 'SystemDrive')
    if (-not $drive) { $drive = 'C:' }
    $candidates = @(
        @{ id = 'temp'; path = (Get-EsOrigEnv 'TEMP'); method = 'write-test' },
        @{ id = 'local_appdata'; path = (Get-EsOrigEnv 'LOCALAPPDATA'); method = 'write-test' },
        @{ id = 'local_programs'; path = (Join-EsPathSafe (Get-EsOrigEnv 'LOCALAPPDATA') 'Programs'); method = 'write-test' },
        @{ id = 'appdata'; path = (Get-EsOrigEnv 'APPDATA'); method = 'write-test' },
        @{ id = 'home'; path = (Get-EsOrigEnv 'USERPROFILE'); method = 'write-test' },
        @{ id = 'programdata'; path = (Get-EsOrigEnv 'ProgramData'); method = 'write-test' },
        @{ id = 'cwd'; path = $cwd; method = 'write-test' },
        @{ id = 'script_dir'; path = $scriptDir; method = 'write-test' },
        @{ id = 'system_drive_root'; path = ($drive + '\'); method = 'acl' },
        @{ id = 'program_files'; path = (Get-EsOrigEnv 'ProgramFiles'); method = 'acl' }
    )
    # A location in or below a credential store (cwd or TEMP in ~/.ssh, ...) is never tested,
    # listed or written: it is left out (and logged).
    $kept = @()
    foreach ($candidate in $candidates) {
        if ($candidate.path -and (Get-EsCredentialFolder ([string]$candidate.path))) {
            Write-EsLog ('fs.locations: ' + $candidate.id + ' skipped (credential store)')
            continue
        }
        $kept += $candidate
    }
    return $kept
}

function Get-EsPersonalFolders {
    # Desktop, Documents and OneDrive roots (lower-case): never written to; synced folders
    # would also upload a test file.
    $folders = @()
    $profilePath = [string](Get-EsOrigEnv 'USERPROFILE')
    if ($profilePath) { $folders += @((Join-Path $profilePath 'Desktop'), (Join-Path $profilePath 'Documents')) }
    $shell = Get-EsRegValues 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    if ($shell) {
        foreach ($name in @('Desktop', 'Personal', '{F42EE2D3-909F-4907-8871-4C22FC0BF756}')) {
            if ($shell[$name]) { $folders += [string]$shell[$name] }
        }
    }
    $folders += @((Get-EsOrigEnv 'OneDrive'), (Get-EsOrigEnv 'OneDriveCommercial'), (Get-EsOrigEnv 'OneDriveConsumer'))
    return @($folders | Where-Object { $_ } | ForEach-Object { ([string]$_).TrimEnd('\').ToLowerInvariant() } | Sort-Object -Unique)
}

function Test-EsUnderFolder([string]$Path, [object[]]$Folders) {
    $lower = $Path.TrimEnd('\').ToLowerInvariant()
    foreach ($folder in @($Folders)) { if ($lower -eq $folder -or $lower.StartsWith($folder + '\')) { return $true } }
    return $false
}

function probe_fs_locations {
    $r = New-EsResult
    $locations = @()
    $personal = @(Get-EsPersonalFolders)
    $r.sources += 'registry HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders (Desktop, Documents)'
    $oneDrive = @(@((Get-EsOrigEnv 'OneDrive'), (Get-EsOrigEnv 'OneDriveCommercial'), (Get-EsOrigEnv 'OneDriveConsumer')) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLowerInvariant() })
    foreach ($candidate in @(Get-EsCandidateDirs)) {
        $path = [string]$candidate.path
        $entry = @{
            id = $candidate.id; path = $(if ($path) { $path } else { $null }); method = $candidate.method; exists = $false
            writable = $null; can_create_dirs = $null; free_mb = $null; fstype = $null; network = $false; onedrive = $false; noexec = $null
        }
        if ($path) {
            $entry.network = Test-EsNetworkPath $path
            $entry.onedrive = Test-EsUnderFolder $path $oneDrive
            if ($candidate.method -eq 'write-test' -and (Test-EsUnderFolder $path $personal)) {
                # Desktop, Documents and synced folders: judged from the ACL, no file written.
                $entry.method = 'acl'
                $entry.write_test_skipped = 'personal or synced folder'
            }
            if (Test-EsLocalPath $path) {
                $entry.exists = Test-EsSafePath $path 'Container'
                if ($entry.exists -and $entry.method -eq 'write-test') {
                    $r.sources += ('write and delete a test file in ' + $path)
                    $entry.writable = Test-EsWritableDir $path
                } elseif ($entry.exists) {
                    $r.sources += ('read ACL of ' + $path)
                    $access = Get-EsSddlAccess $path
                    $entry.writable = $access.create_files
                    $entry.can_create_dirs = $access.create_dirs
                }
                $volume = Get-EsVolumeFor $path
                if ($volume) { $entry.free_mb = $volume['free_mb']; $entry.fstype = $volume['fstype'] }
            }
        }
        $locations += $entry
    }
    $install = @($locations | Where-Object {
            $script:ES_INSTALL_LOCATION_IDS -contains $_.id -and ($_.writable -eq $true -or ($_.id -eq 'system_drive_root' -and $_.can_create_dirs -eq $true))
        } | ForEach-Object { $_.id })
    $r.data.locations = $locations
    $r.data.writable_install_locations = $install
    return $r
}

function Get-EsLinkOutcome([string]$Link, [string]$Text) {
    if (Test-Path -LiteralPath $Link) { return @{ result = 'ok'; detail = $null } }
    $detail = ([string]$Text).Trim()
    if ($detail.Length -gt 200) { $detail = $detail.Substring(0, 200) }
    if ($detail -match '(?i)privilege|1314|Administrator') { return @{ result = 'denied'; detail = $detail } }
    return @{ result = 'error'; detail = $detail }
}

function Test-EsLinkCreation([hashtable]$Result, [string]$Kind, [string]$Link, [string]$Target) {
    # Kind: HardLink, Junction or SymbolicLink. Symbolic links use cmd mklink like most tools do.
    $flags = @{ HardLink = '/H'; Junction = '/J'; SymbolicLink = $null }
    $useCmd = ($Kind -eq 'SymbolicLink' -or $script:ES_PS_MAJOR -lt 5)
    if ($useCmd) {
        $arguments = @('/d', '/c', 'mklink')
        if ($flags[$Kind]) { $arguments += $flags[$Kind] }
        $run = Invoke-EsCommand -FilePath (Get-EsSystemTool 'cmd.exe') -Arguments ($arguments + @($Link, $Target)) -TimeoutSec 15
        $Result.sources += ('run cmd /c mklink ' + $flags[$Kind] + ' (in the scanner temp folder)')
        $outcome = Get-EsLinkOutcome $Link (Get-EsCommandText $run)
        if ($outcome.result -eq 'ok' -or $script:ES_PS_MAJOR -lt 5) { return $outcome }
    }
    try {
        $null = New-Item -ItemType $Kind -Path $Link -Value $Target -ErrorAction Stop
        return (Get-EsLinkOutcome $Link '')
    } catch { return (Get-EsLinkOutcome $Link $_.Exception.Message) }
}

function probe_fs_semantics {
    $r = New-EsResult
    $d = $r.data
    $base = Join-Path $script:ES_TMP 'fs'
    $null = New-Item -ItemType Directory -Path $base -Force -ErrorAction Stop
    $r.sources += 'write and delete test files in the scanner temp folder'
    $file = Join-Path $base 'Case.tmp'
    Set-Content -LiteralPath $file -Value 'envscan' -ErrorAction Stop
    $d.case_sensitive = -not (Test-Path -LiteralPath (Join-Path $base 'CASE.TMP'))
    $junctionTarget = Join-Path $base 'jtarget'
    $null = New-Item -ItemType Directory -Path $junctionTarget -Force
    $hard = Test-EsLinkCreation $r 'HardLink' (Join-Path $base 'hard.tmp') $file
    $junction = Test-EsLinkCreation $r 'Junction' (Join-Path $base 'junction') $junctionTarget
    $symlink = Test-EsLinkCreation $r 'SymbolicLink' (Join-Path $base 'symlink.tmp') $file
    $d.hardlink = $hard.result
    $d.junction = $junction.result
    $d.symlink = $symlink.result
    $d.symlink_detail = $symlink.detail
    if (Test-Path -LiteralPath (Join-Path $base 'junction')) { Remove-Item -LiteralPath (Join-Path $base 'junction') -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
    $fsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\FileSystem (LongPathsEnabled, NtfsDisable8dot3NameCreation)'
    $long = Get-EsRegValue $fsKey 'LongPathsEnabled'
    $d.long_paths_enabled = ([string]$long -eq '1')
    $short = Get-EsRegValue $fsKey 'NtfsDisable8dot3NameCreation'
    $d.short_names = $(switch ([string]$short) { '0' { 'enabled' } '1' { 'disabled' } '2' { 'per-volume' } '3' { 'disabled except system volume' } default { $null } })
    $d.name_max = 255
    $d.path_max = $(if ($d.long_paths_enabled) { 32767 } else { 260 })
    $volume = Get-EsVolumeFor ([string]$script:ES_TMP)
    $d.temp_fstype = $(if ($volume) { $volume['fstype'] } else { $null })
    return $r
}

function Get-EsExecOutcome([hashtable]$Run) {
    $text = Get-EsCommandText $Run
    $detail = $text
    if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 300) }
    if ($text -match 'envscan-exec-ok') { return @{ outcome = 'ok'; detail = $null } }
    if ($Run.timed_out) { return @{ outcome = 'error'; detail = 'timed out' } }
    if ($text -match '(?i)blocked|group policy|disabled|digitally signed|execution polic|restriction|AppLocker|denied|administrator') {
        return @{ outcome = 'blocked'; detail = $detail }
    }
    if ($Run.error) { $detail = $Run.error }
    return @{ outcome = 'error'; detail = $detail }
}

function Invoke-EsExecTest([hashtable]$Result, [hashtable]$Location, [hashtable]$Test) {
    # Creates the script as a new file (never an existing one), runs it, always deletes it.
    $entry = @{ id = $Location['id']; path = $Test.file; kind = $Test.kind; outcome = 'error'; detail = $null }
    if ($Test.kind -eq 'cmd' -and $Test.file -match $script:ES_CMD_META_RE) {
        $entry.outcome = 'skipped'
        $entry.detail = 'path contains cmd.exe metacharacters'
        return $entry
    }
    $created = $false
    try {
        $null = New-Item -ItemType File -Path $Test.file -ErrorAction Stop
        $created = $true
        Set-Content -LiteralPath $Test.file -Value $Test.body -Encoding Ascii -ErrorAction Stop
        $run = Invoke-EsCommand -FilePath $Test.exe -Arguments ($Test.args + @($Test.file)) -TimeoutSec 30
        $Result.sources += ('run ' + $run.command)
        $outcome = Get-EsExecOutcome $run
        $entry.outcome = $outcome.outcome
        $entry.detail = $outcome.detail
    } catch { $entry.detail = $_.Exception.Message }
    finally { if ($created) { Remove-Item -LiteralPath $Test.file -Force -ErrorAction SilentlyContinue } }
    return $entry
}

function probe_fs_exec_test {
    $r = New-EsResult
    if (-not (Test-EsDependency $r 'fs.locations')) { return $r }
    $locations = @((Get-EsData 'fs.locations')['locations'] | Where-Object {
            $_ -and $_['writable'] -eq $true -and $_['method'] -eq 'write-test' -and $script:ES_EXEC_TEST_IDS -contains $_['id']
        })
    if ($locations.Count -eq 0) { $r.status = 'not_found'; $r.notes += 'no writable per-user location to test'; return $r }
    $powershell = Get-EsSystemTool 'WindowsPowerShell\v1.0\powershell.exe'
    $cmd = Get-EsSystemTool 'cmd.exe'
    $results = @()
    foreach ($location in $locations) {
        $stem = Join-Path ([string]$location['path']) ('envscan-exec-' + $PID + '-' + (Get-Random))
        $tests = @(
            @{ kind = 'cmd'; file = ($stem + '.cmd'); body = '@echo envscan-exec-ok'; exe = $cmd; args = @('/d', '/c') },
            @{ kind = 'ps1'; file = ($stem + '.ps1'); body = "Write-Output 'envscan-exec-ok'"; exe = $powershell; args = @('-NoProfile', '-NonInteractive', '-File') }
        )
        foreach ($test in $tests) { $results += Invoke-EsExecTest $r $location $test }
    }
    $r.data.results = $results
    return $r
}

function probe_proc_list {
    $r = New-EsResult
    $items = @(Add-EsCimItems $r 'Win32_Process')
    $processes = @($items | Sort-Object { [int]$_.ProcessId } | Select-Object -First $script:ES_MAX_PROCESSES | ForEach-Object {
            # Redact before cutting: a cut could split a secret from the option that marks it.
            $line = Protect-EsCommandLine ([string]$_.CommandLine)
            if ($line -and $line.Length -gt 500) { $line = $line.Substring(0, 500) + '...' }
            @{
                pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = [string]$_.Name; user = $null
                path = $(if ($_.ExecutablePath) { [string]$_.ExecutablePath } else { $null })
                cmdline = $(if ($line) { $line } else { $null })
            }
        })
    $r.data.count = $items.Count
    $r.data.processes = $processes
    $r.data.truncated = ($items.Count -gt $script:ES_MAX_PROCESSES)
    $r.data.visible_details = @($processes | Where-Object { $_.path }).Count
    return $r
}

function probe_svc_list {
    $r = New-EsResult
    $items = @(Add-EsCimItems $r 'Win32_Service')
    $services = @($items | Sort-Object { [string]$_.Name } | Select-Object -First $script:ES_MAX_SERVICES | ForEach-Object {
            @{
                name = [string]$_.Name; display = [string]$_.DisplayName; state = [string]$_.State; start_mode = [string]$_.StartMode
                account = [string]$_.StartName; path = (Protect-EsCommandLine ([string]$_.PathName)); pid = [int]$_.ProcessId
            }
        })
    $r.data.manager = 'scm'
    $r.data.count = $items.Count
    $r.data.running = @($items | Where-Object { [string]$_.State -eq 'Running' }).Count
    $r.data.services = $services
    $r.data.truncated = ($items.Count -gt $script:ES_MAX_SERVICES)
    return $r
}

function probe_sched_tasks {
    $r = New-EsResult
    $states = @{ '0' = 'unknown'; '1' = 'disabled'; '2' = 'queued'; '3' = 'ready'; '4' = 'running' }
    $query = Get-EsCimSafe -Class 'MSFT_ScheduledTask' -Namespace 'root/Microsoft/Windows/TaskScheduler' -TimeoutSec 60
    $r.sources += 'CIM root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask'
    if ($query.status -ne 'ok') { $r.status = $query.status; $r.error = $query.error; return $r }
    $microsoft = 0
    $tasks = @()
    foreach ($task in @($query.items | Sort-Object { [string]$_.TaskPath + [string]$_.TaskName })) {
        $path = [string]$task.TaskPath
        if ($path -like '\Microsoft\*') { $microsoft++; continue }
        if ($tasks.Count -ge $script:ES_MAX_TASKS) { continue }
        $actions = @(@($task.Actions) | Where-Object { $_ -and $_.Execute } | ForEach-Object { Protect-EsCommandLine (([string]$_.Execute + ' ' + [string]$_.Arguments).Trim()) })
        $principal = $null
        if ($task.Principal) { $principal = [string]$task.Principal.UserId }
        $tasks += @{ name = [string]$task.TaskName; path = $path; state = $states[[string][int]$task.State]; actions = $actions; principal = $principal }
    }
    $r.data.count = @($query.items).Count
    $r.data.microsoft_task_count = $microsoft
    $r.data.tasks = $tasks
    $r.data.user_crontab = @()
    $r.data.timers = @()
    $r.data.linger = $null
    return $r
}
