# ---------------------------------------------------------------------------
# 20-probes-os: OS identity, time and locale, health, updates, hardware,
# session context and virtualization.
# ---------------------------------------------------------------------------

function ConvertTo-EsArch([string]$Name) {
    switch -regex ($Name) {
        '^(AMD64|x64|x86_64|EM64T)$' { return 'x86_64' }
        '^(x86|i[3-6]86)$' { return 'x86' }
        '^(ARM64|aarch64)$' { return 'arm64' }
        '^ARM' { return 'arm' }
        '^IA64$' { return 'ia64' }
    }
    if ($Name) { return 'other' }
    return $null
}

function Get-EsArchFacts($Cpu) {
    # OS architecture (seen through WOW64 and ARM64 emulation) and the scanner's own process.
    $arch = ConvertTo-EsArch $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = ConvertTo-EsArch $env:PROCESSOR_ARCHITEW6432 }
    if ($Cpu -and [int]$Cpu.Architecture -eq 12) { $arch = 'arm64' }
    return @{
        arch = $arch
        process_arch = ConvertTo-EsArch $env:PROCESSOR_ARCHITECTURE
        userland_bits = $(if (@('x86_64', 'arm64', 'ia64') -contains $arch) { 64 } else { 32 })
        architecture_code = $(if ($Cpu) { [int]$Cpu.Architecture } else { $null })
    }
}

function Get-EsDomainFacts($Cs) {
    # Domain or workgroup membership; unknown ($null) when Win32_ComputerSystem was unreadable.
    $facts = @{ domain = $null; domain_joined = $null; fqdn = $null }
    if (-not $Cs) { return $facts }
    $facts.domain_joined = [bool]$Cs.PartOfDomain
    if ($Cs.PartOfDomain) {
        $facts.domain = [string]$Cs.Domain
        $facts.fqdn = ([string]$Cs.DNSHostName + '.' + [string]$Cs.Domain).ToLowerInvariant()
    } else {
        $facts.workgroup = [string]$Cs.Workgroup
    }
    return $facts
}

function probe_os_identity {
    $r = New-EsResult
    $d = $r.data
    $os = @(Add-EsCimItems $r 'Win32_OperatingSystem') | Select-Object -First 1
    $cs = @(Add-EsCimItems $r 'Win32_ComputerSystem') | Select-Object -First 1
    $cpu = @(Add-EsCimItems $r 'Win32_Processor') | Select-Object -First 1
    $cvKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $cv = Get-EsRegValues $cvKey
    $r.sources += 'registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if ($null -eq $cv) { $cv = @{}; Add-EsNote $r 'CurrentVersion registry key unreadable' }
    if (-not $os -and $cv.Count -eq 0) { $r.status = 'error'; $r.error = 'no OS information source was readable'; return $r }

    $build = [string]$cv['CurrentBuild']
    if (-not $build -and $os) { $build = [string]$os.BuildNumber }
    $name = $null
    if ($os) { $name = ([string]$os.Caption).Trim() }
    if (-not $name) {
        $name = [string]$cv['ProductName']
        if ($build -match '^\d+$' -and [int]$build -ge 22000) { $name = $name.Replace('Windows 10', 'Windows 11') }
    }
    $d.family = 'windows'
    $d.name = $name
    $d.version = $(if ($os) { [string]$os.Version } else { [string]$cv['CurrentVersion'] })
    $d.build = $(if ($cv['UBR']) { $build + '.' + $cv['UBR'] } else { $build })
    $d.display_version = $(if ($cv['DisplayVersion']) { [string]$cv['DisplayVersion'] } else { [string]$cv['ReleaseId'] })
    $d.edition = [string]$cv['EditionID']
    $d.install_type = [string]$cv['InstallationType']
    $d.kernel = $d.version
    $d.product_type = $(if ($os) { [int]$os.ProductType } else { $null })
    $d.install_date_utc = $(if ($os) { Format-EsUtc (ConvertFrom-EsCimDate $os.InstallDate) } else { $null })
    $d.system_root = $env:SystemRoot
    $facts = Get-EsArchFacts $cpu
    foreach ($key in @($facts.PSBase.Keys)) { $d[$key] = $facts[$key] }
    $d.wow64_process = [bool]$env:PROCESSOR_ARCHITEW6432
    if ($d.wow64_process) { Add-EsNote $r 'the scanner ran as a 32-bit process on 64-bit Windows; registry and System32 views are redirected' 'partial' }
    $d.hostname = [string]$env:COMPUTERNAME
    $facts = Get-EsDomainFacts $cs
    foreach ($key in @($facts.PSBase.Keys)) { $d[$key] = $facts[$key] }
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
    $d.directory_joined = (@(Get-EsRegSubkeys 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo').Count -gt 0)
    $d.distro_id = $null
    $d.distro_like = $null
    $d.wsl = $false
    $d.rosetta = $null
    return $r
}

function probe_os_time_locale {
    $r = New-EsResult
    $d = $r.data
    $now = Get-Date
    $offset = [int](($now - $now.ToUniversalTime()).TotalMinutes)
    $sign = '+'
    if ($offset -lt 0) { $sign = '-'; $offset = -1 * $offset }
    $hours = ($offset - ($offset % 60)) / 60
    $d.utc_offset = $sign + ([string]$hours).PadLeft(2, '0') + ':' + ([string]($offset % 60)).PadLeft(2, '0')
    $d.timezone = $null
    try {
        $tz = Get-TimeZone -ErrorAction Stop
        $d.timezone = [string]$tz.Id
        $d.timezone_display = [string]$tz.DisplayName
        $r.sources += 'Get-TimeZone'
    } catch {
        $zone = @(Add-EsCimItems $r 'Win32_TimeZone') | Select-Object -First 1
        if ($zone) { $d.timezone = [string]$zone.StandardName; $d.timezone_display = [string]$zone.Caption }
    }
    $culture = Get-Culture
    $d.locale = [string]$culture.Name
    $d.ui_locale = [string](Get-UICulture).Name
    $d.decimal_separator = [string]$culture.NumberFormat.NumberDecimalSeparator
    $d.thousands_separator = [string]$culture.NumberFormat.NumberGroupSeparator
    $d.date_format = [string]$culture.DateTimeFormat.ShortDatePattern
    $d.list_separator = [string]$culture.TextInfo.ListSeparator
    $r.sources += 'Get-Culture, Get-UICulture'
    try { $d.system_locale = [string](Get-WinSystemLocale -ErrorAction Stop).Name; $r.sources += 'Get-WinSystemLocale' }
    catch { $d.system_locale = $null }
    $cp = Get-EsRegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage'
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage'
    if ($cp) { $d.codepage_ansi = [string]$cp['ACP']; $d.codepage_oem = [string]$cp['OEMCP'] }
    try { $d.codepage_console = [string][Console]::OutputEncoding.CodePage } catch { $d.codepage_console = $null }
    $d.utf8_system_codepage = ($d.codepage_ansi -eq '65001')
    $d.encoding = $(if ($d.codepage_ansi -eq '65001') { 'UTF-8' } elseif ($d.codepage_ansi) { 'cp' + $d.codepage_ansi } else { $null })
    $d.utf8_available = $true
    $console = Get-EsRegValues 'HKCU:\Console'
    $r.sources += 'registry HKCU\Console'
    $d.virtual_terminal_level = $(if ($console) { $console['VirtualTerminalLevel'] } else { $null })
    return $r
}

function probe_os_health {
    $r = New-EsResult
    $d = $r.data
    $os = @(Add-EsCimItems $r 'Win32_OperatingSystem') | Select-Object -First 1
    $boot = $null
    if ($os) { $boot = ConvertFrom-EsCimDate $os.LastBootUpTime }
    $d.last_boot_utc = Format-EsUtc $boot
    $d.uptime_seconds = $(if ($boot) { [long]((Get-EsUtc) - $boot).TotalSeconds } else { $null })
    $cpu = @(Add-EsCimItems $r 'Win32_Processor') | Select-Object -First 1
    $d.cpu_load_percent = $(if ($cpu) { $cpu.LoadPercentage } else { $null })
    $d.load = $null
    $reasons = @()
    $checks = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending', 'component servicing'),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired', 'Windows Update')
    )
    foreach ($check in $checks) {
        $r.sources += ('registry ' + ($check[0] -replace '^HKLM:', 'HKLM'))
        if (Test-EsRegKey $check[0]) { $reasons += $check[1] }
    }
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control\Session Manager (PendingFileRenameOperations)'
    if ($null -ne (Get-EsRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')) {
        $reasons += 'pending file rename operations'
    }
    $d.pending_reboot = ($reasons.Count -gt 0)
    $d.pending_reasons = $reasons
    return $r
}

function probe_os_updates {
    $r = New-EsResult
    $items = @(Add-EsCimItems $r 'Win32_QuickFixEngineering')
    $hotfixes = @($items | Sort-Object HotFixID | ForEach-Object {
            @{ id = [string]$_.HotFixID; description = [string]$_.Description; installed_on = [string]$_.InstalledOn }
        })
    $r.data.count = $hotfixes.Count
    $r.data.hotfixes = $hotfixes
    $ids = @($hotfixes | ForEach-Object { $_.id })
    $build = [string](Get-EsData 'os.identity')['build']
    # Only a successful query proves absence; later rollups may also include these updates.
    if ($r.status -eq 'ok' -and $build -match '^(\d+)' -and [int]$matches[1] -lt 9600) {
        $r.data.legacy_updates = @{
            'KB2999226 (Universal C Runtime)' = ($ids -contains 'KB2999226')
            'KB4474419 (SHA-2 code signing)' = ($ids -contains 'KB4474419')
            'KB3140245 (WinHTTP TLS 1.1/1.2 default)' = ($ids -contains 'KB3140245')
        }
    }
    if ($hotfixes.Count -eq 0 -and $r.status -eq 'ok') { $r.status = 'not_found' }
    return $r
}

function probe_hw_cpu {
    $r = New-EsResult
    $d = $r.data
    $cpus = @(Add-EsCimItems $r 'Win32_Processor')
    if ($cpus.Count -eq 0) { $r.status = 'error'; return $r }
    $first = $cpus[0]
    $cores = 0
    $logical = 0
    foreach ($cpu in $cpus) { $cores += [int]$cpu.NumberOfCores; $logical += [int]$cpu.NumberOfLogicalProcessors }
    $d.model = ([string]$first.Name).Trim()
    $d.vendor = [string]$first.Manufacturer
    $d.sockets = $cpus.Count
    $d.cores = $cores
    $d.logical = $logical
    $d.max_clock_mhz = $first.MaxClockSpeed
    $d.architecture_code = [int]$first.Architecture
    $d.virtualization_firmware_enabled = $first.VirtualizationFirmwareEnabled
    $d.l3_cache_kb = $first.L3CacheSize
    $key = Get-EsRegValues 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0'
    $r.sources += 'registry HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0'
    if ($key) { $d.identifier = [string]$key['Identifier'] }
    $d.features = $null
    $d.flags = $null
    $r.notes += 'Windows does not expose instruction-set flags (AVX, AVX2, AVX-512) to standard users; infer them from the CPU model.'
    return $r
}

function probe_hw_memory {
    $r = New-EsResult
    $d = $r.data
    $os = @(Add-EsCimItems $r 'Win32_OperatingSystem') | Select-Object -First 1
    if (-not $os) { $r.status = 'error'; return $r }
    $d.total_mb = [long]([long]$os.TotalVisibleMemorySize / 1024)
    $d.available_mb = [long]([long]$os.FreePhysicalMemory / 1024)
    $d.commit_limit_mb = [long]([long]$os.TotalVirtualMemorySize / 1024)
    $d.commit_free_mb = [long]([long]$os.FreeVirtualMemory / 1024)
    $d.swap_total_mb = [long]([long]$os.SizeStoredInPagingFiles / 1024)
    $d.swap_free_mb = [long]([long]$os.FreeSpaceInPagingFiles / 1024)
    $files = @(Add-EsCimItems $r 'Win32_PageFileUsage')
    $d.pagefiles = @($files | ForEach-Object { @{ path = [string]$_.Name; allocated_mb = $_.AllocatedBaseSize; current_usage_mb = $_.CurrentUsage } })
    return $r
}

function Get-EsNetworkDriveEntries {
    # Mapped network drives (from Initialize-EsDrives); never contacted, so no size or type.
    $entries = @()
    foreach ($drive in @($script:ES_NETWORK_DRIVES)) {
        $entries += @{
            mount = ($drive + '\'); device = $script:ES_NETWORK_DRIVE_TARGETS[$drive]; fstype = $null; label = $null
            kind = 'network'; total_mb = $null; free_mb = $null; network = $true; removable = $false
        }
    }
    return $entries
}

function probe_hw_storage {
    # Local volumes from Win32_Volume, which only enumerates local volumes; Win32_LogicalDisk
    # would ask the file server of every mapped drive for its size (network traffic).
    $r = New-EsResult
    $volumes = @(Add-EsCimItems $r 'Win32_Volume' 'root/cimv2' 'DriveLetter IS NOT NULL')
    $kinds = @{ 2 = 'removable'; 3 = 'local'; 5 = 'optical'; 6 = 'ramdisk' }
    $local = @($volumes | ForEach-Object {
            $type = [int]$_.DriveType
            @{
                mount = ([string]$_.DriveLetter + '\'); device = [string]$_.DeviceID; fstype = [string]$_.FileSystem
                label = [string]$_.Label; kind = $kinds[$type]
                total_mb = $(if ($_.Capacity) { [long]([uint64]$_.Capacity / 1MB) } else { $null })
                free_mb = $(if ($null -ne $_.FreeSpace) { [long]([uint64]$_.FreeSpace / 1MB) } else { $null })
                network = $false; removable = ($type -eq 2 -or $type -eq 5)
            }
        })
    $network = @(Get-EsNetworkDriveEntries)
    $r.sources += 'PowerShell drive list and registry HKCU\Network (mapped drives; not contacted)'
    if ($network.Count -gt 0) { $r.notes += 'mapped network drives are listed without size: querying them would contact the file server' }
    $r.data.volumes = @($local + $network)
    if ($volumes.Count -eq 0 -and $r.status -eq 'ok') { $r.status = 'error' }
    return $r
}

function Get-EsVolumeFor([string]$Path) {
    # Volume entry from hw.storage for a local path (drive letter match).
    if (-not $Path -or $Path -notmatch '^([A-Za-z]):') { return $null }
    $drive = $matches[1].ToUpperInvariant() + ':\'
    foreach ($volume in @((Get-EsData 'hw.storage')['volumes'])) {
        if ($volume -and ([string]$volume['mount']).ToUpperInvariant() -eq $drive) { return $volume }
    }
    return $null
}

function probe_hw_gpu {
    $r = New-EsResult
    $controllers = @(Add-EsCimItems $r 'Win32_VideoController')
    # AdapterRAM is 32-bit: 4 GB or more reads as at most 4095 MB.
    if (@($controllers | Where-Object { $_.AdapterRAM -and [uint64]$_.AdapterRAM -ge 4293918720 }).Count -gt 0) {
        $r.notes += 'vram_mb is capped near 4096 MB (Win32_VideoController.AdapterRAM is a 32-bit value)'
    }
    $r.data.gpus = @($controllers | ForEach-Object {
            @{
                name = [string]$_.Name; driver_version = [string]$_.DriverVersion
                vram_mb = $(if ($_.AdapterRAM) { [long]([uint64]$_.AdapterRAM / 1MB) } else { $null })
                processor = [string]$_.VideoProcessor; status = [string]$_.Status
                resolution = $(if ($_.CurrentHorizontalResolution) { [string]$_.CurrentHorizontalResolution + 'x' + [string]$_.CurrentVerticalResolution } else { $null })
            }
        })
    if ($controllers.Count -eq 0 -and $r.status -eq 'ok') { $r.status = 'not_found' }
    return $r
}

function probe_session_context {
    $r = New-EsResult
    $d = $r.data
    $r.sources += @('environment SESSIONNAME, WT_SESSION, TERM_PROGRAM, SSH_CONNECTION', 'Get-Process -Id $PID', '$Host')
    $sessionId = $null
    try { $sessionId = [int](Get-Process -Id $PID -ErrorAction Stop).SessionId } catch { }
    $name = [string]$env:SESSIONNAME
    $type = 'unknown'
    if ($env:SSH_CONNECTION -or $env:SSH_CLIENT) { $type = 'ssh' }
    elseif ($sessionId -eq 0) { $type = 'service' }
    elseif ($name -like 'RDP-*') { $type = 'rdp' }
    elseif ($name -eq 'Console') { $type = 'console' }
    $d.type = $type
    $d.session_name = $name
    $d.session_id = $sessionId
    try { $d.interactive = [bool][Environment]::UserInteractive } catch { $d.interactive = $null }
    $d.display = ($type -eq 'console' -or $type -eq 'rdp')
    $terminal = [string]$Host.Name
    if ($env:WT_SESSION) { $terminal = 'Windows Terminal' }
    elseif ($env:TERM_PROGRAM) { $terminal = [string]$env:TERM_PROGRAM }
    elseif ($env:ConEmuANSI) { $terminal = 'ConEmu' }
    $d.terminal = $terminal
    $d.host_name = [string]$Host.Name
    $d.tty = $null
    $desktop = Get-EsRegValues 'HKCU:\Control Panel\Desktop'
    $r.sources += 'registry HKCU\Control Panel\Desktop'
    $d.dpi = $(if ($desktop -and $desktop['LogPixels']) { $desktop['LogPixels'] } else { $null })
    $gpu = Get-EsData 'hw.gpu'
    $d.resolution = $null
    foreach ($item in @($gpu['gpus'])) { if ($item -and $item['resolution']) { $d.resolution = $item['resolution']; break } }
    return $r
}

function Get-EsVmProduct([string]$Signature) {
    # Virtual machine product named by the system and BIOS vendor and model strings, else $null.
    switch -regex ($Signature) {
        'VMware' { return 'VMware' }
        'VirtualBox|innotek' { return 'VirtualBox' }
        'Amazon EC2|amazon' { return 'Amazon EC2' }
        'Google Compute Engine|Google' { return 'Google Compute Engine' }
        'Xen|HVM domU' { return 'Xen' }
        'QEMU|KVM|Bochs' { return 'KVM/QEMU' }
        'Parallels' { return 'Parallels' }
        'OpenStack' { return 'OpenStack' }
        'Virtual Machine|Hyper-V' { return 'Hyper-V' }
    }
    return $null
}

function probe_virt_platform {
    $r = New-EsResult
    $d = $r.data
    $cs = @(Add-EsCimItems $r 'Win32_ComputerSystem') | Select-Object -First 1
    $bios = @(Add-EsCimItems $r 'Win32_BIOS') | Select-Object -First 1
    $vendor = $(if ($cs) { [string]$cs.Manufacturer } else { $null })
    $model = $(if ($cs) { [string]$cs.Model } else { $null })
    $d.vendor = $vendor
    $d.model = $model
    $d.bios_vendor = $(if ($bios) { [string]$bios.Manufacturer } else { $null })
    $d.bios_version = $(if ($bios) { [string]$bios.SMBIOSBIOSVersion } else { $null })
    $d.hypervisor = $(if ($cs) { $cs.HypervisorPresent } else { $null })
    $product = Get-EsVmProduct (@($vendor, $model, $d.bios_vendor, $d.bios_version) -join ' ')
    $d.vm_product = $product
    $container = $null
    $r.sources += 'registry HKLM\SYSTEM\CurrentControlSet\Control (ContainerType)'
    $containerType = Get-EsRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control' 'ContainerType'
    if ($null -ne $containerType -or @('ContainerAdministrator', 'ContainerUser') -contains [string]$env:USERNAME) {
        $container = @{ detected = $true; engine = 'windows-container'; kubernetes = [bool]$env:KUBERNETES_SERVICE_HOST }
    } else {
        $container = @{ detected = $false; engine = $null; kubernetes = [bool]$env:KUBERNETES_SERVICE_HOST }
    }
    $d.container = $container
    # 'none' only when the computer system query worked; otherwise unknown ($null).
    $d.virtualization = $(if ($container.detected) { 'container' } elseif ($product) { 'vm' } elseif ($cs) { 'none' } else { $null })
    $r.sources += 'registry HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss'
    $lxss = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    $d.wsl_distros = @(Get-EsRegSubkeys $lxss | ForEach-Object {
            $values = Get-EsRegValues ($lxss + '\' + $_)
            if ($values) { @{ name = [string]$values['DistributionName']; version = $values['Version']; base_path = [string]$values['BasePath'] } }
        })
    $docker = @{ path = '\\.\pipe\docker_engine'; accessible = $null }
    try { $docker.accessible = [bool](Test-Path -LiteralPath '\\.\pipe\docker_engine' -ErrorAction Stop) } catch { }
    $d.docker_socket = $docker
    # Only below a local ProgramFiles: a share or an empty value is never looked at.
    $programFiles = [string](Get-EsOrigEnv 'ProgramFiles')
    $d.docker_desktop = ((Test-EsLocalPath $programFiles) -and (Test-EsSafePath (Join-Path $programFiles 'Docker\Docker\Docker Desktop.exe')))
    $features = @((Get-EsData 'pkg.features')['enabled'])
    $d.hyperv_features = @($features | Where-Object { $_ -match '(?i)hyper-v|VirtualMachinePlatform|Containers|Subsystem-Linux|HypervisorPlatform' })
    $d.kvm = $null
    return $r
}

function probe_virt_engine {
    # docker info against the local default context only (--context default overrides a
    # DOCKER_CONTEXT or a remote context saved in the docker configuration). podman is
    # inventory only: its connections may be ssh to another host.
    $r = New-EsResult
    if (-not (Test-EsDependency $r 'tools.inventory')) { return $r }
    $tools = (Get-EsData 'tools.inventory')['tools']
    $found = $false
    $dockerHost = [string]$script:ES_ENV_SNAPSHOT['DOCKER_HOST']
    $docker = $null
    $podman = $null
    if ($tools) { $docker = $tools['docker']; $podman = $tools['podman'] }
    if ($podman -and $podman['found']) {
        $found = $true
        $r.data.podman = @{ version = $podman['version']; info = 'not run: podman connections may use ssh to another host' }
    }
    if ($docker -and $docker['found'] -and $docker['path']) {
        $found = $true
        if ($dockerHost -and $dockerHost -notmatch '^npipe://') {
            Add-EsNote $r ('docker info not run: DOCKER_HOST points to ' + $dockerHost) ''
        } else {
            $arguments = @('--context', 'default', 'info')
            if ($dockerHost) { $arguments = @('info') }
            $run = Invoke-EsTool $r 'docker info' ([string]$docker['path']) $arguments 30 -AllowFailure
            $r.data.docker = @{ exit_code = $run.exit_code; reachable = ($run.exit_code -eq 0) }
        }
    }
    if (-not $found -and $r.status -eq 'ok') { $r.status = 'not_found' }
    return $r
}
