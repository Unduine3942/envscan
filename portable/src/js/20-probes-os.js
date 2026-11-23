// ---------------------------------------------------------------------------
// 20-probes-os: OS identity, time and locale, health, updates, hardware,
// session context and virtualization (port of src/ps/20-probes-os.ps1).
// ---------------------------------------------------------------------------

// One prop list per WMI class for all probes here, so the engine's query cache is shared.
var JSOS_OS_PROPS = ["Caption", "Version", "BuildNumber", "ProductType", "InstallDate", "LastBootUpTime",
    "TotalVisibleMemorySize", "FreePhysicalMemory", "TotalVirtualMemorySize", "FreeVirtualMemory",
    "SizeStoredInPagingFiles", "FreeSpaceInPagingFiles"];
var JSOS_CS_PROPS = ["Manufacturer", "Model", "HypervisorPresent", "PartOfDomain", "Domain", "DNSHostName", "Workgroup"];
var JSOS_CPU_PROPS = ["Name", "Manufacturer", "NumberOfCores", "NumberOfLogicalProcessors", "MaxClockSpeed",
    "Architecture", "VirtualizationFirmwareEnabled", "L3CacheSize", "LoadPercentage"];
var JSOS_MB = 1048576;

// ------------------------------------------------------------------ small helpers (JScript only)

function jsOs_first(items) {
    return (items && items.length > 0) ? items[0] : null;
}

function jsOs_str(value) {
    // PowerShell [string] cast: $null becomes ''.
    return (value === null || value === undefined) ? "" : String(value);
}

function jsOs_num(value) {
    // A WMI number; uint64 values arrive as strings. null when absent or not a number.
    if (value === null || value === undefined || value === "") { return null; }
    var n = Number(value);
    return isNaN(n) ? null : n;
}

function jsOs_round(value) {
    // PowerShell [long] cast of a double: round half to even.
    var floor = Math.floor(value);
    var diff = value - floor;
    if (diff > 0.5) { return floor + 1; }
    if (diff < 0.5) { return floor; }
    return (floor % 2 === 0) ? floor : floor + 1;
}

function jsOs_div(value, divisor) {
    var n = jsOs_num(value);
    return n === null ? null : jsOs_round(n / divisor);
}

function jsOs_val(table, name) {
    // Case-insensitive lookup in a registry value table (ps hashtables ignore case); null when absent.
    if (!table) { return null; }
    if (esHas(table, name)) { return table[name] === undefined ? null : table[name]; }
    var lower = name.toLowerCase();
    for (var key in table) {
        if (esHas(table, key) && key.toLowerCase() === lower) { return table[key]; }
    }
    return null;
}

function jsOs_cim(result, className, props, namespace, filter) {
    return addEsCimItems(result, className, namespace || "root/cimv2", filter || "", props);
}

// ------------------------------------------------------------------ identity

function convertToEsArch(name) {
    var text = jsOs_str(name);
    if (/^(AMD64|x64|x86_64|EM64T)$/i.test(text)) { return "x86_64"; }
    if (/^(x86|i[3-6]86)$/i.test(text)) { return "x86"; }
    if (/^(ARM64|aarch64)$/i.test(text)) { return "arm64"; }
    if (/^ARM/i.test(text)) { return "arm"; }
    if (/^IA64$/i.test(text)) { return "ia64"; }
    if (text) { return "other"; }
    return null;
}

function getEsArchFacts(cpu) {
    // OS architecture (seen through WOW64 and ARM64 emulation) and the scanner's own process.
    var arch = convertToEsArch(getEsEnv("PROCESSOR_ARCHITECTURE"));
    if (getEsEnv("PROCESSOR_ARCHITEW6432")) { arch = convertToEsArch(getEsEnv("PROCESSOR_ARCHITEW6432")); }
    if (cpu && Number(cpu.Architecture) === 12) { arch = "arm64"; }
    return {
        arch: arch,
        process_arch: convertToEsArch(getEsEnv("PROCESSOR_ARCHITECTURE")),
        userland_bits: (arch === "x86_64" || arch === "arm64" || arch === "ia64") ? 64 : 32,
        architecture_code: cpu ? Number(cpu.Architecture) : null
    };
}

function getEsDomainFacts(cs) {
    // Domain or workgroup membership; unknown (null) when Win32_ComputerSystem was unreadable.
    var facts = { domain: null, domain_joined: null, fqdn: null };
    if (!cs) { return facts; }
    facts.domain_joined = !!cs.PartOfDomain;
    if (cs.PartOfDomain) {
        facts.domain = jsOs_str(cs.Domain);
        facts.fqdn = (jsOs_str(cs.DNSHostName) + "." + jsOs_str(cs.Domain)).toLowerCase();
    } else {
        facts.workgroup = jsOs_str(cs.Workgroup);
    }
    return facts;
}

function jsOs_copyInto(target, source) {
    for (var key in source) { if (esHas(source, key)) { target[key] = source[key]; } }
}

function jsOs_identityVersion(d, os, cv) {
    var build = jsOs_str(jsOs_val(cv, "CurrentBuild"));
    if (!build && os) { build = jsOs_str(os.BuildNumber); }
    var name = os ? esTrim(jsOs_str(os.Caption)) : "";
    if (!name) {
        name = jsOs_str(jsOs_val(cv, "ProductName"));
        if (/^\d+$/.test(build) && parseInt(build, 10) >= 22000) { name = name.replace("Windows 10", "Windows 11"); }
    }
    var ubr = jsOs_val(cv, "UBR");
    var display = jsOs_val(cv, "DisplayVersion");
    d.family = "windows";
    d.name = name;
    d.version = os ? jsOs_str(os.Version) : jsOs_str(jsOs_val(cv, "CurrentVersion"));
    d.build = ubr ? build + "." + ubr : build;
    d.display_version = display ? jsOs_str(display) : jsOs_str(jsOs_val(cv, "ReleaseId"));
    d.edition = jsOs_str(jsOs_val(cv, "EditionID"));
    d.install_type = jsOs_str(jsOs_val(cv, "InstallationType"));
    d.kernel = d.version;
    d.product_type = os ? Number(os.ProductType) : null;
    d.install_date_utc = os ? formatEsUtc(convertFromEsCimDate(os.InstallDate)) : null;
    d.system_root = getEsEnv("SystemRoot");
}

function probe_os_identity() {
    var r = newEsResult();
    var d = r.data;
    var os = jsOs_first(jsOs_cim(r, "Win32_OperatingSystem", JSOS_OS_PROPS));
    var cs = jsOs_first(jsOs_cim(r, "Win32_ComputerSystem", JSOS_CS_PROPS));
    var cpu = jsOs_first(jsOs_cim(r, "Win32_Processor", JSOS_CPU_PROPS));
    var cv = getEsRegValues("HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    r.sources.push("registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    if (cv === null || cv === undefined) { cv = {}; addEsNote(r, "CurrentVersion registry key unreadable"); }
    if (!os && esKeys(cv).length === 0) { r.status = "error"; r.error = "no OS information source was readable"; return r; }
    jsOs_identityVersion(d, os, cv);
    jsOs_copyInto(d, getEsArchFacts(cpu));
    d.wow64_process = !!getEsEnv("PROCESSOR_ARCHITEW6432");
    if (d.wow64_process) { addEsNote(r, "the scanner ran as a 32-bit process on 64-bit Windows; registry and System32 views are redirected", "partial"); }
    d.hostname = jsOs_str(getEsEnv("COMPUTERNAME"));
    jsOs_copyInto(d, getEsDomainFacts(cs));
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo");
    d.directory_joined = getEsRegSubkeys("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo").length > 0;
    d.distro_id = null;
    d.distro_like = null;
    d.wsl = false;
    d.rosetta = null;
    return r;
}

// ------------------------------------------------------------------ time and locale

function jsOs_utcOffset() {
    var offset = -new Date().getTimezoneOffset();
    var sign = "+";
    if (offset < 0) { sign = "-"; offset = -offset; }
    return sign + esPad2(Math.floor(offset / 60)) + ":" + esPad2(offset % 60);
}

function jsOs_cultureName(tag) {
    // "en-us" -> "en-US", "zh-hans-cn" -> "zh-Hans-CN" (.NET culture name casing).
    var parts = jsOs_str(tag).split("-");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
        var part = parts[i];
        if (i === 0) { out.push(part.toLowerCase()); }
        else if (part.length === 2) { out.push(part.toUpperCase()); }
        else if (part.length === 4) { out.push(part.charAt(0).toUpperCase() + part.substr(1).toLowerCase()); }
        else { out.push(part); }
    }
    return out.join("-");
}

function jsOs_lcidName(lcid) {
    // Culture name of a hexadecimal LCID ("00000409") from the MIME RFC 1766 table, else null.
    var text = jsOs_str(lcid);
    if (!/^[0-9A-Fa-f]{4,8}$/.test(text)) { return null; }
    var value = getEsRegValue("HKLM:\\SOFTWARE\\Classes\\MIME\\Database\\Rfc1766", text.substr(text.length - 4).toUpperCase());
    if (value === null || value === undefined) { return null; }
    var tag = jsOs_str(value).split(";")[0];
    return tag ? jsOs_cultureName(tag) : null;
}

function jsOs_firstText(value) {
    // First entry of a REG_MULTI_SZ (or the string itself), else null.
    if (value === null || value === undefined) { return null; }
    if (esIsArray(value)) { return value.length > 0 && value[0] ? String(value[0]) : null; }
    return String(value) || null;
}

function jsOs_timezone(r, d) {
    // Time zone id (= Get-TimeZone Id) and display name from the registry; WMI as the fallback.
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation (TimeZoneKeyName)");
    var id = jsOs_str(getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", "TimeZoneKeyName"));
    id = id.replace(/\u0000[\s\S]*$/, "");
    d.timezone = null;
    if (id) {
        r.sources.push("registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\<id> (Display)");
        var display = getEsRegValue("HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\" + id, "Display");
        d.timezone = id;
        d.timezone_display = jsOs_str(display);
        if (display !== null && display !== undefined) { return; }
    }
    var zone = jsOs_first(jsOs_cim(r, "Win32_TimeZone", ["StandardName", "Caption"]));
    if (zone) {
        if (!d.timezone) { d.timezone = jsOs_str(zone.StandardName); }
        d.timezone_display = jsOs_str(zone.Caption);
    }
}

function jsOs_culture(r, d) {
    // Get-Culture (user locale with overrides) and Get-UICulture from the user's registry settings.
    var intl = getEsRegValues("HKCU:\\Control Panel\\International");
    r.sources.push("registry HKCU\\Control Panel\\International (LocaleName, Locale, sDecimal, sThousand, sShortDate, sList)");
    if (!intl) { intl = {}; addEsNote(r, "HKCU\\Control Panel\\International unreadable: user locale unknown", "partial"); }
    var name = jsOs_val(intl, "LocaleName");
    d.locale = name ? String(name) : jsOs_lcidName(jsOs_val(intl, "Locale"));
    d.decimal_separator = jsOs_val(intl, "sDecimal");
    d.thousands_separator = jsOs_val(intl, "sThousand");
    d.date_format = jsOs_val(intl, "sShortDate");
    d.list_separator = jsOs_val(intl, "sList");
    r.sources.push("registry HKCU\\Control Panel\\Desktop (PreferredUILanguages) and \\MuiCached (MachinePreferredUILanguages)");
    var ui = jsOs_firstText(getEsRegValue("HKCU:\\Control Panel\\Desktop", "PreferredUILanguages"));
    if (!ui) { ui = jsOs_firstText(getEsRegValue("HKCU:\\Control Panel\\Desktop\\MuiCached", "MachinePreferredUILanguages")); }
    if (!ui) { ui = jsOs_lcidName(getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language", "InstallLanguage")); }
    d.ui_locale = ui;
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Locale (default value) and HKLM\\SOFTWARE\\Classes\\MIME\\Database\\Rfc1766");
    d.system_locale = jsOs_lcidName(getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Locale", ""));
}

function jsOs_codepages(r, d, console) {
    var cp = getEsRegValues("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage");
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage");
    if (cp) { d.codepage_ansi = jsOs_str(jsOs_val(cp, "ACP")); d.codepage_oem = jsOs_str(jsOs_val(cp, "OEMCP")); }
    // No console API in WSH: the console default (HKCU\Console CodePage, else the OEM code page).
    var configured = jsOs_val(console, "CodePage");
    d.codepage_console = (configured !== null && Number(configured) > 0) ? String(configured) : (d.codepage_oem || null);
    if (d.codepage_console) { addEsNote(r, "codepage_console is the console default (HKCU\\Console CodePage, else the OEM code page); a chcp in the calling console is not seen", ""); }
    d.utf8_system_codepage = (d.codepage_ansi === "65001");
    d.encoding = d.codepage_ansi === "65001" ? "UTF-8" : (d.codepage_ansi ? "cp" + d.codepage_ansi : null);
    d.utf8_available = true;
}

function probe_os_time_locale() {
    var r = newEsResult();
    var d = r.data;
    d.utc_offset = jsOs_utcOffset();
    jsOs_timezone(r, d);
    jsOs_culture(r, d);
    var console = getEsRegValues("HKCU:\\Console");
    r.sources.push("registry HKCU\\Console");
    jsOs_codepages(r, d, console);
    d.virtual_terminal_level = console ? jsOs_val(console, "VirtualTerminalLevel") : null;
    return r;
}

// ------------------------------------------------------------------ health and updates

function probe_os_health() {
    var r = newEsResult();
    var d = r.data;
    var os = jsOs_first(jsOs_cim(r, "Win32_OperatingSystem", JSOS_OS_PROPS));
    var boot = os ? convertFromEsCimDate(os.LastBootUpTime) : null;
    d.last_boot_utc = formatEsUtc(boot);
    d.uptime_seconds = boot ? jsOs_round((getEsUtc().getTime() - boot.getTime()) / 1000) : null;
    var cpu = jsOs_first(jsOs_cim(r, "Win32_Processor", JSOS_CPU_PROPS));
    d.cpu_load_percent = cpu ? jsOs_num(cpu.LoadPercentage) : null;
    d.load = null;
    var reasons = [];
    var checks = [
        ["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending", "component servicing"],
        ["HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired", "Windows Update"]
    ];
    for (var i = 0; i < checks.length; i++) {
        r.sources.push("registry " + checks[i][0].replace(/^HKLM:/, "HKLM"));
        if (testEsRegKey(checks[i][0])) { reasons.push(checks[i][1]); }
    }
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager (PendingFileRenameOperations)");
    var pending = getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", "PendingFileRenameOperations");
    if (pending !== null && pending !== undefined) { reasons.push("pending file rename operations"); }
    d.pending_reboot = reasons.length > 0;
    d.pending_reasons = reasons;
    return r;
}

function jsOs_installedOn(value) {
    // As PowerShell shows QFE InstalledOn ([string] of its DateTime: MM/dd/yyyy HH:mm:ss, invariant).
    var text = jsOs_str(value);
    var m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(text);
    var date = null;
    if (m) { date = new Date(parseInt(m[3], 10), parseInt(m[1], 10) - 1, parseInt(m[2], 10)); }
    else if (/^[0-9A-Fa-f]{15,16}$/.test(text)) { date = new Date(parseInt(text, 16) / 10000 - 11644473600000); }
    if (!date || isNaN(date.getTime())) { return text; }
    return esPad2(date.getMonth() + 1) + "/" + esPad2(date.getDate()) + "/" + esPad4(date.getFullYear()) + " "
        + esPad2(date.getHours()) + ":" + esPad2(date.getMinutes()) + ":" + esPad2(date.getSeconds());
}

function jsOs_hotfixes(items) {
    var out = [];
    for (var i = 0; i < items.length; i++) {
        var item = items[i];
        out.push({ id: jsOs_str(item.HotFixID), description: jsOs_str(item.Description), installed_on: jsOs_installedOn(item.InstalledOn) });
    }
    out.sort(function (a, b) {
        var x = a.id.toLowerCase();
        var y = b.id.toLowerCase();
        return x < y ? -1 : (x > y ? 1 : 0);
    });
    return out;
}

function probe_os_updates() {
    var r = newEsResult();
    var hotfixes = jsOs_hotfixes(jsOs_cim(r, "Win32_QuickFixEngineering", ["HotFixID", "Description", "InstalledOn"]));
    r.data.count = hotfixes.length;
    r.data.hotfixes = hotfixes;
    var ids = [];
    for (var i = 0; i < hotfixes.length; i++) { ids.push(hotfixes[i].id); }
    var build = jsOs_str(getEsData("os.identity").build);
    var m = /^(\d+)/.exec(build);
    // Only a successful query proves absence; later rollups may also include these updates.
    if (r.status === "ok" && m && parseInt(m[1], 10) < 9600) {
        r.data.legacy_updates = {
            "KB2999226 (Universal C Runtime)": esContainsI(ids, "KB2999226"),
            "KB4474419 (SHA-2 code signing)": esContainsI(ids, "KB4474419"),
            "KB3140245 (WinHTTP TLS 1.1/1.2 default)": esContainsI(ids, "KB3140245")
        };
    }
    if (hotfixes.length === 0 && r.status === "ok") { r.status = "not_found"; }
    return r;
}

// ------------------------------------------------------------------ hardware

function probe_hw_cpu() {
    var r = newEsResult();
    var d = r.data;
    var cpus = jsOs_cim(r, "Win32_Processor", JSOS_CPU_PROPS);
    if (cpus.length === 0) { r.status = "error"; return r; }
    var first = cpus[0];
    var cores = 0;
    var logical = 0;
    for (var i = 0; i < cpus.length; i++) {
        cores += Number(cpus[i].NumberOfCores) || 0;
        logical += Number(cpus[i].NumberOfLogicalProcessors) || 0;
    }
    d.model = esTrim(jsOs_str(first.Name));
    d.vendor = jsOs_str(first.Manufacturer);
    d.sockets = cpus.length;
    d.cores = cores;
    d.logical = logical;
    d.max_clock_mhz = jsOs_num(first.MaxClockSpeed);
    d.architecture_code = Number(first.Architecture);
    d.virtualization_firmware_enabled = (first.VirtualizationFirmwareEnabled === undefined) ? null : first.VirtualizationFirmwareEnabled;
    d.l3_cache_kb = jsOs_num(first.L3CacheSize);
    var key = getEsRegValues("HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
    r.sources.push("registry HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
    if (key) { d.identifier = jsOs_str(jsOs_val(key, "Identifier")); }
    d.features = null;
    d.flags = null;
    r.notes.push("Windows does not expose instruction-set flags (AVX, AVX2, AVX-512) to standard users; infer them from the CPU model.");
    return r;
}

function jsOs_pagefiles(items) {
    var out = [];
    for (var i = 0; i < items.length; i++) {
        out.push({ path: jsOs_str(items[i].Name), allocated_mb: jsOs_num(items[i].AllocatedBaseSize), current_usage_mb: jsOs_num(items[i].CurrentUsage) });
    }
    return out;
}

function probe_hw_memory() {
    var r = newEsResult();
    var d = r.data;
    var os = jsOs_first(jsOs_cim(r, "Win32_OperatingSystem", JSOS_OS_PROPS));
    if (!os) { r.status = "error"; return r; }
    d.total_mb = jsOs_div(os.TotalVisibleMemorySize, 1024);
    d.available_mb = jsOs_div(os.FreePhysicalMemory, 1024);
    d.commit_limit_mb = jsOs_div(os.TotalVirtualMemorySize, 1024);
    d.commit_free_mb = jsOs_div(os.FreeVirtualMemory, 1024);
    d.swap_total_mb = jsOs_div(os.SizeStoredInPagingFiles, 1024);
    d.swap_free_mb = jsOs_div(os.FreeSpaceInPagingFiles, 1024);
    d.pagefiles = jsOs_pagefiles(jsOs_cim(r, "Win32_PageFileUsage", ["Name", "AllocatedBaseSize", "CurrentUsage"]));
    return r;
}

function getEsNetworkDriveEntries() {
    // Mapped network drives (from initializeEsDrives); never contacted, so no size or type.
    var entries = [];
    var drives = ES_NETWORK_DRIVES || [];
    for (var i = 0; i < drives.length; i++) {
        var target = esHas(ES_NETWORK_DRIVE_TARGETS, drives[i]) ? ES_NETWORK_DRIVE_TARGETS[drives[i]] : null;
        entries.push({
            mount: drives[i] + "\\", device: target === undefined ? null : target, fstype: null, label: null,
            kind: "network", total_mb: null, free_mb: null, network: true, removable: false
        });
    }
    return entries;
}

function jsOs_volumeEntry(item) {
    var kinds = { "2": "removable", "3": "local", "5": "optical", "6": "ramdisk" };
    var type = Number(item.DriveType);
    var capacity = jsOs_num(item.Capacity);
    var free = jsOs_num(item.FreeSpace);
    return {
        mount: jsOs_str(item.DriveLetter) + "\\", device: jsOs_str(item.DeviceID), fstype: jsOs_str(item.FileSystem),
        label: jsOs_str(item.Label), kind: esHas(kinds, String(type)) ? kinds[String(type)] : null,
        total_mb: capacity ? jsOs_round(capacity / JSOS_MB) : null,
        free_mb: free !== null ? jsOs_round(free / JSOS_MB) : null,
        network: false, removable: (type === 2 || type === 5)
    };
}

function probe_hw_storage() {
    // Local volumes from Win32_Volume, which only enumerates local volumes; Win32_LogicalDisk
    // would ask the file server of every mapped drive for its size (network traffic).
    var r = newEsResult();
    var volumes = jsOs_cim(r, "Win32_Volume", ["DriveLetter", "DeviceID", "FileSystem", "Label", "DriveType", "Capacity", "FreeSpace"],
        "root/cimv2", "DriveLetter IS NOT NULL");
    var list = [];
    for (var i = 0; i < volumes.length; i++) { list.push(jsOs_volumeEntry(volumes[i])); }
    var network = getEsNetworkDriveEntries();
    r.sources.push("registry HKCU\\Network and the drive list (mapped drives; not contacted)");
    if (network.length > 0) { r.notes.push("mapped network drives are listed without size: querying them would contact the file server"); }
    r.data.volumes = list.concat(network);
    if (volumes.length === 0 && r.status === "ok") { r.status = "error"; }
    return r;
}

function getEsVolumeFor(path) {
    // Volume entry from hw.storage for a local path (drive letter match).
    var m = /^([A-Za-z]):/.exec(jsOs_str(path));
    if (!m) { return null; }
    var drive = m[1].toUpperCase() + ":\\";
    var volumes = getEsData("hw.storage").volumes || [];
    for (var i = 0; i < volumes.length; i++) {
        if (volumes[i] && jsOs_str(volumes[i].mount).toUpperCase() === drive) { return volumes[i]; }
    }
    return null;
}

function jsOs_uint32(value) {
    // AdapterRAM is a uint32 that the WMI bridge may hand over as a signed number.
    var n = jsOs_num(value);
    return (n !== null && n < 0) ? n + 4294967296 : n;
}

function jsOs_gpuEntry(item) {
    var ram = jsOs_uint32(item.AdapterRAM);
    var horizontal = jsOs_num(item.CurrentHorizontalResolution);
    return {
        name: jsOs_str(item.Name), driver_version: jsOs_str(item.DriverVersion),
        vram_mb: ram ? jsOs_round(ram / JSOS_MB) : null,
        processor: jsOs_str(item.VideoProcessor), status: jsOs_str(item.Status),
        resolution: horizontal ? String(horizontal) + "x" + jsOs_str(item.CurrentVerticalResolution) : null
    };
}

function probe_hw_gpu() {
    var r = newEsResult();
    var controllers = jsOs_cim(r, "Win32_VideoController", ["Name", "DriverVersion", "AdapterRAM", "VideoProcessor", "Status",
        "CurrentHorizontalResolution", "CurrentVerticalResolution"]);
    var gpus = [];
    var capped = false;
    for (var i = 0; i < controllers.length; i++) {
        // AdapterRAM is 32-bit: 4 GB or more reads as at most 4095 MB.
        var ram = jsOs_uint32(controllers[i].AdapterRAM);
        if (ram && ram >= 4293918720) { capped = true; }
        gpus.push(jsOs_gpuEntry(controllers[i]));
    }
    if (capped) { r.notes.push("vram_mb is capped near 4096 MB (Win32_VideoController.AdapterRAM is a 32-bit value)"); }
    r.data.gpus = gpus;
    if (controllers.length === 0 && r.status === "ok") { r.status = "not_found"; }
    return r;
}
