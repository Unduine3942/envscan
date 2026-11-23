// ---------------------------------------------------------------------------
// 20-probes-virt: session context and virtualization (port of the second half of
// src/ps/20-probes-os.ps1; helpers jsOs_* are in 20-probes-os.js).
// ---------------------------------------------------------------------------

var JSOS_DOCKER_PIPE = "\\\\.\\pipe\\docker_engine";

function jsOs_sessionId(r) {
    // No process API in WSH: the session id is the numeric subkey of HKCU\Volatile Environment
    // (one per logon session of this user). Unknown (null) when there is not exactly one.
    r.sources.push("registry HKCU\\Volatile Environment (session subkey names)");
    var names = getEsRegSubkeys("HKCU:\\Volatile Environment");
    var ids = [];
    for (var i = 0; i < names.length; i++) { if (/^\d+$/.test(names[i])) { ids.push(parseInt(names[i], 10)); } }
    if (ids.length === 1) { return ids[0]; }
    addEsNote(r, "session id unknown: HKCU\\Volatile Environment has " + ids.length + " session subkeys", "partial");
    return null;
}

function jsOs_sessionType(sessionId, name) {
    if (getEsEnv("SSH_CONNECTION") || getEsEnv("SSH_CLIENT")) { return "ssh"; }
    if (sessionId === 0) { return "service"; }
    if (/^RDP-/i.test(name)) { return "rdp"; }
    if (name.toLowerCase() === "console") { return "console"; }
    return "unknown";
}

function jsOs_hostName() {
    // The script host executable (cscript.exe), the counterpart of PowerShell's $Host.Name.
    var full = jsOs_str(WScript.FullName);
    return full.substr(full.lastIndexOf("\\") + 1);
}

function jsOs_terminal(hostName) {
    if (getEsEnv("WT_SESSION")) { return "Windows Terminal"; }
    if (getEsEnv("TERM_PROGRAM")) { return getEsEnv("TERM_PROGRAM"); }
    if (getEsEnv("ConEmuANSI")) { return "ConEmu"; }
    return hostName;
}

function probe_session_context() {
    var r = newEsResult();
    var d = r.data;
    r.sources.push("environment SESSIONNAME, WT_SESSION, TERM_PROGRAM, SSH_CONNECTION", "WScript.FullName");
    var sessionId = jsOs_sessionId(r);
    var name = jsOs_str(getEsEnv("SESSIONNAME"));
    var type = jsOs_sessionType(sessionId, name);
    d.type = type;
    d.session_name = name;
    d.session_id = sessionId;
    // [Environment]::UserInteractive is false only without a visible window station (session 0).
    d.interactive = sessionId === null ? null : sessionId > 0;
    d.display = (type === "console" || type === "rdp");
    d.host_name = jsOs_hostName();
    d.terminal = jsOs_terminal(d.host_name);
    d.tty = null;
    var desktop = getEsRegValues("HKCU:\\Control Panel\\Desktop");
    r.sources.push("registry HKCU\\Control Panel\\Desktop");
    var dpi = jsOs_val(desktop, "LogPixels");
    d.dpi = dpi ? dpi : null;
    var gpus = getEsData("hw.gpu").gpus || [];
    d.resolution = null;
    for (var i = 0; i < gpus.length; i++) { if (gpus[i] && gpus[i].resolution) { d.resolution = gpus[i].resolution; break; } }
    return r;
}

function getEsVmProduct(signature) {
    // Virtual machine product named by the system and BIOS vendor and model strings, else null.
    var text = jsOs_str(signature);
    var table = [
        [/VMware/i, "VMware"], [/VirtualBox|innotek/i, "VirtualBox"], [/Amazon EC2|amazon/i, "Amazon EC2"],
        [/Google Compute Engine|Google/i, "Google Compute Engine"], [/Xen|HVM domU/i, "Xen"],
        [/QEMU|KVM|Bochs/i, "KVM/QEMU"], [/Parallels/i, "Parallels"], [/OpenStack/i, "OpenStack"],
        [/Virtual Machine|Hyper-V/i, "Hyper-V"]
    ];
    for (var i = 0; i < table.length; i++) { if (table[i][0].test(text)) { return table[i][1]; } }
    return null;
}

function jsOs_container(r) {
    r.sources.push("registry HKLM\\SYSTEM\\CurrentControlSet\\Control (ContainerType)");
    var containerType = getEsRegValue("HKLM:\\SYSTEM\\CurrentControlSet\\Control", "ContainerType");
    var user = jsOs_str(getEsEnv("USERNAME")).toLowerCase();
    var kubernetes = !!getEsEnv("KUBERNETES_SERVICE_HOST");
    if ((containerType !== null && containerType !== undefined) || user === "containeradministrator" || user === "containeruser") {
        return { detected: true, engine: "windows-container", kubernetes: kubernetes };
    }
    return { detected: false, engine: null, kubernetes: kubernetes };
}

function jsOs_wslDistros(r) {
    r.sources.push("registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss");
    var lxss = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss";
    var out = [];
    var names = getEsRegSubkeys(lxss);
    for (var i = 0; i < names.length; i++) {
        var values = getEsRegValues(lxss + "\\" + names[i]);
        if (values) {
            out.push({ name: jsOs_str(jsOs_val(values, "DistributionName")), version: jsOs_val(values, "Version"),
                base_path: jsOs_str(jsOs_val(values, "BasePath")) });
        }
    }
    return out;
}

function jsOs_dockerFacts(r, d) {
    // FSO cannot see named pipes (FileExists is false even for existing pipes): unknown.
    d.docker_socket = { path: JSOS_DOCKER_PIPE, accessible: null };
    addEsNote(r, "docker_socket.accessible unknown: Windows Script Host cannot test a named pipe", "partial");
    // Only below a local ProgramFiles: a share or an empty value is never looked at.
    var programFiles = jsOs_str(getEsOrigEnv("ProgramFiles"));
    d.docker_desktop = !!(testEsLocalPath(programFiles) && testEsSafePath(esJoinPath(programFiles, "Docker\\Docker\\Docker Desktop.exe")));
}

function jsOs_hypervFeatures() {
    var features = getEsData("pkg.features").enabled || [];
    var out = [];
    for (var i = 0; i < features.length; i++) {
        if (/hyper-v|VirtualMachinePlatform|Containers|Subsystem-Linux|HypervisorPlatform/i.test(jsOs_str(features[i]))) { out.push(features[i]); }
    }
    return out;
}

function probe_virt_platform() {
    var r = newEsResult();
    var d = r.data;
    var cs = jsOs_first(jsOs_cim(r, "Win32_ComputerSystem", JSOS_CS_PROPS));
    var bios = jsOs_first(jsOs_cim(r, "Win32_BIOS", ["Manufacturer", "SMBIOSBIOSVersion"]));
    d.vendor = cs ? jsOs_str(cs.Manufacturer) : null;
    d.model = cs ? jsOs_str(cs.Model) : null;
    d.bios_vendor = bios ? jsOs_str(bios.Manufacturer) : null;
    d.bios_version = bios ? jsOs_str(bios.SMBIOSBIOSVersion) : null;
    d.hypervisor = (cs && cs.HypervisorPresent !== undefined) ? cs.HypervisorPresent : null;
    var product = getEsVmProduct([jsOs_str(d.vendor), jsOs_str(d.model), jsOs_str(d.bios_vendor), jsOs_str(d.bios_version)].join(" "));
    d.vm_product = product;
    var container = jsOs_container(r);
    d.container = container;
    // 'none' only when the computer system query worked; otherwise unknown (null).
    d.virtualization = container.detected ? "container" : (product ? "vm" : (cs ? "none" : null));
    d.wsl_distros = jsOs_wslDistros(r);
    jsOs_dockerFacts(r, d);
    d.hyperv_features = jsOs_hypervFeatures();
    d.kvm = null;
    return r;
}

function jsOs_dockerInfo(r, docker) {
    var dockerHost = jsOs_str(getEsOrigEnv("DOCKER_HOST"));
    if (dockerHost && !/^npipe:\/\//i.test(dockerHost)) {
        addEsNote(r, "docker info not run: DOCKER_HOST points to " + dockerHost, "");
        return;
    }
    var args = dockerHost ? ["info"] : ["--context", "default", "info"];
    var run = invokeEsTool(r, "docker info", jsOs_str(docker.path), args, 30, undefined, true);
    r.data.docker = { exit_code: run.exit_code, reachable: run.exit_code === 0 };
}

function probe_virt_engine() {
    // docker info against the local default context only (--context default overrides a
    // DOCKER_CONTEXT or a remote context saved in the docker configuration). podman is
    // inventory only: its connections may be ssh to another host.
    var r = newEsResult();
    if (!testEsDependency(r, "tools.inventory")) { return r; }
    var tools = getEsData("tools.inventory").tools;
    var docker = tools ? tools.docker : null;
    var podman = tools ? tools.podman : null;
    var found = false;
    if (podman && podman.found) {
        found = true;
        r.data.podman = { version: podman.version === undefined ? null : podman.version, info: "not run: podman connections may use ssh to another host" };
    }
    if (docker && docker.found && docker.path) {
        found = true;
        jsOs_dockerInfo(r, docker);
    }
    if (!found && r.status === "ok") { r.status = "not_found"; }
    return r;
}
