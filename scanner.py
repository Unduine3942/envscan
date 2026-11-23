#!/usr/bin/env python3
"""
System & Environment Scanner
Collects system capabilities, software versions, permissions, and policies
that impact software development and project implementation.

Output: scan_report.md (human-readable) and scan_report.json (machine-readable)
"""

import argparse
import platform
import subprocess
import os
import sys
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional


OUTPUT_DIR = Path(__file__).parent / "output"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: list, timeout: int = 20) -> str:
    """Run a command; return stdout+stderr combined, empty string on failure."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace"
        )
        return (r.stdout or r.stderr or "").strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return ""


def ps(script: str, timeout: int = 30) -> str:
    """Run a PowerShell command and return output."""
    # No -ExecutionPolicy flag: inline -Command strings don't need it,
    # and omitting -ExecutionPolicy Bypass avoids EDR/Defender false-positive alerts.
    return run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout
    )


def tool_version(name: str, *flags: str) -> Optional[str]:
    """Return first non-empty line from `name flags`, or None if missing."""
    path = shutil.which(name)
    if not path:
        return None
    out = run([name] + list(flags))
    first = next((l.strip() for l in out.splitlines() if l.strip()), None)
    return first


def mb(value_bytes: int) -> str:
    gb = value_bytes / (1024 ** 3)
    return f"{gb:.1f} GB" if gb >= 1 else f"{value_bytes / (1024**2):.0f} MB"


# ---------------------------------------------------------------------------
# Section collectors
# ---------------------------------------------------------------------------

def collect_system() -> dict:
    info = {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "os_edition": ps("(Get-WmiObject Win32_OperatingSystem).Caption"),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "scan_time": datetime.now().isoformat(timespec="seconds"),
    }
    # Windows build / UBR
    ubr = ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR")
    if ubr:
        info["os_update_build"] = ubr
    info["powershell_version"] = ps("$PSVersionTable.PSVersion.ToString()")
    return info


def collect_hardware() -> dict:
    cpu_name = ps("(Get-WmiObject Win32_Processor).Name")
    cpu_cores = ps("(Get-WmiObject Win32_Processor).NumberOfCores")
    cpu_logical = ps("(Get-WmiObject Win32_Processor).NumberOfLogicalProcessors")
    cpu_speed = ps("(Get-WmiObject Win32_Processor).MaxClockSpeed")
    ram_bytes = ps("(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory")
    virtualization = ps("(Get-WmiObject Win32_Processor).VirtualizationFirmwareEnabled")
    # Hyper-V via registry (no elevation needed)
    hyper_v = ps(
        "$hv = Get-ItemProperty "
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization' "
        "-ErrorAction SilentlyContinue; "
        "if ($hv) { 'Available' } else { "
        "$feat = (Get-WmiObject -Query "
        "\"SELECT * FROM Win32_OptionalFeature WHERE Name='Microsoft-Hyper-V'\" "
        "-ErrorAction SilentlyContinue); "
        "if ($feat) { $feat.Caption + ': ' + @{1='Enabled';2='Disabled'}[[int]$feat.InstallState] } "
        "else { 'Not installed' } }"
    )

    hardware = {
        "cpu_name": cpu_name,
        "cpu_cores_physical": cpu_cores,
        "cpu_cores_logical": cpu_logical,
        "cpu_max_speed_mhz": cpu_speed,
        "virtualization_enabled": virtualization,
        "hyper_v": hyper_v or "Not available / Not installed",
    }
    if ram_bytes.isdigit():
        hardware["ram_total"] = mb(int(ram_bytes))
    else:
        hardware["ram_total"] = ram_bytes

    # Disk usage for all drives
    disks = []
    ps_disk = ps(
        "Get-PSDrive -PSProvider FileSystem | "
        "Select-Object Name, @{N='Used';E={$_.Used}}, @{N='Free';E={$_.Free}} | "
        "ConvertTo-Json"
    )
    try:
        raw = json.loads(ps_disk)
        if isinstance(raw, dict):
            raw = [raw]
        for d in raw:
            used = d.get("Used") or 0
            free = d.get("Free") or 0
            total = used + free
            disks.append({
                "drive": d.get("Name", "?") + ":",
                "total": mb(total) if total else "N/A",
                "free": mb(free) if free else "N/A",
                "used": mb(used) if used else "N/A",
            })
    except (json.JSONDecodeError, TypeError):
        pass

    hardware["disks"] = disks
    return hardware


def collect_dev_tools() -> dict:
    tools = {}

    checks = [
        # (display_name, executable, version_flags...)
        ("Python",          "python",       "--version"),
        ("Python3",         "python3",      "--version"),
        ("pip",             "pip",          "--version"),
        ("pip3",            "pip3",         "--version"),
        ("Node.js",         "node",         "--version"),
        ("npm",             "npm",          "--version"),
        ("yarn",            "yarn",         "--version"),
        ("pnpm",            "pnpm",         "--version"),
        ("npx",             "npx",          "--version"),
        ("Bun",             "bun",          "--version"),
        ("Deno",            "deno",         "--version"),
        ("Go",              "go",           "version"),
        ("Rust (rustc)",    "rustc",        "--version"),
        ("Cargo",           "cargo",        "--version"),
        ("Java",            "java",         "-version"),
        ("javac",           "javac",        "-version"),
        ("Maven",           "mvn",          "--version"),
        ("Gradle",          "gradle",       "--version"),
        ("Kotlin",          "kotlin",       "-version"),
        ("Ruby",            "ruby",         "--version"),
        ("Gem",             "gem",          "--version"),
        ("PHP",             "php",          "--version"),
        ("Composer",        "composer",     "--version"),
        (".NET SDK",        "dotnet",       "--version"),
        ("NuGet",           "nuget",        "help"),
        ("Perl",            "perl",         "--version"),
        ("Swift",           "swift",        "--version"),
        ("Clang",           "clang",        "--version"),
        ("GCC",             "gcc",          "--version"),
        ("Make",            "make",         "--version"),
        ("CMake",           "cmake",        "--version"),
        ("Ninja",           "ninja",        "--version"),
        ("MSBuild",         "msbuild",      "/version"),
        ("Git",             "git",          "--version"),
        ("Git LFS",         "git-lfs",      "--version"),
        ("Mercurial",       "hg",           "--version"),
        ("SVN",             "svn",          "--version"),
        ("Docker",          "docker",       "--version"),
        ("Docker Compose",  "docker",       "compose", "version"),
        ("Podman",          "podman",       "--version"),
        ("kubectl",         "kubectl",      "version", "--client", "--short"),
        ("Helm",            "helm",         "version", "--short"),
        ("Minikube",        "minikube",     "version"),
        ("Terraform",       "terraform",    "--version"),
        ("Ansible",         "ansible",      "--version"),
        ("AWS CLI",         "aws",          "--version"),
        ("Azure CLI",       "az",           "version"),
        ("gcloud",          "gcloud",       "--version"),
        ("OpenSSL",         "openssl",      "version"),
        ("curl",            "curl",         "--version"),
        ("wget",            "wget",         "--version"),
        ("jq",              "jq",           "--version"),
        ("yq",              "yq",           "--version"),
        ("sqlite3",         "sqlite3",      "--version"),
        ("psql",            "psql",         "--version"),
        ("mysql",           "mysql",        "--version"),
        ("mongosh",         "mongosh",      "--version"),
        ("redis-cli",       "redis-cli",    "--version"),
        ("Chocolatey",      "choco",        "--version"),
        ("Scoop",           "scoop",        "--version"),
        ("winget",          "winget",       "--version"),
        ("conda",           "conda",        "--version"),
        ("poetry",          "poetry",       "--version"),
        ("pipenv",          "pipenv",       "--version"),
        ("uv",              "uv",           "--version"),
        ("VS Code",         "code",         "--version"),
        ("vim",             "vim",          "--version"),
        ("nvim",            "nvim",         "--version"),
        # WSL version via PowerShell (wsl.exe outputs UTF-16 which corrupts in subprocess)
        # Handled separately in collect_network; omit here
    ]

    for entry in checks:
        display, exe, *flags = entry
        ver = tool_version(exe, *flags)
        if ver:
            tools[display] = ver.splitlines()[0]

    return tools


def collect_env_vars() -> dict:
    important_keys = [
        "PATH", "PYTHONPATH", "PYTHONHOME", "JAVA_HOME", "GOPATH", "GOROOT",
        "CARGO_HOME", "RUSTUP_HOME", "NODE_PATH", "GEM_HOME",
        "ANDROID_HOME", "ANDROID_SDK_ROOT", "NDK_HOME",
        "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
        "PROGRAMFILES(X86)", "WINDIR", "SYSTEMROOT",
        "TEMP", "TMP",
        "COMPUTERNAME", "USERNAME", "USERDOMAIN", "USERDNSDOMAIN",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "DOCKER_HOST", "KUBECONFIG", "AWS_DEFAULT_REGION",
        "VCPKG_ROOT", "CMAKE_PREFIX_PATH",
        "VIRTUAL_ENV", "CONDA_DEFAULT_ENV",
        "NVM_HOME", "NVM_SYMLINK",
    ]
    result = {}
    for key in important_keys:
        val = os.environ.get(key) or os.environ.get(key.lower())
        if val:
            result[key] = val
    return result


def collect_path_entries() -> list:
    raw = os.environ.get("PATH", "")
    sep = ";" if platform.system() == "Windows" else ":"
    entries = [p.strip() for p in raw.split(sep) if p.strip()]
    return entries


def collect_user_permissions() -> dict:
    data = {}
    data["username"] = os.environ.get("USERNAME", os.getlogin())

    # Is admin?
    try:
        import ctypes
        data["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        data["is_admin"] = "Unknown"

    # whoami /all — privileges and groups
    whoami_all = run(["whoami", "/all"])
    data["whoami_all"] = whoami_all

    # Current groups
    groups_raw = run(["whoami", "/groups", "/fo", "csv"])
    data["groups_csv"] = groups_raw

    # UAC setting
    uac_raw = ps(
        "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\Policies\\System).EnableLUA"
    )
    data["uac_enabled"] = uac_raw

    # Elevation policy
    consent = ps(
        "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\Policies\\System).ConsentPromptBehaviorAdmin"
    )
    data["uac_consent_level"] = consent

    return data


def collect_group_policies() -> dict:
    data = {}
    # gpresult summary — /r gives applied GPOs
    gp = run(["gpresult", "/r"], timeout=45)
    data["gpresult_summary"] = gp if gp else "Not available or requires elevation"

    # PowerShell execution policy
    data["ps_execution_policy"] = ps("Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String")

    # AppLocker policies
    applocker = ps(
        "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | "
        "ConvertTo-Json -Depth 3 -ErrorAction SilentlyContinue"
    )
    data["applocker"] = applocker or "Not configured or not accessible"

    # Software Restriction Policies (registry)
    srp = ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers' "
        "-ErrorAction SilentlyContinue | ConvertTo-Json -ErrorAction SilentlyContinue"
    )
    data["software_restriction_policies"] = srp or "Not configured"

    return data


def collect_security() -> dict:
    data = {}

    # Windows Defender status
    defender = ps(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | "
        "Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, "
        "RealTimeProtectionEnabled, IoavProtectionEnabled | "
        "ConvertTo-Json -ErrorAction SilentlyContinue"
    )
    try:
        data["windows_defender"] = json.loads(defender)
    except (json.JSONDecodeError, TypeError):
        data["windows_defender"] = defender or "Not accessible"

    # Firewall profiles
    firewall = ps(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    )
    try:
        data["firewall_profiles"] = json.loads(firewall)
    except (json.JSONDecodeError, TypeError):
        data["firewall_profiles"] = firewall

    # Secure Boot
    secure_boot = ps("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue 2>&1")
    data["secure_boot"] = secure_boot or "N/A (legacy BIOS or VM)"

    # BitLocker status
    bitlocker = ps(
        "Get-BitLockerVolume -ErrorAction SilentlyContinue | "
        "Select-Object MountPoint, VolumeStatus, ProtectionStatus | "
        "ConvertTo-Json -ErrorAction SilentlyContinue"
    )
    data["bitlocker"] = bitlocker or "Not accessible / Not enabled"

    # DEP / NX
    dep = ps(
        "(Get-WmiObject Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy"
    )
    dep_map = {"0": "AlwaysOff", "1": "AlwaysOn", "2": "OptIn", "3": "OptOut"}
    data["dep_policy"] = dep_map.get(dep, dep)

    # ASLR
    aslr = ps(
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' "
        "-ErrorAction SilentlyContinue).MoveImages"
    )
    data["aslr_enabled"] = "Enabled" if aslr and aslr != "0" else "System default (enabled)"

    return data


def collect_network() -> dict:
    data = {}

    # IP configuration
    ipconfig = run(["ipconfig", "/all"])
    data["ipconfig"] = ipconfig

    # Proxy settings
    proxy = ps(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
        "-ErrorAction SilentlyContinue | Select-Object ProxyEnable, ProxyServer, ProxyOverride | "
        "ConvertTo-Json -ErrorAction SilentlyContinue"
    )
    try:
        data["proxy_settings"] = json.loads(proxy)
    except (json.JSONDecodeError, TypeError):
        data["proxy_settings"] = proxy

    # DNS
    dns = ps(
        "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses } | "
        "Select-Object InterfaceAlias, AddressFamily, ServerAddresses | "
        "ConvertTo-Json -ErrorAction SilentlyContinue"
    )
    try:
        data["dns_servers"] = json.loads(dns)
    except (json.JSONDecodeError, TypeError):
        data["dns_servers"] = dns

    # WSL: read from registry (wsl.exe outputs UTF-16 which breaks most pipelines)
    wsl_info = ps(
        "$distros = Get-ChildItem 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss' "
        "-ErrorAction SilentlyContinue; "
        "if ($distros) { "
        "  $distros | ForEach-Object { "
        "    $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; "
        "    [PSCustomObject]@{ Name=$p.DistributionName; State=$p.State; Version=$p.Version } "
        "  } | ConvertTo-Json "
        "} else { 'WSL not installed' }"
    )
    data["wsl_distros"] = wsl_info or "WSL not installed"

    return data


def collect_installed_packages() -> dict:
    data = {}
    # Pip global packages
    pip_list = run(["pip", "list", "--format=columns"])
    data["pip_global"] = pip_list or "pip not found"

    # npm global
    npm_global = run(["npm", "list", "-g", "--depth=0"])
    data["npm_global"] = npm_global or "npm not found"

    return data


# ---------------------------------------------------------------------------
# Safe-mode collectors  (skip commands that trigger EDR/SIEM alerts)
# Omitted: whoami /all, whoami /groups, gpresult /r, AppLocker queries,
#          Get-MpComputerStatus, Get-BitLockerVolume
# ---------------------------------------------------------------------------

def collect_user_permissions_safe() -> dict:
    """Username and admin status only — no privilege/group enumeration."""
    data: dict = {"username": os.environ.get("USERNAME", os.getlogin())}
    try:
        import ctypes
        data["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        data["is_admin"] = "Unknown"
    data["whoami_all"] = "Skipped (safe mode)"
    data["groups_csv"] = "Skipped (safe mode)"
    # UAC level is a plain registry read — not a recon command
    data["uac_enabled"] = ps(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA"
    )
    data["uac_consent_level"] = ps(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\Policies\\System' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin"
    )
    return data


def collect_group_policies_safe() -> dict:
    """PS execution policy only — no gpresult, AppLocker, or SRP queries."""
    return {
        "ps_execution_policy": ps(
            "Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String"
        ),
        "gpresult_summary": "Skipped (safe mode)",
        "applocker": "Skipped (safe mode)",
        "software_restriction_policies": "Skipped (safe mode)",
    }


def collect_security_safe() -> dict:
    """Firewall, DEP, ASLR, Secure Boot only — no Defender or BitLocker API calls."""
    data: dict = {}
    data["windows_defender"] = "Skipped (safe mode)"

    firewall = ps(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    )
    try:
        data["firewall_profiles"] = json.loads(firewall)
    except (json.JSONDecodeError, TypeError):
        data["firewall_profiles"] = firewall

    secure_boot = ps("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue 2>&1")
    data["secure_boot"] = secure_boot or "N/A (legacy BIOS or VM)"

    data["bitlocker"] = "Skipped (safe mode)"

    dep = ps(
        "(Get-WmiObject Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy"
    )
    dep_map = {"0": "AlwaysOff", "1": "AlwaysOn", "2": "OptIn", "3": "OptOut"}
    data["dep_policy"] = dep_map.get(dep, dep)

    aslr = ps(
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"
        "\\Memory Management' -ErrorAction SilentlyContinue).MoveImages"
    )
    data["aslr_enabled"] = "Enabled" if aslr and aslr != "0" else "System default (enabled)"

    return data


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def kv_table(items: dict) -> str:
    if not items:
        return "_No data_\n"
    lines = ["| Property | Value |", "|----------|-------|"]
    for k, v in items.items():
        v_str = str(v).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {k} | {v_str} |")
    return "\n".join(lines) + "\n"


def tool_table(tools: dict) -> str:
    if not tools:
        return "_No tools detected_\n"
    lines = ["| Tool | Version |", "|------|---------|"]
    for name, ver in sorted(tools.items()):
        v = str(ver).replace("|", "\\|").replace("\n", " ")[:120]
        lines.append(f"| {name} | {v} |")
    return "\n".join(lines) + "\n"


def code_block(content: str, lang: str = "") -> str:
    content = content.strip() if content else "_Not available_"
    return f"```{lang}\n{content}\n```\n"


def build_markdown(data: dict, safe: bool = False) -> str:
    sys_info = data["system"]
    hw = data["hardware"]
    tools = data["dev_tools"]
    env = data["environment_variables"]
    path_entries = data["path_entries"]
    user = data["user_permissions"]
    gp = data["group_policies"]
    sec = data["security"]
    net = data["network"]
    pkgs = data["installed_packages"]

    lines = []

    mode_label = "SAFE MODE" if safe else "FULL MODE"
    mode_note = (
        "_Safe mode: privilege enumeration, group policy queries, "
        "and Defender/BitLocker API calls were skipped._"
        if safe else
        "_Full mode: all sections collected._"
    )

    lines.append("# System Environment Scan Report")
    lines.append("")
    lines.append(f"**Mode:** {mode_label}  ")
    lines.append(f"**Generated:** {sys_info.get('scan_time', 'Unknown')}  ")
    lines.append(f"**Host:** {sys_info.get('hostname', 'Unknown')}  ")
    lines.append(f"**User:** {user.get('username', 'Unknown')}  ")
    lines.append(f"**Admin:** {user.get('is_admin', 'Unknown')}  ")
    lines.append("")
    lines.append(f"> {mode_note}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # TOC
    lines.append("## Table of Contents")
    lines.append("")
    toc = [
        "System Overview", "Hardware", "Development Tools", "Package Managers & Extras",
        "Environment Variables", "PATH Entries", "User & Permissions",
        "Group Policies", "Security Settings", "Network", "Installed Packages"
    ]
    for item in toc:
        anchor = item.lower().replace(" ", "-").replace("&", "").replace("--", "-")
        lines.append(f"- [{item}](#{anchor})")
    lines.append("")

    # System Overview
    lines.append("## System Overview")
    lines.append("")
    sys_display = {
        "Hostname": sys_info.get("hostname"),
        "OS Edition": sys_info.get("os_edition") or sys_info.get("os"),
        "OS Release": sys_info.get("os_release"),
        "OS Version": sys_info.get("os_version"),
        "Update Build (UBR)": sys_info.get("os_update_build", "N/A"),
        "Architecture": sys_info.get("architecture"),
        "PowerShell Version": sys_info.get("powershell_version"),
        "Python Version (runtime)": sys_info.get("python_version"),
    }
    lines.append(kv_table({k: v for k, v in sys_display.items() if v}))

    # Hardware
    lines.append("## Hardware")
    lines.append("")
    hw_display = {
        "CPU": hw.get("cpu_name"),
        "Physical Cores": hw.get("cpu_cores_physical"),
        "Logical Processors": hw.get("cpu_cores_logical"),
        "Max Clock Speed": f"{hw.get('cpu_max_speed_mhz', '?')} MHz",
        "Total RAM": hw.get("ram_total"),
        "Virtualization Firmware": hw.get("virtualization_enabled"),
        "Hyper-V": hw.get("hyper_v"),
    }
    lines.append(kv_table({k: v for k, v in hw_display.items() if v}))
    lines.append("")
    lines.append("### Disk Drives")
    lines.append("")
    if hw.get("disks"):
        lines.append("| Drive | Total | Used | Free |")
        lines.append("|-------|-------|------|------|")
        for d in hw["disks"]:
            lines.append(f"| {d['drive']} | {d['total']} | {d['used']} | {d['free']} |")
        lines.append("")
    else:
        lines.append("_No disk data available_\n")

    # Dev Tools
    lines.append("## Development Tools")
    lines.append("")

    categories = {
        "Languages & Runtimes": [
            "Python", "Python3", "Node.js", "Go", "Rust (rustc)", "Java", "Kotlin",
            "Ruby", "PHP", "Perl", "Swift", "Clang", "GCC", "Deno", "Bun", ".NET SDK"
        ],
        "Build & Compile Tools": [
            "javac", "Maven", "Gradle", "Make", "CMake", "Ninja", "MSBuild", "Cargo"
        ],
        "Package Managers": [
            "pip", "pip3", "npm", "yarn", "pnpm", "npx", "Gem", "Composer",
            "NuGet", "Chocolatey", "Scoop", "winget", "conda", "poetry", "pipenv", "uv"
        ],
        "Version Control": ["Git", "Git LFS", "Mercurial", "SVN"],
        "Containers & Orchestration": [
            "Docker", "Docker Compose", "Podman", "kubectl", "Helm", "Minikube"
        ],
        "Cloud & Infrastructure": ["Terraform", "Ansible", "AWS CLI", "Azure CLI", "gcloud"],
        "Databases (CLI)": ["sqlite3", "psql", "mysql", "mongosh", "redis-cli"],
        "Utilities": ["OpenSSL", "curl", "wget", "jq", "yq"],
        "Editors & IDEs": ["VS Code", "vim", "nvim"],
        "Subsystems": [],  # WSL handled in Network section via registry
    }

    for cat, names in categories.items():
        cat_tools = {n: tools[n] for n in names if n in tools}
        if cat_tools:
            lines.append(f"### {cat}")
            lines.append("")
            lines.append(tool_table(cat_tools))

    # Catch-all for uncategorized
    all_categorized = {n for names in categories.values() for n in names}
    extras = {k: v for k, v in tools.items() if k not in all_categorized}
    if extras:
        lines.append("### Other")
        lines.append("")
        lines.append(tool_table(extras))

    not_found = sorted(
        n for cat_names in categories.values() for n in cat_names if n not in tools
    )
    if not_found:
        lines.append("### Not Found / Not Installed")
        lines.append("")
        lines.append(", ".join(f"`{n}`" for n in not_found))
        lines.append("")

    # Package Managers & Extras — alias pointing to section above
    lines.append("## Package Managers & Extras")
    lines.append("")
    lines.append("_See [Development Tools](#development-tools) > Package Managers above._")
    lines.append("")

    # Environment Variables
    lines.append("## Environment Variables")
    lines.append("")
    if env:
        lines.append("| Variable | Value |")
        lines.append("|----------|-------|")
        for k, v in sorted(env.items()):
            if k == "PATH":
                continue  # covered in PATH section
            v_safe = str(v).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| `{k}` | {v_safe} |")
        lines.append("")
    else:
        lines.append("_No environment variable data_\n")

    # PATH Entries
    lines.append("## PATH Entries")
    lines.append("")
    lines.append(f"**Total entries:** {len(path_entries)}")
    lines.append("")
    if path_entries:
        for i, entry in enumerate(path_entries, 1):
            exists = Path(entry).exists()
            status = "" if exists else " _(missing)_"
            lines.append(f"{i}. `{entry}`{status}")
        lines.append("")

    # User & Permissions
    lines.append("## User & Permissions")
    lines.append("")
    lines.append(f"**Username:** `{user.get('username', 'N/A')}`  ")
    lines.append(f"**Administrator:** {user.get('is_admin', 'Unknown')}  ")
    lines.append(f"**UAC Enabled:** {user.get('uac_enabled', 'Unknown')}  ")
    uac_levels = {
        "0": "Never notify", "1": "Notify (no dim)", "2": "Always notify (default)",
        "3": "Elevate without prompting (dangerous)", "5": "Default UAC behavior"
    }
    consent = str(user.get("uac_consent_level", ""))
    lines.append(f"**UAC Consent Level:** {uac_levels.get(consent, consent)}  ")
    lines.append("")
    lines.append("### Privileges & Groups (whoami /all)")
    lines.append("")
    lines.append(code_block(user.get("whoami_all", "Not available")))

    # Group Policies
    lines.append("## Group Policies")
    lines.append("")
    lines.append("### PowerShell Execution Policy")
    lines.append("")
    lines.append(code_block(gp.get("ps_execution_policy", "Not available")))
    lines.append("### GPResult Summary")
    lines.append("")
    lines.append(code_block(gp.get("gpresult_summary", "Not available (may require elevation)")))
    lines.append("### AppLocker Policy")
    lines.append("")
    lines.append(code_block(gp.get("applocker", "Not configured")))
    lines.append("### Software Restriction Policies")
    lines.append("")
    lines.append(code_block(gp.get("software_restriction_policies", "Not configured")))

    # Security
    lines.append("## Security Settings")
    lines.append("")
    sec_display = {}

    def_raw = sec.get("windows_defender", {})
    if isinstance(def_raw, dict):
        sec_display["Defender AM Service"] = def_raw.get("AMServiceEnabled")
        sec_display["Defender Antivirus"] = def_raw.get("AntivirusEnabled")
        sec_display["Defender Real-Time Protection"] = def_raw.get("RealTimeProtectionEnabled")
        sec_display["Defender Antispyware"] = def_raw.get("AntispywareEnabled")
    else:
        sec_display["Windows Defender"] = str(def_raw)

    fw_raw = sec.get("firewall_profiles", [])
    if isinstance(fw_raw, list):
        for p in fw_raw:
            if isinstance(p, dict):
                sec_display[f"Firewall ({p.get('Name', '?')})"] = (
                    "Enabled" if p.get("Enabled") else "Disabled"
                )
    elif isinstance(fw_raw, dict):
        sec_display[f"Firewall ({fw_raw.get('Name', '?')})"] = (
            "Enabled" if fw_raw.get("Enabled") else "Disabled"
        )

    sec_display["Secure Boot"] = sec.get("secure_boot", "N/A")
    sec_display["DEP Policy"] = sec.get("dep_policy")
    sec_display["ASLR"] = sec.get("aslr_enabled")

    lines.append(kv_table({k: v for k, v in sec_display.items() if v is not None}))
    lines.append("")
    lines.append("### BitLocker")
    lines.append("")
    lines.append(code_block(str(sec.get("bitlocker", "Not accessible"))))

    # Network
    lines.append("## Network")
    lines.append("")
    lines.append("### IP Configuration (ipconfig /all)")
    lines.append("")
    lines.append(code_block(net.get("ipconfig", "Not available")))

    proxy = net.get("proxy_settings", {})
    lines.append("### Proxy Settings")
    lines.append("")
    if isinstance(proxy, dict):
        lines.append(kv_table({
            "Proxy Enabled": proxy.get("ProxyEnable"),
            "Proxy Server": proxy.get("ProxyServer"),
            "Proxy Override": proxy.get("ProxyOverride"),
        }))
    else:
        lines.append(code_block(str(proxy)))

    lines.append("### DNS Servers")
    lines.append("")
    dns = net.get("dns_servers", [])
    if isinstance(dns, list):
        for entry in dns:
            if isinstance(entry, dict):
                iface = entry.get("InterfaceAlias", "?")
                addrs = entry.get("ServerAddresses", [])
                if addrs:
                    lines.append(f"**{iface}:** {', '.join(addrs)}  ")
        lines.append("")
    else:
        lines.append(code_block(str(dns)))

    lines.append("### WSL Distributions")
    lines.append("")
    lines.append(code_block(net.get("wsl_distros", "WSL not installed")))

    # Installed Packages
    lines.append("## Installed Packages")
    lines.append("")
    lines.append("### pip (global)")
    lines.append("")
    lines.append(code_block(pkgs.get("pip_global", "pip not found")))
    lines.append("### npm (global)")
    lines.append("")
    lines.append(code_block(pkgs.get("npm_global", "npm not found")))

    lines.append("---")
    lines.append("")
    lines.append(f"_Report generated by Environment Scanner on {sys_info.get('scan_time', 'Unknown')}_")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="System & Environment Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modes:
  full (default)  All sections: privilege enumeration, group policies,
                  Defender/BitLocker status. Best for personal machines.

  --safe          Skips whoami /all, gpresult, AppLocker, Defender API, and
                  BitLocker queries. Use on corporate or managed machines to
                  avoid triggering EDR/SIEM alerts.

examples:
  python scanner.py
  python scanner.py --safe
        """,
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Skip commands that may trigger EDR/SIEM alerts on managed machines",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    safe = args.safe

    mode_label = "SAFE" if safe else "FULL"
    print(f"Environment Scanner starting... [{mode_label} MODE]")
    print(f"Python {sys.version.split()[0]} on {platform.system()} {platform.release()}")
    print()

    steps = [
        ("System info",        collect_system),
        ("Hardware",           collect_hardware),
        ("Development tools",  collect_dev_tools),
        ("Environment vars",   collect_env_vars),
        ("PATH entries",       collect_path_entries),
        ("User & permissions", collect_user_permissions_safe if safe else collect_user_permissions),
        ("Group policies",     collect_group_policies_safe  if safe else collect_group_policies),
        ("Security settings",  collect_security_safe        if safe else collect_security),
        ("Network",            collect_network),
        ("Installed packages", collect_installed_packages),
    ]

    key_map = {
        "System info":        "system",
        "Hardware":           "hardware",
        "Development tools":  "dev_tools",
        "Environment vars":   "environment_variables",
        "PATH entries":       "path_entries",
        "User & permissions": "user_permissions",
        "Group policies":     "group_policies",
        "Security settings":  "security",
        "Network":            "network",
        "Installed packages": "installed_packages",
    }

    data: dict = {}
    for label, fn in steps:
        print(f"  [{label}]...", end="", flush=True)
        try:
            data[key_map[label]] = fn()
            print(" done")
        except Exception as e:
            data[key_map[label]] = {"error": str(e)}
            print(f" ERROR: {e}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "_safe" if safe else ""

    json_path = OUTPUT_DIR / f"scan_{ts}{suffix}.json"
    json_latest = OUTPUT_DIR / f"scan_latest{suffix}.json"
    for path in (json_path, json_latest):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    md_content = build_markdown(data, safe=safe)
    md_path = OUTPUT_DIR / f"scan_{ts}{suffix}.md"
    md_latest = OUTPUT_DIR / f"scan_latest{suffix}.md"
    for path in (md_path, md_latest):
        with open(path, "w", encoding="utf-8") as f:
            f.write(md_content)

    print()
    print("Scan complete.")
    print(f"  Markdown : {md_path}")
    print(f"  JSON     : {json_path}")
    print(f"  Latest   : {md_latest}")


if __name__ == "__main__":
    main()
