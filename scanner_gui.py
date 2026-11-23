#!/usr/bin/env python3
"""
scanner_gui.py — tkinter GUI for the Environment Scanner.

Run:  python scanner_gui.py
"""

import json
import queue
import threading
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional, Set

import scanner as _sc


# ---------------------------------------------------------------------------
# Queue message types
# ---------------------------------------------------------------------------

@dataclass
class ProgressMsg:
    step: int    # 1-based
    total: int
    label: str


@dataclass
class StepDoneMsg:
    ok: bool
    error: str = field(default="")


@dataclass
class ResultMsg:
    data: dict
    markdown: str
    safe: bool
    md_path: Path
    json_path: Path


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

class ScanWorker(threading.Thread):
    def __init__(self, safe: bool, q: "queue.Queue[object]") -> None:
        super().__init__(daemon=True)
        self._safe = safe
        self._q = q

    def run(self) -> None:
        safe = self._safe
        steps = [
            ("System info",        _sc.collect_system),
            ("Hardware",           _sc.collect_hardware),
            ("Development tools",  _sc.collect_dev_tools),
            ("Environment vars",   _sc.collect_env_vars),
            ("PATH entries",       _sc.collect_path_entries),
            ("User & permissions", _sc.collect_user_permissions_safe if safe else _sc.collect_user_permissions),
            ("Group policies",     _sc.collect_group_policies_safe   if safe else _sc.collect_group_policies),
            ("Security settings",  _sc.collect_security_safe         if safe else _sc.collect_security),
            ("Network",            _sc.collect_network),
            ("Installed packages", _sc.collect_installed_packages),
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

        total = len(steps)
        data: dict = {}
        for i, (label, fn) in enumerate(steps, 1):
            self._q.put(ProgressMsg(i, total, label))
            try:
                data[key_map[label]] = fn()
                self._q.put(StepDoneMsg(ok=True))
            except Exception as exc:
                data[key_map[label]] = {"error": str(exc)}
                self._q.put(StepDoneMsg(ok=False, error=str(exc)))

        _sc.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = "_safe" if safe else ""

        json_path = _sc.OUTPUT_DIR / f"scan_{ts}{suffix}.json"
        json_latest = _sc.OUTPUT_DIR / f"scan_latest{suffix}.json"
        for path in (json_path, json_latest):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

        md_content = _sc.build_markdown(data, safe=safe)
        md_path = _sc.OUTPUT_DIR / f"scan_{ts}{suffix}.md"
        md_latest = _sc.OUTPUT_DIR / f"scan_latest{suffix}.md"
        for path in (md_path, md_latest):
            with open(path, "w", encoding="utf-8") as f:
                f.write(md_content)

        self._q.put(ResultMsg(data, md_content, safe, md_path, json_path))


# ---------------------------------------------------------------------------
# Section definitions
# Each entry: (display label, data_key, renderer, renderer_kwargs)
# ---------------------------------------------------------------------------

SECTIONS = [
    ("Overview",           None,                   "overview", {}),
    ("System",             "system",               "kv",       {}),
    ("Hardware",           "hardware",             "kv",       {}),
    ("Dev Tools",          "dev_tools",            "tools",    {}),
    ("Environment Vars",   "environment_variables","kv",       {}),
    ("PATH Entries",       "path_entries",         "list",     {}),
    ("User & Permissions", "user_permissions",     "mixed",    {"long_keys": {"whoami_all", "groups_csv"}}),
    ("Group Policies",     "group_policies",       "mixed",    {"long_keys": {"gpresult_summary", "ps_execution_policy",
                                                                               "applocker", "software_restriction_policies"}}),
    ("Security",           "security",             "mixed",    {"long_keys": {"windows_defender", "firewall", "bitlocker"}}),
    ("Network",            "network",              "mixed",    {"long_keys": {"ip_config", "wsl_distros"}}),
    ("Packages",           "installed_packages",   "packages", {}),
]


# ---------------------------------------------------------------------------
# Renderer helpers (module-level, called by ScannerApp._show_section)
# ---------------------------------------------------------------------------

_FONT_MONO = ("Courier New", 9)
_FONT_UI   = ("Segoe UI", 10)
_FONT_SM   = ("Segoe UI", 9)
_COL_GREEN = "#1e8e3e"
_COL_GREY  = "#aaaaaa"
_COL_ALT   = "#f1f3f4"
_COL_ERR   = "#d93025"


def _scrolled(parent: tk.Widget, widget_cls: type, **kw) -> tuple:
    """Wrap widget_cls in a frame with Y + X scrollbars. Returns (frame, widget)."""
    frame = tk.Frame(parent)
    w = widget_cls(frame, **kw)
    ysb = ttk.Scrollbar(frame, orient=tk.VERTICAL,   command=w.yview)
    xsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=w.xview)
    w.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
    xsb.pack(side=tk.BOTTOM, fill=tk.X)
    ysb.pack(side=tk.RIGHT,  fill=tk.Y)
    w.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    return frame, w


def _tree(parent: tk.Widget, cols: list) -> tuple:
    """Scrolled Treeview with alternating row tags configured. Returns (frame, tree)."""
    frame, tv = _scrolled(parent, ttk.Treeview, columns=cols, show="headings", selectmode="browse")
    tv.tag_configure("alt", background=_COL_ALT)
    return frame, tv


def _footer(parent: tk.Widget, text: str) -> None:
    tk.Label(parent, text=text, font=_FONT_SM, fg="#5f6368", anchor="w").pack(
        side=tk.BOTTOM, fill=tk.X, padx=4, pady=2
    )


def render_kv(parent: tk.Widget, data: dict, skip: Optional[Set[str]] = None) -> None:
    """Two-column Property / Value treeview."""
    skip = skip or set()
    frame, tv = _tree(parent, ["k", "v"])
    tv.heading("k", text="Property")
    tv.heading("v", text="Value")
    tv.column("k", width=230, minwidth=120, stretch=False)
    tv.column("v", width=520, minwidth=200, stretch=True)

    rows = [(k, v) for k, v in data.items() if k not in skip]
    for i, (k, v) in enumerate(rows):
        val = str(v) if v is not None else "(not set)"
        val = val.replace("\n", " ↵ ")
        if len(val) > 250:
            val = val[:247] + "…"
        tags = ("alt",) if i % 2 else ()
        tv.insert("", tk.END, values=(k.replace("_", " ").title(), val), tags=tags)

    _footer(parent, f"  {len(rows)} properties")
    frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)


def render_tools(parent: tk.Widget, data: dict) -> None:
    """Tool / Version treeview; installed rows green, missing grey."""
    frame, tv = _tree(parent, ["tool", "ver"])
    tv.heading("tool", text="Tool")
    tv.heading("ver",  text="Version")
    tv.column("tool", width=200, minwidth=120, stretch=False)
    tv.column("ver",  width=520, minwidth=200, stretch=True)
    tv.tag_configure("ok",   foreground=_COL_GREEN)
    tv.tag_configure("miss", foreground=_COL_GREY)

    installed = {k: v for k, v in sorted(data.items()) if v and str(v).strip()}
    missing   = {k: v for k, v in sorted(data.items()) if k not in installed}

    for k, v in installed.items():
        first = str(v).splitlines()[0][:160]
        tv.insert("", tk.END, values=(k, first), tags=("ok",))
    for k in missing:
        tv.insert("", tk.END, values=(k, "— not found"), tags=("miss",))

    _footer(parent, f"  {len(installed)} installed  ·  {len(missing)} not found")
    frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)


def render_list(parent: tk.Widget, items: list) -> None:
    """Single-column entry list."""
    frame, tv = _tree(parent, ["v"])
    tv.heading("v", text="Entry")
    tv.column("v", width=750, stretch=True)

    for i, item in enumerate(items):
        tags = ("alt",) if i % 2 else ()
        tv.insert("", tk.END, values=(str(item),), tags=tags)

    _footer(parent, f"  {len(items)} entries")
    frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)


def render_text_block(parent: tk.Widget, text: str) -> None:
    """Read-only scrollable text block (monospace)."""
    frame, t = _scrolled(parent, tk.Text, font=_FONT_MONO, wrap=tk.NONE, bg="#f8f9fa", relief=tk.FLAT)
    t.insert("1.0", text or "(empty)")
    t.config(state=tk.DISABLED)
    frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)


def render_mixed(parent: tk.Widget, data: dict, long_keys: Set[str]) -> None:
    """
    Compact KV treeview for short fields (top) +
    tabbed text blocks for long-text fields (bottom).
    Uses a vertical PanedWindow when both halves are present.
    """
    short = {k: v for k, v in data.items() if k not in long_keys}
    long  = {k: v for k, v in data.items() if k in long_keys}

    if short and long:
        pane = tk.PanedWindow(parent, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=5)
        pane.pack(fill=tk.BOTH, expand=True)
        top = tk.Frame(pane)
        pane.add(top, height=160)
        render_kv(top, short)
        bot = tk.Frame(pane)
        pane.add(bot)
        _render_text_tabs(bot, long)
    elif short:
        render_kv(parent, short)
    else:
        _render_text_tabs(parent, long)


def _render_text_tabs(parent: tk.Widget, blocks: dict) -> None:
    """Render each text block in a notebook tab (or a labeled frame if only one)."""
    if len(blocks) == 1:
        k, v = next(iter(blocks.items()))
        lf = ttk.LabelFrame(parent, text=k.replace("_", " ").title(), padding=4)
        lf.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        render_text_block(lf, str(v))
    else:
        nb = ttk.Notebook(parent)
        nb.pack(fill=tk.BOTH, expand=True)
        for k, v in blocks.items():
            tab = tk.Frame(nb)
            nb.add(tab, text=k.replace("_", " ").title())
            render_text_block(tab, str(v))


def render_packages(parent: tk.Widget, data: dict) -> None:
    """pip and npm package lists in sub-tabs."""
    nb = ttk.Notebook(parent)
    nb.pack(fill=tk.BOTH, expand=True)

    for key, label in [("pip_global", "pip"), ("npm_global", "npm")]:
        items = data.get(key, [])
        tab   = tk.Frame(nb)
        count = len(items) if isinstance(items, list) else "?"
        nb.add(tab, text=f"{label}  ({count})")
        if isinstance(items, list):
            render_list(tab, items)
        else:
            render_text_block(tab, str(items))


def render_overview(parent: tk.Widget, all_data: dict) -> None:
    """Full-scan summary dashboard — one card per section."""
    canvas = tk.Canvas(parent, bg="#f0f2f5", highlightthickness=0)
    vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side=tk.RIGHT, fill=tk.Y)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    inner = tk.Frame(canvas, bg="#f0f2f5")
    win = canvas.create_window((0, 0), window=inner, anchor="nw")

    def _resize(ev: tk.Event) -> None:
        canvas.itemconfig(win, width=ev.width)
    canvas.bind("<Configure>", _resize)

    def _scroll_region(_ev=None) -> None:
        canvas.configure(scrollregion=canvas.bbox("all"))
    inner.bind("<Configure>", _scroll_region)

    def _on_enter(_ev=None) -> None:
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))

    def _on_leave(_ev=None) -> None:
        canvas.unbind_all("<MouseWheel>")

    canvas.bind("<Enter>", _on_enter)
    canvas.bind("<Leave>", _on_leave)

    def _card(title: str, color: str) -> tk.Frame:
        outer = tk.Frame(inner, bg="#f0f2f5")
        outer.pack(fill=tk.X, padx=12, pady=(8, 0))
        hdr = tk.Frame(outer, bg=color)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text=title, font=("Segoe UI", 10, "bold"),
                 bg=color, fg="white", anchor="w", padx=10, pady=4).pack(fill=tk.X)
        body = tk.Frame(outer, bg="white", bd=1, relief=tk.SOLID)
        body.pack(fill=tk.X)
        return body

    def _row(body: tk.Frame, label: str, value: str, idx: int) -> None:
        bg = _COL_ALT if idx % 2 else "white"
        r = tk.Frame(body, bg=bg)
        r.pack(fill=tk.X)
        tk.Label(r, text=label, font=("Segoe UI", 9, "bold"),
                 bg=bg, fg="#3c4043", anchor="w",
                 padx=10, pady=3, width=24, justify=tk.LEFT).pack(side=tk.LEFT)
        tk.Label(r, text=str(value) if value is not None else "(not set)",
                 font=("Segoe UI", 9), bg=bg, fg="#202124",
                 anchor="w", padx=4, pady=3,
                 wraplength=580, justify=tk.LEFT).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _safe_json(raw: object) -> object:
        if isinstance(raw, (dict, list)):
            return raw
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return raw

    # ── 1. System & Identity ─────────────────────────────────
    s = all_data.get("system", {})
    body = _card("System & Identity", "#1565C0")
    os_str = s.get("os_edition") or f"{s.get('os', '')} {s.get('os_release', '')}".strip()
    ubr = s.get("os_update_build", "")
    build_str = f"{s.get('os_version', '')}  (UBR {ubr})" if ubr else s.get("os_version", "")
    sys_rows = [
        ("Hostname",      s.get("hostname")),
        ("OS",            os_str),
        ("Build",         build_str),
        ("Architecture",  s.get("architecture")),
        ("Python",        s.get("python_version")),
        ("PowerShell",    s.get("powershell_version")),
        ("Scan Time",     s.get("scan_time")),
    ]
    for i, (lbl, val) in enumerate(sys_rows):
        if val:
            _row(body, lbl, str(val), i)

    # ── 2. Hardware ──────────────────────────────────────────
    hw = all_data.get("hardware", {})
    body = _card("Hardware", "#1b5e20")
    cores = (f"{hw.get('cpu_cores_physical', '?')} physical  /  "
             f"{hw.get('cpu_cores_logical', '?')} logical")
    hw_rows = [
        ("CPU",            hw.get("cpu_name")),
        ("Cores",          cores),
        ("RAM",            hw.get("ram_total")),
        ("Virtualization", hw.get("virtualization_enabled")),
        ("Hyper-V",        hw.get("hyper_v")),
    ]
    for i, (lbl, val) in enumerate(hw_rows):
        _row(body, lbl, str(val) if val else "", i)
    for j, d in enumerate(hw.get("disks", [])):
        disk_str = (f"Total: {d.get('total', '?')}  ·  "
                    f"Free: {d.get('free', '?')}  ·  "
                    f"Used: {d.get('used', '?')}")
        _row(body, f"Drive {d.get('drive', '?')}", disk_str, len(hw_rows) + j)

    # ── 3. User & Permissions ────────────────────────────────
    up = all_data.get("user_permissions", {})
    body = _card("User & Permissions", "#b71c1c")
    is_adm = up.get("is_admin")
    adm_str = ("YES — Administrator" if is_adm is True else
               "NO — Standard user"  if is_adm is False else str(is_adm))
    _UAC_MAP = {
        "0": "No prompt", "1": "Creds on secure desktop",
        "2": "Consent on secure desktop", "3": "Creds (non-secure desktop)",
        "4": "Consent (non-secure desktop)", "5": "Consent for non-Windows binaries",
    }
    uac_level = str(up.get("uac_consent_level", ""))
    for i, (lbl, val) in enumerate([
        ("Username",       up.get("username")),
        ("Administrator",  adm_str),
        ("UAC Enabled",    up.get("uac_enabled")),
        ("UAC Consent",    _UAC_MAP.get(uac_level, uac_level)),
    ]):
        _row(body, lbl, str(val) if val is not None else "", i)

    # ── 4. Security Settings ─────────────────────────────────
    sec = all_data.get("security", {})
    body = _card("Security Settings", "#bf360c")

    def_raw = _safe_json(sec.get("windows_defender", ""))
    if isinstance(def_raw, dict):
        dp = [f"{lbl}: {'ON' if def_raw.get(k) else 'OFF'}"
              for k, lbl in [("AntivirusEnabled",       "AV"),
                              ("RealTimeProtectionEnabled", "RTP"),
                              ("AntispywareEnabled",     "AS")]]
        defender_str = "  ·  ".join(dp)
    else:
        defender_str = str(def_raw)[:100] if def_raw else "Not accessible"

    fw_raw = _safe_json(sec.get("firewall_profiles", []))
    if isinstance(fw_raw, list):
        fw_str = "  ·  ".join(
            f"{p.get('Name', '?')}: {'ON' if p.get('Enabled') else 'OFF'}"
            for p in fw_raw if isinstance(p, dict)
        )
    elif isinstance(fw_raw, dict):
        fw_str = f"{fw_raw.get('Name', '?')}: {'ON' if fw_raw.get('Enabled') else 'OFF'}"
    else:
        fw_str = str(fw_raw)[:100]

    bl_raw = _safe_json(sec.get("bitlocker", ""))
    if isinstance(bl_raw, list):
        bl_str = "  ·  ".join(
            f"{v.get('MountPoint', '?')}: {v.get('ProtectionStatus', '?')}"
            for v in bl_raw if isinstance(v, dict)
        )
    elif isinstance(bl_raw, dict):
        bl_str = f"{bl_raw.get('MountPoint', '?')}: {bl_raw.get('ProtectionStatus', '?')}"
    else:
        bl_str = str(bl_raw)[:100]

    for i, (lbl, val) in enumerate([
        ("Windows Defender", defender_str),
        ("Firewall",         fw_str),
        ("BitLocker",        bl_str),
        ("Secure Boot",      sec.get("secure_boot")),
        ("DEP Policy",       sec.get("dep_policy")),
        ("ASLR",             sec.get("aslr_enabled")),
    ]):
        _row(body, lbl, str(val) if val is not None else "", i)

    # ── 5. Group Policies ────────────────────────────────────
    gp = all_data.get("group_policies", {})
    body = _card("Group Policies", "#4a148c")

    ps_exec_raw = gp.get("ps_execution_policy", "")
    if ps_exec_raw and ps_exec_raw != "Skipped (safe mode)":
        ps_lines = [l.strip() for l in ps_exec_raw.splitlines()
                    if l.strip() and "---" not in l
                    and l.strip() not in ("Scope", "ExecutionPolicy")]
        ps_exec = "  |  ".join(ps_lines[:5]) if ps_lines else ps_exec_raw[:100]
    else:
        ps_exec = ps_exec_raw or "Not available"

    _SKIP = frozenset({
        "Not configured or not accessible", "Skipped (safe mode)",
        "Not configured", "Not available or requires elevation",
    })
    al_raw = gp.get("applocker", "")
    al_str = "Configured" if al_raw and al_raw not in _SKIP else (al_raw or "Not configured")
    srp_raw = gp.get("software_restriction_policies", "")
    srp_str = "Configured" if srp_raw and srp_raw not in _SKIP else (srp_raw or "Not configured")
    gpr = gp.get("gpresult_summary", "")
    gpr_str = "Available" if gpr and gpr not in _SKIP else (gpr or "Not available")

    for i, (lbl, val) in enumerate([
        ("PS Execution Policy",   ps_exec),
        ("AppLocker",             al_str),
        ("Software Restrictions", srp_str),
        ("GPResult",              gpr_str),
    ]):
        _row(body, lbl, str(val), i)

    # ── 6. Network ───────────────────────────────────────────
    net = all_data.get("network", {})
    body = _card("Network", "#006064")

    ip_lines = [l for l in net.get("ipconfig", "").splitlines() if "IPv4 Address" in l]
    if ip_lines:
        ips = []
        for l in ip_lines:
            parts = l.split(":", 1)
            if len(parts) > 1:
                ip = parts[1].strip().replace("(Preferred)", "").replace("(Tentative)", "").strip()
                if ip:
                    ips.append(ip)
        ip_str = "  ·  ".join(ips) if ips else "Not found"
    else:
        ip_str = "Not available"

    dns_raw = _safe_json(net.get("dns_servers", []))
    if isinstance(dns_raw, list):
        dns_parts = [
            f"{e.get('InterfaceAlias', '?')}: {', '.join(e.get('ServerAddresses', []))}"
            for e in dns_raw[:4] if isinstance(e, dict) and e.get("ServerAddresses")
        ]
        dns_str = "  |  ".join(dns_parts) if dns_parts else "Not configured"
    elif isinstance(dns_raw, dict) and dns_raw.get("ServerAddresses"):
        dns_str = ", ".join(dns_raw.get("ServerAddresses", []))
    else:
        dns_str = str(dns_raw)[:80] if dns_raw else "Not available"

    proxy_raw = _safe_json(net.get("proxy_settings", {}))
    if isinstance(proxy_raw, dict):
        pe = proxy_raw.get("ProxyEnable")
        ps_srv = proxy_raw.get("ProxyServer")
        proxy_str = ("Enabled" if pe else "Disabled") + (f" → {ps_srv}" if ps_srv else "")
    else:
        proxy_str = str(proxy_raw)[:80] if proxy_raw else "Not configured"

    wsl_raw = net.get("wsl_distros", "WSL not installed")
    wsl_parsed = _safe_json(wsl_raw)
    if isinstance(wsl_parsed, list):
        wsl_str = (", ".join(d.get("Name", "?") for d in wsl_parsed if isinstance(d, dict))
                   or "Not installed")
    elif isinstance(wsl_parsed, dict):
        wsl_str = wsl_parsed.get("Name", str(wsl_raw)[:60])
    else:
        wsl_str = str(wsl_raw)[:80]

    for i, (lbl, val) in enumerate([
        ("IPv4 Addresses", ip_str),
        ("DNS Servers",    dns_str),
        ("Proxy",          proxy_str),
        ("WSL Distros",    wsl_str),
    ]):
        _row(body, lbl, str(val), i)

    # ── 7. Environment ───────────────────────────────────────
    env = all_data.get("environment_variables", {})
    path_entries = all_data.get("path_entries", [])
    body = _card(
        f"Environment  ({len(env)} vars  ·  {len(path_entries)} PATH entries)",
        "#37474f",
    )
    _DEV_KEYS = [
        "JAVA_HOME", "GOPATH", "GOROOT", "PYTHONPATH", "PYTHONHOME",
        "CARGO_HOME", "RUSTUP_HOME", "NODE_PATH", "ANDROID_HOME",
        "ANDROID_SDK_ROOT", "VIRTUAL_ENV", "CONDA_DEFAULT_ENV",
        "HTTP_PROXY", "HTTPS_PROXY", "KUBECONFIG", "AWS_DEFAULT_REGION",
    ]
    dev_vars = [(k, env[k]) for k in _DEV_KEYS if k in env]
    if dev_vars:
        for i, (k, v) in enumerate(dev_vars):
            _row(body, k, str(v), i)
    else:
        tk.Label(body, text="  No notable development environment variables set.",
                 font=("Segoe UI", 9), fg=_GREY_TXT, bg="white",
                 anchor="w", padx=10, pady=4).pack(fill=tk.X)

    # ── 8. Development Tools ─────────────────────────────────
    tools = all_data.get("dev_tools", {})
    installed_tools = {k: v for k, v in tools.items() if v and str(v).strip()}
    body = _card(f"Development Tools  ({len(installed_tools)} installed)", "#0d47a1")

    if installed_tools:
        grid_f = tk.Frame(body, bg="white")
        grid_f.pack(fill=tk.X, padx=8, pady=6)
        COLS = 2
        for j, (tname, tver) in enumerate(sorted(installed_tools.items())):
            ver_short = str(tver).splitlines()[0][:50]
            cell = tk.Frame(grid_f, bg="white")
            cell.grid(row=j // COLS, column=j % COLS, sticky="w", padx=(0, 16), pady=1)
            tk.Label(cell, text=f"• {tname}", font=("Segoe UI", 9, "bold"),
                     bg="white", fg=_COL_GREEN, anchor="w").pack(side=tk.LEFT)
            tk.Label(cell, text=f"  {ver_short}", font=("Segoe UI", 9),
                     bg="white", fg=_GREY_TXT, anchor="w").pack(side=tk.LEFT)
        for c in range(COLS):
            grid_f.columnconfigure(c, weight=1)
    else:
        tk.Label(body, text="  No development tools found in PATH.",
                 font=("Segoe UI", 9), fg=_GREY_TXT, bg="white",
                 anchor="w", padx=10, pady=4).pack(fill=tk.X)

    # ── 9. Installed Packages ────────────────────────────────
    pkg = all_data.get("installed_packages", {})
    body = _card("Installed Packages", "#e65100")

    pip_raw = pkg.get("pip_global", "")
    if isinstance(pip_raw, list):
        pip_str = f"{len(pip_raw)} packages"
    elif pip_raw and pip_raw != "pip not found":
        lines = [l for l in pip_raw.splitlines()
                 if l.strip() and not l.startswith("-") and "Package" not in l]
        pip_str = f"{len(lines)} packages"
    else:
        pip_str = pip_raw or "pip not found"

    npm_raw = pkg.get("npm_global", "")
    if isinstance(npm_raw, str) and npm_raw and npm_raw != "npm not found":
        npm_lines = [l for l in npm_raw.splitlines()[1:] if l.strip()]
        npm_str = f"{len(npm_lines)} packages"
    else:
        npm_str = npm_raw or "npm not found"

    for i, (lbl, val) in enumerate([
        ("pip (global)", pip_str),
        ("npm (global)", npm_str),
    ]):
        _row(body, lbl, val, i)

    tk.Frame(inner, bg="#f0f2f5", height=16).pack()


def render_error(parent: tk.Widget, message: str) -> None:
    tk.Label(
        parent,
        text=f"Section failed to collect:\n{message}",
        font=_FONT_UI,
        fg=_COL_ERR,
        wraplength=600,
        justify=tk.LEFT,
    ).pack(padx=24, pady=24, anchor="nw")


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------

POLL_MS    = 100
_BLUE      = "#1a73e8"
_GREEN_DK  = "#1e8e3e"
_RED       = "#d93025"
_GREY_TXT  = "#5f6368"


class ScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("System & Environment Scanner")
        self.geometry("1100x740")
        self.minsize(820, 540)

        self._q: "queue.Queue[object]" = queue.Queue()
        self._worker: Optional[ScanWorker] = None
        self._data: dict = {}
        self._markdown: str = ""
        self._safe_var    = tk.BooleanVar(value=False)
        self._status_var  = tk.StringVar(value="Ready — click Run Scan to begin")
        self._log_widget: Optional[tk.Text] = None

        self._build_ui()

    # ── Layout ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Title bar
        title_bar = tk.Frame(self, bg=_BLUE, pady=8)
        title_bar.pack(fill=tk.X)
        tk.Label(
            title_bar,
            text="System & Environment Scanner",
            font=("Segoe UI", 13, "bold"),
            bg=_BLUE, fg="white",
        ).pack(side=tk.LEFT, padx=14)

        # Controls
        ctrl = tk.Frame(self, pady=8)
        ctrl.pack(fill=tk.X, padx=14)

        self._safe_chk = tk.Checkbutton(
            ctrl,
            text="Safe Mode  (skips privilege enumeration & security API calls)",
            variable=self._safe_var,
            font=("Segoe UI", 10),
        )
        self._safe_chk.pack(side=tk.LEFT)

        self._export_btn = ttk.Button(ctrl, text="Export Report", command=self._export, state=tk.DISABLED)
        self._export_btn.pack(side=tk.RIGHT, padx=(4, 0))

        self._run_btn = ttk.Button(ctrl, text="▶  Run Scan", command=self._start_scan)
        self._run_btn.pack(side=tk.RIGHT, padx=4)

        # Progress row
        prog = tk.Frame(self)
        prog.pack(fill=tk.X, padx=14, pady=(0, 4))
        self._prog = ttk.Progressbar(prog, mode="determinate", maximum=10, length=180)
        self._prog.pack(side=tk.LEFT, padx=(0, 10))
        self._prog_label = tk.Label(prog, text="", font=("Segoe UI", 10), anchor="w")
        self._prog_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=2)

        # Status bar (packed before main area so it stays at bottom)
        sb = tk.Frame(self, relief=tk.SUNKEN, bd=1)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(sb, textvariable=self._status_var, font=("Segoe UI", 9),
                 anchor="w", padx=8, pady=3).pack(fill=tk.X)

        # Main paned area: nav (left) + content (right)
        self._main_pane = tk.PanedWindow(
            self, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=5
        )
        self._main_pane.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Left nav panel
        nav = tk.Frame(self._main_pane)
        self._main_pane.add(nav, width=172)

        tk.Label(nav, text="SECTIONS", font=("Segoe UI", 9, "bold"),
                 fg=_GREY_TXT, anchor="w").pack(fill=tk.X, padx=8, pady=(6, 2))

        self._nav_list = tk.Listbox(
            nav,
            font=("Segoe UI", 10),
            selectmode=tk.SINGLE,
            activestyle="none",
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
            selectbackground=_BLUE,
            selectforeground="white",
            state=tk.DISABLED,
        )
        for label, *_ in SECTIONS:
            self._nav_list.insert(tk.END, f"  {label}")
        self._nav_list.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 4))
        self._nav_list.bind("<<ListboxSelect>>", self._on_nav_select)

        # Right content panel
        self._content = tk.Frame(self._main_pane)
        self._main_pane.add(self._content)

        # Start with progress log visible
        self._show_log()

    # ── Log area (shown during scan) ─────────────────────────────────────────

    def _show_log(self) -> None:
        for w in self._content.winfo_children():
            w.destroy()
        self._log_widget = None

        frame, t = _scrolled(
            self._content, tk.Text,
            font=("Courier New", 10), wrap=tk.NONE, bg="#f8f9fa",
            relief=tk.FLAT, state=tk.DISABLED,
        )
        t.tag_configure("dim", foreground=_GREY_TXT)
        t.tag_configure("ok",  foreground=_GREEN_DK)
        t.tag_configure("err", foreground=_RED)
        frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self._log_widget = t

    def _log(self, text: str, tag: str = "") -> None:
        t = self._log_widget
        if t is None:
            return
        t.config(state=tk.NORMAL)
        t.insert(tk.END, text, tag) if tag else t.insert(tk.END, text)
        t.see(tk.END)
        t.config(state=tk.DISABLED)

    # ── Section display ───────────────────────────────────────────────────────

    def _on_nav_select(self, _event=None) -> None:
        sel = self._nav_list.curselection()
        if sel and self._data:
            self._show_section(sel[0])

    def _show_section(self, idx: int) -> None:
        _, data_key, renderer_key, kw = SECTIONS[idx]

        for w in self._content.winfo_children():
            w.destroy()
        self._log_widget = None

        if renderer_key == "overview":
            render_overview(self._content, self._data)
            return

        default = [] if renderer_key == "list" else {}
        data = self._data.get(data_key, default)

        # Show error banner if this section failed
        if isinstance(data, dict) and list(data.keys()) == ["error"]:
            render_error(self._content, data["error"])
            return

        if renderer_key == "kv":
            render_kv(self._content, data if isinstance(data, dict) else {})
        elif renderer_key == "tools":
            render_tools(self._content, data if isinstance(data, dict) else {})
        elif renderer_key == "list":
            render_list(self._content, data if isinstance(data, list) else [])
        elif renderer_key == "mixed":
            render_mixed(self._content, data if isinstance(data, dict) else {}, kw.get("long_keys", set()))
        elif renderer_key == "packages":
            render_packages(self._content, data if isinstance(data, dict) else {})

    # ── Scan lifecycle ────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        self._run_btn.config(state=tk.DISABLED)
        self._safe_chk.config(state=tk.DISABLED)
        self._export_btn.config(state=tk.DISABLED)
        self._nav_list.config(state=tk.DISABLED)
        self._prog["value"] = 0
        self._prog_label["text"] = ""
        self._data = {}
        self._markdown = ""

        self._show_log()
        mode = "SAFE" if self._safe_var.get() else "FULL"
        self._log(f"Starting {mode} MODE scan…\n\n", "dim")
        self._status_var.set(f"Scanning [{mode} MODE]…")

        self._worker = ScanWorker(safe=self._safe_var.get(), q=self._q)
        self._worker.start()
        self.after(POLL_MS, self._poll)

    def _poll(self) -> None:
        try:
            while True:
                msg = self._q.get_nowait()
                if isinstance(msg, ProgressMsg):
                    self._prog_label["text"] = f"{msg.step}/{msg.total}  —  {msg.label}"
                    self._status_var.set(f"Scanning — {msg.step}/{msg.total}: {msg.label}")
                    self._log(f"  [{msg.step}/{msg.total}] {msg.label}… ", "dim")
                elif isinstance(msg, StepDoneMsg):
                    self._prog["value"] += 1
                    if msg.ok:
                        self._log("done\n", "ok")
                    else:
                        self._log(f"ERROR: {msg.error}\n", "err")
                elif isinstance(msg, ResultMsg):
                    self._on_result(msg)
                    return
        except queue.Empty:
            pass
        self.after(POLL_MS, self._poll)

    def _on_result(self, msg: ResultMsg) -> None:
        self._data     = msg.data
        self._markdown = msg.markdown
        self._prog["value"] = 10
        self._prog_label["text"] = "10/10  —  Complete"

        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mode = "SAFE" if msg.safe else "FULL"
        self._status_var.set(
            f"Scan complete [{mode} MODE]  —  {ts}  |  {msg.md_path.name}"
        )

        self._nav_list.config(state=tk.NORMAL)
        self._nav_list.selection_clear(0, tk.END)
        self._nav_list.selection_set(0)
        self._show_section(0)

        self._run_btn.config(state=tk.NORMAL)
        self._safe_chk.config(state=tk.NORMAL)
        self._export_btn.config(state=tk.NORMAL)

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export Scan Report",
            defaultextension=".md",
            filetypes=[
                ("Markdown", "*.md"),
                ("JSON",     "*.json"),
                ("All files","*.*"),
            ],
        )
        if not path:
            return
        try:
            content = (
                json.dumps(self._data, indent=2, default=str)
                if path.endswith(".json")
                else self._markdown
            )
            Path(path).write_text(content, encoding="utf-8")
            messagebox.showinfo("Export complete", f"Report saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()
