"""envscan.ps1 parity with the envscan.js security-review fixes, in FullLanguage and
ConstrainedLanguage (the library may only use what CLM and PS 2.0 syntax allow):

- M2: Get-EsSystemTool and the child cwd come from [Environment]::SystemDirectory, never from
  $env:SystemRoot / SystemDrive / windir; an untrusted Windows folder refuses batch files and temp.
- L2: Get-EsRefusedFolder / Get-EsPathLinkReason refuse a path in or below a credential store, so
  PSModulePath, PATH, JAVA_HOME and the cwd pointing into ~/.ssh are never listed, read or written;
  Get-EsDefaultOutputParents and Get-EsCandidateDirs skip them.
- L3: Initialize-EsTemp refuses a TEMP on a mapped network drive (drives are initialized first).

The cases run in one PowerShell process per mode; Get-Item, Get-ChildItem, Get-Content and
Test-Path are wrapped (in a child scope, as in tests/ps/link_cases.ps1) to record every path the
library touches.
"""
from __future__ import annotations

import ctypes
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import ps_command, ps_quote, requires_powershell

pytestmark = [pytest.mark.integration, requires_powershell]

MODES = ("FullLanguage", "ConstrainedLanguage")

CASES = r"""
param([string]$Lib, [string]$Scratch)
. $Lib
Initialize-EsRedaction
$out = @{}
$ssh = Join-Path $Scratch 'home\.ssh'
$null = New-Item -ItemType Directory -Path (Join-Path $ssh 'Modules\CanaryModZ\1.0') -Force
$null = New-Item -ItemType Directory -Path (Join-Path $ssh 'bin') -Force
$null = New-Item -ItemType Directory -Path (Join-Path $ssh 'jdk\bin') -Force
Set-Content -LiteralPath (Join-Path $ssh 'config') -Value 'Host canaryhostz' -Encoding Ascii
Set-Content -LiteralPath (Join-Path $ssh 'jdk\release') -Value 'JAVA_VERSION="99.canary"' -Encoding Ascii
$batch = Join-Path $Scratch 'hello.cmd'
Set-Content -LiteralPath $batch -Value '@echo hi' -Encoding Ascii

# ---- M2: the environment does not choose the Windows folder
$saved = @{ SystemRoot = $env:SystemRoot; SystemDrive = $env:SystemDrive; windir = $env:windir }
$env:SystemRoot = Join-Path $Scratch 'fakeroot'
$env:windir = $env:SystemRoot
$env:SystemDrive = 'Q:'
$script:ES_WINDOWS_DIR = $null
Initialize-EsDrives
Initialize-EsTemp
$out.tool = Get-EsSystemTool 'cmd.exe'
$out.cwd = $script:ES_CHILD_CWD
$run = Invoke-EsCommand -FilePath $out.tool -Arguments @('/d', '/c', 'cd')
$out.cd = ([string]$run.stdout).Trim()
$out.cd_error = $run.error
$out.batch_ok = (Invoke-EsCommand -FilePath $batch).stdout
$env:SystemRoot = $saved.SystemRoot
$env:windir = $saved.windir
$env:SystemDrive = $saved.SystemDrive

$script:ES_NETWORK_DRIVES = @('Z:')
$fakes = @()
foreach ($fake in @('\\host\share\Windows', 'C:Windows', 'Z:\Windows', '', 'C:\', ($ssh + '\Windows'))) {
    $script:ES_WINDOWS_DIR = $fake
    $temp = 'created'
    $keep = $script:ES_TMP
    try { Initialize-EsTemp } catch { $temp = $_.Exception.Message }
    $script:ES_TMP = $keep
    $fakes += @{ fake = $fake; tool = (Get-EsSystemTool 'cmd.exe'); batch = (Invoke-EsCommand -FilePath $batch).error; temp = $temp }
}
$out.fakes = $fakes
$script:ES_WINDOWS_DIR = $null

# ---- L3: a TEMP on a mapped network drive
$savedTemp = $env:TEMP
$env:TEMP = 'Z:\Temp'
$keep = $script:ES_TMP
$out.network_temp = 'created'
try { Initialize-EsTemp } catch { $out.network_temp = $_.Exception.Message }
$env:TEMP = Join-Path $ssh 'tmp'
$out.ssh_temp = 'created'
try { Initialize-EsTemp } catch { $out.ssh_temp = $_.Exception.Message }
$env:TEMP = $savedTemp
$script:ES_TMP = $keep
$script:ES_NETWORK_DRIVES = @()

# ---- L2: credential stores
$env:PSModulePath = Join-Path $ssh 'Modules'
$env:Path = (Join-Path $ssh 'bin') + ';' + $env:Path
$env:JAVA_HOME = Join-Path $ssh 'jdk'
Save-EsEnvSnapshot
$script:ES_PATH_DIRS = $null
$script:ES_LINK_CACHE = @{}
$script:Touched = @()
$config = Join-Path $ssh 'config'
Set-Location -LiteralPath $ssh
& {
    function Get-Item { param([string]$Path, [string]$LiteralPath, [switch]$Force, $ErrorAction = 'Continue')
        $script:Touched += ('item|' + $LiteralPath + $Path)
        if ($LiteralPath) { return (Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force -ErrorAction $ErrorAction) }
        Microsoft.PowerShell.Management\Get-Item -Path $Path -Force:$Force -ErrorAction $ErrorAction }
    function Get-Content { param([string]$LiteralPath, [int]$TotalCount = -1, $Encoding = $null, $ErrorAction = 'Continue')
        $script:Touched += ('read|' + $LiteralPath)
        $more = @{}
        if ($Encoding) { $more['Encoding'] = $Encoding }
        Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -TotalCount $TotalCount -ErrorAction $ErrorAction @more }
    function Get-ChildItem { param([string]$LiteralPath, [switch]$Force, [switch]$Name, $ErrorAction = 'Continue')
        $script:Touched += ('list|' + $LiteralPath)
        Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force:$Force -Name:$Name -ErrorAction $ErrorAction }
    function Test-Path { param([string]$LiteralPath, $PathType = 'Any')
        $script:Touched += ('test|' + $LiteralPath)
        Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType }
    $refused = Get-EsRefusedFolder $config
    $out.refused_path = $refused.path
    $out.refused_reason = $refused.reason
    $out.link = Get-EsPathLinkReason $config
    $out.safe = Test-EsSafePath $ssh 'Container'
    $out.read = (Read-EsTextFile $config).error
    $out.entries = @(Get-EsDirEntries $ssh).Count
    $listed = New-EsResult
    $out.listable = Test-EsListableFolder $listed (Join-Path $ssh 'Modules')
    $out.listed_notes = @($listed.notes)
    $modules = New-EsResult
    $out.mods = @(Get-EsModulePackages $modules)
    $out.module_notes = @($modules.notes)
    $out.path_dirs = @(Get-EsPathDirs)
    $out.parents = @(Get-EsDefaultOutputParents)
    $out.ids = @(Get-EsCandidateDirs | ForEach-Object { $_.id })
    $java = probe_runtime_java
    $out.java = ConvertTo-EsJson $java.data
}
Set-Location -LiteralPath $Scratch
$out.touched = @($script:Touched)
Remove-EsTemp
$out.language_mode = [string]$ExecutionContext.SessionState.LanguageMode
ConvertTo-EsJson $out
"""


def windows_dir() -> str:
    buffer = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, 260)
    return buffer.value


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    mode = request.param
    scratch = tmp_path_factory.mktemp(f"psreview-{mode}")
    cases = scratch / "review_cases.ps1"
    cases.write_text(CASES, encoding="ascii")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != "FullLanguage" else ""
    proc = ps_command(f"{prefix}& {ps_quote(cases)} -Lib {ps_quote(lib)} -Scratch {ps_quote(scratch)}",
                      timeout=600, cwd=scratch)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    data = json.loads(proc.stdout)
    assert data["language_mode"] == mode
    data["scratch"] = str(scratch)
    return data


def test_system_tool_and_child_cwd_ignore_the_environment(results: dict[str, Any]) -> None:
    assert results["tool"].lower() == str(Path(windows_dir()) / "System32" / "cmd.exe").lower()
    assert results["cwd"].lower() == windows_dir()[:2].lower() + "\\"
    assert results["cd_error"] is None and results["cd"].lower() == results["cwd"].lower()
    assert results["batch_ok"].strip() == "hi"


def test_untrusted_windows_folder_refuses_batch_files_and_temp(results: dict[str, Any]) -> None:
    assert len(results["fakes"]) == 6
    for case in results["fakes"]:
        assert case["tool"] is None, case
        assert case["batch"].startswith("not run"), case
        assert "Windows folder" in case["temp"], case


def test_temp_on_a_network_drive_or_in_a_credential_store_is_refused(results: dict[str, Any]) -> None:
    assert "no usable TEMP folder" in results["network_temp"]
    assert "credential store" in results["ssh_temp"]
    assert not (Path(results["scratch"]) / "home" / ".ssh" / "tmp").exists()


def test_credential_store_paths_are_refused_by_the_guards(results: dict[str, Any]) -> None:
    ssh = str(Path(results["scratch"]) / "home" / ".ssh")
    assert results["refused_path"] == ssh and results["refused_reason"] == "credential store"
    assert results["link"] == "credential store"
    assert results["safe"] is False and results["read"] == "credential store" and results["entries"] == 0
    assert results["listable"] is False and f"{ssh} not read: credential store" in results["listed_notes"]
    assert results["mods"] == [] and f"{ssh} not read: credential store" in results["module_notes"]


def test_path_psmodulepath_java_home_and_cwd_in_a_store_are_never_touched(results: dict[str, Any]) -> None:
    assert not [d for d in results["path_dirs"] if ".ssh" in d.lower()]
    assert not [p for p in results["parents"] if ".ssh" in p.lower()]
    assert "cwd" not in results["ids"]
    assert "canary" not in results["java"].lower()
    assert results["touched"], "the wrappers recorded nothing"
    touched = [t for t in results["touched"] if ".ssh" in t.lower()]
    assert touched == [], touched
