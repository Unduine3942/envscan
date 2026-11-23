"""Integration tests for envscan.cmd: the PowerShell launcher and the cmd.exe fallback collector.

envscan.cmd is assembled straight from src/cmd (independent of the other build targets) and
copied next to a stub envscan.ps1 that records how it was started. The dev box execution
policy is Restricted, so pass-through runs set PSExecutionPolicyPreference (the Process scope
a caller may set for its own child; envscan.cmd itself never adds -ExecutionPolicy).
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import pytest

import target_cmd
from conftest import (CANARY_VALUES, CMD32, PORTABLE, POWERSHELL, SECRET_CANARIES, all_output_text, canary_hits,
                      expected_probe_listing, find_output, scrubbed_env)
from spec import load_spec, validate_spec

LOG = logging.getLogger(__name__)
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name != "nt", reason="envscan.cmd needs cmd.exe"),
]

CMD = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe")
FAKE_FOLDER = r"C:\fake\envscan-output-folder"
STUB = r"""# envscan.ps1 test stub: records how envscan.cmd started it, exits with STUB_EXIT.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lines = @('argc=' + $args.Count)
foreach ($a in $args) { $lines += ('arg=[' + $a + ']') }
$lines += ('arch=' + $env:PROCESSOR_ARCHITECTURE)
$lines += ('cwd=' + (Get-Location).Path)
$names = @(Get-ChildItem env: | Where-Object { $_.Name -like '__ES_*' } | ForEach-Object { $_.Name })
$lines += ('es_vars=' + ($names -join ','))
$lines += ('ps_telemetry_optout=[' + $env:POWERSHELL_TELEMETRY_OPTOUT + ']')
$lines += ('ps_updatecheck=[' + $env:POWERSHELL_UPDATECHECK + ']')
$lines += ('tmp=[' + $env:TMP + ']')
Set-Content -LiteralPath (Join-Path $here 'stub-record.txt') -Value $lines -Encoding ASCII
[Console]::Error.WriteLine('stub stderr line')
Write-Output 'C:\fake\envscan-output-folder'
exit ([int]$env:STUB_EXIT)
"""
# Never inherited from the developer's shell: they change the launcher's decision.
CONTROLLED_ENV = ("PSEXECUTIONPOLICYPREFERENCE", "ENVSCAN_TEST_POLICY", "STUB_EXIT")
ALLOW_PROCESS_SCOPE = {"PSExecutionPolicyPreference": "RemoteSigned"}

# The fallback's own redaction, one or more canaries per rule of spec/redaction.toml:
# name -> (value, how env.vars must print it). Whole-value replacement is allowed wherever
# batch cannot find where a secret ends; URL and bare userinfo passwords are cut out exactly.
R = "<redacted>"
SECRET_CASES = {
    # NAME RULES: segment, contains, name suffix, camelCase boundaries
    "ENVSCAN_AUTH": ("canary-segment-auth-5522", R),
    "MYSECRETVALUE": ("canary-contains-4411", R),
    "ENVSCAN_DBPW": ("canary-suffix-pw-1a", R),
    "ENVSCAN_dbPin": ("canary-camel-1d", R),
    # private key, auth schemes, token prefixes, conda tokens
    "ENVSCAN_PEM": ("-----BEGIN PRIVATE KEY-----canary-pem-material", "<redacted: private key>"),
    "ENVSCAN_BEARER_HDR": ("Bearer canary-bearer-c0ffee12", R),
    "ENVSCAN_BASIC": ("Basic canary-basic-8a", R),
    "ENVSCAN_PLAIN_JWT": ("eyJhbGciOiJIUzI1NiJ9.canaryjwtpayload0123456789.sig", R),
    "ENVSCAN_PLAIN_GH": ("note ghp_canaryBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", R),
    "ENVSCAN_PADDED": ("AKIACANARY12345678==", R),
    "ENVSCAN_CONDA": ("https://conda.example/t/canary-conda-9a/main", R),
    # pair keys (exact_exceptions do not protect Pwd= inside a value)
    "ENVSCAN_CONNECTION": ("Server=db;Uid=u;Pwd=canary-pair-2a;", R),
    "ENVSCAN_AZURE": ("DefaultEndpointsProtocol=https;AccountName=a;AccountKey=canary-pair-2b;EndpointSuffix=x", R),
    # secret keys inside values (= and :, quoted keys, camelCase keys, query strings)
    "MAVEN_OPTS": ("-Xmx1g -Dhttp.proxyPassword=canary-maven-3a", R),
    "JAVA_TOOL_OPTIONS": ("-Djavax.net.ssl.trustStorePassword=canary-jto-3b", R),
    "GRADLE_OPTS": ("-Dorg.gradle.jvmargs=-Xmx2g -Dsystemprop.https.proxyPassword=canary-gradle-3c", R),
    "ENVSCAN_JSON": ('{"apiKey": "canary-json-3d"}', R),
    "ENVSCAN_YAMLISH": ("client_secret: canary-yaml-3e", R),
    "ENVSCAN_KV_CAMEL": ("mode=1;userPass=canary-kvcamel-3f", R),
    "ENVSCAN_BLOB": ("https://acct.blob.core.windows.net/c/x?sv=2022-11-02&sig=canary-sig-6a&se=2030", R),
    "ENVSCAN_CALLBACK": ("https://h.example/cb?x=1&access_token=canary-qs-6b", R),
    "ENVSCAN_QTOKEN": ("https://h.example/?token=canary-qs-6c", R),
    # command-line options
    "ENVSCAN_CMD_TOKEN": ("tool.exe --token canary-opt-7a --verbose", R),
    "ENVSCAN_CMD_SLASH": ("setup.exe /password:canary-opt-7b /quiet", R),
    "ENVSCAN_CMD_USER": ("curl -u bob:canary-opt-7c https://x.example", R),
    "ENVSCAN_CMD_HDR": ('curl -H "X-Session-Id: canary-opt-7d" https://x.example', R),
    "ENVSCAN_CMD_PASSFILE": ("tool --keystorepass canary-opt-7e", R),
    # tool options: a tool's own password option, attached or separate, after the tool's name
    "ENVSCAN_MYSQL_CMD": ("mysql -u root -pcanary-tool-8a appdb", R),
    "ENVSCAN_SCHTASKS_CMD": ("schtasks /create /tn t /tr x.exe /ru u /rp canary-tool-8b", R),
    "ENVSCAN_SSHPASS_CMD": ('"C:\\tools\\sshpass.exe" -p canary-tool-8c ssh h', R),
    "ENVSCAN_REDIS_CMD": ("cmd /c redis-cli.exe -h r -a canary-tool-8d ping", R),
    # name suffix PASS
    "SSHPASS": ("canary-sshpass-8e", R),
    "ENVSCAN_DBPASS": ("canary-dbpass-8f", R),
    # URL userinfo (password to the LAST @, token as user name) and bare user:password@host
    "ENVSCAN_DB_URL": ("postgres://dbuser:canary-dburl-pw-6e1d@db.corp.example:5432/app",
                       "postgres://dbuser:<redacted>@db.corp.example:5432/app"),
    "ENVSCAN_URL_AT": ("https://user:p@ss-canary-at-7a@host.example/x", "https://user:<redacted>@host.example/x"),
    "ENVSCAN_URL_SEMI": ("http://u:pa;ss-canary-5c@h1/x", "http://u:<redacted>@h1/x"),
    "ENVSCAN_URL_EMPTYHOST": ("http://user:canary-emptyhost-pw-8b@", "http://user:<redacted>@"),
    "ENVSCAN_GIT_REMOTE": ("https://canary5tokenuser0123456789abcdef01234567@github.com/org/repo.git",
                           "https://<redacted>@github.com/org/repo.git"),
    "HTTPS_PROXY": ("proxyuser:canary-bare-4a@proxy.corp.example:8080", "proxyuser:<redacted>@proxy.corp.example:8080"),
    # Scheme-less user:password@host anywhere in a value (shared with the ps1 and sh rules):
    # only the password is cut out; DOMAIN\user keeps its backslash; an "@" inside the password
    # extends it to the next "@" when the first one is not followed by a host.
    "ENVSCAN_UI_WORDS": ("--proxy bob:canary-ui-1a@proxy.corp:3128 --x", f"--proxy bob:{R}@proxy.corp:3128 --x"),
    "ENVSCAN_UI_DOMAIN": ("CORP\\jdoe:canary-ui-1b@proxy.corp:8080", f"CORP\\jdoe:{R}@proxy.corp:8080"),
    "ENVSCAN_UI_CURL": ("curl -x bob:canary-ui-1c@proxy:3128 https://x", f"curl -x bob:{R}@proxy:3128 https://x"),
    "ENVSCAN_UI_CURL_DOMAIN": ("curl -x CORP\\jdoe:canary-ui-1d@proxy.corp:8080 https://x",
                               f"curl -x CORP\\jdoe:{R}@proxy.corp:8080 https://x"),
    "ENVSCAN_UI_TEXT": ("use bob:canary-ui-1e@proxy.corp:3128 now", f"use bob:{R}@proxy.corp:3128 now"),
    "ENVSCAN_UI_QUOTED": ('proxy = "bob:canary-ui-1f@proxy.corp:3128"', f'proxy = "bob:{R}@proxy.corp:3128"'),
    "ENVSCAN_UI_LINE": ("proxy = bob:canary-ui-1g@proxy.corp:3128", f"proxy = bob:{R}@proxy.corp:3128"),
    "ENVSCAN_UI_AT_INSIDE": ("x user:canary-ui-1h@canary-ui-1i@proxy:8080 y", f"x user:{R}@proxy:8080 y"),
    "ENVSCAN_UI_TERMINATOR": ("a u:canary-ui-1j@h.example;next", f"a u:{R}@h.example;next"),
    "ENVSCAN_UI_IPV6": ("u:canary-ui-1k@[fd00::1]:8080 x", f"u:{R}@[fd00::1]:8080 x"),
    "ENVSCAN_UI_IPV6_PATH": ("u:canary-ui-1n@[::1]:80/x", f"u:{R}@[::1]:80/x"),
    "ENVSCAN_UI_IPV6_NOPORT": ("u:canary-ui-1o@[fd00::1] y", f"u:{R}@[fd00::1] y"),
    # Second review: a user name with "@" (UPN), and # ? \ after the host (tests/test_ps_redaction.py
    # userinfo_upn_user, userinfo_then_fragment, userinfo_then_query, userinfo_then_backslash).
    "ENVSCAN_UI_UPN": ("john.doe@corp.com:canary-ui-2a@proxy.corp:8080", f"john.doe@corp.com:{R}@proxy.corp:8080"),
    "ENVSCAN_UI_FRAGMENT": ("jdoe:canary-ui-2b@proxy.corp#frag", f"jdoe:{R}@proxy.corp#frag"),
    "ENVSCAN_UI_QUERY": ("jdoe:canary-ui-2c@proxy.corp?x=1", f"jdoe:{R}@proxy.corp?x=1"),
    "ENVSCAN_UI_BACKSLASH": ("jdoe:canary-ui-2d@proxy.corp\\share", f"jdoe:{R}@proxy.corp\\share"),
    "ENVSCAN_UI_UPN_CMD": ("curl -x john.doe@corp.com:canary-ui-2e@proxy.corp:8080 https://x",
                           f"curl -x john.doe@corp.com:{R}@proxy.corp:8080 https://x"),
    # JSON with escaped quotes inside a value or a command line: the fallback replaces it whole.
    "ENVSCAN_CFG_JSON": ('{\\"password\\":\\"canary-esc-3a\\"}', R),
    "ENVSCAN_DOCKER_CMD": ('docker run -e CFG="{\\"password\\":\\"canary-esc-3b\\"}" img', R),
    "ENVSCAN_CFG_LINE": ('CFG={\\"user\\":\\"bob\\",\\"password\\":\\"canary-esc-3c\\"}', R),
    "ENVSCAN_UI_TWICE": ("a:canary-ui-1l@h1 b:canary-ui-1m@h2", f"a:{R}@h1 b:{R}@h2"),
    # Lists of user:password@host joined by ; or , (test_ps_redaction.py userinfo_list_semicolon,
    # userinfo_list_comma): every password is cut out, not only the first.
    "ENVSCAN_UI_LIST_SEMI": ("http=svc:canary-ui-3a@proxy.corp:80;https=svc:canary-ui-3b@proxy.corp:80",
                             f"http=svc:{R}@proxy.corp:80;https=svc:{R}@proxy.corp:80"),
    "ENVSCAN_UI_LIST_COMMA": ("u:canary-ui-3c@h1:80,u:canary-ui-3d@h2:80", f"u:{R}@h1:80,u:{R}@h2:80"),
    "ENVSCAN_UI_LIST_SAMEHOST": ("u:canary-ui-3e@h;u:canary-ui-3f@h", f"u:{R}@h;u:{R}@h"),
    "ENVSCAN_UI_LIST_THREE": ("a:canary-ui-3g@h1,b:canary-ui-3h@h2;c:canary-ui-3i@h3",
                              f"a:{R}@h1,b:{R}@h2;c:{R}@h3"),
    # tool options of spec/redaction.toml (a tool name may start with a digit) and curl's attached -u
    "ENVSCAN_DOCKER_LOGIN": ("docker login -u bob -p canary-tool-9a registry.example", R),
    "ENVSCAN_PODMAN_LOGIN": ("podman login -u bob -pcanary-tool-9b quay.example", R),
    "ENVSCAN_OC_LOGIN": ("oc login -u bob -p canary-tool-9c https://api.example:6443", R),
    "ENVSCAN_TWINE_CMD": ("twine upload -u bob -p canary-tool-9d dist/*", R),
    "ENVSCAN_7Z_CMD": ("7z x -pcanary-tool-9e a.7z", R),
    "ENVSCAN_7ZA_CMD": ('"C:\\Program Files\\7-Zip\\7za.exe" a -pcanary-tool-9f out.7z in', R),
    "ENVSCAN_RAR_CMD": ("rar a -pcanary-tool-9g out.rar in", R),
    "ENVSCAN_UNRAR_CMD": ("unrar x -pcanary-tool-9h in.rar", R),
    "ENVSCAN_ZIP_CMD": ("zip -P canary-tool-9i out.zip in", R),
    "ENVSCAN_UNZIP_CMD": ("unzip -P canary-tool-9j in.zip", R),
    "ENVSCAN_SIGNTOOL_CMD": ("signtool sign /f c.pfx /p canary-tool-9k x.exe", R),
    "ENVSCAN_CERTUTIL_CMD": ("certutil -p canary-tool-9l -importpfx c.pfx", R),
    "ENVSCAN_XFREERDP_CMD": ("xfreerdp /u:bob /p:canary-tool-9m /v:host", R),
    "ENVSCAN_RDESKTOP_CMD": ("rdesktop -u bob -p canary-tool-9n host", R),
    "ENVSCAN_SSHKEYGEN_CMD": ("ssh-keygen -t ed25519 -N canary-tool-9o -f k", R),
    "ENVSCAN_CURL_ATTACHED": ("curl -ubob:canary-opt-7f https://x.example", R),
    # option words of spec/redaction.toml
    "ENVSCAN_OPT_COOKIE": ("app --cookie canary-opt-7g", R),
    "ENVSCAN_OPT_JWT": ("app --jwt=canary-opt-7h", R),
    "ENVSCAN_OPT_OTP": ("app -otp canary-opt-7i", R),
    "ENVSCAN_OPT_PIN": ("app /pin:canary-opt-7j", R),
    "ENVSCAN_OPT_DSN": ("app --dsn canary-opt-7k", R),
    "ENVSCAN_OPT_SAS": ("app --sas canary-opt-7l", R),
    "ENVSCAN_OPT_CONNSTR": ("app --connstr canary-opt-7m", R),
    "ENVSCAN_OPT_CREDS": ("app --creds canary-opt-7n", R),
    # Values that only start with the placeholder, escaped quotes, keys and names ending in
    # AUTHORIZATION (parity cases of tests/test_ps_redaction.py): the fallback replaces them whole.
    "ENVSCAN_PH_PREFIX": (f"password={R}canary-phprefix-2a", R),
    "ENVSCAN_TOKEN_REST": (f"password=ghp_{'A' * 36}!canary-rest-2b", R),
    "ENVSCAN_COLON_TOKEN": (f"password=canary-colon-2c:ghp_{'B' * 36}", R),
    "ENVSCAN_JSON_ESCAPED": ('{"password":"abc\\"canary-jsonesc-2d"}', R),
    "ENVSCAN_JSON_ESCAPED2": ('{"password": "a\\"b\\"canary-jsonesc-2e", "x": 1}', R),
    "ENVSCAN_PROXY_AUTHZ": ('"proxy_authorization": "canary-pauthz-2f"', R),
    "ENVSCAN_ENV_AUTHZ": ("env HTTP_AUTHORIZATION=canary-authz-2g app", R),
    "ENVSCAN_CONN_TOKEN_REST": (f"app Server=x;Password=ghp_{'C' * 36}!canary-rest-2h", R),
    "HTTP_AUTHORIZATION": ("canary-name-authz-2i", R),
    "PROXY_AUTHORIZATION": ("canary-name-pauthz-2j", R),
}
EXTRA_SECRETS = {name: value for name, (value, _) in SECRET_CASES.items()}
EXTRA_CANARIES = tuple(m for value in EXTRA_SECRETS.values() for m in re.findall(r"(?i)canary[a-z0-9-]*", value))
# Must survive unredacted and unmangled.
PLAIN = {
    "ENVSCAN_SPECIAL": "a&b|c<d>e!f%g^h (x) \"q\"",
    "ENVSCAN_TOKEN_PATH": r"C:\tokens\not-secret",
    "ENVSCAN_AUTH_METHOD": "plain-auth-method",
    "ENVSCAN_TOKEN_TYPE": "plain-token-type",
    "OLDPWD": r"C:\plain\oldpwd",
    "KEY": "plain-key-value",
    "AUTHOR": "plain-author-value",
    "KEYBOARD_LAYOUT": "plain-keyboard-value",
    "ENVSCAN_TZ": "Asia/Seoul",
    "ENVSCAN_TIME": "12:30:45",
    "ENVSCAN_REPO_URL": "https://repo.corp.example/a@b",
    "ENVSCAN_URL_NOUSER": "http://@host.example/",
    "ENVSCAN_SHORT_USER_URL": "https://u@h.example/",
    "ENVSCAN_URL_END": "see http://",
    "ENVSCAN_EMAIL": "firstname.lastname.longer@corp.example.com",
    "ENVSCAN_WORDPREFIX": "xghp_notatoken0123456789abcdefgh",
    "ENVSCAN_SHORT_PREFIX": "ghp_short",
    "ENVSCAN_BASICWORD": "basic mode",
    "ENVSCAN_UNIXPATH": "/mingw64/bin/git-askpass.exe",
    "ENVSCAN_PLAINCMD": "python -u script.py --verbose",
    "GIT_ASKPASS": r"C:\tools\askpass.exe",
    # tool options are case-sensitive for "-" (mysql -P is the port) and need the tool's name
    "ENVSCAN_MYSQL_PORT": "mysql -P 3306 -h db.example",
    "ENVSCAN_AZ_NOTOOL": "lazy -p 5",
    "ENVSCAN_7Z_NOTOOL": "a7z -p 5",
    # user@host:path, image digests and paths with "@" are no credentials.
    "ENVSCAN_SCP_TARGET": "scp f.txt deploy@build.corp:/srv/x",
    "ENVSCAN_IMAGE_DIGEST": "docker pull docker.io/library/alpine:3.18@sha256:" + "0" * 64,
    "ENVSCAN_BARE_DIGEST": "alpine:3.18@sha256:" + "ab" * 32,
    "ENVSCAN_GIT_SCP": "git@github.com:org/repo.git",
    "ENVSCAN_WIN_PATH_AT": "C:\\tools\\bin@2\\x.exe",
    "ENVSCAN_NODE_TYPES": "C:\\Users\\me\\node_modules\\@types",
    "ENVSCAN_PORT_TOO_LONG": "u:p@host:123456",
    "ENVSCAN_TWO_PORTS": "u:p@host:80:90",
    "ENVSCAN_IPV6_NOT_ENDED": "u:p@[fd00::1]x",
    "ENVSCAN_IPV6_PORT_TOO_LONG": "u:p@[fd00::1]:123456",
    "ENVSCAN_NO_HOST": "u:p@,host",
    "ENVSCAN_UPN_PORT": "see john.doe@corp.com:8080 now",  # test_ps_redaction.py upn_with_port_kept
}


@dataclass(frozen=True)
class Run:
    returncode: int
    stdout: str
    stderr: str
    bundle: Path
    work: Path
    temp: Path

    @property
    def record(self) -> str | None:
        path = self.bundle / "stub-record.txt"
        return path.read_text(encoding="ascii") if path.exists() else None

    @property
    def report(self) -> str:
        return (find_output(self.work) / "envscan-fallback.txt").read_text(encoding="utf-8", errors="replace")

    @property
    def stdout_lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]


@pytest.fixture(scope="session")
def cmd_script(tmp_path_factory: pytest.TempPathFactory) -> Path:
    spec = load_spec(PORTABLE / "spec")
    assert validate_spec(spec) == []
    text = target_cmd.assemble(spec, PORTABLE / "src" / "cmd")
    assert target_cmd.lint(text) == []
    path = tmp_path_factory.mktemp("cmd-build") / "envscan.cmd"
    path.write_bytes(text.encode("ascii"))
    return path


@pytest.fixture(scope="session")
def cmd_probe_ids() -> list[str]:
    return [p["id"] for p in load_spec(PORTABLE / "spec").probes_for("cmd")]


def _quote(arg: str) -> str:
    return f'"{arg}"' if any(ch in arg for ch in ' &()^|<>,;=') else arg


def run_cmd(script: Path, root: Path, args: Sequence[str] = (), *, env: Mapping[str, str] | None = None,
            stub: bool = True, exe: str = CMD, timeout: int = 900, raw: str | None = None,
            cwd: Path | None = None, invoke: str | None = None) -> Run:
    """Copy envscan.cmd (and the stub) into root/bundle and run it from root/work (or cwd).

    raw replaces args with a verbatim argument string (unquoted commas, empty "" arguments).
    invoke replaces the quoted full path of the script on the command line (e.g. a bare name
    that cmd.exe looks up on PATH)."""
    bundle, work, temp = root / "bundle", root / "work", root / "temp"
    for folder in (bundle, work, temp):
        folder.mkdir(parents=True, exist_ok=True)
    shutil.copy2(script, bundle / "envscan.cmd")
    if stub:
        (bundle / "envscan.ps1").write_text(STUB, encoding="ascii")
    overrides = {"TEMP": str(temp), "TMP": str(temp), **(env or {})}
    replaced = {name.upper() for name in overrides} | set(CONTROLLED_ENV)
    # Windows names ignore case: an override replaces the inherited variable whatever its case.
    environment = {k: v for k, v in scrubbed_env().items() if k.upper() not in replaced}
    environment.update(overrides)
    arguments = raw if raw is not None else " ".join(_quote(a) for a in args)
    target = invoke if invoke is not None else f'"{bundle / "envscan.cmd"}"'
    line = f'"{exe}" /d /s /c "{target} {arguments}"'
    proc = subprocess.run(line, capture_output=True, env=environment, cwd=cwd or work, timeout=timeout,
                          stdin=subprocess.DEVNULL)
    run = Run(proc.returncode, proc.stdout.decode("oem", "replace"), proc.stderr.decode("oem", "replace"),
              bundle, work, temp)
    LOG.info("envscan.cmd %s -> %s", args, proc.returncode)
    return run


@lru_cache(maxsize=1)
def effective_policy() -> str:
    environment = {k: v for k, v in os.environ.items() if k.upper() not in CONTROLLED_ENV}
    proc = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", "Get-ExecutionPolicy"],
                          capture_output=True, text=True, env=environment, stdin=subprocess.DEVNULL, timeout=120)
    return proc.stdout.strip()


def section(report: str, probe_id: str) -> str:
    match = re.search(rf"^=== probe: {re.escape(probe_id)} ===\n(.*?)^status: (\w+)$", report, re.M | re.S)
    assert match, f"no section for {probe_id}"
    return match.group(0)


def assert_no_secret(run: Run, values: Sequence[str]) -> None:
    texts = [run.stdout, run.stderr, *(all_output_text(folder) for folder in run.work.glob("envscan-*"))]
    assert canary_hits(texts, values) == [], "secrets leaked into the output"


# ------------------------------------------------------------------ launcher

@pytest.mark.parametrize("code", [0, 1, 2])
def test_passthrough_forwards_arguments_cwd_and_exit_code(cmd_script: Path, tmp_path: Path, code: int) -> None:
    out_dir = str(tmp_path / "out dir")
    run = run_cmd(cmd_script, tmp_path, ["--deep", "--out", out_dir, "--only", "env.*"],
                  env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": str(code)})
    assert run.returncode == code, run.stderr
    record = run.record
    assert record is not None, f"stub did not run: {run.stderr}"
    assert "argc=5" in record
    assert f"arg=[--deep]\narg=[--out]\narg=[{out_dir}]\narg=[--only]\narg=[env.*]" in record
    assert f"cwd={run.work}" in record
    assert "es_vars=\n" in record, "launcher variables leaked into PowerShell"
    assert run.stdout_lines == [FAKE_FOLDER]
    assert "stub stderr line" in run.stderr
    assert list(run.temp.iterdir()) == [], "temporary error file was not deleted"
    assert not list(run.work.glob("envscan-*")), "fallback must not run when PowerShell succeeded"


@pytest.mark.skipif(not Path(CMD32).exists(), reason="no 32-bit cmd.exe on this system")
def test_32bit_cmd_relaunches_in_64bit_cmd(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--net"], env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "2"}, exe=CMD32)
    assert run.returncode == 2, run.stderr
    record = run.record or ""
    assert "arg=[--net]" in record
    assert "arch=x86" not in record and "arch=" in record
    assert "es_vars=\n" in record


# Run after envscan.cmd on the same command line: what the caller's session holds afterwards.
CALLER_VIEW = "& set POWERSHELL_ & set TMP"


def caller_lines(run: Run, name: str) -> list[str]:
    return [line for line in run.stdout_lines if line.upper().startswith(name.upper() + "=")]


@pytest.mark.parametrize("capture", [True, False], ids=["capture-file", "no-temp-folder"])
def test_powershell_starts_without_telemetry_or_update_check(cmd_script: Path, tmp_path: Path, capture: bool) -> None:
    """pwsh contacts Microsoft at startup unless these are set; the caller's session keeps its own."""
    env = {**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0", "POWERSHELL_UPDATECHECK": "LTS",
           "POWERSHELL_TELEMETRY_OPTOUT": "0"}
    if not capture:  # neither TEMP nor TMP nor LOCALAPPDATA\Temp is the user's own: no capture file
        env.update({"TEMP": "C:\\", "TMP": "C:\\", "LOCALAPPDATA": "C:\\"})
    run = run_cmd(cmd_script, tmp_path, [], env=env, raw="--net " + CALLER_VIEW)
    record = run.record or ""
    assert "ps_telemetry_optout=[1]\n" in record and "ps_updatecheck=[Off]\n" in record, record
    assert run.stdout_lines[0] == FAKE_FOLDER, run.stderr
    assert caller_lines(run, "POWERSHELL_TELEMETRY_OPTOUT") == ["POWERSHELL_TELEMETRY_OPTOUT=0"]
    assert caller_lines(run, "POWERSHELL_UPDATECHECK") == ["POWERSHELL_UPDATECHECK=LTS"]
    assert caller_lines(run, "TMP") == [f"TMP={env.get('TMP', run.temp)}"]


@pytest.mark.parametrize("tmp", ["C:\\" + "t" * 300, "&mkdir x&rem " + "u" * 300],
                         ids=["long-absolute", "long-relative"])
@pytest.mark.parametrize("mode", ["launch", "fallback"])
def test_temp_path_too_long_for_windows_never_hangs(cmd_script: Path, tmp_path: Path, tmp: str, mode: str) -> None:
    """A TMP (or TEMP, when TMP is not set) over MAX_PATH makes every FOR /F command and Windows
    PowerShell spin forever; the script and PowerShell get a short TMP of their own."""
    env = {**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0", "TMP": tmp}
    args = "--net" if mode == "launch" else "--fallback --only session.context,os.identity"
    run = run_cmd(cmd_script, tmp_path, [], env=env, raw=args + " " + CALLER_VIEW, timeout=120)
    assert caller_lines(run, "TMP") == [f"TMP={tmp}"], "the caller's TMP must be left unchanged"
    assert not (run.work / "x").exists()
    if mode == "launch":
        record = run.record or ""
        assert f"tmp=[{run.temp}]\n" in record, record
    else:
        assert "status: ok" in section(run.report, "os.identity")
    assert list(run.temp.iterdir()) == []


def on_path(root: Path) -> dict[str, str]:
    """PATH with root/bundle (the folder run_cmd copies envscan.cmd into) first."""
    return {"PATH": f"{root / 'bundle'};{os.environ.get('PATH', '')}"}


@pytest.mark.parametrize("exe", [CMD32, CMD], ids=["cmd32", "cmd64"])
def test_script_started_by_name_from_path_finds_itself(cmd_script: Path, tmp_path: Path, exe: str) -> None:
    """Started as "envscan.cmd" through PATH from another folder: at the top of a script, %~f0
    would name <working directory>\\envscan.cmd, so the 32-bit relaunch must not use it."""
    if not Path(exe).exists():
        pytest.skip(f"{exe} not found")
    version = run_cmd(cmd_script, tmp_path / "v", ["--fallback", "--version"], exe=exe, invoke='"envscan.cmd"',
                      env=on_path(tmp_path / "v"))
    assert version.returncode == 0, version.stderr
    assert version.stdout_lines == [f"envscan {load_spec(PORTABLE / 'spec').version} (cmd)"]
    launch = run_cmd(cmd_script, tmp_path / "n", ["--net"], exe=exe, invoke='"envscan.cmd"',
                     env={**on_path(tmp_path / "n"), **ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0"})
    assert launch.returncode == 0, launch.stderr
    assert launch.record is not None and "arg=[--net]" in launch.record
    assert "arch=x86\n" not in launch.record
    assert list(launch.temp.iterdir()) == []


@pytest.mark.skipif(not Path(CMD32).exists(), reason="no 32-bit cmd.exe on this system")
def test_32bit_relaunch_never_runs_a_script_from_the_working_directory(cmd_script: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "envscan.cmd").write_bytes(b"@echo DECOY-RAN\r\n@exit /b 7\r\n")
    env = {**on_path(tmp_path), "NoDefaultCurrentDirectoryInExePath": "1"}
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--version"], exe=CMD32, invoke='"envscan.cmd"', env=env,
                  cwd=elsewhere)
    assert "DECOY-RAN" not in run.stdout + run.stderr
    assert run.returncode == 0, run.stderr
    assert run.stdout_lines == [f"envscan {load_spec(PORTABLE / 'spec').version} (cmd)"]


def test_help_prints_usage_and_starts_nothing(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--help"], env=ALLOW_PROCESS_SCOPE)
    assert run.returncode == 0
    assert "Usage: envscan.cmd [options]" in run.stdout
    assert "--fallback" in run.stdout
    assert run.record is None
    assert not list(run.work.iterdir())


README_SECTION = 'the README section "When Windows blocks the script"'


def test_restricted_policy_falls_back_and_offers_process_scope(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--only", "session.context"], env={"ENVSCAN_TEST_POLICY": "restricted"})
    assert run.returncode == 0, run.stderr
    assert run.record is None, "PowerShell must not be started when the policy forbids the script"
    folder = find_output(run.work)
    assert run.stdout_lines == [str(folder)]
    # The process-scoped command line is shown on the console only, never kept in the report.
    assert "-ExecutionPolicy Bypass -File" in run.stderr
    assert "affects only that one" in run.stderr
    report = run.report
    assert "bypass" not in report.lower() and "-executionpolicy" not in report.lower()
    assert "reason: the PowerShell execution policy is Restricted" in report
    assert README_SECTION in report
    assert "test_hook: ENVSCAN_TEST_POLICY=restricted" in report


def test_group_policy_never_offers_bypass(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--only", "session.context"], env={"ENVSCAN_TEST_POLICY": "allsigned-gpo"})
    assert run.returncode == 0, run.stderr
    assert run.record is None
    assert "Group Policy" in run.stderr and "sign envscan.ps1" in run.stderr
    for text in (run.stderr, run.report):
        assert "bypass" not in text.lower()
    assert "scope MachinePolicy" in run.report and README_SECTION in run.report


def test_blocked_powershell_points_to_application_control(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--only", "session.context"], env={"ENVSCAN_TEST_POLICY": "blocked"})
    assert run.returncode == 0, run.stderr
    assert run.record is None
    assert "application control" in run.stderr
    assert "bypass" not in (run.stderr + run.report).lower()


def test_refusal_by_powershell_is_detected_after_launch(cmd_script: Path, tmp_path: Path) -> None:
    if effective_policy() not in ("Restricted", "AllSigned"):
        pytest.skip(f"needs an execution policy that refuses unsigned scripts, have {effective_policy()!r}")
    run = run_cmd(cmd_script, tmp_path, ["--only", "session.context"], env={"ENVSCAN_TEST_POLICY": "allowed"})
    assert run.returncode == 0, run.stderr
    assert run.record is None, "the stub must not have run under a refusing policy"
    assert "PowerShell refused to load envscan.ps1" in run.stderr
    assert "PowerShell error output:" in run.report
    assert "UnauthorizedAccess" in run.report
    assert list(run.temp.iterdir()) == [], "temporary error file was not deleted"


def test_unexpected_powershell_exit_code_falls_back(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--only", "session.context"], env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "7"})
    assert run.record is not None, "the stub should have run"
    assert run.returncode == 0, run.stderr
    assert "exit code 7" in run.report
    assert run.stdout_lines[-1] == str(find_output(run.work))


def test_missing_ps1_falls_back(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--only", "session.context"], stub=False, env=ALLOW_PROCESS_SCOPE)
    assert run.returncode == 0, run.stderr
    assert "envscan.ps1 is not next to envscan.cmd" in run.report


def test_prediction_matches_powershell(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "shell.info"])
    assert run.returncode == 0, run.stderr
    text = section(run.report, "shell.info")
    predicted = re.search(r"^predicted_policy: (\S+)$", text, re.M)
    assert predicted, text
    assert predicted.group(1) == effective_policy()
    refused = effective_policy() in ("Restricted", "AllSigned")
    assert ("predicted_result: would be refused" in text) == refused


@pytest.fixture
def windows_without_reg(tmp_path: Path) -> Iterator[Path]:
    """A Windows directory whose System32 has no reg.exe (as when application control blocks it):
    copies of findstr.exe and chcp.com and a junction to the real WindowsPowerShell folder. The
    crypto provider rsaenh.dll is loaded from %SystemRoot%\\System32: without a copy, Windows
    PowerShell does not start (error 0x8009001d) and the refusal path is never reached."""
    real = Path(CMD).parent
    root = tmp_path / "fakewin"
    system = root / "System32"
    system.mkdir(parents=True)
    for name in ("findstr.exe", "chcp.com", "rsaenh.dll"):
        shutil.copy2(real / name, system / name)
    link = system / "WindowsPowerShell"
    subprocess.run(f'"{CMD}" /d /c mklink /J "{link}" "{real / "WindowsPowerShell"}"', check=True,
                   capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    try:
        yield root
    finally:
        os.rmdir(link)  # removes the junction itself, never the real folder


def test_unreadable_registry_never_offers_bypass(cmd_script: Path, tmp_path: Path, windows_without_reg: Path) -> None:
    """When reg.exe cannot read the registry, a Group Policy setting cannot be ruled out: the
    policy is unknown, PowerShell is started and only its own refusal leads to the fallback."""
    env = {"SystemRoot": str(windows_without_reg), "windir": str(windows_without_reg), "STUB_EXIT": "0"}
    launch = run_cmd(cmd_script, tmp_path / "launch", ["--only", "shell.info"], env=env)
    assert "bypass" not in launch.stderr.lower()
    if launch.record is None:  # this machine's policy refused the script
        assert "PowerShell refused to load envscan.ps1" in launch.stderr, launch.stderr
        assert "could not be read" in launch.stderr
        assert "bypass" not in launch.report.lower()
    else:
        assert launch.returncode == 0, launch.stderr
    assert list(launch.temp.iterdir()) == []
    forced = run_cmd(cmd_script, tmp_path / "forced", ["--fallback", "--only", "shell.info"], env=env)
    assert forced.returncode == 1, forced.stderr  # partial: the registry could not be read
    text = section(forced.report, "shell.info")
    for line in ("predicted_policy: unknown", "predicted_scope: unknown", "predicted_by_group_policy: unknown",
                 "predicted_result: unknown"):
        assert line in text, text
    assert "the execution policy could not be read" in text
    assert text.endswith("status: partial")
    assert "registry: reg.exe could not read the registry" in forced.report


@pytest.mark.slow
def test_unreadable_registry_keeps_every_probe_running(cmd_script: Path, tmp_path: Path, windows_without_reg: Path,
                                                       cmd_probe_ids: list[str]) -> None:
    """cmd.exe ends the whole batch file (exit code 255) when a program of a pipe cannot be
    started, so reg.exe output is never piped: with reg.exe (and most of System32) missing, every
    probe still reports, and those that read the registry say what they could not read."""
    env = {"SystemRoot": str(windows_without_reg), "windir": str(windows_without_reg)}
    run = run_cmd(cmd_script, tmp_path, ["--fallback"], env=env)
    assert run.returncode == 1, run.stderr
    assert "=== summary ===" in run.report
    statuses = {pid: section(run.report, pid).rsplit("status: ", 1)[1] for pid in cmd_probe_ids}
    # ipconfig.exe and route.exe are missing from the copied System32 as well.
    assert {pid for pid, status in statuses.items() if status == "error"} <= {"net.interfaces", "net.routes"}, statuses
    for pid in ("os.identity", "hw.cpu", "pkg.installed", "runtime.dotnet", "shell.info"):
        assert statuses[pid] == "partial", section(run.report, pid)
    assert "net_framework_4: not read" in section(run.report, "runtime.dotnet")
    assert list(run.temp.iterdir()) == []


# ------------------------------------------------------------------ fallback collector

@pytest.fixture(scope="module")
def full_fallback(cmd_script: Path, tmp_path_factory: pytest.TempPathFactory) -> Run:
    env = {**SECRET_CANARIES, **EXTRA_SECRETS, **PLAIN}
    return run_cmd(cmd_script, tmp_path_factory.mktemp("full"), ["--fallback"], env=env)


@pytest.mark.slow
def test_fallback_writes_every_probe_section(full_fallback: Run, cmd_probe_ids: list[str]) -> None:
    run = full_fallback
    folder = find_output(run.work)
    assert run.stdout_lines == [str(folder)], "stdout must be exactly the output folder"
    report = run.report
    assert "This is NOT the full envscan report" in report
    statuses = {pid: re.search(r"^status: (\w+)$", section(report, pid), re.M).group(1) for pid in cmd_probe_ids}
    assert set(statuses.values()) <= {"ok", "partial", "error", "not_found"}
    assert "error" not in statuses.values(), statuses
    assert run.returncode == (1 if "partial" in statuses.values() else 0), statuses
    summary = report.split("=== summary ===", 1)[1]
    for pid, status in statuses.items():
        assert f"{pid}: {status}" in summary
    assert "The system cannot find the batch label" not in report
    # A syntax error inside a called label only ends that call: the report looks complete.
    for message in SYNTAX_ERRORS:
        assert message not in run.stderr + report, message


@pytest.mark.slow
def test_fallback_folder_name_is_utc(full_fallback: Run) -> None:
    folder = find_output(full_fallback.work)
    match = re.fullmatch(r"envscan-[A-Za-z0-9._-]+-(\d{8}T\d{6})Z", folder.name)
    assert match, folder.name
    stamp = dt.datetime.strptime(match.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=dt.timezone.utc)
    assert abs(dt.datetime.now(dt.timezone.utc) - stamp) < dt.timedelta(minutes=30)


@pytest.mark.slow
def test_fallback_never_writes_secrets(full_fallback: Run) -> None:
    assert_no_secret(full_fallback, [*CANARY_VALUES, *EXTRA_CANARIES])
    env_section = section(full_fallback.report, "env.vars")
    assert "\nHTTP_PROXY=http://proxyuser:<redacted>@proxy.corp.example:8080\n" in env_section
    for name in ("ENVSCAN_CANARY_PASSWORD", "ENVSCAN_CANARY_TOKEN", "MY_API_KEY", "GH_PAT_VALUE"):
        assert f"\n{name}=<redacted>\n" in env_section, name
    wrong = {name: shown for name, (_, shown) in SECRET_CASES.items() if f"\n{name}={shown}\n" not in env_section}
    assert not wrong, f"not printed as expected: {wrong}"


@pytest.mark.slow
def test_fallback_keeps_plain_values_intact(full_fallback: Run) -> None:
    env_section = section(full_fallback.report, "env.vars")
    for name, value in PLAIN.items():
        assert f"{name}={value}" in env_section, name
    assert "__ES_" not in env_section.replace("names starting with __ES_", "")
    proxy_section = section(full_fallback.report, "net.proxy")
    assert "HTTP_PROXY=http://proxyuser:<redacted>@proxy.corp.example:8080" in proxy_section


SYNTAX_ERRORS = ("was unexpected at this time", "The syntax of the command is incorrect")


def test_escaped_json_never_shows_the_password(cmd_script: Path, tmp_path: Path) -> None:
    """The quote after a key may be escaped, {\\"password\\":\\"x\\"}: in an environment value and in
    a docker-style command line (second review)."""
    env = {"CFG": '{\\"password\\":\\"hunter2\\"}',
           "ENVSCAN_DOCKER_LINE": 'docker run -e CFG="{\\"password\\":\\"hunter2\\"}" img'}
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "env.vars"], env=env)
    assert run.returncode == 0, run.stderr
    text = section(run.report, "env.vars")
    assert f"\nCFG={R}\n" in text and f"\nENVSCAN_DOCKER_LINE={R}\n" in text, text
    assert "hunter2" not in run.report + run.stdout + run.stderr


def test_multiline_environment_values_are_listed_on_one_line(cmd_script: Path, tmp_path: Path) -> None:
    """"set" prints the lines of a value as further lines; none of them may stop the probe, run as
    a command or be taken for a variable, and every line break is shown as <CR> or <LF>."""
    marker = tmp_path / "inj-multiline"
    env = {
        "ENVSCAN_A_MULTI": 'first line\n"second & line\n|third=x',
        "ENVSCAN_B_CRLF": "one\r\ntwo",
        "ENVSCAN_C_HOSTILE": f'a\n"&mkdir "{marker}"&rem "\nb',
        "ENVSCAN_D_PATHLINE": "x\nPATH=not-the-path",
        "ENVSCAN_E_TOKEN": "canary-ml-tok-1\ncanary-ml-tok-2",
        "ENVSCAN_F_URL": "see\nhttp://u:canary-ml-pw-3@h.example/x",
        "ENVSCAN_G_PEM": "-----BEGIN PRIVATE KEY-----\ncanary-ml-pem-4\n-----END PRIVATE KEY-----",
        "ENVSCAN_H_LONGLINE": "x\n" + "z" * 7000,
        "ENVSCAN_I_PASSWORD_LINES": "canary-ml-pw-5\nsecond",
        "ENVSCAN_J_OPTION_LINE": "tool\n--password canary-ml-opt-6",
        **SECRET_CANARIES,
    }
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "env.vars"], env=env)
    assert not marker.exists(), "a line of a value ran as a command"
    for message in SYNTAX_ERRORS:
        assert message not in run.stdout + run.stderr + run.report
    assert run.returncode == 0, run.stderr
    text = section(run.report, "env.vars")
    assert text.endswith("status: ok")
    expected = [
        'ENVSCAN_A_MULTI=first line<LF> "second & line<LF> |third=x',
        "ENVSCAN_B_CRLF=one<CR><LF> two",
        f'ENVSCAN_C_HOSTILE=a<LF> "&mkdir "{marker}"&rem "<LF> b',
        "ENVSCAN_D_PATHLINE=x<LF> PATH=not-the-path",
        f"ENVSCAN_E_TOKEN={R}",
        f"ENVSCAN_F_URL=see<LF> http://u:{R}@h.example/x",
        "ENVSCAN_G_PEM=<redacted: private key>",
        "ENVSCAN_H_LONGLINE=x<LF> " + "z" * 7000,
        f"ENVSCAN_I_PASSWORD_LINES={R}",
        f"ENVSCAN_J_OPTION_LINE={R}",
    ]
    lines = text.splitlines()
    for line in expected:
        assert line in lines, line[:80]
    assert len([line for line in lines if line.startswith("PATH=")]) == 1, "PATH listed twice"
    assert "note: line breaks inside values are shown as <CR> and <LF>" in text
    assert "=== summary ===" in run.report
    assert_no_secret(run, [*CANARY_VALUES, "canary-ml-tok", "canary-ml-pw", "canary-ml-pem", "canary-ml-opt"])


def test_values_too_long_for_cmd_are_reported_not_dropped(cmd_script: Path, tmp_path: Path) -> None:
    """cmd.exe cannot read a value of more than about 8000 characters, and "set" joins the next
    variable to it: the value is reported as not shown and the probe as partial."""
    env = {"ENVSCAN_LONG_VALUE": "v" * 9000, **SECRET_CANARIES}
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "env.vars"], env=env)
    assert run.returncode == 1, run.stderr
    text = section(run.report, "env.vars")
    assert "ENVSCAN_LONG_VALUE: not shown, the value is longer than cmd.exe can read" in text
    assert "the variable after it in this list may be missing" in text
    assert text.endswith("status: partial")
    assert_no_secret(run, CANARY_VALUES)


@pytest.mark.slow
def test_fallback_cleans_up_its_test_files(full_fallback: Run) -> None:
    for folder in (full_fallback.bundle, full_fallback.work, full_fallback.temp):
        assert not list(folder.glob("envscan-probe-*.tmp"))
    fs_section = section(full_fallback.report, "fs.locations")
    assert "current_directory:" in fs_section and "script_directory:" in fs_section


def test_fallback_version_and_list_probes(cmd_script: Path, tmp_path: Path, cmd_probe_ids: list[str]) -> None:
    version = run_cmd(cmd_script, tmp_path / "v", ["--fallback", "--version"])
    assert version.returncode == 0
    assert version.stdout_lines == [f"envscan {load_spec(PORTABLE / 'spec').version} (cmd)"]
    listing = run_cmd(cmd_script, tmp_path / "l", ["--fallback", "--list-probes"])
    assert listing.returncode == 0
    assert listing.stdout.splitlines() == expected_probe_listing(load_spec(PORTABLE / "spec"), "cmd")
    assert [line.split()[0] for line in listing.stdout.splitlines() if not line.startswith(" ")] == cmd_probe_ids
    assert not list((tmp_path / "v" / "work").iterdir()) and not list((tmp_path / "l" / "work").iterdir())


def test_fallback_rejects_unknown_arguments(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--bogus"])
    assert run.returncode == 2
    assert "unknown argument: --bogus" in run.stderr
    assert "Usage: envscan.cmd" in run.stderr
    assert run.stdout == ""
    assert not list(run.work.iterdir())


def test_fallback_does_not_echo_a_secret_argument(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--password=canary-badarg-9z"])
    assert run.returncode == 2
    assert "envscan: <redacted>" in run.stderr
    assert canary_hits([run.stdout, run.stderr], ["canary-badarg-9z"]) == []


def test_fallback_out_creates_the_parent(cmd_script: Path, tmp_path: Path) -> None:
    parent = tmp_path / "new parent" / "nested"
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "session.context", "--out", str(parent)])
    assert run.returncode == 0, run.stderr
    folder = find_output(parent)
    assert run.stdout_lines == [str(folder)]
    assert (folder / "envscan-fallback.txt").exists()


def test_fallback_only_and_skip_select_probes(cmd_script: Path, tmp_path: Path, cmd_probe_ids: list[str]) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "net.*,session.context", "--skip", "net.routes"])
    assert run.returncode == 0, run.stderr
    report = run.report
    selected = {pid for pid in cmd_probe_ids if (pid.startswith("net.") or pid == "session.context")}
    selected.discard("net.routes")
    for pid in cmd_probe_ids:
        status = re.search(r"^status: (\w+)$", section(report, pid), re.M).group(1)
        assert (status == "skipped") == (pid not in selected), (pid, status)


def long_path(shift: int) -> tuple[list[str], str]:
    """A PATH longer than 7000 characters and the entries the fallback should check.

    With shift 0 the 7000th character is the ';' after the last kept entry; with shift > 0 the
    cut lands `shift` characters before the end of that entry, which must then be dropped.
    """
    entries = [str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32")]
    while len(";".join(entries)) < 6900:
        entries.append(rf"C:\envscan-missing\{len(entries):04d}")
    stem = r"C:\envscan-missing\last"
    last = stem + "z" * (7000 - len(";".join(entries)) - 2 - len(stem) + shift)
    after = [rf"C:\envscan-after-cut\{number}" for number in range(20)]
    value = ";".join([*entries, last, *after])
    assert (value[6999] == ";") == (shift == 0)
    return ([*entries, last] if shift == 0 else entries), value


@pytest.mark.parametrize("shift", [0, 5], ids=["cut-at-separator", "cut-inside-entry"])
def test_fallback_cuts_a_very_long_path_at_the_last_full_entry(cmd_script: Path, tmp_path: Path, shift: int) -> None:
    kept, value = long_path(shift)
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "env.path"], env={"PATH": value})
    assert run.returncode == 1, run.stderr  # partial
    text = section(run.report, "env.path")
    assert text.endswith("status: partial")
    assert "only the entries in the first 7000 were checked" in text
    assert re.findall(r"^  \[[^\]]+\] (.*)$", text, re.M) == kept
    assert f"summary: {len(kept)} entries, {len(kept) - 1} missing" in text
    assert "envscan-after-cut" not in text
