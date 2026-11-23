"""The envscan.js lint (tools/target_js.py lint): each bypass found by the security review is a
failing case, the forms the engine really uses stay clean, and the real dist/envscan.js lints clean.

The lint sees the whole text (cross-line rules match across line breaks) and reports line numbers.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import target_js  # noqa: E402


def lint(body: str) -> list[str]:
    """Lint errors of a snippet (CRLF line ends, like an assembled script)."""
    return target_js.lint(body.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n")


# ------------------------------------------------------------------ review bypasses

BYPASSES = {
    "wscript-createobject": 'var x = WScript.CreateObject("MSXML2.XMLHTTP");',
    "wscript-getobject": 'var w = WScript.GetObject("winmgmts:");',
    "this-activex-concat": 'var x = new this["Active" + "XObject"]("x");',
    "this-eval-concat": 'this["ev" + "al"]("x");',
    "constructor-chain": '[].constructor.constructor("code")();',
    "getobject-newline": 'var g = GetObject\n("x");',
    "shellexecute-newline": "x.ShellExecute\n(1);",
    "second-activex-on-line": 'var a = new ActiveXObject("WScript.Shell"), b = new ActiveXObject(name);',
    "activex-other-line": 'var a = new ActiveXObject("WScript.Shell");\nvar b = new ActiveXObject(\nname);',
    "activex-progid-not-allowed": 'var a = new ActiveXObject("Shell.Application");',
    "shell-run": 'ES_SHELL.Run("calc");',
    "shell-run-lowercase": 'ES_SHELL.run("calc");',
    "any-run": 'obj.Run("calc");',
    "popup": 'ES_SHELL.Popup("hi");',
    "logevent": "ES_SHELL.LogEvent(0, 'x');",
    "env-system": 'ES_SHELL.Environment("SYSTEM").Item("X") = "y";',
    "env-user": "var e = ES_SHELL.Environment('USER');",
    "env-volatile": 'var e = ES_SHELL.Environment("VOLATILE");',
    "env-computed": "var e = ES_SHELL.Environment(kind);",
    "set-timeout": 'setTimeout("x()", 1);',
    "set-interval": "setInterval(f, 1);",
    "copy-file": "ES_FSO.CopyFile(a, b);",
    "move-file": "ES_FSO.MoveFile(a, b);",
    "copy-folder": "ES_FSO.CopyFolder(a, b);",
    "move-folder": "ES_FSO.MoveFolder(a, b);",
    "delete-folder": "ES_FSO.DeleteFolder(a, true);",
    "folder-delete": "ES_FSO.GetFolder(a).Delete(true);",
    "fso-member-not-allowed": "var d = ES_FSO.GetSpecialFolderX(2);",
    "fso-alias": "var f = ES_FSO; f.CopyFile(a, b);",
    "shell-alias": "run(ES_SHELL);",
    "shell-computed": 'ES_SHELL["Exec"]("x");',
    "bracket-banned-name": 'var f = obj["constructor"];',
    "bracket-eval": 'var f = ES_GLOBAL_X["eval"];',
    "this-index": "var g = this[name];",
    "this-alias": "var g = this;",
    "global-lookup-untagged": "var fn = ES_GLOBAL[name];",
    "concat-two-literals": 'var f = g["ex" + "ecScript"];',
    "concat-banned-prefix": 'var f = g["constr" + x];',
    "concat-banned-suffix": 'var f = g[x + "Object"];',
    "function-ref": "var F = Function;",
    "eval-ref": "var e = eval;",
    "connect-remote": 'locator.ConnectServer("server", "root\\\\cimv2");',
    "has-own-property-direct": "if (obj.hasOwnProperty(k)) { x = 1; }",
    "has-own-property-bracket": 'if (obj["hasOwnProperty"](k)) { x = 1; }',
}


@pytest.mark.parametrize("name", sorted(BYPASSES))
def test_bypass_is_rejected(name: str) -> None:
    assert lint(BYPASSES[name]), name


def test_cross_line_errors_name_the_line() -> None:
    errors = lint('var a = 1;\nvar g = GetObject\n("x");')
    assert errors and all("line 2" in e for e in errors), errors
    errors = lint("var a = 1;\nvar b = 2;\nx.ShellExecute\n(1);")
    assert any("line 3" in e for e in errors), errors


# ------------------------------------------------------------------ forms the engine uses

CLEAN = {
    "fso-calls": 'var a = ES_FSO.FileExists("x") && ES_FSO.FolderExists("y");',
    "fso-special-folder": "var w = String(ES_FSO.GetSpecialFolder(0).Path);",
    "shell-process-env": 'var ES_PROCESS_ENV = ES_SHELL.Environment("PROCESS");',
    "shell-exec": "child = ES_SHELL.Exec(commandLine);",
    "header": 'var ES_FSO = new ActiveXObject("Scripting.FileSystemObject");\n'
              'var ES_SHELL = new ActiveXObject("WScript.Shell");',
    "locator": 'var locator = new ActiveXObject("WbemScripting.SWbemLocator");\n'
               'return locator.ConnectServer(".", ns);',
    "tagged-cleanup": "try { ES_FSO.DeleteFolder(ES_TMP, true); } catch (e) { x = 1; }  // lint-allow: temp-cleanup",
    "tagged-global": "var fn = ES_GLOBAL[name];  // lint-allow: global-lookup",
    "slot-concat": 'seen["k" + key] = true; created["p" + id] = 1;',
    "array-literal-concat": 'return ["--" + option + " needs probe ids"];',
    "literal-index": 'var t = getEsData("x")["tools"]; delete entry["proxy_settings"];',
    "own-property-call": "if (Object.prototype.hasOwnProperty.call(obj, k)) { x = 1; }",
    "wscript-members": "WScript.Sleep(10); WScript.Quit(0); var n = WScript.Arguments.length;",
    "strings-not-code": 'var s = "ES_SHELL.Run( and eval( and this[x]";  // a comment: GetObject(',
}


@pytest.mark.parametrize("name", sorted(CLEAN))
def test_engine_forms_are_clean(name: str) -> None:
    assert lint(CLEAN[name]) == [], name


def test_activex_counted_per_file_not_per_line() -> None:
    assert lint('var a = new ActiveXObject("WScript.Shell");\nvar b = new ActiveXObject("Scripting.FileSystemObject");') == []
    assert lint('var a = new ActiveXObject("WScript.Shell");\nvar b = ActiveXObject;')


def test_real_dist_lints_clean(tmp_path: Path) -> None:
    from js_harness import build_js
    dist, _lib = build_js(tmp_path)
    assert target_js.lint(dist.read_bytes().decode("ascii")) == []
