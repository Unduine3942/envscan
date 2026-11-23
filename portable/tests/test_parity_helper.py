"""Unit tests of tests/parity.py with hand-made envscan.json documents."""
from __future__ import annotations

import copy
from typing import Any

import parity
import pytest

pytestmark = pytest.mark.unit


def make_doc() -> dict[str, Any]:
    return {
        "probes": {
            "os.identity": {"status": "ok", "data": {"family": "linux", "arch": "x86_64", "hostname": "a", "kernel": "5.15"}},
            "hw.memory": {"status": "ok", "data": {"total_mb": 16003, "available_mb": 1234}},
            "limits.process": {"status": "ok", "data": {"nofile_soft": 1024, "nofile_hard": 4096, "nproc_soft": 63704,
                                                        "nproc_hard": 63704, "stack_kb_soft": 8192, "core_soft": 0,
                                                        "memlock_kb_soft": 64, "address_space_soft": "unlimited"}},
            "env.path": {"status": "ok", "data": {"separator": ":", "entries": [
                {"path": "/usr/local/bin", "exists": True}, {"path": "/usr/bin", "exists": True}]}},
            "pkg.sources": {"status": "ok", "data": {
                "endpoints": ["https://nexus.corp", "http://proxy.corp:3128"],
                "proxy_urls": [{"tool": "npm", "url": "http://proxy.corp:3128", "source": ".npmrc"},
                               {"tool": "pip", "url": "http://proxy.corp:3128", "source": "pip.conf"}]}},
            "tools.inventory": {"status": "ok", "data": {"tools": {
                "git": {"found": True, "version": "2.43.0"}, "node": {"found": False}, "python3": {"found": True}}}},
        },
        "findings": [{"id": "pkg.mirror", "severity": "info"}, {"id": "net.proxy_configured", "severity": "info"}],
    }


def test_normalize_extracts_the_key_facts() -> None:
    facts = parity.normalize(make_doc())
    assert facts == {
        "os.identity": {"family": "linux", "arch": "x86_64"},
        "hw.memory.total_mb": 16000,
        "limits.process": {"nofile_soft": 1024, "nofile_hard": 4096, "nproc_soft": 63704, "nproc_hard": 63704,
                           "stack_kb_soft": 8192, "core_soft": 0, "memlock_kb_soft": 64, "address_space_soft": "unlimited"},
        "env.path": ["/usr/local/bin", "/usr/bin"],
        "pkg.sources": {"endpoints": ["http://proxy.corp:3128", "https://nexus.corp"], "proxy_urls": ["http://proxy.corp:3128"]},
        "tools.found": ["git", "python3"],
        "findings": ["net.proxy_configured", "pkg.mirror"],
    }


def test_identical_documents_have_no_difference() -> None:
    assert parity.compare(make_doc(), copy.deepcopy(make_doc())) == []


def test_noise_is_not_a_difference() -> None:
    other = make_doc()
    other["probes"]["os.identity"]["data"].update(hostname="b", kernel="6.1")
    other["probes"]["hw.memory"]["data"].update(total_mb=16050, available_mb=1)
    other["probes"]["tools.inventory"]["data"]["tools"]["git"]["version"] = "2.44.0"
    other["probes"]["pkg.sources"]["data"]["proxy_urls"].reverse()
    other["findings"].reverse()
    assert parity.compare(make_doc(), other) == []


def test_differences_are_reported_by_key() -> None:
    other = make_doc()
    other["probes"]["os.identity"]["data"]["arch"] = "arm64"
    other["probes"]["limits.process"]["data"]["nofile_soft"] = 2048
    other["probes"]["env.path"]["data"]["entries"].append({"path": "/opt/bin"})
    other["probes"]["hw.memory"]["data"]["total_mb"] = 8001
    other["findings"].append({"id": "fs.low_disk"})
    diffs = {d.key: (d.left, d.right) for d in parity.compare(make_doc(), other)}
    assert diffs == {
        "os.identity.arch": ("x86_64", "arm64"),
        "limits.process.nofile_soft": (1024, 2048),
        "env.path": (["/usr/local/bin", "/usr/bin"], ["/usr/local/bin", "/usr/bin", "/opt/bin"]),
        "hw.memory.total_mb": (16000, 8064),
        "findings": (["net.proxy_configured", "pkg.mirror"], ["fs.low_disk", "net.proxy_configured", "pkg.mirror"]),
    }


def test_a_missing_probe_is_a_difference_not_an_error() -> None:
    other = make_doc()
    del other["probes"]["limits.process"]
    del other["probes"]["hw.memory"]
    keys = {d.key for d in parity.compare(make_doc(), other)}
    assert "hw.memory.total_mb" in keys and "limits.process.nofile_soft" in keys
    assert parity.normalize({})["hw.memory.total_mb"] is None
    assert parity.normalize({})["findings"] == []


def test_ignore_skips_keys_and_their_children() -> None:
    other = make_doc()
    other["probes"]["limits.process"]["data"]["nofile_soft"] = 1
    other["probes"]["os.identity"]["data"]["arch"] = "arm64"
    assert parity.compare(make_doc(), other, ignore=["limits.process"]) == [("os.identity.arch", "x86_64", "arm64")]


def test_memory_rounding_step() -> None:
    assert parity.round_mb(16003) == 16000
    assert parity.round_mb(16064) == 16128  # a half rounds up
    assert parity.round_mb(16063) == 16000
    assert parity.round_mb(100, 50) == 100
    assert parity.round_mb(None) is None and parity.round_mb("x") is None and parity.round_mb(True) is None
    other = make_doc()
    other["probes"]["hw.memory"]["data"]["total_mb"] = 16100
    assert parity.compare(make_doc(), other) != []
    assert parity.compare(make_doc(), other, memory_step_mb=1024) == []


def test_string_forms_are_accepted() -> None:
    doc = {"probes": {"env.path": {"data": {"entries": ["/a", "/b"]}},
                      "pkg.sources": {"data": {"proxy_urls": ["http://p:1", "http://p:1"]}}}}
    facts = parity.normalize(doc)
    assert facts["env.path"] == ["/a", "/b"] and facts["pkg.sources"]["proxy_urls"] == ["http://p:1"]


def test_difference_string_form() -> None:
    assert str(parity.Difference("a.b", 1, 2)) == "a.b: 1 != 2"


def test_malformed_entries_do_not_crash() -> None:
    doc = {"probes": {"env.path": {"data": {"entries": [{"exists": True}, {"path": "/a"}, None, 5]}},
                      "pkg.sources": {"data": {"proxy_urls": [{"tool": "x"}, ["unhashable"], {"url": "http://p:1"}, "http://p:1"]}}}}
    facts = parity.normalize(doc)
    assert facts["env.path"] == ["/a"]
    assert facts["pkg.sources"]["proxy_urls"] == ["http://p:1"]


def test_empty_mapping_differs_from_missing() -> None:
    assert parity.diff({"a": {}}, {}) == [("a", {}, None)]
    assert parity.diff({"a": {}}, {"a": {}}) == []
    assert parity.diff({"a": {"b": 1}}, {"a": {}}) == [("a", None, {}), ("a.b", 1, None)]
