import json
import pathlib
from datetime import datetime, timezone

import pytest

from steps.common import validate
from steps.scan.scan import event_name, events

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)
OSV = json.loads((FIXTURES / "osv-scanner.json").read_text())  # saída real do osv-scanner 2.7.1 sobre o demo-service
BY_ID = {e["id"]: e for e in events(OSV, "open-eda-labs/demo-service", "/work/repo", NOW)}


def ev(advisory, package):
    return BY_ID[f"{advisory}:open-eda-labs/demo-service:{package}"]


def test_one_event_per_advisory_and_package_all_valid():
    assert len(BY_ID) == 19  # 1 commons-text + 8 log4j-core + 6 jetty-server + 1 json-smart + 3 org.json
    for e in BY_ID.values():
        validate(e, "alert-event")
        assert e["type"] == "io.github.open-eda-labs.vulnerability.detected"
        assert e["source"] == "/osv-scanner/lab"


def test_event_fields():
    e = ev("GHSA-599f-7c49-w659", "org.apache.commons:commons-text")
    assert e["data"] == {
        "advisory_id": "GHSA-599f-7c49-w659",
        "aliases": ["CVE-2022-42889"],
        "repository": "open-eda-labs/demo-service",
        "ecosystem": "Maven",
        "package": "org.apache.commons:commons-text",
        "installed_version": "1.9",
        "severity": "critical",
        "manifest_path": "pom.xml",
    }
    assert e["subject"] == "demo-service"


def test_event_has_no_fixed_version_and_one_trace_per_round():
    # fixed_version é opcional no contrato e a menor versão corrigida enganaria: o alvo é a última release (ADR-0005)
    assert not any("fixed_version" in e["data"] for e in BY_ID.values())
    assert len({e["traceparent"] for e in BY_ID.values()}) == 1
    tp = "00-" + "ab" * 16 + "-" + "cd" * 8 + "-01"
    assert {e["traceparent"] for e in events(OSV, "open-eda-labs/demo-service", "/work/repo", NOW, tp)} == {tp}


def test_manifest_path_with_symlink_root(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    osv = {"results": [{"source": {"path": str(tmp_path / "real" / "target" / "bom.json")}, "packages": [
        {"package": {"name": "org.a:b", "version": "1"}, "vulnerabilities": [{"id": "GHSA-599f-7c49-w659"}]}]}]}
    assert events(osv, "o/r", tmp_path / "link", NOW)[0]["data"]["manifest_path"] == "target/bom.json"


def test_names_are_deterministic_and_unique():
    names = [event_name(e) for e in BY_ID.values()]
    assert len(set(names)) == len(names)
    assert names == [event_name(e) for e in events(OSV, "open-eda-labs/demo-service", "/work/repo", NOW)]


def test_advisory_without_cve_or_ghsa_is_skipped():
    osv = {"results": [{"source": {"path": "/r/pom.xml"}, "packages": [{"package": {"name": "a:b", "version": "1"}, "vulnerabilities": [{"id": "OSV-2020-1"}]}]}]}
    assert events(osv, "o/r", "/r", NOW) == []


@pytest.mark.parametrize("bad", ["Maven", "x"])
def test_invalid_event_is_rejected(bad):
    osv = {"results": [{"source": {"path": "/r/pom.xml"}, "packages": [{"package": {"name": bad, "version": "1"}, "vulnerabilities": [{"id": "GHSA-599f-7c49-w659"}]}]}]}
    with pytest.raises(ValueError):
        events(osv, "o/r", "/r", NOW)
