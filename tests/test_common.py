import json
import pathlib
from datetime import datetime, timezone

import pytest

from steps.common import check_trace, recommendation, validate
from steps.scan.scan import events

OSV = json.loads((pathlib.Path(__file__).parent / "fixtures" / "osv-scanner.json").read_text())
EVENT = next(e for e in events(OSV, "open-eda-labs/demo-service", "/work/repo", datetime(2026, 11, 15, tzinfo=timezone.utc))
             if e["data"]["advisory_id"] == "GHSA-jfh8-c2jp-5v3q")
EV = [{"collector": "osv-scanner", "query_id": "rescan", "value": "GHSA-jfh8-c2jp-5v3q ausente; 7 outros advisories no pacote"}]


def test_pr_opened():
    rec = recommendation(EVENT, "pr_opened", {"to_version": "2.15.0", "ci_status": "pending", "rescan": "clean", "evidence": EV},
                         pr_number=17, patch_sha256="a" * 64)
    assert rec["trace_id"] == EVENT["traceparent"].split("-")[1]
    assert rec["event"] == {"source": EVENT["source"], "id": EVENT["id"]}
    assert rec["fix"]["level"] == "N1" and rec["suggested_action"]["type"] == "review_pr"


def test_no_change():
    rec = recommendation(EVENT, "no_change", {"ci_status": "not_run", "rescan": "not_run", "evidence": EV})
    assert "pr_number" not in rec["fix"] and "patch_sha256" not in rec["fix"]


@pytest.mark.parametrize("reason", ["build_failed", "tests_failed", "timeout"])
def test_failed(reason):
    rec = recommendation(EVENT, "failed", {"to_version": "2.15.0", "ci_status": "failed", "rescan": "not_run", "evidence": EV}, reason)
    assert rec["failure_reason"] == reason and rec["suggested_action"]["type"] == "escalate"


def test_schema_rejects_inconsistent_documents():
    with pytest.raises(ValueError):  # failed exige failure_reason
        recommendation(EVENT, "failed", {"ci_status": "failed", "rescan": "not_run", "evidence": EV})
    with pytest.raises(ValueError):  # pr_opened exige PR e hash
        recommendation(EVENT, "pr_opened", {"to_version": "2.15.0", "ci_status": "pending", "rescan": "clean", "evidence": EV})
    with pytest.raises(ValueError):  # texto com URL é barrado
        recommendation(EVENT, "no_change", {"ci_status": "not_run", "rescan": "not_run",
                                            "evidence": [{"collector": "osv-scanner", "query_id": "x", "value": "veja https://x.io/a"}]})
    validate({**EVENT}, "alert-event")


def test_check_trace_one_trace_per_round(monkeypatch):
    monkeypatch.delenv("TRACEPARENT", raising=False)
    other = {**EVENT, "traceparent": "00-" + "ab" * 16 + "-" + "cd" * 8 + "-01"}
    check_trace([EVENT, EVENT])
    with pytest.raises(SystemExit):  # dois trace_id na mesma rodada
        check_trace([EVENT, other])
    monkeypatch.setenv("TRACEPARENT", other["traceparent"])
    check_trace([other])
    with pytest.raises(SystemExit):  # evento de outro trace que o TRACEPARENT repassado
        check_trace([EVENT])
