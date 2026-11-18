"""Contrato e utilidades dos passos sem modelo: validação por schema, montagem da recommendation, POST."""

import json
import os
import pathlib
import secrets
import sys
import urllib.request

import yaml
from jsonschema import Draft202012Validator

CONTRACT = pathlib.Path(__file__).resolve().parent.parent / "tests" / "contract"
SCHEMA_VERSION = "0.1.0"
EVIDENCE = "osv-scanner"
ACTION = {
    "pr_opened": ("review_pr", "Revisar o diff do bump e o CI do PR"),
    "no_change": ("escalate", "N1 não resolveu; avaliar o nível N2"),
    "failed": ("escalate", "N1 falhou; avaliar o nível N2"),
}


def traceparent():
    """O traceparent da rodada: o de TRACEPARENT, se definido; senão um novo (W3C, versão 00)."""
    return os.environ.get("TRACEPARENT") or f"00-{secrets.token_hex(16)}-{secrets.token_hex(8)}-01"


def check_trace(events):
    """Todos os eventos da rodada têm o mesmo trace_id (e o de TRACEPARENT, se definido)."""
    ids = {e["traceparent"].split("-")[1] for e in events}
    if len(ids) > 1 or (os.environ.get("TRACEPARENT") and ids != {os.environ["TRACEPARENT"].split("-")[1]}):
        die(f"eventos da rodada com trace_id diferentes entre si ou de TRACEPARENT: {sorted(ids)}")


def validate(doc, name):
    """Levanta ValueError se `doc` não valida contra o schema do contrato (alert-event ou recommendation)."""
    schema = yaml.safe_load((CONTRACT / f"{name}.yaml").read_text(encoding="utf-8"))
    v = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        raise ValueError(f"{name} inválido: " + "; ".join(f"{'/'.join(map(str, e.path))}: {e.message}" for e in errors))
    return doc


def ref(source, query_id, value):
    return {"collector": source, "query_id": query_id, "value": value}


def n2_versions(level):
    """O contrato exige prompt e modelo versionados em `level: N2`; vêm de N2_PROMPT e N2_MODEL (vazio é recusado pelo schema)."""
    return {"prompt": os.environ.get("N2_PROMPT", ""), "model": os.environ.get("N2_MODEL", "")} if level == "N2" else {}


def recommendation(event, status, fix, failure_reason=None, pr_number=None, patch_sha256=None):
    """Recommendation de vuln fix N1. `fix` traz advisory, versões, ci_status, rescan e evidence."""
    d = event["data"]
    fix = {"advisory_id": d["advisory_id"], "package": d["package"], "from_version": d["installed_version"], "level": "N1", **fix}
    if pr_number:
        fix.update(pr_number=pr_number, patch_sha256=patch_sha256)
    kind, text = ACTION[status]
    doc = {
        "kind": "vuln_fix",
        "status": status,
        "trace_id": event["traceparent"].split("-")[1],
        "event": {"source": event["source"], "id": event["id"]},
        "versions": {"schema": SCHEMA_VERSION, **n2_versions(fix["level"])},
        "hypotheses": [],
        "not_enough_evidence": False,
        "suggested_action": {"type": kind, "text": text},
        "fix": fix,
    }
    if failure_reason:
        doc["failure_reason"] = failure_reason
    return validate(doc, "recommendation")


def post(url, body, headers=None, shown=None):
    """POST JSON. Com DRY_RUN=1 imprime a requisição (sem cabeçalhos; `shown` esconde URL secreta) e não envia."""
    if os.environ.get("DRY_RUN") == "1":
        print(json.dumps({"POST": shown or url, "body": body}, ensure_ascii=False, indent=2))
        return None
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def die(msg):
    sys.exit(f"erro: {msg}")
