"""Passo scan (sem modelo): OSV-Scanner sobre o SBOM do demo-service → um evento por (advisory, pacote) em /work/events/.

O parent e a lib vêm de outros repositórios (GitHub Packages exige credencial), então o scan não lê o pom.xml:
instala parent e lib no ~/.m2 a partir dos clones e escaneia o `target/bom.json` que o Maven gera com a árvore resolvida.
Uso: REPOSITORY=owner/nome python -m steps.scan.scan [/work]
Tudo no volume de trabalho do Workflow: clona (raso) demo-parent, demo-lib e demo-service em /work/repos, se ainda não estiverem lá, e grava
/work/shas.json (o commit de cada um: fix e publish trabalham nesses SHAs), /work/traceparent (um por rodada), /work/events/<hash do id>.json
(o fix lê essa pasta) e /work/osv-scanner.json.
"""

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from steps.common import die, traceparent, validate

SOURCE = "/osv-scanner/lab"
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}
ADVISORY = re.compile(r"^(CVE-[0-9]{4}-[0-9]{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$")
# Falhas de resolução do OSV-Scanner (ex.: HTTP 429 do Maven Central) saem como aviso e deixam o resultado incompleto.
INCOMPLETE = re.compile(r"failed resolution|Error during extraction|API query failed")


def scan(repo, lockfile="target/bom.json"):
    """Roda o OSV-Scanner (fonte `native`: só Maven Central e base OSV, sem deps.dev). Retorna o JSON; falha se incompleto."""
    r = subprocess.run(
        ["osv-scanner", "scan", "source", "--data-source", "native", "-L", lockfile, "--format", "json"],
        cwd=repo, capture_output=True, text=True,
    )
    if r.returncode not in (0, 1) or INCOMPLETE.search(r.stderr):  # 1 = achou vulnerabilidade; o log vai para stderr
        die("osv-scanner falhou ou resolveu a árvore de forma incompleta:\n" + r.stderr[-2000:])
    return json.loads(r.stdout)


def events(osv, repository, root, now, tp=None):
    """Transforma o JSON do osv-scanner em eventos alert-event (vulnerability.detected), sem repetir o id. Todos com o mesmo `tp` (traceparent da rodada)."""
    out = {}
    tp, root = tp or traceparent(), pathlib.Path(root).resolve()
    name = repository.split("/")[1]
    for result in osv["results"]:
        manifest = os.path.relpath(pathlib.Path(result["source"]["path"]).resolve(), root)  # sem resolve() uma raiz symlink dá ../..
        for p in result["packages"]:
            pkg = p["package"]
            for v in p.get("vulnerabilities", []):
                ids = list(dict.fromkeys([v["id"], *v.get("aliases", [])]))
                known = [i for i in ids if ADVISORY.match(i)]
                if not known:
                    print(f"advisory sem CVE/GHSA ignorado: {v['id']}", file=sys.stderr)
                    continue
                data = {
                    "advisory_id": known[0],
                    "repository": repository,
                    "ecosystem": "Maven",
                    "package": pkg["name"],
                    "installed_version": pkg["version"],
                    "severity": SEVERITY.get(v.get("database_specific", {}).get("severity"), "unknown"),
                    "manifest_path": manifest,
                }
                if known[1:]:
                    data["aliases"] = known[1:9]
                eid = f"{data['advisory_id']}:{repository}:{pkg['name']}"
                out[eid] = {
                    "specversion": "1.0",
                    "id": eid,
                    "source": SOURCE,
                    "type": "io.github.open-eda-labs.vulnerability.detected",
                    "time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "datacontenttype": "application/json",
                    "subject": name,
                    "traceparent": tp,
                    "dataref": f"s3://scan-results/osv-scanner/{now:%Y-%m-%d}/{name}.json",
                    "data": data,
                }
    return [validate(e, "alert-event") for e in out.values()]


def event_name(event):
    """Nome determinístico por evento: base do nome do arquivo e do Workflow do Argo."""
    return hashlib.sha256(event["id"].encode()).hexdigest()[:12]


def main(work="/work"):
    repository = os.environ["REPOSITORY"]
    work = pathlib.Path(work).resolve()
    shas = {}
    for name, goal in (("demo-parent", "install"), ("demo-lib", "install"), ("demo-service", "package")):
        d = work / "repos" / name
        if not (d / ".git").exists():
            subprocess.run(["git", "clone", "-q", "--depth", "1", f"https://github.com/{repository.split('/')[0]}/{name}.git", str(d)], check=True)
        shas[name] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True, check=True).stdout.strip()
        r = subprocess.run(["mvn", "-B", "-ntp", "-q", goal, "-DskipTests"], cwd=d, capture_output=True, text=True)
        if r.returncode:
            die(f"mvn {goal} em {name} falhou:\n" + (r.stdout + r.stderr)[-2000:])
    repo = work / "repos" / "demo-service"
    osv = scan(repo)
    tp = traceparent()
    shutil.rmtree(work / "events", ignore_errors=True)  # retentativa do passo: nada de evento da tentativa anterior
    (work / "events").mkdir()
    (work / "shas.json").write_text(json.dumps(shas))
    (work / "traceparent").write_text(tp)
    (work / "osv-scanner.json").write_text(json.dumps(osv))
    for e in events(osv, repository, repo, datetime.now(timezone.utc), tp):
        (work / "events" / f"{event_name(e)}.json").write_text(json.dumps(e, separators=(",", ":")))


if __name__ == "__main__":
    main(*sys.argv[1:])
