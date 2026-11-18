"""Passo fix N1 (ADR-0005; sem modelo, sem credencial de escrita): última release dos pacotes acusados, parent → lib → service.

Uso: python -m steps.fix.fix [/work] [/work/fix]
Entrada: /work/events/*.json, /work/shas.json e /work/repos/{demo-parent,demo-lib,demo-service} (clones do scan, levados ao SHA de shas.json).
O alvo de cada pacote é a última release no Maven Central (versions-maven-plugin; pré-release fora). O fix nasce no parent
(versões) e na lib; o serviço só sobe parent e lib. "Corrigido" = build verde + testes verdes + re-scan sem os advisories.
Cada unidade de subida é provada sozinha (parent → lib → service); as que passam são combinadas, e uma combinação vermelha é
bisseccionada. Antes de desistir de uma unidade chama o gancho N2 (N2_HOOK; vazio por padrão): `$N2_HOOK <in> <out>`, com
<in>/repo (o repositório que quebrou) e <in>/error.log, e devolve <out>/patch.diff. Sem gancho, ou com gancho que falha, sai com
código diferente de zero ou estoura o tempo, a unidade volta à versão anterior e a rodada segue.
Verde que veio de patch do gancho grava `level: N2` na recommendation, e o contrato então exige N2_PROMPT e N2_MODEL no ambiente do publish.
Saída: /work/fix/<repo>/patch.diff (só repositório alterado), result.json, shas.json (cópia), fixes/<evento>.json (bloco `fix` dos
advisories fechados; o publish monta a recommendation com o PR) e recommendations/<evento>.json (no_change e failed). stdout: `ready`
se há patch, senão `done`. Falha de infraestrutura (rede, Maven Central) sai com erro, sem recommendation, depois das tentativas do `mvn`.
"""

import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from steps.common import EVIDENCE, check_trace, die, recommendation, ref
from steps.scan.scan import event_name, scan

# shortcut: topologia fixa do app de demonstração (REPOS, demo-lib.version); tirar da convenção do pom quando houver um segundo app
PARENT, LIB, SERVICE = REPOS = ("demo-parent", "demo-lib", "demo-service")
PLUGIN = "org.codehaus.mojo:versions-maven-plugin:2.19.1"
# Pré-release (alpha, beta, rc, milestone...) não é versão publicada (ADR-0005). maven.version.ignore é regex de correspondência total.
PRE_RELEASE = r"(?i).*[-._](alpha|beta|rc|cr|m|b|ea|milestone|preview|pre|pr|dev|snapshot|nightly)([-._]?[0-9]+)*"
MAX_VOLTAS = 3  # culpados removidos da combinação antes de passar para o fallback guloso
HOOK_TIMEOUT = 3600
RETRIES, WAIT = 3, 30  # a única camada de retentativa: Maven Central devolve 429 e 404 espúrios, o mvn espera e repete
BUILD_NET = re.compile(r"Could not (transfer|find) artifact|Connection (reset|refused)|status code: (429|5[0-9][0-9])")
PLUGIN_NET = re.compile(r"Could not transfer metadata [^\n]*\bcentral\b")  # o 401 do GitHub Packages anônimo é ruído
TESTS = re.compile(r"There are test failures|Tests run:[^\n]*(Failures|Errors): [1-9]")
REASON = {"build": "build_failed", "resolve": "build_failed", "tests": "tests_failed", "timeout": "timeout"}


def mvn(cwd, *args):
    """(returncode, log, infra). `infra`: ainda sem resolver o Maven Central depois das tentativas."""
    for i in range(RETRIES):
        try:
            r = subprocess.run(["mvn", "-B", "-ntp", *args], cwd=cwd, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            return 124, "timeout", False
        log = r.stdout + r.stderr
        infra = bool(PLUGIN_NET.search(log) or (r.returncode and BUILD_NET.search(log)))
        if not infra:
            break
        time.sleep(WAIT * (i + 1))
    return r.returncode, log, infra


def plugin(cwd, goal, *args):
    """Goal do versions-maven-plugin. Não envolve código: falha, ou resultado incompleto depois das tentativas do `mvn`, é de infraestrutura."""
    rc, log, infra = mvn(cwd, f"{PLUGIN}:{goal}", "-DgenerateBackupPoms=false", *args)
    if rc or infra:
        die(f"versions:{goal} falhou ou ficou incompleto:\n" + log[-2000:])


def patch_version(v):
    return re.sub(r"[0-9]+$", lambda m: str(int(m.group()) + 1), v)


def own_version(repo, artifact):
    # shortcut: lê o <version> logo após o <artifactId> próprio; os POMs do lab seguem esse formato, trocar por help:evaluate se mudar.
    return re.search(rf"<artifactId>{re.escape(artifact)}</artifactId>\s*<version>([^<]+)</version>", (repo / "pom.xml").read_text()).group(1)


def units(events, parent_pom):
    """Agrupa os pacotes acusados em unidades de subida. Cada unidade tem os `carriers` (g:a que o parent declara ou passa a
    declarar) e os pacotes acusados. Pacote gerenciado pelo parent sobe por si; membro de BOM importado sobe o BOM (shortcut: casa
    pelo prefixo do groupId); o resto é transitivo e passa a ser fixado no parent. Família = mesmo carrier-group e mesma versão."""
    boms = re.findall(r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>[^<]+</version>\s*<type>pom</type>\s*<scope>import", parent_pom)
    found = {}
    for e in events:
        d = e["data"]
        g, a = d["package"].split(":")
        bom = next((b for b in boms if g.startswith(b[0])), None)
        carrier = bom if bom and f"<artifactId>{a}</artifactId>" not in parent_pom else (g, a)
        u = found.setdefault((carrier[0], d["installed_version"]), {"carriers": set(), "packages": {}})
        u["carriers"].add(carrier)
        u["packages"][d["package"]] = d["installed_version"]
    return [{"key": f"{g}@{v}", **u} for (g, v), u in sorted(found.items())]


def edit_parent(repo, us):
    """Sobe os carriers das unidades `us` para a última release e o próprio parent em um patch (a property vai junto)."""
    pom = repo / "pom.xml"
    text = pom.read_text()
    carriers = sorted({c for u in us for c in u["carriers"]})
    new = [c for c in carriers if not re.search(rf"<artifactId>{re.escape(c[1])}</artifactId>\s*<version>", text)]
    if new:  # transitivo: entra no dependencyManagement com versão 0, que o plugin troca pela última release
        entries = "".join(f"      <dependency>\n        <groupId>{g}</groupId>\n        <artifactId>{a}</artifactId>\n        <version>0</version>\n      </dependency>\n" for g, a in new)
        text = text.replace("    </dependencies>\n  </dependencyManagement>", entries + "    </dependencies>\n  </dependencyManagement>")
        pom.write_text(text)
    if not carriers:
        return
    ignore = f"-Dmaven.version.ignore={PRE_RELEASE}"
    plugin(repo, "use-latest-releases", "-Dincludes=" + ",".join(f"{g}:{a}" for g, a in carriers), ignore)
    props = {p for g, a in carriers for p in re.findall(rf"<artifactId>{re.escape(a)}</artifactId>\s*<version>\$\{{([^}}]+)\}}", text)}
    if props:
        plugin(repo, "update-properties", "-DincludeProperties=" + ",".join(sorted(props)), ignore)


def apply(repo, patch):
    subprocess.run(["git", "apply", "-"], cwd=repo, input=patch, text=True, check=True)


def fail(repo, kind, log, d=None, keep=False):
    if not keep:
        shutil.rmtree(d, ignore_errors=True)
    return {"ok": False, "repo": repo, "kind": kind, "log": log[-3000:], "dir": d if keep else None}


def trial(base, us, keep=False):
    r = _trial(base, us, keep)
    print(f"prova [{', '.join(u['key'] for u in us)}]: " + ("verde" if r["ok"] else f"{r['kind']} em {r['repo']}"), file=sys.stderr, flush=True)
    return r


def _trial(base, us, keep):
    """Aplica `us` sobre cópias de `base` e constrói parent → lib → service. Dict: ok, repo e kind do que quebrou, log, osv, versions."""
    d = pathlib.Path(tempfile.mkdtemp())
    for r in REPOS:
        shutil.copytree(base[r], d / r, ignore=shutil.ignore_patterns("target"))
    p, lib, svc = (d / r for r in REPOS)
    pv, lv = patch_version(own_version(p, PARENT)), patch_version(own_version(lib, LIB))
    edit_parent(p, us)
    plugin(p, "set", f"-DnewVersion={pv}")
    # (repo, comandos de versão, goal de build); o goal do serviço é verify, o da lib e do parent é install
    steps = [(p, [], "install"),
             (lib, [("update-parent", f"-DparentVersion={pv}"), ("set", f"-DnewVersion={lv}")], "install"),
             (svc, [("update-parent", f"-DparentVersion={pv}"), ("set-property", "-Dproperty=demo-lib.version", f"-DnewVersion={lv}")], "verify")]
    for repo, edits, goal in steps:
        for g, *a in edits:
            plugin(repo, g, *a)
        for u in us:
            if repo.name in u.get("patch", {}):
                apply(repo, u["patch"][repo.name])
        rc, log, infra = mvn(repo, "-q", goal)
        if rc:
            kind = "timeout" if log == "timeout" else "resolve" if infra else "tests" if TESTS.search(log) else "build"
            return fail(repo.name, kind, log, d, keep)
    osv = scan(svc)
    bom = json.loads((svc / "target" / "bom.json").read_text())["components"]
    versions = {f"{c.get('group', '')}:{c['name']}": c["version"] for c in bom}
    r = {"ok": True, "osv": osv, "versions": versions, "dir": d}
    if not keep:  # o diff final é lido do diretório; a prova isolada de cada unidade não precisa dele
        r["dir"] = None
        shutil.rmtree(d, ignore_errors=True)
    return r


def residual(osv):
    """{pacote: ids dos advisories (id e aliases) que o re-scan ainda acusa}"""
    out = {}
    for res in osv["results"]:
        for p in res["packages"]:
            out.setdefault(p["package"]["name"], set()).update(i for v in p.get("vulnerabilities", []) for i in [v["id"], *v.get("aliases", [])])
    return out


def n2(base, ctx, u, r):
    """Gancho N2: um comando externo recebe o repositório que quebrou e o log; devolve patch.diff. Sem gancho (ou sem patch) mantém `r`.
    O patch vale para a unidade `u` e a prova se repete sobre o contexto `ctx` (as unidades já adotadas)."""
    hook = os.environ.get("N2_HOOK")
    if not hook or not r["dir"]:
        return r
    with tempfile.TemporaryDirectory() as t:
        t = pathlib.Path(t)
        shutil.copytree(r["dir"] / r["repo"], t / "in" / "repo")
        (t / "in" / "error.log").write_text(r["log"])
        (t / "out").mkdir()
        try:
            subprocess.run([*shlex.split(hook), str(t / "in"), str(t / "out")], check=True, timeout=HOOK_TIMEOUT)
            patch = (t / "out" / "patch.diff").exists()
        except (subprocess.SubprocessError, OSError):  # falha, saída diferente de zero ou timeout: N2 não resolveu esta unidade
            patch = False
        shutil.rmtree(r["dir"], ignore_errors=True)
        if not patch:
            return {**r, "dir": None}
        u["patch"] = {r["repo"]: (t / "out" / "patch.diff").read_text()}
    return trial(base, [*ctx, u], keep=True)  # a prova verde vira o `final`: o diff sai do diretório dela


def culprit(base, us, bad):
    """Bisseção: `bad` é a prova vermelha de `us`; acha a menor fatia inicial vermelha e devolve (unidade, prova vermelha)."""
    lo, hi = 0, len(us)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        r = trial(base, us[:mid])
        if r["ok"]:
            lo = mid
        else:
            hi, bad = mid, r
    return us[hi - 1], bad


def summary(log):
    """Primeiras linhas de erro do Maven (só para o result.json; o log inteiro não sai do passo)."""
    errs = [re.sub(r"/\S*?/(demo-(?:parent|lib|service))/", r"\1/", l.replace("[ERROR]", "").strip()) for l in log.splitlines() if "[ERROR]" in l]
    errs = [l for l in errs if l and not re.search(r"Help|COMPILATION ERROR|BUILD FAILURE|^For more|^Re-run|^-> ", l)]
    return " | ".join(errs[:2])[:300] or log.strip()[-200:]


def count(osv):
    return sum(len(p.get("vulnerabilities", [])) for res in osv["results"] for p in res["packages"])


def main(in_dir="/work", out="/work/fix"):
    in_dir, out = pathlib.Path(in_dir), pathlib.Path(out)
    events = [json.loads(p.read_text()) for p in sorted((in_dir / "events").glob("*.json"))]
    check_trace(events)
    base = {r: in_dir / "repos" / r for r in REPOS}
    shas = json.loads((in_dir / "shas.json").read_text())
    for r in REPOS:  # o commit que o scan viu, não o que main virou depois
        subprocess.run(["git", "checkout", "-q", "--force", "--detach", shas[r]], cwd=base[r], check=True)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy(in_dir / "shas.json", out)
    first = trial(base, [])  # sem unidades: prova que a base está verde, o piso do "sempre verde"
    if not first["ok"]:
        die(f"a base não fecha verde em {first['repo']} ({first['kind']}):\n" + first["log"])
    all_units = units(events, (base[PARENT] / "pom.xml").read_text())
    # 1. cada unidade sozinha: ["verde" ou a prova vermelha]
    alone = {u["key"]: trial(base, [u]) for u in all_units}
    chosen = [u for u in all_units if alone[u["key"]]["ok"]]
    # 2. as verdes juntas; combinação vermelha: a bisseção tira a culpada (no máximo MAX_VOLTAS vezes; passou disso, parte da base)
    voltas = 0
    while chosen:
        final = trial(base, chosen, keep=True)
        if final["ok"]:
            break
        if voltas == MAX_VOLTAS:
            chosen = []  # o passo 3 refaz o conjunto de forma gulosa: uma unidade por vez, enquanto fica verde
            break
        bad, _ = culprit(base, chosen, final)
        chosen = [u for u in chosen if u is not bad]
        shutil.rmtree(final["dir"] or "", ignore_errors=True)
        voltas += 1
    if not chosen:
        final = {**first, "dir": None}
    # 3. as que ficaram de fora tentam de novo sobre o conjunto verde, uma por vez (uma depende da outra: commons-compress pede um commons-io novo);
    # entra a que mantém tudo verde, e é essa prova (ou o N2) que explica a que não entrou
    proof = {}
    for u in all_units:
        if u in chosen:
            continue
        r = n2(base, chosen, u, trial(base, [*chosen, u], keep=True))
        if r["ok"]:
            shutil.rmtree(final["dir"] or "", ignore_errors=True)
            chosen, final = [*chosen, u], r
        else:
            proof[u["key"]] = r
            shutil.rmtree(r["dir"] or "", ignore_errors=True)

    left = residual(final["osv"])
    packages = []
    for u in all_units:
        r = proof.get(u["key"])
        a = alone[u["key"]]
        for pkg, frm in u["packages"].items():
            row = {"package": pkg, "from": frm, "unit": u["key"], "sozinho": "verde" if a["ok"] else f"{a['kind']} em {a['repo']}"}
            if r:
                row.update(status="voltou", repo=r["repo"], kind=r["kind"], detail=summary(r["log"]))
            else:
                row.update(to=final["versions"].get(pkg), status="sem_correcao" if left.get(pkg) else "corrigido", restam=sorted(left.get(pkg, [])))
            packages.append(row)
    by = {p["package"]: p for p in packages}

    versions = {}
    if chosen:
        for r in REPOS:
            diff = subprocess.run(["git", "diff", "--no-color"], cwd=final["dir"] / r, capture_output=True, text=True, check=True).stdout
            (out / r).mkdir(exist_ok=True)
            (out / r / "patch.diff").write_text(diff)
        versions = {PARENT: own_version(final["dir"] / PARENT, PARENT), LIB: own_version(final["dir"] / LIB, LIB)}
        shutil.rmtree(final["dir"], ignore_errors=True)

    for sub in ("fixes", "recommendations"):
        (out / sub).mkdir(exist_ok=True)
    patched = {u["key"] for u in all_units if "patch" in u}  # o verde da unidade veio de patch do gancho N2
    for e in events:
        d, row = e["data"], by[e["data"]["package"]]
        level = {"level": "N2" if row["unit"] in patched else "N1"}
        gone = not {d["advisory_id"], *d.get("aliases", [])} & set(row.get("restam", []))
        to = {"to_version": row["to"]} if row.get("to") else {}
        if row["status"] == "voltou":
            ev = [ref("maven", "build-test", f"{row['kind']} falhou em {row['repo']}")]
            rec = recommendation(e, "failed", {"ci_status": "failed", "rescan": "not_run", "evidence": ev}, REASON[row["kind"]])
        elif gone:
            ev = [ref("maven", "build-test", "build e testes verdes em demo-lib e demo-service"), ref(EVIDENCE, "rescan", f"{d['advisory_id']} ausente do re-scan")]
            (out / "fixes" / f"{event_name(e)}.json").write_text(json.dumps({**to, **level, "ci_status": "pending", "rescan": "clean", "evidence": ev}, ensure_ascii=False))
            continue
        else:
            ev = [ref(EVIDENCE, "rescan", "advisory presente na última release publicada")]
            rec = recommendation(e, "no_change", {**to, **level, "ci_status": "passed", "rescan": "still_vulnerable", "evidence": ev})
        (out / "recommendations" / f"{event_name(e)}.json").write_text(json.dumps(rec, ensure_ascii=False))
    shutil.copytree(in_dir / "events", out / "events", dirs_exist_ok=True)
    result = {"round": datetime.now(timezone.utc).strftime("%Y%m%d"), "org": events[0]["data"]["repository"].split("/")[0], "versions": versions,
              "advisories_restantes": count(final["osv"]), "packages": packages}
    (out / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1))
    print("ready" if chosen else "done")


if __name__ == "__main__":
    main(*sys.argv[1:])
