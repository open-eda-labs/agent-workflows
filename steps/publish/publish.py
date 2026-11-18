"""Passo publish (sem modelo): patch.diff de cada repositório -> branch e PR draft. Único passo com credencial de escrita (D-02, D-31).

Uso: GITHUB_TOKEN=<token curto de GitHub App> python -m steps.publish.publish [/work/fix] [/work/publish] [/work/repos]
Entrada: a saída do fix em /work/fix (result.json, shas.json, <repo>/patch.diff, fixes/, events/, recommendations/). Um PR draft por
repositório com patch por rodada, na ordem parent, lib, service, sobre o commit que o scan viu (shas.json), nunca sobre main de novo. O fix só
grava patch do serviço na rodada que sobe parent e lib para releases já publicadas, então o PR do serviço abre quando o patch existe.
Antes de qualquer push, `check_patches` valida os patches. O branch é `vuln-fix/<12 hex do sha256 do primeiro patch>` (o do parent, onde o
fix nasce; na rodada de release, o da lib ou do serviço): com PR aberto nesse branch o passo não faz nada e reaproveita o número.
Saída: prs.json, result.json e recommendations/ em /work/publish (as do fix mais a `pr_opened`, com o primeiro PR da rodada).
Nunca faz merge nem tag. DRY_RUN=1: sem nenhum acesso à rede; usa os repositórios de /work/repos, aplica e comita o patch localmente, imprime a
requisição do PR em vez de enviá-la e grava prs.json e result.json com números de PR fictícios (`dry_run: true`).
"""

import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

from steps.common import check_trace, die, post, recommendation, validate
from steps.fix.fix import LIB, PARENT, REPOS, SERVICE

API = "https://api.github.com"
BASE = "main"  # base do PR; o conteúdo vem do commit do scan
MAX_DIFF_LINES = 1000  # linhas de diff (todos os patches somados) que um humano ainda revisa num PR draft
FORBIDDEN = re.compile(r"\.github/|(.*/)?Dockerfile$|.*\.sh$")  # re.match: `.github/` só no começo do caminho  # CI, imagem e scripts: o agente não mexe
VERSION_TAG = re.compile(r"<([\w.-]*version)>([^<]*)<")
REASON = {"build": "build falhou", "resolve": "dependência não resolvida", "tests": "testes falharam", "timeout": "tempo limite"}


def git(*args, cwd, env=None):
    return subprocess.run(["git", "-c", "user.name=vuln-fixer", "-c", "user.email=vuln-fixer@users.noreply.github.com", *args],
                          cwd=cwd, check=True, capture_output=True, text=True, env=env).stdout.strip()


def pr_body(repo, result):
    """Corpo do PR a partir do result.json (texto livre do log do Maven não entra)."""
    pk, v = result["packages"], result["versions"]
    done = [p for p in pk if p["status"] == "corrigido"]
    stuck = [p for p in pk if p["status"] == "sem_correcao"]
    back = [p for p in pk if p["status"] == "voltou"]
    intro = {PARENT: f"Sobe as versões de terceiros para a última release publicada. Nova versão: {v[PARENT]}. A regra de ouro (ADR-0005) manda o fix nascer aqui.",
             LIB: f"Aponta para o demo-parent {v[PARENT]} e passa a ser a versão {v[LIB]}; build e testes verdes.",
             SERVICE: f"Sobe o parent para {v[PARENT]} e a demo-lib para {v[LIB]}; nenhuma versão de terceiro mora no serviço."}[repo]
    lines = ["Correção automática N1 (ADR-0005, sem modelo).", "", intro, "", f"Corrigidos ({len(done)}):", ""]
    lines += [f"- {p['package']}: {p['from']} para {p['to']}" for p in done] or ["- nenhum"]
    lines += ["", f"Ainda acusados no re-scan final, sem correção nesta rodada ({len(stuck)}):", ""]
    lines += [f"- {p['package']}: {p['from']} para {p['to']}; restam {len(p['restam'])} advisories" for p in stuck] or ["- nenhum"]
    lines += ["", f"Não corrigidos, precisa de migração de código ({len(back)}):", ""]
    lines += [f"- {p['package']}: {p['from']} ficou; {REASON[p['kind']]} em {p['repo']}" for p in back] or ["- nenhum"]
    lines += ["", f"Advisories restantes no re-scan final: {result['advisories_restantes']}", "", "PR draft aberto pelo vuln fixer. O merge e a tag de release são humanos, com CI verde."]
    return "\n".join(lines)


def check_patches(patches):
    """{repo: texto do patch}. Levanta ValueError se o diff passa de MAX_DIFF_LINES, se algum patch toca `.github/`, Dockerfile ou `*.sh`, ou se
    o patch do serviço declara versão de terceiro: só o <version> do parent e a property demo-lib.version podem mudar (regra de ouro, ADR-0005)."""
    if sum(len(t.splitlines()) for t in patches.values()) > MAX_DIFF_LINES:
        raise ValueError(f"diff maior que {MAX_DIFF_LINES} linhas")
    for repo, text in patches.items():
        pom = artifact = None  # `artifact`: o último <artifactId> visto (contexto ou acréscimo) no hunk
        for line in text.splitlines():
            if m := re.match(r"diff --git a/(\S+) b/(\S+)", line):
                if any(FORBIDDEN.match(f) for f in m.groups()):
                    raise ValueError(f"{repo}: patch toca {m[2]}")
                pom, artifact = m[2].endswith("pom.xml"), None
            elif line.startswith("@@"):
                artifact = None
            elif repo == SERVICE and pom and line[:1] in " +":
                if re.search(r"</?(dependency|parent)>", line):
                    artifact = None  # a versão pode vir antes do artifactId: não herda o do bloco anterior
                if a := re.search(r"<artifactId>([^<]+)<", line):
                    artifact = a[1]
                if (v := VERSION_TAG.search(line)) and line[0] == "+":
                    ok = v[1] == "demo-lib.version" or (v[1] == "version" and (v[2].startswith("${") or artifact == PARENT))
                    if not ok:
                        raise ValueError(f"{repo}: versão de terceiro declarada no serviço: {line[1:].strip()}")


def existing(org, repo, branch, headers):
    """Número do PR aberto com este branch, ou None."""
    req = urllib.request.Request(f"{API}/repos/{org}/{repo}/pulls?head={org}:{branch}&state=open", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        prs = json.loads(resp.read())
    return prs[0]["number"] if prs else None


def open_pr(org, repo, sha, branch, patch, title, body, dry, repos):
    headers = {"Authorization": f"Bearer {os.environ.get('GITHUB_TOKEN', '')}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if not dry and (n := existing(org, repo, branch, headers)):
        print(f"PR #{n} já aberto em {org}/{repo} no branch {branch}: nada a fazer")
        return n
    work = tempfile.mkdtemp()
    if dry:  # sem rede: o repositório que o fix deixou no volume, no commit do scan
        shutil.copytree(repos / repo, work, dirs_exist_ok=True)
        git("checkout", "-q", "--force", "--detach", sha, cwd=work)
    else:
        git("init", "-q", cwd=work)
        git("fetch", "-q", "--depth", "1", f"https://github.com/{org}/{repo}.git", sha, cwd=work)
        git("checkout", "-q", "--detach", "FETCH_HEAD", cwd=work)
        git("remote", "add", "origin", f"https://github.com/{org}/{repo}.git", cwd=work)
    git("checkout", "-b", branch, cwd=work)
    subprocess.run(["git", "apply", "-"], cwd=work, input=patch, check=True)
    git("commit", "-a", "-m", title, cwd=work)
    if dry:
        print(f"git push origin HEAD:refs/heads/{branch}  (não executado em DRY_RUN; {org}/{repo})")
    else:
        token = base64.b64encode(f"x-access-token:{os.environ['GITHUB_TOKEN']}".encode()).decode()
        env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
               "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {token}"}
        git("push", "origin", f"HEAD:refs/heads/{branch}", cwd=work, env=env)
    resp = post(f"{API}/repos/{org}/{repo}/pulls", {"title": title, "head": branch, "base": BASE, "body": body, "draft": True}, headers)
    shutil.rmtree(work, ignore_errors=True)
    return json.loads(resp)["number"] if resp else None


def main(in_dir="/work/fix", out="/work/publish", repos="/work/repos"):
    in_dir, out, repos = pathlib.Path(in_dir), pathlib.Path(out), pathlib.Path(repos)
    result = json.loads((in_dir / "result.json").read_text())
    commits = json.loads((in_dir / "shas.json").read_text())
    org, dry = result["org"], os.environ.get("DRY_RUN") == "1"
    fixes, events = {}, []  # valida tudo antes de qualquer escrita
    for f in sorted((in_dir / "fixes").glob("*.json")):
        event = validate(json.loads((in_dir / "events" / f.name).read_text()), "alert-event")
        events.append(event)
        fixes[f.name] = (event, json.loads(f.read_text()))
        recommendation(event, "pr_opened", fixes[f.name][1], pr_number=1, patch_sha256="0" * 64)
    check_trace(events)
    patches = {r: (in_dir / r / "patch.diff").read_bytes() for r in REPOS if (in_dir / r / "patch.diff").exists()}
    patches = {r: p for r, p in patches.items() if p}
    if not patches:
        die("sem patch: nada a publicar")
    check_patches({r: p.decode() for r, p in patches.items()})
    shas = {r: hashlib.sha256(p).hexdigest() for r, p in patches.items()}
    lead = next(iter(patches))  # o primeiro de REPOS: o parent, ou, na rodada de release, a lib ou o serviço
    branch = f"vuln-fix/{shas[lead][:12]}"
    n = sum(p["status"] == "corrigido" for p in result["packages"])
    prs = []
    for repo in patches:
        title = f"fix(deps): demo-parent {result['versions'][PARENT]} e demo-lib {result['versions'][LIB]}" if repo == SERVICE else \
            f"fix(deps): {n} pacotes para a última release ({repo})" if n else f"fix(deps): demo-lib no demo-parent {result['versions'][PARENT]}"
        number = open_pr(org, repo, commits[repo], branch, patches[repo], title, pr_body(repo, result), dry, repos)
        prs.append({"repository": f"{org}/{repo}", "number": number or len(prs) + 1, **({"dry_run": True} if dry else {})})  # sem rede, número fictício
    out.mkdir(parents=True, exist_ok=True)
    (out / "recommendations").mkdir(exist_ok=True)
    shutil.copytree(in_dir / "recommendations", out / "recommendations", dirs_exist_ok=True)
    for name, (event, fix) in fixes.items():
        rec = recommendation(event, "pr_opened", fix, pr_number=prs[0]["number"], patch_sha256=shas[lead])
        (out / "recommendations" / name).write_text(json.dumps(rec, ensure_ascii=False))
    (out / "prs.json").write_text(json.dumps(prs))
    (out / "result.json").write_text(json.dumps({**result, **({"dry_run": True} if dry else {})}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
