import json
import pathlib
import re
import subprocess
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from steps.common import recommendation
from steps.fix import fix
from steps.scan.scan import events

OSV = json.loads((pathlib.Path(__file__).parent / "fixtures" / "osv-scanner.json").read_text())
EVENTS = events(OSV, "open-eda-labs/demo-service", "/work/repo", datetime(2026, 11, 15, tzinfo=timezone.utc))
PARENT_POM = """<project>
  <artifactId>demo-parent</artifactId>
  <version>1.0.0</version>
  <properties><log4j2.version>2.14.1</log4j2.version></properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>${jackson.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
      <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>${log4j2.version}</version>
      </dependency>
      <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-text</artifactId>
        <version>1.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""


def ev(package, version, advisory="GHSA-599f-7c49-w659"):
    e = json.loads(json.dumps(EVENTS[0]))
    e["data"].update(package=package, installed_version=version, advisory_id=advisory)
    e["id"] = f"{advisory}:open-eda-labs/demo-service:{package}"
    return e


@pytest.mark.parametrize("v", ["2.0.0-alpha1", "1.0.0-beta-2", "5.0.0-RC1", "5.0.0.RC1", "3.0.0-M4", "3.0.0.M4", "12.1.0.beta0", "4.0.0-alpha.1.2", "1.0-SNAPSHOT",
                               "2.0.0-rc-1", "1.0.0-preview3", "2.5.0.CR2", "7.0.0-ea", "1.0-dev-3", "2.0-nightly"])
def test_pre_release_is_ignored(v):
    assert re.fullmatch(fix.PRE_RELEASE, v)


@pytest.mark.parametrize("v", ["9.4.40.v20210413", "33.8.0-jre", "20260814", "2.26.1", "1.0.0.Final", "5.3.39", "4.5.13", "1.10.0", "6.0.0", "2.0.0-android", "1.4.0.RELEASE"])
def test_release_is_kept(v):
    assert not re.fullmatch(fix.PRE_RELEASE, v)


def test_units_pick_carrier_and_family():
    us = {u["key"]: u for u in fix.units([ev("org.apache.logging.log4j:log4j-core", "2.14.1"), ev("org.apache.logging.log4j:log4j-api", "2.14.1"),
                                          ev("com.fasterxml.jackson.core:jackson-databind", "2.13.2"), ev("com.fasterxml.jackson.core:jackson-core", "2.13.2"),
                                          ev("org.apache.commons:commons-text", "1.9"), ev("net.minidev:json-smart", "2.5.0")], PARENT_POM)}
    assert us["com.fasterxml.jackson@2.13.2"]["carriers"] == {("com.fasterxml.jackson", "jackson-bom")}  # membro de BOM sobe o BOM
    assert len(us["com.fasterxml.jackson@2.13.2"]["packages"]) == 2
    assert us["org.apache.logging.log4j@2.14.1"]["carriers"] == {("org.apache.logging.log4j", "log4j-core"), ("org.apache.logging.log4j", "log4j-api")}
    assert us["org.apache.commons@1.9"]["carriers"] == {("org.apache.commons", "commons-text")}
    assert us["net.minidev@2.5.0"]["carriers"] == {("net.minidev", "json-smart")}  # transitivo: passa a ser fixado no parent
    assert len(us) == 4


def test_edit_parent_builds_plugin_commands(tmp_path, monkeypatch):
    (tmp_path / "pom.xml").write_text(PARENT_POM)
    calls = []
    monkeypatch.setattr(fix, "plugin", lambda cwd, goal, *a: calls.append((goal, *a)))
    us = fix.units([ev("org.apache.logging.log4j:log4j-core", "2.14.1"), ev("com.fasterxml.jackson.core:jackson-core", "2.13.2"), ev("net.minidev:json-smart", "2.5.0")], PARENT_POM)
    fix.edit_parent(tmp_path, us)
    ignore = f"-Dmaven.version.ignore={fix.PRE_RELEASE}"
    assert calls == [
        ("use-latest-releases", "-Dincludes=com.fasterxml.jackson:jackson-bom,net.minidev:json-smart,org.apache.logging.log4j:log4j-core", ignore),
        ("update-properties", "-DincludeProperties=jackson.version,log4j2.version", ignore),
    ]
    text = (tmp_path / "pom.xml").read_text()  # o transitivo entrou com versão 0 para o plugin trocar
    assert "<artifactId>json-smart</artifactId>\n        <version>0</version>" in text and text.count("json-smart") == 1


def test_plugin_command_and_single_retry_layer(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(fix, "mvn", lambda cwd, *a: seen.append(a) or (0, "", False))
    fix.plugin(tmp_path, "set", "-DnewVersion=1.0.1")
    assert seen == [(f"{fix.PLUGIN}:set", "-DgenerateBackupPoms=false", "-DnewVersion=1.0.1")] and "2.19.1" in fix.PLUGIN
    for answer in ((1, "ArrayIndexOutOfBoundsException", False), (0, "Could not transfer metadata x from/to central", True)):
        seen.clear()
        monkeypatch.setattr(fix, "mvn", lambda cwd, *a, answer=answer: seen.append(a) or answer)
        with pytest.raises(SystemExit):  # resultado incompleto ou falha é infraestrutura, nunca "limpo"; o plugin não repete por cima do mvn
            fix.plugin(tmp_path, "set")
        assert len(seen) == 1


def test_mvn_retries_central_429_then_succeeds(monkeypatch, tmp_path):
    answers = iter([(1, "status code: 429"), (0, "ok")])
    monkeypatch.setattr(fix.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=(x := next(answers))[0], stdout=x[1], stderr=""))
    monkeypatch.setattr(fix, "WAIT", 0)
    assert fix.mvn(tmp_path, "-q", "verify") == (0, "ok", False)
    monkeypatch.setattr(fix.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="Could not find artifact a:b:1", stderr=""))
    assert fix.mvn(tmp_path, "-q", "verify")[2] is True  # persistente depois das tentativas: sinalizado como infra


def test_summary_drops_noise_and_local_paths():
    log = "[ERROR] COMPILATION ERROR :\n[ERROR] /tmp/x/y/demo-lib/src/A.java:[3,1] cannot find symbol\n[ERROR] -> [Help 1]\n"
    assert fix.summary(log) == "demo-lib/src/A.java:[3,1] cannot find symbol"


def sh(d, *a):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d, check=True, capture_output=True, text=True).stdout.strip()


def git_repo(path, changed):
    path.mkdir(parents=True)
    run = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=path, check=True, capture_output=True)
    run("init", "-b", "main")
    pom = lambda v: f"<artifactId>{path.name}</artifactId>\n<version>{v}</version>\n"
    (path / "pom.xml").write_text(pom("1.0.0"))
    run("add", ".")
    run("commit", "-m", "base")
    if changed:
        (path / "pom.xml").write_text(pom("1.0.1"))


@pytest.fixture
def world(tmp_path):
    ins = tmp_path / "in"
    (ins / "events").mkdir(parents=True)
    for e in EVENTS:
        (ins / "events" / f"{fix.event_name(e)}.json").write_text(json.dumps(e))
    for r in fix.REPOS:
        git_repo(ins / "repos" / r, False)
    (ins / "repos" / fix.PARENT / "pom.xml").write_text(PARENT_POM)
    shas = {}
    for r in fix.REPOS:
        d = ins / "repos" / r
        sh(d, "add", "."), sh(d, "commit", "-q", "--allow-empty", "-m", "scan")
        shas[r] = sh(d, "rev-parse", "HEAD")
        (d / "depois.txt").write_text("main avançou depois do scan")  # o fix tem de voltar ao SHA de shas.json
        sh(d, "add", "."), sh(d, "commit", "-qm", "depois")
    (ins / "shas.json").write_text(json.dumps(shas))
    return ins


def fake_trial(tmp_path, red, together=(), residual=(), needs=None):
    """Executor falso: build vermelho para as chaves em `red`, para `together` só quando juntas, para `needs` {k: outra} sem a outra;
    advisory sobrando nos pacotes de `residual`."""
    n = []

    def mk(us):
        d = tmp_path / f"t{len(n)}"
        n.append(d)
        for r in fix.REPOS:
            git_repo(d / r, bool(us))
        return d

    def trial(base, us, keep=False):
        keys = {u["key"] for u in us}
        bad = next((k for k in sorted(u["key"] for u in us if "patch" not in u) if k in red), None)  # patch do gancho conserta a unidade
        if bad:
            return {"ok": False, "repo": "demo-lib", "kind": "tests", "log": f"[ERROR] Tests run: 3, Failures: 1 em {bad}", "dir": mk(us) if keep else None}
        lacking = next((k for k in sorted(keys) if (needs or {}).get(k) not in keys | {None}), None)
        if lacking:
            return {"ok": False, "repo": "demo-lib", "kind": "tests", "log": f"[ERROR] NoClassDefFound em {lacking}", "dir": None}
        if set(together) <= keys and together:
            return {"ok": False, "repo": "demo-service", "kind": "build", "log": "[ERROR] cannot find symbol", "dir": None}
        d = mk(us)
        pk = [p for u in us for p in u["packages"]]
        osv = {"results": [{"packages": [{"package": {"name": p}, "vulnerabilities": [{"id": e["data"]["advisory_id"]} for e in EVENTS if e["data"]["package"] == p] if p in residual else []} for p in pk]}]}
        return {"ok": True, "osv": osv, "versions": {p: "9.9.9" for p in pk}, "dir": d if keep else None}
    return trial


def run_main(world, tmp_path, monkeypatch, plan=({}, {}), **kw):
    monkeypatch.setattr(fix, "trial", fake_trial(tmp_path, **kw))
    monkeypatch.setattr(fix, "release", lambda repo: None)
    monkeypatch.setattr(fix, "release_plan", lambda base, tags: plan)  # sem release nova por padrão
    out = tmp_path / "out"
    fix.main(world, out)
    return out, json.loads((out / "result.json").read_text())


def status(result):
    return {p["package"].split(":")[1]: (p["status"], p.get("repo"), p.get("kind")) for p in result["packages"]}


def test_loop_reverts_failing_unit_and_ends_green(world, tmp_path, monkeypatch, capsys):
    out, result = run_main(world, tmp_path, monkeypatch, red={"org.json@20220320"}, residual={"org.eclipse.jetty:jetty-server"})
    s = status(result)
    assert s["json"] == ("voltou", "demo-lib", "tests")
    assert s["jetty-server"][0] == "sem_correcao" and s["commons-text"][0] == "corrigido" and s["log4j-core"][0] == "corrigido"
    assert result["advisories_restantes"] == sum(e["data"]["package"] == "org.eclipse.jetty:jetty-server" for e in EVENTS)
    assert capsys.readouterr().out.strip() == "ready"
    for r in (fix.PARENT, fix.LIB):  # um patch.diff por repositório alterado; o serviço não tem release a que apontar
        assert (out / r / "patch.diff").read_text().startswith("diff --git")
    assert not (out / fix.SERVICE).exists()
    assert result["versions"] == {"demo-parent": "1.0.1", "demo-lib": "1.0.1"}
    shas = json.loads((world / "shas.json").read_text())
    assert json.loads((out / "shas.json").read_text()) == shas  # o publish trabalha nos mesmos SHAs
    assert all(sh(world / "repos" / r, "rev-parse", "HEAD") == shas[r] and not (world / "repos" / r / "depois.txt").exists() for r in fix.REPOS)


def test_recommendations_one_per_advisory(world, tmp_path, monkeypatch):
    out, result = run_main(world, tmp_path, monkeypatch, red={"org.json@20220320"}, residual={"org.eclipse.jetty:jetty-server"})
    recs = {json.loads(p.read_text())["fix"]["package"].split(":")[1]: json.loads(p.read_text()) for p in (out / "recommendations").glob("*.json")}
    assert recs["json"]["status"] == "failed" and recs["json"]["failure_reason"] == "tests_failed"
    assert recs["jetty-server"]["status"] == "no_change" and recs["jetty-server"]["fix"]["rescan"] == "still_vulnerable"
    fixed = {json.loads((world / "events" / p.name).read_text())["data"]["package"] for p in (out / "fixes").glob("*.json")}
    assert "org.apache.commons:commons-text" in fixed and "org.json:json" not in fixed
    assert not any(r["status"] == "pr_opened" for r in recs.values())  # o pr_opened é do publish
    n_events = len(list((world / "events").glob("*.json")))
    assert len(list((out / "recommendations").glob("*.json"))) + len(list((out / "fixes").glob("*.json"))) == n_events


def test_loop_bisects_combination_failure(world, tmp_path, monkeypatch):
    # commons-text e json-smart passam sozinhas e quebram juntas: a bisseção tira uma e a combinação fecha
    out, result = run_main(world, tmp_path, monkeypatch, red=set(), together={"org.apache.commons@1.9", "net.minidev@2.5.0"})
    s = status(result)
    assert [v[0] for k, v in s.items() if k in ("commons-text", "json-smart")].count("voltou") == 1
    back = next(v for v in s.values() if v[0] == "voltou")
    assert back[1:] == ("demo-service", "build")
    assert all(v[0] == "corrigido" for v in s.values() if v[0] != "voltou")


def test_unit_that_needs_another_is_adopted_in_context(world, tmp_path, monkeypatch):
    # commons-compress pede um commons-io novo: sozinho quebra, sobre o conjunto verde passa
    out, result = run_main(world, tmp_path, monkeypatch, red=set(), needs={"org.json@20220320": "org.apache.commons@1.9"})
    row = next(p for p in result["packages"] if p["package"] == "org.json:json")
    assert row["status"] == "corrigido" and row["sozinho"] == "tests em demo-lib"


def test_nothing_closes_ends_on_base_without_patch(world, tmp_path, monkeypatch, capsys):
    keys = {u["key"] for u in fix.units(EVENTS, PARENT_POM)}
    out, result = run_main(world, tmp_path, monkeypatch, red=keys)
    assert {v[0] for v in status(result).values()} == {"voltou"} and result["versions"] == {}
    assert capsys.readouterr().out.strip() == "done" and not list(out.glob("*/patch.diff"))


def test_n2_hook_patch_is_kept_and_retried(world, tmp_path, monkeypatch):
    hook = tmp_path / "hook.sh"
    hook.write_text('#!/bin/sh\ntest -f "$1/error.log" && test -d "$1/repo" && printf "x" > "$2/patch.diff"\n')
    hook.chmod(0o755)
    monkeypatch.setenv("N2_HOOK", str(hook))
    u = {"key": "k", "carriers": set(), "packages": {}}
    bad = tmp_path / "bad"
    git_repo(bad / "demo-lib", True)
    calls = []
    monkeypatch.setattr(fix, "trial", lambda base, us, keep=False: calls.append(us[0].get("patch")) or {"ok": True, "dir": None})
    r = fix.n2({}, [], u, {"ok": False, "repo": "demo-lib", "kind": "tests", "log": "falhou", "dir": bad})
    assert r["ok"] and u["patch"] == {"demo-lib": "x"} and calls == [{"demo-lib": "x"}]
    monkeypatch.delenv("N2_HOOK")  # sem gancho a prova vermelha segue
    assert fix.n2({}, [], {"key": "k"}, {"ok": False, "dir": None})["ok"] is False


def hook(tmp_path, body):
    h = tmp_path / "hook.sh"
    h.write_text(f"#!/bin/sh\n{body}\n")
    h.chmod(0o755)
    return str(h)


def levels(out):
    return {json.loads((out / "fixes" / p.name).read_text()).get("to_version", p.name): json.loads((out / "fixes" / p.name).read_text())["level"] for p in (out / "fixes").glob("*.json")}


@pytest.mark.parametrize("body", ['printf x > "$2/patch.diff"; exit 1', "exit 3", "sleep 5"])
def test_n2_hook_failure_or_timeout_is_not_resolved_and_round_goes_on(world, tmp_path, monkeypatch, body):
    monkeypatch.setenv("N2_HOOK", hook(tmp_path, body))
    monkeypatch.setattr(fix, "HOOK_TIMEOUT", 0.3)
    out, result = run_main(world, tmp_path, monkeypatch, red={"org.json@20220320"})
    s = status(result)
    assert s["json"] == ("voltou", "demo-lib", "tests") and s["commons-text"][0] == "corrigido"  # a unidade volta, a rodada segue


def test_level_is_n2_only_when_the_hook_patch_made_it_green(world, tmp_path, monkeypatch):
    monkeypatch.setenv("N2_HOOK", hook(tmp_path, 'printf x > "$2/patch.diff"'))
    out, result = run_main(world, tmp_path, monkeypatch, red={"org.json@20220320"})
    by_pkg = {p["package"]: p for p in result["packages"]}
    assert by_pkg["org.json:json"]["status"] == "corrigido"
    lv = {}
    for f in (out / "fixes").glob("*.json"):
        pkg = json.loads((world / "events" / f.name).read_text())["data"]["package"]
        lv[pkg] = json.loads(f.read_text())["level"]
    assert lv["org.json:json"] == "N2" and lv["org.apache.commons:commons-text"] == "N1"


def test_n2_level_needs_prompt_and_model_in_the_recommendation(monkeypatch):
    fixb = {"level": "N2", "to_version": "1.10.0", "ci_status": "pending", "rescan": "clean", "evidence": [{"collector": "osv-scanner", "query_id": "q", "value": "v"}]}
    monkeypatch.delenv("N2_PROMPT", raising=False)
    with pytest.raises(ValueError):  # contrato: level N2 exige versions.prompt e versions.model
        recommendation(EVENTS[0], "pr_opened", fixb, pr_number=1, patch_sha256="a" * 64)
    monkeypatch.setenv("N2_PROMPT", "vuln-fix.v1")
    monkeypatch.setenv("N2_MODEL", "qwen3:4b")
    assert recommendation(EVENTS[0], "pr_opened", fixb, pr_number=1, patch_sha256="a" * 64)["versions"]["model"] == "qwen3:4b"


def test_too_many_rounds_falls_back_to_greedy_not_to_nothing(world, tmp_path, monkeypatch):
    monkeypatch.setattr(fix, "MAX_VOLTAS", 0)
    out, result = run_main(world, tmp_path, monkeypatch, red=set(), together={"org.apache.commons@1.9", "net.minidev@2.5.0"})
    s = status(result)
    assert [v[0] for k, v in s.items() if k in ("commons-text", "json-smart")].count("voltou") == 1  # uma por vez: só a que quebra o conjunto sai
    assert sum(v[0] == "corrigido" for v in s.values()) == len(s) - 1 and result["versions"]


def test_residual_collects_ids_and_aliases():
    left = fix.residual({"results": [{"packages": [{"package": {"name": "a:b"}, "vulnerabilities": [{"id": "GHSA-1", "aliases": ["CVE-1"]}]}, {"package": {"name": "c:d"}}]}]})
    assert left == {"a:b": {"GHSA-1", "CVE-1"}, "c:d": set()}


def test_patch_version():
    assert fix.patch_version("1.0.0") == "1.0.1" and fix.patch_version("1.0.9") == "1.0.10"


LS = "aaa\trefs/tags/v1.0.0\nbbb\trefs/tags/v1.0.1\nbbb\trefs/tags/v1.0.1^{}\nccc\trefs/tags/v1.0.10\nddd\trefs/tags/v2.0.0-rc1\neee\trefs/tags/v3.0\nfff\trefs/tags/release-9.9.9\nggg\trefs/tags/v1.0.2-beta.1\nhhh\trefs/heads/v8.8.8\n"


def test_latest_tag_is_highest_stable_ignoring_prerelease_and_odd_tags():
    assert fix.latest_tag(LS) == "1.0.10"  # 1.0.10 > 1.0.2 na ordem numérica; v2.0.0-rc1, v3.0, release-9.9.9 e branch ficam de fora
    assert fix.latest_tag("") is None and fix.latest_tag("a\trefs/tags/v1.0.0-rc1\n") is None


def poms(tmp_path, svc=("1.0.0", "1.0.0"), lib_parent="1.0.1"):
    """Três repositórios com só o pom.xml: `svc` = (<parent>, demo-lib.version) do serviço."""
    block = lambda v: f"<parent>\n<groupId>labs.demo</groupId>\n<artifactId>demo-parent</artifactId>\n<version>{v}</version>\n</parent>\n"
    for r, text in {"demo-parent": "<artifactId>demo-parent</artifactId>\n<version>1.0.1</version>\n",
                    "demo-lib": block(lib_parent) + "<artifactId>demo-lib</artifactId>\n<version>1.0.1</version>\n",
                    "demo-service": block(svc[0]) + f"<artifactId>demo-service</artifactId>\n<version>0.1.0</version>\n<properties><demo-lib.version>{svc[1]}</demo-lib.version></properties>\n"}.items():
        (tmp_path / r).mkdir()
        (tmp_path / r / "pom.xml").write_text(text)
    return {r: tmp_path / r for r in fix.REPOS}


def test_release_plan_service_follows_new_tags(tmp_path):
    edits, v = fix.release_plan(poms(tmp_path), ("1.0.1", "1.0.1"))
    assert edits == {"demo-service": [("update-parent", "-DparentVersion=[1.0.1]"), ("set-property", "-Dproperty=demo-lib.version", "-DnewVersion=1.0.1")]}
    assert v == {"demo-parent": "1.0.1", "demo-lib": "1.0.1"}


def test_release_plan_only_what_is_newer(tmp_path):
    edits, v = fix.release_plan(poms(tmp_path, svc=("1.0.1", "1.0.0")), ("1.0.1", "1.0.1"))
    assert edits == {"demo-service": [("set-property", "-Dproperty=demo-lib.version", "-DnewVersion=1.0.1")]} and v["demo-parent"] == "1.0.1"


@pytest.mark.parametrize("tags", [("1.0.0", "1.0.0"), (None, None), ("0.9.0", "1.0.0")])
def test_release_plan_nothing_new(tmp_path, tags):  # igual, sem tag ou tag mais velha que o referenciado
    assert fix.release_plan(poms(tmp_path), tags) == ({}, {})


def test_release_plan_lib_behind_parent_goes_first(tmp_path):
    edits, v = fix.release_plan(poms(tmp_path, lib_parent="1.0.0"), ("1.0.1", "1.0.1"))
    assert list(edits) == ["demo-lib", "demo-service"] and edits["demo-service"] == []
    assert edits["demo-lib"] == [("update-parent", "-DparentVersion=[1.0.1]"), ("set", "-DnewVersion=1.0.2")] and v == {"demo-parent": "1.0.1", "demo-lib": "1.0.2"}


def test_release_plan_lib_already_on_parent_tag_does_not_block_service(tmp_path):
    edits, _ = fix.release_plan(poms(tmp_path), ("1.0.1", "1.0.1"))
    assert list(edits) == ["demo-service"]


def test_release_reads_remote_tags_from_local_remote(tmp_path, monkeypatch):
    r = tmp_path / "demo-parent"
    r.mkdir()
    sh(r, "init", "-b", "main"), sh(r, "commit", "-q", "--allow-empty", "-m", "x")
    for t in ("v1.0.0", "v1.0.1", "v1.1.0-rc1"):
        sh(r, "tag", t)
    monkeypatch.setattr(fix, "REMOTE", str(tmp_path))
    assert fix.release("demo-parent") == "1.0.1"
    with pytest.raises(SystemExit):
        fix.release("inexistente")


SERVICE_ROUND = ({"demo-service": [("update-parent", "-DparentVersion=[1.0.1]")]}, {"demo-parent": "1.0.1", "demo-lib": "1.0.1"})


def test_service_round_green_writes_only_service_patch(world, tmp_path, monkeypatch, capsys):
    out, result = run_main(world, tmp_path, monkeypatch, plan=SERVICE_ROUND, red=set(), residual={"org.eclipse.jetty:jetty-server"})
    assert capsys.readouterr().out.strip() == "ready" and result["versions"] == SERVICE_ROUND[1]
    assert (out / fix.SERVICE / "patch.diff").read_text().startswith("diff --git")
    s = status(result)
    assert s["commons-text"][0] == "corrigido" and s["jetty-server"][0] == "sem_correcao" and len(result["packages"]) == len({e["data"]["package"] for e in EVENTS})


def test_service_round_that_breaks_has_no_service_patch_without_hook(world, tmp_path, monkeypatch, capsys):
    out, result = run_main(world, tmp_path, monkeypatch, plan=SERVICE_ROUND, red={"release"})
    assert capsys.readouterr().out.strip() == "done" and not list(out.glob("*/patch.diff")) and result["versions"] == {}
    assert {v[0] for v in status(result).values()} == {"voltou"}
    recs = [json.loads(p.read_text()) for p in (out / "recommendations").glob("*.json")]
    assert len(recs) == len(EVENTS) and {r["status"] for r in recs} == {"failed"}


def test_service_round_n2_hook_patch_makes_it_green(world, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("N2_HOOK", hook(tmp_path, 'printf x > "$2/patch.diff"'))
    out, result = run_main(world, tmp_path, monkeypatch, plan=SERVICE_ROUND, red={"release"})
    assert capsys.readouterr().out.strip() == "ready" and (out / fix.SERVICE / "patch.diff").exists()
    assert set(levels(out).values()) == {"N2"}


def test_lib_round_has_lib_patch_and_no_recommendations(world, tmp_path, monkeypatch, capsys):
    plan = ({"demo-lib": [("update-parent", "-DparentVersion=[1.0.1]")], "demo-service": []}, {"demo-parent": "1.0.1", "demo-lib": "1.0.2"})
    out, result = run_main(world, tmp_path, monkeypatch, plan=plan, red=set())
    assert capsys.readouterr().out.strip() == "ready" and result["packages"] == [] and not list((out / "fixes").glob("*.json")) and not list((out / "recommendations").glob("*.json"))
    assert (out / fix.LIB / "patch.diff").read_text().startswith("diff --git")
