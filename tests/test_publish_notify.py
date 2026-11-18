import hashlib
import json
import pathlib
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from steps.notify import notify
from steps.publish import publish
from steps.scan.scan import event_name, events

OSV = json.loads((pathlib.Path(__file__).parent / "fixtures" / "osv-scanner.json").read_text())
EVENT = next(e for e in events(OSV, "open-eda-labs/demo-service", "/work/repo", datetime(2026, 11, 15, tzinfo=timezone.utc))
             if e["data"]["advisory_id"] == "GHSA-599f-7c49-w659")
FIX = {"to_version": "1.10.0", "ci_status": "pending", "rescan": "clean",
       "evidence": [{"collector": "osv-scanner", "query_id": "rescan", "value": "GHSA-599f-7c49-w659 ausente do re-scan"}]}
RESULT = {
    "round": "20261115", "org": "open-eda-labs", "versions": {"demo-parent": "1.0.1", "demo-lib": "1.0.1"}, "advisories_restantes": 4,
    "packages": [
        {"package": "org.apache.commons:commons-text", "from": "1.9", "to": "1.10.0", "status": "corrigido", "restam": []},
        {"package": "com.h2database:h2", "from": "1.4.200", "to": "2.4.0", "status": "sem_correcao", "restam": ["GHSA-1", "CVE-1", "GHSA-2", "CVE-2"]},
        {"package": "org.yaml:snakeyaml", "from": "1.33", "status": "voltou", "repo": "demo-lib", "kind": "tests", "detail": "segredo do log"},
        {"package": "org.json:json", "from": "20220320", "status": "voltou", "repo": "demo-service", "kind": "build", "detail": "x"},
    ],
}


def sh(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Três remotos locais no lugar de github.com (url.insteadOf) e, por repositório, um patch real gerado por git diff."""
    in_dir, shas = tmp_path / "in", {}
    for repo in publish.REPOS:
        seed = tmp_path / "seed" / repo
        seed.mkdir(parents=True)
        sh("init", "-b", "main", cwd=seed)
        (seed / "pom.xml").write_text("<v>1.0.0</v>\n")
        sh("add", ".", cwd=seed)
        sh("commit", "-m", "base", cwd=seed)
        shas[repo] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=seed, capture_output=True, text=True, check=True).stdout.strip()
        shutil.copytree(seed, tmp_path / "repos" / repo)  # o clone que o scan deixou no volume
        (tmp_path / "open-eda-labs").mkdir(exist_ok=True)
        bare = tmp_path / "open-eda-labs" / f"{repo}.git"
        sh("clone", "--bare", str(seed), str(bare), cwd=tmp_path)
        (seed / "pom.xml").write_text("<v>1.0.1</v>\n")
        (in_dir / repo).mkdir(parents=True)
        (in_dir / repo / "patch.diff").write_text("" if repo == "demo-service" else subprocess.run(["git", "diff", "--no-color"], cwd=seed, capture_output=True, text=True, check=True).stdout)
        sh("checkout", "pom.xml", cwd=seed)
        (seed / "outro.txt").write_text("main avançou depois do scan\n")  # o PR tem de sair do SHA do scan, não deste commit
        sh("add", ".", cwd=seed)
        sh("commit", "-m", "depois", cwd=seed)
        sh("push", str(bare), "main", cwd=seed)
    cfg = tmp_path / "gitconfig"
    cfg.write_text(f'[url "file://{tmp_path}/"]\n\tinsteadOf = https://github.com/\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GITHUB_TOKEN", "token-de-teste")
    (in_dir / "result.json").write_text(json.dumps(RESULT))
    (in_dir / "shas.json").write_text(json.dumps(shas))
    (in_dir / "events").mkdir()
    (in_dir / "fixes").mkdir()
    (in_dir / "recommendations").mkdir()
    name = f"{event_name(EVENT)}.json"
    (in_dir / "events" / name).write_text(json.dumps(EVENT))
    (in_dir / "fixes" / name).write_text(json.dumps(FIX))
    return in_dir


def capture(monkeypatch, number=None, open_pr=None):
    posts = []
    monkeypatch.setattr(publish, "existing", lambda *a: open_pr)
    n = iter(range(7, 100))
    monkeypatch.setattr(publish, "post", lambda url, body, headers=None, shown=None: posts.append((url, body)) or (json.dumps({"number": next(n)}) if number else None))
    return posts


def heads(tmp_path, repo):
    return subprocess.run(["git", "branch", "--list", "vuln-fix/*"], cwd=tmp_path / "open-eda-labs" / f"{repo}.git", capture_output=True, text=True).stdout


def branch_of(world):
    return "vuln-fix/" + hashlib.sha256((world / "demo-parent" / "patch.diff").read_bytes()).hexdigest()[:12]


def test_dry_run_without_network_writes_prs_and_result_for_notify(world, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "1")
    monkeypatch.delenv("GITHUB_TOKEN")
    posts = capture(monkeypatch)
    monkeypatch.setattr(publish, "existing", lambda *a: pytest.fail("DRY_RUN não consulta a API"))
    shutil.rmtree(tmp_path / "open-eda-labs")  # qualquer clone ou fetch de rede falharia
    out = tmp_path / "out"
    publish.main(world, out, tmp_path / "repos")
    assert [u for u, _ in posts] == ["https://api.github.com/repos/open-eda-labs/demo-parent/pulls", "https://api.github.com/repos/open-eda-labs/demo-lib/pulls"]
    for _, body in posts:
        assert body["draft"] is True and body["base"] == "main" and body["head"] == branch_of(world)
    assert capsys.readouterr().out.count(f"git push origin HEAD:refs/heads/{branch_of(world)}") == 2
    prs = json.loads((out / "prs.json").read_text())
    assert prs == [{"repository": "open-eda-labs/demo-parent", "number": 1, "dry_run": True}, {"repository": "open-eda-labs/demo-lib", "number": 2, "dry_run": True}]
    assert json.loads((out / "result.json").read_text())["dry_run"] is True
    assert json.loads((out / "recommendations" / f"{event_name(EVENT)}.json").read_text())["fix"]["pr_number"] == 1
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.test/x")
    notify.main(out)  # o notify lê o que o publish deixou
    assert "Revisar PR: https://github.com/open-eda-labs/demo-lib/pull/2" in capsys.readouterr().out


SVC_PATCH = "diff --git a/pom.xml b/pom.xml\n--- a/pom.xml\n+++ b/pom.xml\n@@ -1 +1 @@\n-<v>1.0.0</v>\n+<v>1.0.1</v>\n"


def test_service_pr_opens_by_itself_when_the_round_has_a_service_patch(world, tmp_path, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "1")
    posts = capture(monkeypatch)
    publish.main(world, tmp_path / "out", tmp_path / "repos")
    assert [u.split("/")[-2] for u, _ in posts] == ["demo-parent", "demo-lib"]  # rodada de fix: o serviço não tem patch, não há PR dele
    posts.clear()
    (world / "demo-service" / "patch.diff").write_text(SVC_PATCH)
    publish.main(world, tmp_path / "out", tmp_path / "repos")
    assert [u.split("/")[-2] for u, _ in posts] == ["demo-parent", "demo-lib", "demo-service"]
    assert posts[2][1]["title"] == "fix(deps): demo-parent 1.0.1 e demo-lib 1.0.1"
    posts.clear()
    for r in ("demo-parent", "demo-lib"):  # rodada de release: só o serviço; o branch e o pr_opened vêm dele
        (world / r / "patch.diff").write_text("")
    publish.main(world, tmp_path / "out", tmp_path / "repos")
    assert [u.split("/")[-2] for u, _ in posts] == ["demo-service"]
    assert posts[0][1]["head"] == "vuln-fix/" + hashlib.sha256(SVC_PATCH.encode()).hexdigest()[:12]
    rec = json.loads((tmp_path / "out" / "recommendations" / f"{event_name(EVENT)}.json").read_text())
    assert rec["fix"]["pr_number"] == 1 and rec["fix"]["patch_sha256"] == hashlib.sha256(SVC_PATCH.encode()).hexdigest()


def test_nothing_to_publish_without_any_patch(world, tmp_path, monkeypatch):
    for r in publish.REPOS:
        (world / r / "patch.diff").write_text("")
    with pytest.raises(SystemExit):
        publish.main(world, tmp_path / "out", tmp_path / "repos")


def test_lib_only_round_titles_the_pr_by_the_parent(world, tmp_path, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "1")
    posts = capture(monkeypatch)
    (world / "demo-parent" / "patch.diff").write_text("")
    (world / "result.json").write_text(json.dumps({**RESULT, "packages": []}))
    (world / "fixes" / f"{event_name(EVENT)}.json").unlink()
    publish.main(world, tmp_path / "out", tmp_path / "repos")
    assert [u.split("/")[-2] for u, _ in posts] == ["demo-lib"] and posts[0][1]["title"] == "fix(deps): demo-lib no demo-parent 1.0.1"


def test_pr_body_lists_fixed_and_not_fixed_with_reason():
    body = publish.pr_body("demo-parent", RESULT)
    assert "Nova versão: 1.0.1" in body and "Corrigidos (1):" in body and "- org.apache.commons:commons-text: 1.9 para 1.10.0" in body
    assert "com.h2database:h2: 1.4.200 para 2.4.0; restam 4 advisories" in body
    assert "org.yaml:snakeyaml: 1.33 ficou; testes falharam em demo-lib" in body
    assert "org.json:json: 20220320 ficou; build falhou em demo-service" in body
    assert "segredo do log" not in body and "Advisories restantes no re-scan final: 4" in body and "merge e a tag de release são humanos" in body
    assert "regra de ouro" in body and "Sobe o parent para 1.0.1 e a demo-lib para 1.0.1" in publish.pr_body("demo-service", RESULT)


def test_real_run_pushes_branch_never_merges_and_writes_pr_opened(world, tmp_path, monkeypatch):
    posts = capture(monkeypatch, number=True)
    publish.main(world, tmp_path / "out", tmp_path / "repos")
    br = branch_of(world)
    assert br in heads(tmp_path, "demo-parent") and br in heads(tmp_path, "demo-lib") and heads(tmp_path, "demo-service") == ""
    bare = tmp_path / "open-eda-labs" / "demo-parent.git"
    git = lambda *a: subprocess.run(["git", *a], cwd=bare, capture_output=True, text=True, check=True).stdout.strip()
    assert git("rev-parse", f"{br}~1") == json.loads((world / "shas.json").read_text())["demo-parent"] != git("rev-parse", "main")  # sobre o SHA do scan, não sobre main
    assert not any("merge" in u or "tags" in u for u, _ in posts)
    assert json.loads((tmp_path / "out" / "prs.json").read_text()) == [{"repository": "open-eda-labs/demo-parent", "number": 7}, {"repository": "open-eda-labs/demo-lib", "number": 8}]
    rec = json.loads((tmp_path / "out" / "recommendations" / f"{event_name(EVENT)}.json").read_text())
    assert rec["status"] == "pr_opened" and rec["fix"]["pr_number"] == 7 and len(rec["fix"]["patch_sha256"]) == 64  # o PR do parent, onde o fix nasce


def test_second_run_with_open_pr_does_nothing_and_succeeds(world, tmp_path, monkeypatch):
    posts = capture(monkeypatch, number=True, open_pr=42)
    publish.main(world, tmp_path / "out", tmp_path / "repos")
    assert posts == [] and heads(tmp_path, "demo-parent") == ""  # sem push e sem PR novo
    assert json.loads((tmp_path / "out" / "prs.json").read_text())[0]["number"] == 42


def test_invalid_patch_stops_the_round_before_any_push(world, tmp_path, monkeypatch):
    posts = capture(monkeypatch, number=True)
    (world / "demo-lib" / "patch.diff").write_text("diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-a\n+b\n")
    with pytest.raises(ValueError):
        publish.main(world, tmp_path / "out", tmp_path / "repos")
    assert posts == [] and heads(tmp_path, "demo-parent") == "" and not (tmp_path / "out").exists()


SVC_HEAD = "diff --git a/pom.xml b/pom.xml\n--- a/pom.xml\n+++ b/pom.xml\n@@ -1,8 +1,8 @@\n"
PARENT_BLOCK = " <parent>\n   <groupId>labs.demo</groupId>\n   <artifactId>demo-parent</artifactId>\n-  <version>1.0.0</version>\n+  <version>1.0.1</version>\n </parent>\n"


def svc(body):
    return {"demo-service": SVC_HEAD + body}


def test_check_patches_accepts_parent_version_and_lib_property():
    publish.check_patches(svc(PARENT_BLOCK + "-  <demo-lib.version>1.0.0</demo-lib.version>\n+  <demo-lib.version>1.0.1</demo-lib.version>\n"))
    publish.check_patches(svc(" <artifactId>demo-lib</artifactId>\n+<version>${demo-lib.version}</version>\n"))
    publish.check_patches({"demo-lib": "diff --git a/src/A.java b/src/A.java\n@@ -1 +1 @@\n-a\n+b\n"})


@pytest.mark.parametrize("body", [
    " <artifactId>commons-text</artifactId>\n+<version>1.15.0</version>\n",  # versão de terceiro com valor literal
    PARENT_BLOCK + " <dependency>\n+<version>2.0</version>\n+<artifactId>x</artifactId>\n",  # versão antes do artifactId, não herda o do parent
    "+  <jetty.version>12.1.15</jetty.version>\n",  # property de terceiro
    "+<version>1.0</version>\n",  # sem artifactId no hunk: recusa
])
def test_check_patches_rejects_third_party_version_in_service(body):
    with pytest.raises(ValueError, match="versão de terceiro"):
        publish.check_patches(svc(body))


@pytest.mark.parametrize("path", [".github/workflows/ci.yml", "Dockerfile", "docker/Dockerfile", "scripts/build.sh", "run.sh"])
def test_check_patches_rejects_ci_dockerfile_and_scripts(path):
    with pytest.raises(ValueError, match="patch toca"):
        publish.check_patches({"demo-parent": f"diff --git a/{path} b/{path}\n@@ -1 +1 @@\n-a\n+b\n"})


def test_check_patches_accepts_look_alikes_and_enforces_line_limit(monkeypatch):
    publish.check_patches({"demo-lib": "diff --git a/src/github/Dockerfiles.txt b/src/github/Dockerfiles.txt\n@@ -1 +1 @@\n-a\n+b\n"})
    big = "diff --git a/src/A.java b/src/A.java\n@@ -1 +1 @@\n" + "+x\n" * (publish.MAX_DIFF_LINES - 2)
    publish.check_patches({"demo-lib": big})  # exatamente no limite
    with pytest.raises(ValueError, match="maior que"):
        publish.check_patches({"demo-lib": big, "demo-parent": "diff --git a/pom.xml b/pom.xml\n"})


def test_publish_rejects_invalid_fix(world, tmp_path):
    (world / "fixes" / f"{event_name(EVENT)}.json").write_text(json.dumps({**FIX, "rescan": "maybe"}))
    with pytest.raises(ValueError):
        publish.main(world, tmp_path / "out", tmp_path / "repos")


def test_notify_dry_run_one_message_with_pr_links(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "1")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.test/segredo-de-teste")
    monkeypatch.setenv("TRACEPARENT", "00-" + "ab" * 16 + "-" + "cd" * 8 + "-01")
    (tmp_path / "result.json").write_text(json.dumps(RESULT))
    (tmp_path / "prs.json").write_text(json.dumps([{"repository": "open-eda-labs/demo-parent", "number": 7}, {"repository": "open-eda-labs/demo-lib", "number": 8}]))
    notify.main(tmp_path)
    out = capsys.readouterr().out
    assert "segredo-de-teste" not in out and "segredo do log" not in out
    req = json.loads(out)
    assert req["POST"] == "$SLACK_WEBHOOK_URL"
    text = req["body"]["text"]
    assert "1 pacotes corrigidos, 2 voltaram" in text and "1 ainda acusados." in text
    assert "Revisar PR: https://github.com/open-eda-labs/demo-parent/pull/7" in text and "Revisar PR: https://github.com/open-eda-labs/demo-lib/pull/8" in text
    assert text.endswith("trace_id: " + "ab" * 16) and "cdcd" not in text
    assert req["body"]["mrkdwn"] is False and req["body"]["unfurl_links"] is False


def test_notify_refuses_when_no_pr(tmp_path, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "1")
    (tmp_path / "result.json").write_text(json.dumps(RESULT))
    (tmp_path / "prs.json").write_text("[]")
    with pytest.raises(SystemExit):
        notify.main(tmp_path)
