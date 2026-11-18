# agent-workflows

WorkflowEventBinding e WorkflowTemplate de triagem, CronWorkflow vuln-scan e WorkflowTemplate vuln-fix do vuln fixer, e imagens dos passos sem modelo (scan, fix, publicação).

## Estado

Vuln fixer redesenhado pelo [ADR-0005](https://github.com/open-eda-labs/open-eda-labs.github.io/blob/main/docs/adr/0005-correcao-total-e-regra-de-ouro.md) (correção na última release e regra de ouro); a triagem (P3) segue sem implementação. Etapas do plano: P3, P5. Decisões relacionadas: D-05, D-11, D-28, D-30, D-31, D-41, ADR-0005.

Resultado da medição real do novo desenho sobre os três repositórios do app: [docs/fix-measurement.md](docs/fix-measurement.md).

## Contexto

Este repositório faz parte do laboratório open-eda-labs: workflows agênticos disparados por eventos, com Argo Workflows e padrões abertos. Cada peça trocável é um repositório que só depende do contrato versionado em `triage-contract` (D-01, D-27).

A fonte da verdade é o [Plano Mestre](https://github.com/open-eda-labs/open-eda-labs.github.io/blob/main/docs/PLANO_MESTRE.md).

As regras do laboratório valem para todos os repositórios e estão no [perfil da organização](https://github.com/open-eda-labs).

## O que há

| Caminho | Conteúdo |
| --- | --- |
| `steps/scan/` | Clona parent, lib e serviço no volume de trabalho (`/work/repos`) e grava os SHAs (`shas.json`) e o `traceparent` da rodada; instala parent e lib no `~/.m2`, constrói o serviço e roda o OSV-Scanner sobre o `target/bom.json` (árvore resolvida pelo Maven); um evento `vulnerability.detected` por advisory e pacote em `/work/events/` |
| `steps/fix/` | Última release dos pacotes acusados no `demo-parent` (`versions-maven-plugin` 2.19.1), parent, lib e service nessa ordem, com build, testes e re-scan; laço de feedback, gancho N2; volta ao SHA do scan; `patch.diff` por repositório, `result.json`, `fixes/` e `recommendations/` em `/work/fix`. Rodada de release (ver abaixo): lê as tags `vX.Y.Z` de parent e lib e, com release nova, só o serviço sobe |
| `steps/publish/` | Único passo com credencial: valida os patches (`check_patches`), depois abre um PR draft por repositório com patch (parent, lib e service; o patch do serviço só existe na rodada de release) no SHA do scan, com token curto de GitHub App, em um branch determinístico; completa as recommendations com `pr_opened`. Em `DRY_RUN=1` não usa a rede |
| `steps/notify/` | Aviso por rodada no Slack por incoming webhook, "Revisar PR" como links em texto (D-41) |
| `steps/common.py` | Validação pelos schemas, montagem da recommendation, POST com `DRY_RUN` |
| `workflows/` | `CronWorkflow` `vuln-scan` (chama o fix por `templateRef`), `WorkflowTemplate` `vuln-fix`, `rbac.yaml` (conta do executor do Argo) e `maven-settings.yaml` (ConfigMap com o `settings.xml` do GitHub Packages, sem valor secreto) |
| `Dockerfile` | Imagem única dos quatro passos (JDK 21, Maven 3.9.11, OSV-Scanner 2.7.1, Python com as libs de runtime pinadas; bases por digest) |
| `tests/` | pytest; `tests/contract/` tem cópia dos schemas, `tests/fixtures/` a saída real do osv-scanner |
| `docs/fix-measurement.md` | Medição real do desenho atual |

Linguagem: Python 3 (só `jsonschema` e `PyYAML`, as mesmas libs do triage-contract), porque o mapeamento OSV para evento e a validação contra schema pedem lógica que shell com `jq` não testa bem; os comandos externos (`osv-scanner`, `mvn`, `git`) são chamados por `subprocess`.

## Contrato

`tests/contract/*.yaml` são cópias dos schemas do [triage-contract](https://github.com/open-eda-labs/triage-contract) no commit `74e5512` (v0.1.0, ainda não lançada); a origem é lá, nunca se edita aqui. O mesmo diretório vai na imagem para os passos validarem a própria saída. `tests/test_contract_copy.py` compara o hash da cópia com um valor fixo; ao atualizar a cópia (subida da tag do contrato), troque o commit e o hash no teste.

## Como rodar

Requer Python 3.12 ou mais novo. Crie o venv fora do repositório e rode os testes (sem rede):

```sh
python3 -m venv ~/.venvs/agent-workflows
~/.venvs/agent-workflows/bin/pip install -r requirements-dev.txt
~/.venvs/agent-workflows/bin/python -m pytest -q -p no:cacheprovider
```

`requirements.txt` é só o que a imagem usa em runtime; o `pytest` está em `requirements-dev.txt`. O pytest cobre: a transformação OSV para evento (saída real do osv-scanner 2.7.1; `manifest_path` com raiz symlink; um `traceparent` por rodada), a montagem da recommendation, a exclusão de pré-release, a seleção e o agrupamento das unidades, a maior tag estável (sem pré-release nem tag fora do padrão) e a comparação com o pom do serviço e da lib, a rodada de release com executor falso (patch verde só do serviço, quebra sem gancho sem patch do serviço, gancho N2), os comandos do plugin e a retentativa única do `mvn`, o laço do `fix` com executor falso (build que falha, falha só na combinação com bisseção, fallback guloso quando as voltas acabam, nada fecha, volta ao SHA do scan, gancho N2 com patch, com falha, com saída diferente de zero e com timeout, `level: N2`), o validador de patch, o corpo do PR e o `publish` (clone no SHA, `git apply`, commit e push contra remotos locais, PR simulado, branch determinístico, PR já aberto, `DRY_RUN` sem rede) e o `notify`.

Lint: o do CI é o workflow reutilizável da org. Localmente, `yamllint --strict` com a configuração da org e `argo lint --offline workflows/vuln-scan.yaml workflows/vuln-fix.yaml`.

### Refazer a medição completa (sem cluster)

Precisa de `git`, JDK 21, Maven, `osv-scanner` 2.7.1 e rede para Maven Central e OSV (scan e fix); o `publish` e o `notify` rodam sem rede. `PARENT`, `LIB` e `SERVICE` são três repositórios git locais com o estado a medir **commitado** (o fix volta ao SHA do scan; o que não está commitado se perde na cópia, os originais não são tocados). Rode da raiz deste repositório:

```sh
PY=~/.venvs/agent-workflows/bin/python
W=$(mktemp -d) && mkdir "$W/repos"
cp -a "$PARENT" "$W/repos/demo-parent" && cp -a "$LIB" "$W/repos/demo-lib" && cp -a "$SERVICE" "$W/repos/demo-service"
export REPOSITORY=open-eda-labs/demo-service
$PY -m steps.scan.scan "$W"                                                  # sem clone: os repositórios já estão em $W/repos
export TRACEPARENT=$(cat "$W/traceparent")
$PY -m steps.fix.fix "$W" "$W/fix"                                           # dezenas de minutos; imprime `ready` ou `done`
DRY_RUN=1 $PY -m steps.publish.publish "$W/fix" "$W/publish" "$W/repos"
DRY_RUN=1 SLACK_WEBHOOK_URL=x $PY -m steps.notify.notify "$W/publish"
echo "$W"                                                                    # result.json, prs.json e os patch.diff estão aqui
```

### Segunda rodada (release de parent e lib)

Depois do merge dos PRs do parent e da lib e da tag `v*` (humanos; o tag publica no GitHub Packages da org), a rodada seguinte não repete o fix: o passo `fix` lê as tags com `git ls-remote --tags https://github.com/open-eda-labs/<repo>` (repositórios públicos, sem token; `REMOTE_BASE` troca o prefixo, para teste com remoto local), escolhe a maior `vX.Y.Z` estável e compara com o que o serviço referencia (`<parent>` e property `demo-lib.version`). Há release mais nova: só o serviço sobe, `versions:update-parent` e `versions:set-property` com a versão da tag, build, testes e re-scan, pelo mesmo laço e gancho N2; o PR do serviço abre se o resultado é verde. Sem gancho, ou com gancho que não fecha, é "precisa de migração de código": o serviço fica sem patch e sem PR. Se o parent tem release mais nova que o `<parent>` da lib, a rodada sobe só a lib (aponta para o parent novo e passa a patch+1, o PR dela) antes de qualquer subida do serviço. Sem release nova, a rodada é a de sempre e não grava patch do serviço (não haveria versão publicada a que apontar). Não há estado: tudo sai das tags e dos poms no SHA da rodada.

O GitHub Packages para Maven exige autenticação mesmo para pacote público (observado: HTTP 401 sem token; não confirmado na documentação). Por isso os passos `scan` e `fix` montam `workflows/maven-settings.yaml` (ConfigMap `maven-settings`, em `/etc/maven/settings.xml`, passado ao Maven por `MAVEN_ARGS=-s ...`) e leem o token do Secret `github-packages-read`, chave `token` (variável `GITHUB_PACKAGES_TOKEN`, que o Maven interpola). O usuário é fixo, `open-eda-labs`; os repositórios são os dois do pom do serviço (`github` para o parent, `github-demo-lib` para a lib). O Secret não está no repositório: crie-o à mão com um token de leitura de pacotes. A `NetworkPolicy` do `lab-infra` (`k8s/networkpolicy.yaml`) já deixa sair HTTPS para qualquer host, então `maven.pkg.github.com` e `github.com` passam sem mudança.

## Como funciona

```
CronWorkflow vuln-scan
  scan (clona os três repositórios em /work/repos, grava shas.json e traceparent)  --parâmetro traceparent-->
  fix  (templateRef vuln-fix/main, uma execução por rodada)

Volume de trabalho do Workflow (volumeClaimTemplates `work`, em /work): o laboratório não tem artifact repository.
WorkflowTemplate vuln-fix, main
  fix (sem credencial)  --/work/fix-->  publish (GITHUB_TOKEN)  --/work/publish-->  notify (SLACK_WEBHOOK_URL)
  publish e notify só rodam se o fix imprimiu `ready` (há patch verificado)
```

O `fix` agrupa os pacotes acusados em unidades de subida (um pacote gerenciado pelo parent; um BOM importado e seus membros; uma família de mesmo groupId e versão; um transitivo, que passa a ser fixado no parent). Cada unidade é provada sozinha, sobre cópias dos três repositórios: parent (sobe as versões e a própria versão, patch, `mvn install`), lib (aponta para o parent novo, sobe a própria versão, build e testes, `mvn install`), service (aponta para parent e lib, build, testes e re-scan). As que passam são combinadas e a combinação é provada de novo; se ficar vermelha, uma bisseção acha a unidade culpada, que sai (no máximo 3 voltas; passou disso, o conjunto é refeito de forma gulosa, uma unidade por vez enquanto fica verde). Antes de uma unidade sair, o gancho N2 (`N2_HOOK`, vazio por padrão: comando que recebe `<in>` com `repo/` e `error.log` e `<out>` e devolve `<out>/patch.diff`; falha, saída diferente de zero ou timeout contam como "N2 não resolveu" para a unidade, e a rodada segue) tem uma chance. A recommendation grava `level: N2` para o verde que veio de patch do gancho e `N1` nos demais. Antes de qualquer push, o `publish` recusa a rodada se o patch do serviço declara versão de terceiro (só o `<version>` do parent e a property `demo-lib.version` podem mudar), se algum patch toca `.github/`, `Dockerfile` ou `*.sh`, ou se o diff passa de 1000 linhas (`MAX_DIFF_LINES`). O resultado final é sempre verde nos três repositórios; o que saiu fica como "voltou: precisa de migração de código" (ou "sem correção publicada", quando a última release ainda é acusada).

Cada passo lê e escreve no volume `/work`; o `traceparent` da rodada vai do scan para os demais pela variável `TRACEPARENT`. Segredos entram por `secretKeyRef` (`vuln-fixer-github-app` chave `token`; `slack-webhook` chave `url`). A recommendation é por advisory: `failed` e `no_change` saem do `fix`; para os advisories fechados o `fix` grava só o bloco `fix` e o `publish` completa o documento com `pr_opened`, `pr_number` do PR do parent (onde o fix nasce) e o hash do patch do parent.

## Não testado

- Cluster: nenhum Workflow rodou; só o `argo lint --offline` e o yamllint passaram. Não se sabe se o `templateRef` de dentro do `CronWorkflow` resolve os templates com o `volumeClaimTemplates` e o `executor` do próprio cron, se o volume fica gravável para o UID 10001 (`fsGroup`), se o Argo lê o parâmetro de saída `/work/traceparent`, nem se o RBAC de `workflows/rbac.yaml` basta (os erros do Argo v4.1.6 que o motivaram vêm da revisão, não foram reproduzidos aqui).
- Imagem: o `Dockerfile` não foi construído aqui (sem Docker daemon) nem publicado; a tag `0.2.0` não existe e o job `image` do CI nunca rodou. Os digests das duas bases foram lidos do registry do Docker Hub (índice multi-arquitetura), mas a build com eles não foi feita.
- GitHub Packages: parent e lib são resolvidos dos clones (`mvn install` local), não do registro; a leitura autenticada do GitHub Packages, que o CI dos repositórios usa, nunca foi exercitada aqui. O `settings.xml` só foi lido pelo Maven (`help:effective-settings`); nenhum download com token aconteceu, e o 401 sem token é observação, não confirmação. O Secret `github-packages-read` não existe.
- Tags reais: `git ls-remote` nunca rodou contra o github.com; a segunda rodada foi medida com remotos locais (`REMOTE_BASE`) e as releases simuladas por tags locais e `mvn install` (ver `docs/fix-measurement.md`).
- GitHub App: `publish` nunca falou com a API do GitHub. No pytest o fetch do SHA, o `git apply`, o commit e o push foram testados contra remotos locais, e o PR com um `post` simulado; a consulta de PR aberto (`existing`) é simulada e nunca rodou contra o GitHub, e o fetch por SHA nunca rodou contra o github.com.
- Slack: `notify` só foi testado no `DRY_RUN`.
- Gancho N2: só testado com um script de teste; nenhum modelo foi chamado, e o patch do gancho aplicado numa combinação de unidades nunca foi exercitado com Maven. `level: N2` exige `N2_PROMPT` e `N2_MODEL` no ambiente do publish (o contrato pede prompt e modelo); isso não está ligado nos workflows.
- `scan` e `fix` reais (Maven, OSV-Scanner, Maven Central) não rodaram depois destas mudanças; o fluxo ponta a ponta em `DRY_RUN` foi exercitado só com Maven, OSV-Scanner e provas sintéticos.
- Retentativa: o plugin não repete mais por cima do `mvn`; a falha `ArrayIndexOutOfBoundsException` do plugin (provável 429, sem aviso de rede no log) agora derruba o passo, sem retentativa.
- Rede restrita por domínio (só Maven Central, OSV e GitHub): a `NetworkPolicy` do `lab-infra` filtra só por porta; por domínio exige proxy de saída ou outro CNI.

## Pendências

- Emitir o token curto da GitHub App (JWT da App para token de instalação) antes do `publish`; hoje o Secret precisa já conter um token válido.
- `dataref` do evento aponta para `s3://scan-results/osv-scanner/<data>/<repo>.json` (como no exemplo do contrato), mas esse bucket não existe e não há armazenamento: os eventos e o `osv-scanner.json` ficam só no volume do Workflow.
- Diff de SBOM no corpo do PR: ainda não gerado.
- Detecção por tag, não por publicação: a tag `v*` existir não prova que o workflow de release terminou e publicou no GitHub Packages; se a rodada rodar entre os dois, o Maven não acha o artefato e o fix sai com erro de resolução, sem PR (a próxima rodada tenta de novo).
- Rodada da lib atrás do parent: reconstrói o serviço só para o scan; não gera recommendation (nenhum advisory é fechado por ela) e o aviso do Slack diz 0 pacotes corrigidos.
- Com PR aberto no branch `vuln-fix/<12 hex do patch do parent>` o `publish` sai com sucesso sem atualizar o PR; branch já existente sem PR aberto faz o `git push` falhar (falha fechada).
- A recommendation do contrato é por advisory e `pr_number` não diz de qual repositório é; o link que o contrato manda o workflow montar (repositório do evento) apontaria para o serviço. O `notify` monta os links dos PRs a partir de `prs.json`. `manifest_path` do evento vale `target/bom.json` e o schema descreve o `pom.xml`. O schema não foi alterado.
- Pinar as actions do CI por SHA (D-40); o lint do CI usa `open-eda-labs/.github/...lint.yml@main`, referência mutável.
