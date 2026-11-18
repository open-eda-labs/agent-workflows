# Medição do vuln fixer (ADR-0005): última release, parent, lib e service

Medição real, feita em 2026-11-15, do desenho do [ADR-0005](https://github.com/open-eda-labs/open-eda-labs.github.io/blob/main/docs/adr/0005-correcao-total-e-regra-de-ouro.md) (G-P5), sem gancho de N2 (`N2_HOOK` vazio). Substitui a medição do N1 (`osv-scanner fix`, 12 de 20 dependências), cujo número está no ADR-0005.

## Como foi medido

| Item | Valor |
| --- | --- |
| Base | cópias dos commits atuais: `demo-parent` `b5a6c86` (1.0.0), `demo-lib` `b41083e` (1.0.0, 22 testes), `demo-service` `397cbd7` (11 testes) |
| Código medido | `steps/scan` e `steps/fix` deste repositório (base `a7de64d` mais as alterações desta entrega, ainda não commitadas) |
| Ferramentas | OSV-Scanner 2.7.1 (compilado da v2.7.1), JDK 21, Maven 3.9.11, `versions-maven-plugin` 2.19.1 |
| Scan | `osv-scanner scan source --data-source native -L target/bom.json` sobre o SBOM do `demo-service` (55 componentes, árvore resolvida pelo Maven). O scan por `pom.xml` não serve: o parent e a lib não estão no Maven Central e o GitHub Packages pede credencial, então o OSV-Scanner não resolve a árvore |
| Alvo | última release no Maven Central, pré-release fora: `-Dmaven.version.ignore=<regex>` do plugin |
| Fix | `python -m steps.fix.fix`, uma execução, sobre os eventos do scan (95) e as três cópias |
| Verde | build (`mvn install` no parent e na lib, `verify` no serviço), testes e re-scan sem o advisory |
| Duração | scan 12 s; fix 11 min 20 s (31 provas: base, 21 unidades sozinhas, 1 combinação, 8 retentativas). Numa reprodução independente (revisão de 16/11/2026, outra VM) o fix levou cerca de 37 min, com o mesmo resultado (16 corrigidos, 10 que voltaram, 46 advisories); a causa não foi isolada, e a revisão aponta as retentativas aninhadas, que o código já não tem |

O scan acusou 95 pares (advisory, pacote) em 26 pacotes, os mesmos números da medição antiga. Os 26 viram 21 unidades de subida (família: mesmo groupId e mesma versão; membro de BOM sobe o BOM; transitivo passa a ser fixado no parent): log4j (core e api), jackson (databind e core, pelo BOM), jetty (server, http e security), spring (web e core) e 17 unidades de um pacote só.

Pré-release: o Maven Central devolve como `release`/`latest` uma pré-release em três artefatos (protobuf-java `4.37.0-RC3`, log4j-core `3.0.0-beta3`, kotlin-stdlib `2.5.0-RC`), e a regex as descartou: o plugin escolheu `4.36.2`, `2.26.1` e `2.4.21`. Conferi o alvo de 24 dos 25 artefatos portadores contra o `maven-metadata.xml` do Central (a maior versão que a regex não descarta; o log4j-api não foi consultado, sobe pela property junto do log4j-core): nenhuma divergência. O alvo do guava ficou no sabor `-jre` (`33.8.0-jre`; `-android` não foi escolhido).

## Resultado por pacote

"Sozinho" é a prova da unidade isolada (parent, lib e service, nessa ordem; para no primeiro vermelho, então um erro na lib deixa o service sem prova). "Final" é a prova no conjunto que fechou. A coluna "última corrige tudo" vem do re-scan para os corrigidos; para os que voltaram é estimativa pelas faixas `fixed` do OSV com ordenação numérica simples de versão, não verificada por re-scan.

| Pacote | Advisories | De | Para (alvo) | Última corrige tudo | Lib (build e testes) | Service (build e testes) | Estado final |
| --- | --- | --- | --- | --- | --- | --- | --- |
| jackson-databind | 14 | 2.13.2 | 2.23.0 (BOM) | sim | verde | verde | corrigido |
| jackson-core | 3 | 2.13.2 | 2.23.0 (BOM) | sim | verde | verde | corrigido |
| guava | 3 | 31.1-jre | 33.8.0-jre | sim | verde | verde | corrigido |
| protobuf-java | 4 | 3.21.6 | 4.36.2 | sim | verde | verde | corrigido |
| nimbus-jose-jwt | 2 | 9.31 | 10.10 | sim | verde | verde | corrigido |
| okio (transitivo) | 1 | 2.8.0 | 3.18.2 | sim | verde | verde | corrigido |
| commons-io | 2 | 2.6 | 2.22.0 | sim | verde | verde | corrigido |
| json-smart (transitivo) | 1 | 2.5.0 | 2.6.1 | sim | verde | verde | corrigido |
| commons-compress | 2 | 1.21 | 1.28.0 | sim | sozinho: testes (NoClassDefFound de `commons-io` `build.AbstractStreamBuilder`); final: verde | final: verde | corrigido, depende do commons-io novo |
| commons-text | 1 | 1.9 | 1.15.0 | sim | verde | verde | corrigido |
| commons-lang3 | 1 | 3.17.0 | 3.22.0 | sim | verde | verde | corrigido |
| httpclient | 1 | 4.5.12 | 4.5.14 | sim | verde | verde | corrigido |
| log4j-core | 8 | 2.14.1 | 2.26.1 (`log4j2.version`) | sim | verde | verde | corrigido |
| log4j-api | 1 | 2.14.1 | 2.26.1 (`log4j2.version`) | sim | verde | verde | corrigido |
| kotlin-stdlib (transitivo) | 2 | 1.4.10 | 2.4.21 | sim | verde | verde | corrigido |
| org.json | 3 | 20220320 | 20260814 | sim | verde | verde | corrigido |
| h2 | 4 | 1.4.200 | 2.5.252 | sim (estimado) | testes: `H2Test.gravaEConta`, `CREATE TABLE fault_log (key ...)` falha, `key` virou palavra reservada | não executado | voltou: precisa de migração de código (demo-lib) |
| xstream | 18 | 1.4.17 | 1.4.21 | sim (estimado) | testes: `XStreamTest.copiaPorXml`, `ForbiddenClassException labs.demo.chaos.Scenario` (lista de tipos permitidos) | não executado | voltou: precisa de migração de código (demo-lib) |
| commons-beanutils | 3 | 1.9.3 | 1.11.0 | sim (estimado) | testes: `CommonsBeanutilsTest.conjuntoDeChaves`, a propriedade `class` deixou de aparecer | não executado | voltou: precisa de migração de código (demo-lib) |
| snakeyaml | 1 | 1.33 | 2.7 | sim (estimado) | compilação: `Scenarios.java:[58,58]`, `Class<Scenario>` não converte para `LoaderOptions` | não executado | voltou: precisa de migração de código (demo-lib) |
| spring-web | 2 | 5.3.39 | 7.0.10 | sim (estimado) | compilação: `Downstream.java:[19,56]`, falta `org.apache.hc.client5...HttpClient` (o `RestTemplate` novo usa o httpclient5) | não executado | voltou: precisa de migração de código (demo-lib) |
| spring-core (transitivo, família do spring-web) | 2 | 5.3.39 | 7.0.10 | sim (estimado) | o mesmo erro do spring-web | não executado | voltou: precisa de migração de código (demo-lib) |
| commons-configuration2 | 4 | 2.7 | 2.15.1 | sim (estimado) | verde | testes: 2 falhas, `CommonsConfiguration2Test.lookupUrlLeOBannerLocal` e `AppIntegrationTest.healthWorkEMetricas`; o lookup `${url:...}` não é interpolado (provável: lookup `url` fora do padrão nas versões novas) | voltou: precisa de migração de código (demo-service) |
| jetty-server | 6 | 9.4.40.v20210413 | 12.1.15 | sim (estimado) | verde (a lib não usa Jetty) | compilação: símbolo `HttpServletRequest` não encontrado em `Routes` (Jetty 12 usa `jakarta.servlet`) | voltou: precisa de migração de código (demo-service) |
| jetty-http (transitivo, família do jetty-server) | 5 | 9.4.40.v20210413 | 12.1.15 | sim (estimado) | verde | o mesmo erro do jetty-server | voltou (demo-service) |
| jetty-security (transitivo, família do jetty-server) | 1 | 9.4.40.v20210413 | 12.1.15 | sim (estimado) | verde | o mesmo erro do jetty-server | voltou (demo-service) |

Nenhum pacote caiu em "sem versão corrigida publicada": nos 26, a última release traz correção para todos os advisories (verificado por re-scan nos 16 corrigidos; estimado pelo OSV nos 10 que voltaram).

## Fecho

| Medida | Resultado |
| --- | --- |
| Pacotes corrigidos sem modelo, sobre os que têm versão corrigida publicada | **16 de 26 (61,5%)**; o denominador é 26 porque nenhum ficou sem versão corrigida |
| Unidades de subida (famílias) | 14 de 21 (66,7%) |
| Advisories fechados | 49 de 95 (51,6%) |
| Para o N2 | 10 pacotes em 7 unidades, abaixo |
| Advisories no re-scan final | **46**, em 10 pacotes, todos pacotes que voltaram à versão anterior; nos 16 corrigidos restam 0 |

Resíduo do re-scan final, por pacote: xstream 18, jetty-server 6, jetty-http 5, h2 4, commons-configuration2 4, commons-beanutils 3, spring-core 2, spring-web 2, jetty-security 1, snakeyaml 1. O motivo é um só: a última release exige migração de código que o N1 não faz. Isso não é "sem versão corrigida publicada", e por isso não é isento no critério do ADR-0005.

Fica para o N2 (repositório onde o patch teria de nascer):

| Unidade | Pacotes | Migração | Repositório |
| --- | --- | --- | --- |
| h2 2.x | h2 | SQL do `History` (`key` reservado) | demo-lib |
| xstream 1.4.21 | xstream | registrar os tipos permitidos (`allowTypes`) | demo-lib |
| beanutils 1.11 | commons-beanutils | `class` fora das propriedades | demo-lib |
| snakeyaml 2.x | snakeyaml | construtor com `LoaderOptions` | demo-lib |
| spring 7 | spring-web, spring-core | `RestTemplate` com httpclient5 (ou trocar o cliente) | demo-lib |
| commons-configuration2 2.15 | commons-configuration2 | habilitar o lookup `url` | demo-service |
| jetty 12 | jetty-server, jetty-http, jetty-security | `javax.servlet` para `jakarta.servlet`, e `jetty-servlet` para o módulo ee10 | demo-service |

Duas dessas migrações caem no serviço, o que a regra de ouro do ADR-0005 proíbe e o texto das consequências do mesmo ADR admite para o N2 ("na demo-lib ou no serviço"). O dono precisa decidir. O `jetty-servlet` 9.4.40 não foi subido porque o scan não o acusa (a regra é subir só o que o scan acusou); o Jetty 12 ainda exigiria subi-lo junto.

## Conferência final

Reconstruí o estado final a partir dos três `patch.diff` (aplicados em clones novos), `mvn install` no parent e na lib, `mvn verify` no serviço:

- Testes: demo-lib 22 de 22, demo-service 11 de 11, 0 falhas e 0 erros (relatórios do surefire).
- Re-scan independente sobre o SBOM desse estado: 46 advisories em 10 pacotes, os mesmos do resultado do passo.
- `mvn dependency:tree` no serviço, comparado com o `dependencyManagement` do parent novo (propriedades resolvidas): 0 divergências em 25 artefatos gerenciados; jackson-databind e jackson-core 2.23.0 vêm do BOM (`jackson.version`), log4j-core e log4j-api 2.26.1 da property `log4j2.version`, e okio 3.18.2, json-smart 2.6.1 e kotlin-stdlib 2.4.21 (transitivos) passaram a ser fixados no parent. Os pacotes que voltaram aparecem na versão antiga (snakeyaml 1.33, h2 1.4.200, xstream 1.4.17, beanutils 1.9.3, spring 5.3.39, configuration2 2.7, jetty 9.4.40.v20210413).
- O patch do serviço só troca `<parent>` e `demo-lib.version` (1.0.0 para 1.0.1); nenhuma versão de terceiro entrou no serviço. O patch da lib só troca `<parent>` e a própria versão. O parent sobe de 1.0.0 para 1.0.1 e declara os três transitivos.

## Limites desta medição

- A prova isolada dá falso negativo quando um upgrade depende de outro: o commons-compress só fecha junto com o commons-io novo (sozinho, `NoClassDefFound`). Por isso a coluna "Sozinho" não é a medida do pacote; o passo 3 do laço o recupera sobre o conjunto verde.
- Uma rodada só, sobre uma fotografia do Maven Central de 2026-11-15; os números mudam quando o Central muda.
- "Corrigido" é o critério do ADR dentro dos três repositórios; os testes são os 22 e os 11 que existem. Cada dependência é coberta por um teste que a exercita (`demo-service/README.md`), mas isso não prova compatibilidade de comportamento fora deles.
- A estimativa "sim (estimado)" dos 10 pacotes que voltaram não foi confirmada por re-scan: o build não fecha, então não há SBOM da versão nova.
- Primeira versão do laço (cada unidade provada só sozinha) devolvia também o commons-compress: 15 de 26. O passo 3 (retentativa sobre o conjunto verde) o recuperou, porque ele só passa com o commons-io novo. No conjunto verde o erro do commons-configuration2 deixa de ser `NoClassDefFound` (commons-io velho, como acontece sozinho) e passa a ser o comportamento do lookup, que é a causa real.
- Uma execução anterior abortou por falha de infraestrutura: o plugin lançou `ArrayIndexOutOfBoundsException` ao pedir metadados ao Central (provável 429), sem aviso de rede no log. Agora toda falha de goal do plugin é repetida (3 vezes, espera crescente) e, persistindo, o passo sai com erro em vez de gravar resultado.

## Reexecução depois da revisão externa (2026-11-17)

Depois das correções da revisão (laço, volume de trabalho, SHAs fixados, `DRY_RUN` completo) e da renomeação do pacote da lib para `labs.demo.lib`, o fluxo inteiro rodou de novo sobre clones dos três repositórios: scan e fix reais, publish e notify em `DRY_RUN`. O resultado se repetiu: 95 advisories em 26 pacotes, 16 corrigidos, 10 voltaram, 46 advisories restantes, os mesmos pacotes em cada grupo. O scan levou 14 s e o fix cerca de 10 min 30 s; publish e notify terminaram sem rede e sem credenciais. Uma revisão independente, num cluster k3d, chegou aos mesmos números com a versão anterior do código.


## Segunda rodada: o serviço depois da release de parent e lib (2026-11-18)

Medição da rodada que vem depois do merge e da tag de parent e lib: o `fix` lê as tags, vê a release nova e só o serviço sobe. O GitHub Packages não é acessível daqui, então a release foi simulada (veja os limites).

| Item | Valor |
| --- | --- |
| Base | cópias dos HEADs atuais: `demo-parent` `c086cd9`, `demo-lib` `8845066`, `demo-service` `4a42046` (os três originais não foram tocados) |
| Release simulada | nas cópias de parent e lib, os `patch.diff` da primeira medição (parent 1.0.0 para 1.0.1 com os pacotes subidos e os 3 transitivos; lib com `<parent>` 1.0.1 e versão 1.0.1) aplicados, commitados e com a tag `v1.0.1`; `mvn install` das duas no `~/.m2`. Mais três tags que a detecção tem de ignorar: `v1.0.2-rc1`, `release-9.0.0` (nas duas cópias) |
| Detecção | `git ls-remote --tags` contra os remotos locais (`REMOTE_BASE`): maior tag estável 1.0.1 nos dois (a `v1.0.2-rc1` e a `release-9.0.0` ignoradas); o serviço referencia 1.0.0 e 1.0.0: release nova, rodada do serviço. A lib já aponta para o parent 1.0.1, então não há rodada da lib |
| Execução | `scan` (13 s, 95 advisories, os mesmos de antes), `fix` (58 s, 3 provas: base, `release` sozinha, `release` de novo no passo 2; stdout `ready`), `publish` e `notify` em `DRY_RUN` |

Resultado:

| Medida | Resultado |
| --- | --- |
| Serviço, de para | `<parent>` demo-parent 1.0.0 para 1.0.1; `demo-lib.version` 1.0.0 para 1.0.1. O patch só troca essas duas linhas |
| Build | verde (`mvn verify` do serviço; parent e lib 1.0.1 resolvidos do `~/.m2`) |
| Testes | 11 de 11, 0 falhas, 0 erros (relatório do surefire numa cópia limpa com o patch aplicado) |
| Re-scan | 46 advisories em 10 pacotes, os mesmos 10 da primeira rodada (xstream 18, jetty-server 6, jetty-http 5, h2 4, commons-configuration2 4, commons-beanutils 3, spring-core 2, spring-web 2, jetty-security 1, snakeyaml 1 na contagem por advisory); confirmado por um re-scan independente da mesma cópia |
| Pacotes | 16 de 26 corrigidos (a release os trouxe); 10 ainda acusados, sem tentativa de migração: o gancho N2 não estava ligado, e a rodada do serviço não tenta migrar código, só sobe as versões |
| PR do serviço | abriria: `publish` em `DRY_RUN` produziu 1 PR draft no `demo-service`, título `fix(deps): demo-parent 1.0.1 e demo-lib 1.0.1`, e o validador de patch aceitou (só `<parent>` e `demo-lib.version`) |
| Divergência do esperado | nenhuma: parent e lib 1.0.1, build e testes verdes, 46 advisories |

Achado da medição, já corrigido: com `-DparentVersion=1.0.1` o `versions:update-parent` escolheu `1.0.2`, porque o `mvn install` da prova da base (que acontece antes, no mesmo `~/.m2`) deixa o parent em patch+1, e o plugin trata o valor como "esta versão ou a maior disponível". O fix passa agora `-DparentVersion=[1.0.1]` (versão exata). Num pod do cluster a mesma coisa aconteceria, e o `~/.m2` do pod é onde a base instala.

Limites desta medição:

- Release simulada: a leitura de tags foi contra remotos locais e a resolução de parent e lib 1.0.1 foi do `~/.m2` (instalados das cópias), não do GitHub Packages nem do github.com. A leitura autenticada do GitHub Packages, o `settings.xml` com token e o `ls-remote` real não foram exercitados. O `settings.xml` só foi lido pelo Maven (`help:effective-settings`).
- A primeira rodada deixou o patch de parent e lib pronto; aqui eles foram reaplicados das cópias da medição anterior (aplicam limpos nos HEADs atuais), não regerados pelo `fix` desta versão do código.
- O caminho de quebra do serviço (build ou teste vermelho depois da subida) só foi coberto por teste com executor falso, não por Maven; a rodada da lib (parent com release mais nova que o `<parent>` da lib) também.
- Uma rodada só, sobre o Maven Central de 2026-11-18.

## Ensaio do N2 (2026-11-18)

Ensaio da ligação do gancho N2, não medição do G-P5: uma unidade, uma tentativa por modelo.

| Item | Valor |
| --- | --- |
| Unidade | snakeyaml 1.33 para 2.7 (`org.yaml@1.33`), que quebra a compilação da `demo-lib` (`Scenarios.java`, `new Constructor(Scenario.class)`) |
| Base | cópias dos commits atuais de `demo-parent`, `demo-lib` e `demo-service`; eventos da reexecução de 2026-11-17 |
| Caminho | `fix.trial` real (vermelho na lib), `fix.n2` real com `N2_HOOK=n2-adapter` (agent-step-images), Cline CLI 3.0.74, `mvn verify` do adaptador, `fix.trial` de novo com o patch |
| Fora do caminho | re-scan trocado por stub (sem osv-scanner na sessão); `~/.m2` isolado sem os `labs.demo` de rodadas antigas (ver abaixo); sem LiteLLM: o Cline falou direto com o endpoint |

| Modelo | Resultado | Passos do agente | Tokens (entrada, saída) | Duração do N2 |
| --- | --- | --- | --- | --- |
| falso (roteiro em `agent-step-images/tests/fake_openai.py`) | patch de 1 linha, verify verde, prova final verde | 4 | 0, 0 | 43 s |
| `google/gemma-4-31b-it`, NVIDIA NIM (`integrate.api.nvidia.com`) | patch de 1 linha, verify verde, prova final verde | 5 (`run_commands`, `read_files`, `editor`, `run_commands`, `submit_and_exit`) | 28.007, 538 | 112 s |

O Gemma 4 31B chamou as ferramentas do Cline (`tools` em JSON Schema, D-09) sem `response_format`. O patch dos dois foi o mesmo: `new Constructor(Scenario.class, new org.yaml.snakeyaml.LoaderOptions())`. A duração do N2 inclui o harness, o `mvn verify` do adaptador e a prova final (parent, lib e service).

Prova verde por engano: no primeiro ensaio, a prova da lib ficou verde para h2 e snakeyaml porque `update-parent -DparentVersion=<pv>` (sem colchetes) escolheu um `demo-parent` 1.0.2 que sobrou no `~/.m2` da sessão, e não o 1.0.1 que a prova acabara de instalar. Com o `~/.m2` isolado, h2 volta a quebrar nos testes da lib, como na medição. No pod o `~/.m2` nasce vazio, mas uma release do parent no GitHub Packages acima da `pv` provavelmente teria o mesmo efeito (não verificado): a corrigir no `fix` (fixar a versão exata, `[pv]`, como a rodada de release já faz).
