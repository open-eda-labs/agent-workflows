# agent-workflows

WorkflowEventBinding e WorkflowTemplate de triagem, CronWorkflow vuln-scan e WorkflowTemplate vuln-fix do vuln fixer, e imagens dos passos sem modelo (scan, fix, publicação).

## Estado

Esqueleto inicial, sem implementação. Etapas do plano: P3, P5. Decisões relacionadas: D-05, D-11, D-28, D-30, D-31.

## Contexto

Este repositório faz parte do laboratório open-eda-labs: workflows agênticos disparados por eventos, com Argo Workflows e padrões abertos. Cada peça trocável é um repositório que só depende do contrato versionado em `triage-contract` (D-01, D-27).

A fonte da verdade é o [Plano Mestre](https://github.com/open-eda-labs/open-eda-labs.github.io/blob/main/docs/PLANO_MESTRE.md).

## Regras

- Só dados sintéticos ou públicos; nenhum dado, código ou nome de empresa (D-24, D-27).
- Tudo como código, versões pinadas e segredos fora do Git (D-40).
- Mudanças entram por pull request; o agente nunca faz merge (D-02, D-31).
