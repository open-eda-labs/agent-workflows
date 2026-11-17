"""Passo notify (sem modelo): um aviso por rodada no Slack por incoming webhook, "Revisar PR" como links em texto (D-41).

Uso: SLACK_WEBHOOK_URL=<segredo> python -m steps.notify.notify [/work/publish]
Entrada: result.json e prs.json (do publish). DRY_RUN=1 imprime a requisição em vez de enviar.
O texto sai só de contagens, de repositório e número do PR e do trace_id da rodada (TRACEPARENT), montados aqui (D-13); nada do log do Maven entra.
"""

import json
import os
import pathlib
import sys

from steps.common import die, post


def message(result, prs):
    n = {s: sum(p["status"] == s for p in result["packages"]) for s in ("corrigido", "sem_correcao", "voltou")}
    return {
        "text": "\n".join([
            f"Vuln fixer, rodada {result['round']}: {n['corrigido']} pacotes corrigidos, {n['voltou']} voltaram (precisam de migração de código), "
            f"{n['sem_correcao']} sem versão corrigida publicada. Advisories restantes no re-scan: {result['advisories_restantes']}.",
            *[f"Revisar PR: https://github.com/{p['repository']}/pull/{p['number']}" for p in prs],
            *([f"trace_id: {os.environ['TRACEPARENT'].split('-')[1]}"] if os.environ.get("TRACEPARENT") else []),
        ]),
        "mrkdwn": False,
        "unfurl_links": False,
        "unfurl_media": False,
    }


def main(in_dir="/work/publish"):
    in_dir = pathlib.Path(in_dir)
    result = json.loads((in_dir / "result.json").read_text())
    prs = json.loads((in_dir / "prs.json").read_text())
    if not prs:
        die("sem PR aberto: nada a avisar")
    post(os.environ.get("SLACK_WEBHOOK_URL", ""), message(result, prs), shown="$SLACK_WEBHOOK_URL")


if __name__ == "__main__":
    main(*sys.argv[1:])
