"""ASPM CI gate — chama a API, (opcional) dispara DAST em homologacao,
avalia policy contra o ultimo scan e retorna exit codes bem definidos.

Exit codes:
    0  policy passou
    1  policy reprovou (fail count > 0)
    2  erro operacional (API fora, scan falhou, timeout, etc)

Uso tipico em CI:

    # Gate SAST sobre ultimo scan existente
    python bin/aspm_gate.py --asset-id <UUID> --policy default

    # Gate completo: dispara scan de codigo + aguarda + avalia
    python bin/aspm_gate.py --asset-id <UUID> --policy default --wait

    # Gate DAST: dispara scan DAST em homologacao + aguarda + avalia
    python bin/aspm_gate.py --asset-id <UUID> --policy dast \\
        --dast-url https://staging.example.com --dast-profile baseline

Combinar os dois (--wait + --dast-url) e permitido: o gate roda SAST,
depois DAST, e avalia a policy sobre o ultimo scan de codigo. A policy
aplicada tambem engloba findings DAST (eles ficam no mesmo asset).

Sem dependencias alem de httpx (ja no requirements.txt).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

import httpx

# Timeouts curtos aqui so pra request HTTP; nao confundir com timeouts do scan.
_HTTP_TIMEOUT = 30.0


def _die(msg: str, code: int = 2) -> None:
    """Encerra com erro operacional (default exit 2 — distinto de reprovacao)."""
    print(f"aspm_gate: {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# SAST / scan de codigo
# ---------------------------------------------------------------------------


def _start_scan(client: httpx.Client, asset_id: str) -> str:
    r = client.post(f"/assets/{asset_id}/scan")
    if r.status_code not in (200, 202):
        _die(f"nao consegui iniciar scan (HTTP {r.status_code}): {r.text}")
    return r.json()["id"]


def _wait_scan(client: httpx.Client, scan_id: str, timeout_s: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    delay = 2.0
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        r = client.get(f"/scans/{scan_id}")
        if r.status_code != 200:
            _die(f"nao consegui consultar scan (HTTP {r.status_code}): {r.text}")
        last = r.json()
        st = last.get("status")
        if st == "done":
            return last
        if st == "failed":
            _die(f"scan falhou: {last.get('error') or 'sem detalhes'}", code=2)
        print(f"aspm_gate: scan {scan_id} status={st}, aguardando...", file=sys.stderr)
        time.sleep(delay)
        delay = min(delay * 1.5, 15.0)
    _die(f"timeout aguardando scan (ultimo status: {last.get('status')})")
    return last  # unreachable


# ---------------------------------------------------------------------------
# DAST
# ---------------------------------------------------------------------------


def _start_dast(
    client: httpx.Client,
    *,
    asset_id: str,
    target_url: str,
    profile: str,
    authorized: bool,
    allow_private: bool,
    timeout_s: int | None,
    requested_by: str | None,
) -> str:
    options: dict[str, Any] = {}
    if allow_private:
        options["allow_private"] = True
    if timeout_s is not None:
        options["timeout_s"] = timeout_s

    body: dict[str, Any] = {
        "asset_id": asset_id,
        "target_url": target_url,
        "profile": profile,
        "authorized": authorized,
    }
    if requested_by:
        body["requested_by"] = requested_by
    if options:
        body["options"] = options

    r = client.post("/api/dast/scans", json=body)
    if r.status_code == 400:
        _die(
            f"DAST rejeitado pelo backend ({r.status_code}): "
            f"{r.json().get('detail', r.text)}"
        )
    if r.status_code not in (200, 202):
        _die(f"nao consegui iniciar DAST (HTTP {r.status_code}): {r.text}")
    return r.json()["id"]


def _wait_dast(
    client: httpx.Client, scan_id: str, timeout_s: int
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    delay = 3.0
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        r = client.get(f"/api/dast/scans/{scan_id}")
        if r.status_code != 200:
            _die(f"nao consegui consultar DAST (HTTP {r.status_code}): {r.text}")
        last = r.json()
        st = last.get("status")
        if st == "completed":
            return last
        if st in ("failed", "cancelled"):
            # scan rodou mas nao gerou findings uteis — e erro operacional,
            # nao reprovacao de policy. Policy continua sendo avaliada caso
            # o usuario escolha isso (gate --allow-dast-failure).
            _die(
                f"DAST {st}: {last.get('error') or 'sem detalhes'}",
                code=2,
            )
        print(
            f"aspm_gate: dast {scan_id} status={st}, aguardando...",
            file=sys.stderr,
        )
        time.sleep(delay)
        delay = min(delay * 1.5, 15.0)
    _die(
        f"timeout aguardando DAST (ultimo status: {last.get('status')})"
    )
    return last  # unreachable


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def _evaluate(
    client: httpx.Client, policy: str, asset_id: str, scan_id: str | None
) -> dict[str, Any]:
    params: dict[str, str] = {"asset_id": asset_id}
    if scan_id:
        params["scan_id"] = scan_id
    r = client.post(f"/policies/{policy}/evaluate", params=params)
    if r.status_code == 404:
        _die(f"nao encontrado: {r.json().get('detail', r.text)}")
    if r.status_code != 200:
        _die(f"evaluate falhou (HTTP {r.status_code}): {r.text}")
    return r.json()


def _print_table(result: dict[str, Any]) -> None:
    status = "PASS" if result["passed"] else "FAIL"
    print(f"policy    : {result['policy_name']}")
    print(f"asset     : {result['asset_id']}")
    print(f"scan      : {result['scan_id'] or '-'}")
    print(f"findings  : {result['findings_considered']}")
    print(f"fail/warn : {result['fail_count']} / {result['warn_count']}")
    print(f"status    : {status}")
    hits = result.get("rule_hits") or {}
    if hits:
        print("rule hits :")
        for rid, n in hits.items():
            marker = " " if n == 0 else "*"
            print(f"  {marker} {rid}: {n}")
    violations = result.get("violations") or []
    if violations:
        print("\nviolacoes:")
        for v in violations[:50]:
            score = v.get("risk_score")
            score_s = f"score={score}" if score is not None else "score=-"
            print(
                f"  [{v['action'].upper():4}] {v['rule_id']} :: "
                f"{v['tool']}/{v['category']} {score_s} "
                f"{v.get('file_path') or '-'} -- {v['finding_title'][:80]}"
            )
        if len(violations) > 50:
            print(f"  ... (+{len(violations) - 50} outras)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="aspm_gate", description="ASPM CI policy gate (SAST + DAST)"
    )
    ap.add_argument("--api-url", default="http://localhost:8000")
    ap.add_argument("--asset-id", required=True)
    ap.add_argument("--policy", default="default")
    ap.add_argument("--scan-id", default=None)
    ap.add_argument(
        "--wait", action="store_true",
        help="dispara scan de codigo (SAST) e aguarda concluir",
    )
    ap.add_argument(
        "--timeout", type=int, default=900,
        help="timeout do --wait em segundos (SAST)",
    )
    ap.add_argument("--json", dest="as_json", action="store_true")

    # DAST
    ap.add_argument(
        "--dast-url", default=None,
        help="URL de destino DAST em homologacao (dispara scan ZAP antes do gate)",
    )
    ap.add_argument(
        "--dast-profile", default="baseline",
        choices=("passive", "baseline", "active", "full"),
        help="perfil DAST (default: baseline)",
    )
    ap.add_argument(
        "--dast-authorized", action="store_true",
        help="autoriza perfis ofensivos (active/full) — obrigatorio para eles",
    )
    ap.add_argument(
        "--dast-allow-private", action="store_true",
        help="permite alvo em rede privada (requer DAST_ALLOWLIST_HOSTS no backend)",
    )
    ap.add_argument(
        "--dast-timeout", type=int, default=None,
        help="timeout do scan DAST em segundos (default: do perfil)",
    )
    ap.add_argument(
        "--dast-wait-timeout", type=int, default=1800,
        help="timeout de aguardo do DAST no CI (default: 1800s)",
    )
    ap.add_argument(
        "--requested-by", default=None,
        help="identificador do solicitante para registro do DAST",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = _build_parser()
    args = ap.parse_args(argv)

    scan_id = args.scan_id
    with httpx.Client(
        base_url=args.api_url.rstrip("/"), timeout=_HTTP_TIMEOUT
    ) as client:
        if args.wait:
            if scan_id:
                _die("use --wait OU --scan-id, nao ambos")
            scan_id = _start_scan(client, args.asset_id)
            print(f"aspm_gate: scan iniciado: {scan_id}", file=sys.stderr)
            _wait_scan(client, scan_id, args.timeout)

        if args.dast_url:
            print(
                f"aspm_gate: iniciando DAST ({args.dast_profile}) em {args.dast_url}",
                file=sys.stderr,
            )
            dast_id = _start_dast(
                client,
                asset_id=args.asset_id,
                target_url=args.dast_url,
                profile=args.dast_profile,
                authorized=args.dast_authorized,
                allow_private=args.dast_allow_private,
                timeout_s=args.dast_timeout,
                requested_by=args.requested_by or "aspm_gate",
            )
            print(f"aspm_gate: dast iniciado: {dast_id}", file=sys.stderr)
            _wait_dast(client, dast_id, args.dast_wait_timeout)

        result = _evaluate(client, args.policy, args.asset_id, scan_id)

    if args.as_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_table(result)

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
