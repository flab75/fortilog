# SPDX-License-Identifier: AGPL-3.0-or-later
"""Génère la liste des plages IP appartenant à Fortinet, depuis le registre ARIN.

Étape de GÉNÉRATION (réseau requis), pas d'analyse : l'analyse reste 100% hors-ligne
et lit le fichier statique produit ici. À relancer ~2×/an (ou quand de nouvelles plages
Fortinet apparaissent en R8). Le fichier est versionné — l'analyse fonctionne sans réseau.

Source : ARIN Whois-RWS — tous les blocs enregistrés sous l'organisation Fortinet
(`FTC-58` par défaut). Cette énumération par PROPRIÉTÉ capture aussi les plages que
Fortinet héberge chez AWS (anycast `FTNT-AWS-ANYCAST`), annoncées sous l'ASN Amazon et
donc invisibles d'un simple filtre ASN. Données publiques, license-clean.

Usage :
    python -m fortilog.fetch_fortinet_ranges                       # -> data/fortinet_ranges.netset
    python -m fortilog.fetch_fortinet_ranges --org FTC-58 -o chemin.netset
"""
from __future__ import annotations
import argparse
import datetime as _dt
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path

ARIN_NETS_URL = "https://whois.arin.net/rest/org/{org}/nets"
DEFAULT_ORG = "FTC-58"          # Fortinet Inc.
DEFAULT_OUT = "data/fortinet_ranges.netset"


def fetch_netrefs(org: str, timeout: int = 30) -> list[dict]:
    """Récupère la liste des blocs réseau ARIN de l'organisation (start/end address)."""
    url = ARIN_NETS_URL.format(org=org)
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "fortilog/fetch-fortinet-ranges"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)
    refs = data.get("nets", {}).get("netRef", [])
    if isinstance(refs, dict):   # ARIN renvoie un objet seul s'il n'y a qu'un bloc
        refs = [refs]
    return refs


def to_cidrs(netrefs: list[dict]) -> list[ipaddress._BaseNetwork]:
    """Convertit chaque plage start–end en CIDRs minimaux (v4 et v6)."""
    cidrs: list[ipaddress._BaseNetwork] = []
    for ref in netrefs:
        start, end = ref.get("@startAddress"), ref.get("@endAddress")
        if not start or not end:
            continue
        try:
            a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
            cidrs.extend(ipaddress.summarize_address_range(a, b))
        except ValueError:
            continue
    # Tri stable (v4 avant v6, puis par adresse) et déduplication
    uniq = sorted(set(cidrs), key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return uniq


def render(cidrs: list, org: str) -> str:
    today = _dt.date.today().isoformat()
    L = [
        f"# Plages IP Fortinet — générées depuis ARIN (organisation {org}).",
        "# Énumération par PROPRIÉTÉ : inclut les plages anycast hébergées chez AWS,",
        "# invisibles d'un filtre ASN. Données publiques ARIN (license-clean).",
        f"# Régénérer : python -m fortilog.fetch_fortinet_ranges --org {org}",
        f"# Source : {ARIN_NETS_URL.format(org=org)}",
        f"# Généré le : {today} — {len(cidrs)} plage(s).",
    ]
    L += [str(c) for c in cidrs]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Génère la liste des plages IP Fortinet (ARIN).")
    ap.add_argument("--org", default=DEFAULT_ORG, help=f"Handle d'organisation ARIN (défaut {DEFAULT_ORG}).")
    ap.add_argument("-o", "--output", default=DEFAULT_OUT, help=f"Fichier de sortie (défaut {DEFAULT_OUT}).")
    ap.add_argument("--timeout", type=int, default=30, help="Timeout réseau en secondes.")
    args = ap.parse_args()

    try:
        refs = fetch_netrefs(args.org, timeout=args.timeout)
    except Exception as e:
        print(f"❌ Échec de la requête ARIN ({args.org}) : {e}", file=sys.stderr)
        return 1
    cidrs = to_cidrs(refs)
    if not cidrs:
        print(f"❌ Aucune plage trouvée pour l'organisation {args.org}.", file=sys.stderr)
        return 1

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(cidrs, args.org), encoding="utf-8")
    print(f"✅ {len(cidrs)} plage(s) Fortinet écrites dans {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
