# SPDX-License-Identifier: AGPL-3.0-or-later
"""fortilog-ack : lister et acquitter des constats du fichier d'état de suivi.

  fortilog-ack --etat sortie/etat_suivi.json --list
  fortilog-ack --etat sortie/etat_suivi.json ID [ID…] [--motif "faux positif : …"]

Un constat acquitté RESTE signalé dans les analyses suivantes (tag [ACQUITTÉ le …]) ;
il est seulement exclu du décompte d'alerte de la synthèse.
"""
from __future__ import annotations
import argparse
import json
import sys
from datetime import date
from pathlib import Path


def _charger(path: Path) -> dict:
    try:
        etat = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"Fichier d'état introuvable : {path}")
    except (json.JSONDecodeError, OSError) as e:
        sys.exit(f"Fichier d'état illisible : {path} ({e})")
    if not isinstance(etat, dict) or "constats" not in etat:
        sys.exit(f"Fichier d'état mal formé (clé 'constats' absente) : {path}")
    return etat


def _lister(etat: dict) -> None:
    constats = etat.get("constats", {})
    if not constats:
        print("Aucun constat suivi.")
        return
    print(f"{'ID':16}  {'STATUT':8}  {'1re VUE':10}  {'DERNIÈRE':10}  RÈGLE — RÉSUMÉ")
    for cid in sorted(constats, key=lambda i: (constats[i].get("statut", ""), i)):
        c = constats[cid]
        resume = " — ".join(x for x in (c.get("regle", ""), c.get("resume", "")) if x)
        motif = f"  (motif : {c['motif']})" if c.get("motif") else ""
        print(f"{cid:16}  {c.get('statut', '?'):8}  {c.get('premiere_vue', '?'):10}  "
              f"{c.get('derniere_vue', '?'):10}  {resume}{motif}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="fortilog-ack",
        description="Acquitte des constats suivis (ils restent signalés, "
                    "mais sortent du décompte d'alerte).")
    ap.add_argument("ids", nargs="*", help="constat_id à acquitter (cf. --list)")
    ap.add_argument("--etat", required=True, help="chemin du fichier etat_suivi.json")
    ap.add_argument("--list", action="store_true", help="liste les constats suivis")
    ap.add_argument("--motif", default="", help="motif d'acquittement (stocké dans l'état)")
    args = ap.parse_args(argv)

    path = Path(args.etat)
    etat = _charger(path)

    if args.list or not args.ids:
        _lister(etat)
        return 0

    constats = etat["constats"]
    inconnus = [i for i in args.ids if i not in constats]
    if inconnus:
        sys.exit(f"constat_id inconnu(s) : {', '.join(inconnus)} — voir --list")
    today = date.today().isoformat()
    for i in args.ids:
        constats[i]["statut"] = "acquitte"
        constats[i]["date_acquittement"] = today
        if args.motif:
            constats[i]["motif"] = args.motif
        print(f"{i} acquitté ({constats[i].get('regle', '')})")
    path.write_text(json.dumps(etat, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
