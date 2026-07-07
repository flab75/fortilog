# SPDX-License-Identifier: AGPL-3.0-or-later
"""Suivi entre analyses : état persistant des constats + acquittement.

Identité STABLE d'un constat : `constat_id` = sha256 tronqué à 16 hex de la
concaténation normalisée `famille|regle|boitier|discriminant`. Ni le timestamp ni le
volume n'entrent dans l'identité : un même brute-force étalé sur 2 jours = UN constat.

Discriminant par famille :
- `evenement`    : user + srcip — les acteurs ; le `detail` des événements porte des
  volumes/horaires volatils (ex. R13) et n'entre donc PAS dans l'identité.
- `audit_config` : regle + detail — le detail de confaudit porte l'objet du constat
  (ex. « admin=X (aucun trusthost…) ») et est stable d'un run à l'autre.
- `diff_config`  : section + objet — PAS le statut : un objet qui passe
  d'AJOUTÉ à MODIFIÉ reste le même constat à suivre.

Fichier d'état `etat_suivi.json` (défaut : dossier --output, surchargeable --etat) :
{version: 1, analyses: [{date, n_constats}], constats: {id: {premiere_vue,
derniere_vue, statut, regle, resume[, motif, date_acquittement]}}}.
`statut` ∈ nouveau | connu | acquitte. JSON trié/indenté, éditable à la main.

Garde-fous : un constat acquitté RESTE signalé (tag [ACQUITTÉ le JJ/MM/AAAA]), il est
seulement exclu du décompte d'alerte ; un état corrompu -> warning explicite, run
normal SANS suivi et fichier laissé INTACT (jamais écrasé silencieusement).
"""
from __future__ import annotations
import hashlib
import json
import sys
from datetime import date
from pathlib import Path

import pandas as pd

from .common import str_col

ETAT_VERSION = 1
FICHIER_ETAT = "etat_suivi.json"


def _cid(*parts) -> str:
    base = "|".join(str(p).strip().lower() for p in parts)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def ids_evenements(events: pd.DataFrame) -> pd.Series:
    """constat_id par ligne d'événement (regle|boitier|user|srcip)."""
    regle, boit = str_col(events, "regle"), str_col(events, "boitier")
    user, srcip = str_col(events, "user"), str_col(events, "srcip")
    return pd.Series([_cid("evenement", r, b, u, s)
                      for r, b, u, s in zip(regle, boit, user, srcip)], index=events.index)


def ids_audit(ca: pd.DataFrame) -> pd.Series:
    """constat_id par ligne d'audit config (regle|boitier|detail)."""
    regle, boit, det = str_col(ca, "regle"), str_col(ca, "boitier"), str_col(ca, "detail")
    return pd.Series([_cid("audit_config", r, b, d)
                      for r, b, d in zip(regle, boit, det)], index=ca.index)


def ids_diff(cd: pd.DataFrame) -> pd.Series:
    """constat_id par ligne de diff config (boitier|section|objet)."""
    boit, sec, obj = str_col(cd, "boitier"), str_col(cd, "section"), str_col(cd, "objet")
    return pd.Series([_cid("diff_config", b, s, o)
                      for b, s, o in zip(boit, sec, obj)], index=cd.index)


def charger_etat(path: Path):
    """(etat, warning). Absent -> (None, None) ; corrompu -> (None, warning explicite)."""
    if not path.exists():
        return None, None
    try:
        etat = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(etat, dict) or "constats" not in etat:
            return None, f"fichier d'état {path} mal formé (clé 'constats' absente)"
        return etat, None
    except (json.JSONDecodeError, OSError) as e:
        return None, f"fichier d'état {path} illisible ({e})"


def _resume_events(df, i):
    u, s = str_col(df, "user")[i], str_col(df, "srcip")[i]
    return " ".join(x for x in (f"user={u}" if u else "", f"srcip={s}" if s else "") if x)


_FAMILLES = [
    # (clé table, fonction id, resume(df, index) -> str)
    ("events", ids_evenements, _resume_events),
    ("config_audit", ids_audit, lambda df, i: str_col(df, "detail")[i]),
    ("config_diff", ids_diff,
     lambda df, i: f"[{str_col(df, 'statut')[i]}] {str_col(df, 'section')[i]} / "
                   f"{str_col(df, 'objet')[i]}"),
]


def _tag_acquitte(rec: dict) -> str:
    d = rec.get("date_acquittement", "")
    try:
        d = date.fromisoformat(d).strftime("%d/%m/%Y")
    except ValueError:
        pass
    return f" [ACQUITTÉ le {d}]" if d else " [ACQUITTÉ]"


def appliquer_suivi(tables: dict, meta: dict, etat_path) -> None:
    """Annote events/config_audit/config_diff (colonne `suivi` nouveau|connu|acquitte,
    tag [ACQUITTÉ …] ajouté au detail), remplit meta['suivi'], réécrit l'état."""
    path = Path(etat_path)
    etat, warn = charger_etat(path)
    if warn:
        print(f"⚠ Suivi désactivé : {warn} — le fichier n'est pas modifié.", file=sys.stderr)
        meta["suivi"] = {"disponible": False, "warning": warn}
        return

    today = date.today().isoformat()
    connus = (etat or {}).get("constats", {})
    analyses = (etat or {}).get("analyses", [])
    date_prec = analyses[-1].get("date") if analyses else None

    courants: dict[str, dict] = {}  # id -> {regle, resume}
    for key, ids_fn, resume_fn in _FAMILLES:
        df = tables.get(key)
        if df is None or df.empty:
            continue
        ids = ids_fn(df)
        statut = ids.map(lambda i: "acquitte"
                         if connus.get(i, {}).get("statut") == "acquitte"
                         else ("connu" if i in connus else "nouveau"))
        df["suivi"] = statut
        df["constat_id"] = ids
        # tag visible partout (rapport, Excel, UI) — jamais de suppression silencieuse
        acq = statut.eq("acquitte")
        if acq.any() and "detail" in df.columns:
            tags = ids[acq].map(lambda i: _tag_acquitte(connus.get(i, {})))
            df.loc[acq, "detail"] = df.loc[acq, "detail"].fillna("").astype(str) + tags
        for i in df.index[~ids.duplicated()]:
            courants.setdefault(ids[i], {"regle": str_col(df, "regle")[i] or key,
                                         "resume": resume_fn(df, i)})

    # état suivant : les constats déjà connus sont CONSERVÉS même s'ils ont disparu
    nouveaux = {i: c for i, c in courants.items() if i not in connus}
    constats = {}
    for i, rec in connus.items():
        rec = dict(rec)
        if i in courants:
            rec["derniere_vue"] = today
            if rec.get("statut") != "acquitte":
                rec["statut"] = "connu"
        constats[i] = rec
    for i, c in nouveaux.items():
        constats[i] = {"premiere_vue": today, "derniere_vue": today, "statut": "nouveau",
                       "regle": c["regle"], "resume": c["resume"]}

    n_acq = sum(1 for i in courants if connus.get(i, {}).get("statut") == "acquitte")
    meta["suivi"] = {"disponible": True, "anterieur": etat is not None,
                     "date_precedente": date_prec, "n_constats": len(courants),
                     "n_nouveaux": len(nouveaux), "n_acquittes": n_acq}

    path.write_text(json.dumps(
        {"version": ETAT_VERSION,
         "analyses": analyses + [{"date": today, "n_constats": len(courants)}],
         "constats": constats},
        indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
