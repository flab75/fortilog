# SPDX-License-Identifier: AGPL-3.0-or-later
"""Empreinte de dictionnaire et CADENCE par IP source (C1 + C2).

DESCRIPTIF, aucune sévérité : la table dit *comment* une IP s'y prend, pas si c'est grave.

- **Empreinte (C1)** : combien d'identifiants distincts l'IP a tentés, et un échantillon.
  Le vocabulaire est signant à l'œil nu (comptes métier allemands d'un côté, comptes
  techniques anglais + noms de villes de l'autre) — c'est l'auditeur qui le lit, l'outil
  ne nomme aucune « campagne ».
  Le regroupement automatique par similarité (Jaccard sur les jeux d'identifiants) a été
  MESURÉ puis écarté : les bots d'une même campagne se partagent le dictionnaire, donc
  J ≈ 0,01 entre deux IP voisines tapant 635 comptes chacune. Ne pas le ré-introduire sans
  nouvelle mesure (cf. `blocklist.py`, qui regroupe par /24).

- **Cadence (C2)** : intervalle MÉDIAN entre deux tentatives, et sa régularité. Un automate
  tape toutes les ~8 min à la seconde près. L'intérêt pratique est la colonne `suite` :
  * si la cadence projette la tentative suivante APRÈS la fin des logs → « prochaine
    attendue vers HH:MM » : c'est le moment où aller vérifier qu'un blocage agit, au lieu
    d'attendre au hasard. Une PRÉVISION, jamais un fait.
  * si elle la projette AVANT la fin des logs et qu'il ne s'est rien passé → l'IP s'est
    TUE : « aucune tentative depuis … , N intervalle(s) manqué(s) ». C'est l'observation
    qui vaut vérification d'une contre-mesure — sans conclure qu'elle en est la cause.
"""
from __future__ import annotations
import pandas as pd

from .common import FAIL_LOGDESC, str_col

COLS = ["srcip", "boitiers", "n_tentatives", "n_comptes", "echantillon_comptes",
        "cadence_mediane_s", "regularite", "premiere_vue", "derniere_vue",
        "suite", "note"]

NOTE = "descriptif, sans règle d'alerte"


def _regularite(deltas: pd.Series) -> str:
    """Qualifie la dispersion des intervalles. Seuils volontairement grossiers :
    on sépare « automate » de « humain », pas plus."""
    med = deltas.median()
    if not med or med <= 0:
        return ""
    ecart = deltas.std()
    if ecart is None or ecart != ecart:
        return ""
    ratio = ecart / med
    if ratio < 0.25:
        return "très régulière (automate)"
    if ratio < 1.0:
        return "régulière"
    return "irrégulière"


def build_empreintes(full: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    cfg = cfg or {}
    par = cfg.get("empreintes") or {}
    if not par.get("actif", True):
        return pd.DataFrame(columns=COLS)
    mini = int(par.get("min_tentatives", 10))
    maxi = int(par.get("max_lignes", 30))
    if full is None or full.empty or "srcip" not in full.columns:
        return pd.DataFrame(columns=COLS)

    ld = str_col(full, "logdesc")
    srcip = str_col(full, "srcip")
    user = str_col(full, "user")
    mask = ld.isin(FAIL_LOGDESC) & srcip.ne("") & user.ne("")
    if not mask.any():
        return pd.DataFrame(columns=COLS)
    df = pd.DataFrame({"srcip": srcip[mask], "user": user[mask],
                       "boitier": str_col(full, "boitier")[mask],
                       "t": pd.to_datetime(full.loc[mask, "timestamp"], errors="coerce")
                       if "timestamp" in full.columns else pd.NaT})
    # Fin de la fenêtre réellement couverte : au-delà, on ne sait rien (garde-fou D1).
    fin_fenetre = pd.to_datetime(full["timestamp"], errors="coerce").max() \
        if "timestamp" in full.columns else pd.NaT

    rows = []
    for ip, g in df.groupby("srcip"):
        if len(g) < mini:
            continue
        comptes = list(dict.fromkeys(g["user"]))  # ordre d'apparition, sans doublon
        ts = g["t"].dropna().sort_values()
        deltas = ts.diff().dt.total_seconds().dropna()
        med = deltas.median() if len(deltas) else None
        suite = ""
        if med and med > 0 and len(ts):
            attendue = ts.iloc[-1] + pd.Timedelta(seconds=med)
            if pd.isna(fin_fenetre) or attendue > fin_fenetre:
                suite = f"prochaine attendue vers {str(attendue)[:19]} (prévision)"
            else:
                manques = int((fin_fenetre - ts.iloc[-1]).total_seconds() // med)
                suite = (f"aucune tentative depuis {str(ts.iloc[-1])[:19]} — "
                         f"{manques} intervalle(s) manqué(s) à cette cadence")
        rows.append({
            "srcip": ip,
            "boitiers": ", ".join(sorted(set(g["boitier"]) - {""})),
            "n_tentatives": len(g),
            "n_comptes": len(comptes),
            "echantillon_comptes": ", ".join(comptes[:8])
                                   + (f" … (+{len(comptes) - 8})" if len(comptes) > 8 else ""),
            "cadence_mediane_s": round(float(med), 1) if med else "",
            "regularite": _regularite(deltas) if len(deltas) > 2 else "",
            "premiere_vue": ts.iloc[0] if len(ts) else pd.NaT,
            "derniere_vue": ts.iloc[-1] if len(ts) else pd.NaT,
            "suite": suite,
            "note": NOTE,
        })
    out = pd.DataFrame(rows, columns=COLS)
    if out.empty:
        return out
    return out.sort_values("n_tentatives", ascending=False).head(maxi).reset_index(drop=True)
