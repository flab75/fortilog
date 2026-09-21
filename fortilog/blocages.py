# SPDX-License-Identifier: AGPL-3.0-or-later
"""Efficacité des blocages `local-in-policy` (A2) — DESCRIPTIF, aucune sévérité.

Répond à une seule question : « la contre-mesure posée sur cette IP fonctionne-t-elle ? ».
Pour chaque IP source ayant AU MOINS un drop `local-in-policy` dans `traffic/local` :
combien de drops, combien de connexions ont malgré tout ATTEINT le service, et depuis
quand. Une IP sans aucun drop n'est pas un sujet de contre-mesure -> absente de la table.

Garde-fous : on ne conclut pas qu'une IP est « bloquée » dans l'absolu — seulement que,
DANS LA FENÊTRE DES LOGS FOURNIS, plus aucune connexion n'a abouti après le premier drop.
Si les drops local-in ne sont pas journalisés (`local-in-deny-unicast` désactivé sur le
boîtier), la table est vide : absence de preuve, pas preuve d'absence.
"""
from __future__ import annotations
import pandas as pd

from .common import str_col

NOTE = "(descriptif — vérifié sur la fenêtre des logs fournis, à confirmer sur le boîtier)"

# Actions FortiGate signifiant que la connexion a ATTEINT le service (pas de drop).
ACTIONS_ATTEINT = ("accept", "client-rst", "server-rst", "close", "timeout")

COLS = ["srcip", "boitiers", "n_drops", "premier_drop", "dernier_drop",
        "n_atteint_total", "n_atteint_apres_drop", "statut", "note"]


def build_blocages(full: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    if full is None or full.empty or "policytype" not in full.columns:
        return pd.DataFrame(columns=COLS)
    local = (str_col(full, "type").eq("traffic") & str_col(full, "subtype").eq("local")
             & str_col(full, "srcip").ne(""))
    if not local.any():
        return pd.DataFrame(columns=COLS)
    df = full.loc[local, [c for c in ("srcip", "boitier", "timestamp", "action", "policytype")
                          if c in full.columns]].copy()
    df["srcip"] = str_col(df, "srcip")
    action = str_col(df, "action").str.lower()
    drop = action.eq("deny") & str_col(df, "policytype").eq("local-in-policy")
    if not drop.any():
        return pd.DataFrame(columns=COLS)
    atteint = action.isin(ACTIONS_ATTEINT)

    rows = []
    for ip, g in df[drop].groupby("srcip"):
        premier, dernier = g["timestamp"].min(), g["timestamp"].max()
        hits = df[atteint & df["srcip"].eq(ip)]
        apres = hits[hits["timestamp"] > premier] if pd.notna(premier) else hits
        if apres.empty:
            statut = f"bloquée depuis {str(premier)[:19]} — aucun accès depuis"
        else:
            statut = (f"atteint ENCORE le boîtier malgré la règle : {len(apres)} connexion(s) "
                      f"après le premier drop (dernière {str(apres['timestamp'].max())[:19]})")
        rows.append({
            "srcip": ip,
            "boitiers": ", ".join(sorted(set(str_col(g, "boitier")))) if "boitier" in g else "",
            "n_drops": len(g),
            "premier_drop": premier, "dernier_drop": dernier,
            "n_atteint_total": len(hits), "n_atteint_apres_drop": len(apres),
            "statut": statut, "note": NOTE,
        })
    out = pd.DataFrame(rows, columns=COLS)
    return out.sort_values(["n_atteint_apres_drop", "n_drops"], ascending=False).reset_index(drop=True)
