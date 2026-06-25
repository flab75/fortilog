# SPDX-License-Identifier: AGPL-3.0-or-later
"""Corrélation temporelle : reconstruit des CHAÎNES d'indices (IoC) ordonnées.

Objectif : détecter la SÉQUENCE login -> création/modif de compte -> exfiltration
par un même acteur (user) OU une même IP, dans une fenêtre de N minutes — le
scénario reconstitué manuellement lors de l'audit.

Garde-fou NON NÉGOCIABLE : une chaîne est une CORRÉLATION TEMPORELLE, pas une
preuve de compromission. La sortie est explicitement marquée « à confirmer ».
On ne corrèle QUE des événements déjà signalés par detect.run_detection.
"""
from __future__ import annotations
import re
import pandas as pd

from .common import CFG_ACCOUNT_PATHS, str_col

# Étapes canoniques d'une chaîne d'intrusion (dérivées de la sémantique du log,
# pas du libellé de règle — pour dédupliquer les lignes flaggées par 2 règles).
ENTRY = "ACCES"            # login admin réussi / tunnel VPN établi
ESCALATION = "COMPTE"      # création / modification de compte admin/SSO/API
EXFIL = "EXFILTRATION"     # téléchargement de config / de logs
PERSIST = "PERSISTANCE"    # automation déclenchée
LATERAL = "LATERAL"        # accès pool VPN -> management

# Séquence requise par défaut pour qu'une chaîne soit « complète » (critique).
DEFAULT_SEQUENCE = [ENTRY, ESCALATION, EXFIL]
DEFAULT_WINDOW_MIN = 60

_IP_IN_UI = re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)")


def _step_kind(logdesc: str, action: str, cfgpath: str) -> str:
    """Dérive l'étape d'intrusion d'un événement (ou '' si non pertinent)."""
    if logdesc in ("Admin login successful", "SSL VPN tunnel up"):
        return ENTRY
    if logdesc == "Object attribute configured" and cfgpath in CFG_ACCOUNT_PATHS:
        return ESCALATION
    if logdesc == "Admin performed an action from GUI" and action == "download":
        return EXFIL
    if logdesc == "Log file downloaded from GUI":
        return EXFIL
    if logdesc == "Automation stitch triggered":
        return PERSIST
    return ""


def _effective_ip(row: pd.Series) -> str:
    """IP effective : srcip si présent, sinon IP extraite du champ ui (GUI(x)/https(x))."""
    src = str(row.get("srcip", "") or "")
    if src:
        return src
    m = _IP_IN_UI.search(str(row.get("ui", "") or ""))
    return m.group(1) if m else ""


def _find_ordered(steps: list[tuple], sequence: list[str], window: pd.Timedelta):
    """Cherche, dans une liste (timestamp, kind, idx) triée par temps, la première
    sous-séquence ordonnée correspondant à `sequence`, contrainte à `window`
    (dernier - premier <= window). Renvoie la liste des idx, ou None."""
    n = len(steps)
    for start in range(n):
        ts0, kind0, idx0 = steps[start]
        if kind0 != sequence[0]:
            continue
        matched = [idx0]
        last_ts = ts0
        want = 1
        for j in range(start + 1, n):
            ts, kind, idx = steps[j]
            if ts - ts0 > window:
                break
            if kind == sequence[want]:
                matched.append(idx)
                last_ts = ts
                want += 1
                if want == len(sequence):
                    return matched
    return None


def correlate_chains(events: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Reconstruit les chaînes suspectes à partir des événements signalés.

    Renvoie un DataFrame (une ligne par chaîne) avec colonnes :
    chaine_id, cle_type, cle, boitier, debut, fin, duree_min, etapes, n_etapes,
    severite, detail.
    """
    empty = pd.DataFrame(columns=[
        "chaine_id", "cle_type", "cle", "boitier", "debut", "fin",
        "duree_min", "etapes", "n_etapes", "severite", "detail",
    ])
    if events is None or events.empty:
        return empty

    corr = cfg.get("correlation", {}) or {}
    window = pd.Timedelta(minutes=int(corr.get("fenetre_minutes", DEFAULT_WINDOW_MIN)))
    sequence = list(corr.get("sequence_requise", DEFAULT_SEQUENCE))

    df = events.copy()
    if "timestamp" not in df.columns:
        return empty

    g = lambda c: str_col(df, c)
    df["_kind"] = [
        _step_kind(ld, ac, cp)
        for ld, ac, cp in zip(g("logdesc"), g("action"), g("cfgpath"))
    ]
    # Garde-fou anti-bruit : un maillon d'ACCÈS ne démarre une chaîne d'intrusion
    # que s'il est ANORMAL (login externe/hors-référentiel, VPN hors-référentiel —
    # sévérité ≠ info). Un login admin interne connu de routine n'est pas un indice.
    sev = g("severite")
    df.loc[(df["_kind"] == ENTRY) & (sev == "info"), "_kind"] = ""
    # IP effective vectorisée : srcip si présent, sinon IP extraite du champ ui.
    _src = g("srcip")
    _ui_ip = g("ui").str.extract(_IP_IN_UI.pattern, expand=False).fillna("")
    df["_ip"] = _src.where(_src != "", _ui_ip)
    df["_user"] = g("user")

    # On ne garde que les événements porteurs d'une étape, et on déduplique les
    # lignes sous-jacentes flaggées par plusieurs règles.
    df = df[(df["_kind"] != "") & df["timestamp"].notna()].copy()
    if df.empty:
        return empty
    df = df.drop_duplicates(subset=["timestamp", "_user", "_ip", "_kind"])

    rows = []
    seen_signatures = set()
    chain_id = 0

    # Deux clés de corrélation : acteur (user) puis IP effective.
    for cle_type, col in (("acteur", "_user"), ("ip", "_ip")):
        for cle, grp in df.groupby(col):
            if cle == "":
                continue
            grp = grp.sort_values("timestamp")
            steps = list(zip(grp["timestamp"], grp["_kind"], grp.index))
            matched = _find_ordered(steps, sequence, window)
            if not matched:
                continue
            sub = grp.loc[matched].sort_values("timestamp")
            # Signature = ensemble des index d'événements (évite de réémettre la
            # même chaîne via acteur ET ip).
            sig = frozenset(matched)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            chain_id += 1
            debut, fin = sub["timestamp"].min(), sub["timestamp"].max()
            etapes = " → ".join(sub["_kind"].tolist())
            boitier = sub["boitier"].iloc[0] if "boitier" in sub.columns else ""
            regles = (sub["regle"] if "regle" in sub.columns
                      else pd.Series([""] * len(sub), index=sub.index))
            detail = " | ".join(
                f"{str(t)[:19]} {k} [{r}]"
                for t, k, r in zip(sub["timestamp"], sub["_kind"], regles)
            )
            rows.append({
                "chaine_id": chain_id,
                "cle_type": cle_type,
                "cle": cle,
                "boitier": boitier,
                "debut": debut,
                "fin": fin,
                "duree_min": round((fin - debut).total_seconds() / 60, 1),
                "etapes": etapes,
                "n_etapes": len(matched),
                "severite": "critique",
                "detail": detail,
            })

    if not rows:
        return empty
    return pd.DataFrame(rows).sort_values("debut").reset_index(drop=True)
