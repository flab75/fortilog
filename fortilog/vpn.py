# SPDX-License-Identifier: AGPL-3.0-or-later
"""Encart VPN : une ligne = un tunnel SSL-VPN (connexion, clôture, motif, légitimité).

Ce module ne lit QUE ce que le log dit. Les sessions sont reconstruites en appariant
`SSL VPN tunnel up` et `SSL VPN tunnel down` par (boîtier, tunnelid, user) :

- un `up` sans `down` -> « ouverte à la fin de la période » (jamais une durée inventée) ;
- un `down` sans `up`  -> « montée avant la période analysée » ;
- `SSL VPN statistics` (`tunnel-stats`) complète durée/volumes d'une session encore ouverte.

Le BRUIT TLS (`SSL VPN alert`, `SSL VPN new connection`, `SSL VPN exit error`) porte
`user="N/A"` : ce sont des poignées de main de scanners, PAS des sessions. Il est compté
à part, jamais mélangé aux connexions.

La colonne `legitimite` est DESCRIPTIVE : elle liste les points à vérifier (compte hors
référentiel, groupe inconnu, pays inattendu, IP en liste de réputation, pas de 2FA).
Elle ne conclut jamais à une compromission — le verdict reste humain.
"""
from __future__ import annotations
import pandas as pd

from .common import str_col
from .geo import EXTERNE, classify_scope, _nets

UP, DOWN, STATS = "SSL VPN tunnel up", "SSL VPN tunnel down", "SSL VPN statistics"
# Lignes de niveau TLS, sans utilisateur : bruit d'Internet, pas des sessions.
BRUIT = ("SSL VPN alert", "SSL VPN new connection", "SSL VPN exit error")

SESSION_COLS = ["boitier", "user", "groupe", "srcip", "portee", "pays", "org",
                "reputation", "debut", "fin", "duree", "statut", "motif_fin",
                "envoye_mo", "recu_mo", "tunnelip", "tunneltype", "tunnelid", "legitimite"]


def _mo(v) -> str:
    try:
        return f"{int(float(v)) / 1048576:.1f}"
    except (TypeError, ValueError):
        return ""


def _max(serie) -> float:
    return pd.to_numeric(serie, errors="coerce").max()


def _duree(sec) -> str:
    """Secondes -> `2 h 39 min` (le log donne `duration` sur down/stats uniquement)."""
    try:
        s = int(float(sec))
    except (TypeError, ValueError):
        return ""
    h, m = divmod(s // 60, 60)
    return f"{h} h {m:02d} min" if h else f"{m} min"


def build_sessions(full, cfg, comptes_conf=None, enricher=None, repdb=None):
    """-> (DataFrame des sessions, dict de compteurs). Vide si aucun log event/vpn."""
    stats = {"n_sessions": 0, "n_ouvertes": 0, "n_orphelines": 0, "n_users": 0,
             "n_login_fail": 0, "n_bruit_tls": 0, "motifs": {}}
    if full is None or full.empty:
        return pd.DataFrame(columns=SESSION_COLS), stats
    ld = str_col(full, "logdesc")
    stats["n_login_fail"] = int(ld.eq("SSL VPN login fail").sum())
    stats["n_bruit_tls"] = int(ld.isin(BRUIT).sum())

    sess = ld.isin([UP, DOWN, STATS])
    if not sess.any():
        return pd.DataFrame(columns=SESSION_COLS), stats
    d = pd.DataFrame({
        "logdesc": ld[sess], "boitier": str_col(full, "boitier")[sess],
        "user": str_col(full, "user")[sess], "groupe": str_col(full, "group")[sess],
        "srcip": str_col(full, "srcip")[sess], "tunnelip": str_col(full, "tunnelip")[sess],
        "tunneltype": str_col(full, "tunneltype")[sess], "tunnelid": str_col(full, "tunnelid")[sess],
        "reason": str_col(full, "reason")[sess], "duration": str_col(full, "duration")[sess],
        "sentbyte": str_col(full, "sentbyte")[sess], "rcvdbyte": str_col(full, "rcvdbyte")[sess],
        "timestamp": full.loc[sess, "timestamp"] if "timestamp" in full.columns else pd.NaT,
    })
    d = d[d["user"].ne("") & d["user"].ne("N/A")].sort_values("timestamp")
    if d.empty:
        return pd.DataFrame(columns=SESSION_COLS), stats

    # Référentiel : ce qui sert à remplir la colonne `legitimite` (descriptive).
    connus = {u.lower() for u in (set(cfg.get("utilisateurs_vpn_actifs", []))
                                 | set(sum((cfg.get("utilisateurs_locaux") or {}).values(), [])))}
    groupes = {g.lower() for g in cfg.get("groupes_vpn_legitimes", [])}
    pays_ok = {str(p).upper() for p in (cfg.get("pays_attendus") or [])}
    conf = comptes_conf or {}
    nets = _nets(cfg)
    geo_on = enricher is not None and getattr(enricher, "available", False)

    rows = []
    # ponytail: un tunnelid réutilisé par le boîtier pour le même compte fusionnerait deux
    # sessions ; jamais observé sur les exports réels (ids sur 10 chiffres).
    for (boit, uid, tid), g in d.groupby(["boitier", "user", "tunnelid"], sort=False):
        up = g[g["logdesc"].eq(UP)]
        down = g[g["logdesc"].eq(DOWN)]
        fin_rows = down if not down.empty else g[g["logdesc"].eq(STATS)]
        src = next((v for v in g["srcip"] if v), "")
        portee = classify_scope(src, nets) if src else ""
        # Géo seulement sur une IP externe : une IP privée n'a pas de pays (la base
        # renvoie « ZZ » = plage réservée, ce qui n'est pas une information de localisation).
        geo = enricher.lookup(src) if (geo_on and src and portee == EXTERNE) else {}
        rep = ", ".join(repdb.match(src)) if (repdb is not None and src
                                             and portee == EXTERNE) else ""
        if not up.empty:
            statut = "fermée" if not down.empty else "ouverte en fin de période"
        else:
            statut = "montée avant la période analysée"
        last = fin_rows.iloc[-1] if not fin_rows.empty else g.iloc[-1]

        alertes = []
        if uid.lower() not in connus:
            alertes.append("compte hors référentiel")
        grp = next((v for v in g["groupe"] if v and v != "N/A"), "")
        if groupes and grp and grp.lower() not in groupes:
            alertes.append("groupe hors référentiel")
        # Pays : uniquement sur une IP EXTERNE et un code réel — « ZZ » est le
        # marqueur « plage réservée » de la base géo, pas un pays (même règle que R17).
        if pays_ok and geo.get("pays", "").upper() not in pays_ok | {"", "ZZ"}:
            alertes.append(f"pays inattendu ({geo['pays']})")
        if rep:
            alertes.append(f"IP en liste de réputation ({rep})")
        info = conf.get(uid.lower())
        if info is not None and not info.get("two_factor"):
            alertes.append("compte sans double authentification")

        rows.append({
            "boitier": boit, "user": uid, "groupe": grp, "srcip": src, "portee": portee,
            "pays": geo.get("pays", ""), "org": geo.get("org", ""), "reputation": rep,
            "debut": up["timestamp"].min() if not up.empty else pd.NaT,
            "fin": down["timestamp"].max() if not down.empty else pd.NaT,
            "duree": _duree(_max(g["duration"])),
            "statut": statut,
            "motif_fin": (last["reason"] if not down.empty and last["reason"] not in ("", "N/A")
                          else ("" if down.empty else "non précisé")),
            # Volumes : le max de la session — `tunnel down` remet parfois les compteurs
            # à 0 (mode ssl-web sans trafic tunnelé), les `tunnel statistics` les portent.
            "envoye_mo": _mo(_max(g["sentbyte"])), "recu_mo": _mo(_max(g["rcvdbyte"])),
            "tunnelip": next((v for v in g["tunnelip"] if v), ""),
            "tunneltype": next((v for v in g["tunneltype"] if v), ""),
            "tunnelid": tid,
            "legitimite": " ; ".join(alertes) if alertes
                          else "aucun écart au référentiel (à confirmer)",
        })
    out = (pd.DataFrame(rows, columns=SESSION_COLS)
             .sort_values(["debut", "user"], na_position="last", ignore_index=True))
    stats.update(n_sessions=len(out), n_users=int(out["user"].nunique()),
                 n_ouvertes=int(out["statut"].eq("ouverte en fin de période").sum()),
                 n_orphelines=int(out["statut"].eq("montée avant la période analysée").sum()),
                 motifs=out.loc[out["motif_fin"].ne(""), "motif_fin"].value_counts().to_dict())
    return out, stats
