# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agrégats PUREMENT DESCRIPTIFS du bruit réseau entrant (aucune sévérité, aucun
constat) — même contrat que `utm_stats` : on décrit ce que les logs montrent, on ne
qualifie pas, on ne conclut pas.

Deux sujets, tous deux observés sur de vrais logs et qu'on reconstituait à la main :
  * **IPsec phase 1** (`logdesc="IPsec phase 1 error"`) : négociations IKE refusées,
    avec le `reason` tel quel (le plus fréquent : `peer SA proposal not match local
    policy`). Beaucoup d'IP pour une poignée de paquets chacune = balayage d'Internet ;
    l'outil le montre, il ne le nomme pas « scan ».
  * **ICMP entrant** (ping) sur `traffic/local`, sources EXTERNES seulement — les pings
    internes (une imprimante qui sonde sa passerelle) noieraient le tableau.

Limite assumée : le protocole n'est pas dans le frame d'analyse (une colonne de plus sur
des millions de lignes), l'ICMP est reconnu par `app="PING"` renseigné par le FortiGate.
Un export où ce champ est vide ne remonte rien — omission franche, jamais d'estimation.
"""
from __future__ import annotations
import pandas as pd

from . import geo
from .common import str_col
from .utm_stats import NOTE

COLS = ["sujet", "source", "detail", "occurrences", "n_lignes_sujet", "n_sources_sujet",
        "premiere_vue", "derniere_vue", "pays", "asn", "org", "note"]

IPSEC_LOGDESC = "IPsec phase 1 error"
SUJET_IPSEC = "IPsec phase 1 — négociation refusée"
SUJET_ICMP = "ICMP entrant (ping) — sources externes"


def _rows(sujet, df, enricher, top_n):
    """df : colonnes ip / detail / t. Une ligne par IP, triée par volume, bornée à
    `top_n` — d'où les totaux du sujet répétés sur chaque ligne : sans eux, une liste
    tronquée laisserait croire que 20 sources sont tout ce qu'il y a."""
    out = []
    for ip, g in df.groupby("ip"):
        ts = pd.to_datetime(g["t"], errors="coerce").dropna().sort_values()
        det = g["detail"][g["detail"].ne("")]
        info = (enricher.lookup(ip) or {}) if enricher else {}
        out.append({
            "sujet": sujet, "source": ip,
            "detail": ", ".join(f"{v} ×{n}" for v, n in det.value_counts().items()),
            "occurrences": len(g),
            "n_lignes_sujet": len(df), "n_sources_sujet": int(df["ip"].nunique()),
            "premiere_vue": ts.iloc[0] if len(ts) else pd.NaT,
            "derniere_vue": ts.iloc[-1] if len(ts) else pd.NaT,
            "pays": info.get("pays", ""), "asn": info.get("asn", ""),
            "org": info.get("org", ""), "note": NOTE,
        })
    out.sort(key=lambda r: r["occurrences"], reverse=True)
    return out[:top_n]


def build_reseau_descriptifs(full: pd.DataFrame, cfg: dict, enricher=None) -> pd.DataFrame:
    if full is None or full.empty or "srcip" not in full.columns:
        return pd.DataFrame(columns=COLS)
    par = cfg.get("reseau_descriptif") or {}
    if not par.get("actif", True):
        return pd.DataFrame(columns=COLS)
    top_n = int(par.get("top_n", 20))

    srcip = str_col(full, "srcip")
    t = full["timestamp"] if "timestamp" in full.columns else pd.Series(pd.NaT, index=full.index)
    if enricher is None:
        enricher = geo.load_enricher(cfg)
    rows = []

    ipsec = str_col(full, "logdesc").eq(IPSEC_LOGDESC) & srcip.ne("")
    if ipsec.any():
        rows += _rows(SUJET_IPSEC, pd.DataFrame({
            "ip": srcip[ipsec], "detail": str_col(full, "reason")[ipsec], "t": t[ipsec],
        }), enricher, top_n)

    # ICMP : externes seulement, l'infrastructure connue (peers, DNS) n'est pas du bruit.
    icmp = (str_col(full, "type").eq("traffic") & str_col(full, "subtype").eq("local")
            & str_col(full, "app").str.upper().eq("PING") & srcip.ne(""))
    if icmp.any():
        nets, infra = geo._nets(cfg), geo._infra_ips(cfg)
        ips = srcip[icmp]
        ext = ips.map(lambda ip: geo.classify_scope(ip, nets) == geo.EXTERNE) & ~ips.isin(infra)
        if ext.any():
            idx = ips[ext].index
            rows += _rows(SUJET_ICMP, pd.DataFrame({
                "ip": ips[ext], "detail": str_col(full, "action")[idx], "t": t[idx],
            }), enricher, top_n)

    return pd.DataFrame(rows, columns=COLS)
