# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agrégats PUREMENT DESCRIPTIFS (aucune sévérité, aucune détection) pour les types
UTM sans règle dédiée : utm/ips (signatures/attaques), utm/webfilter et utm/dns
(domaines/catégories), utm/antivirus (verdicts). Un champ absent des logs fournis
(profil non journalisé) fait omettre la ligne correspondante — jamais de valeur
inventée. Relit les champs via une 2ᵉ passe ciblée (mêmes `source_file`/`_row` que
la feuille « Données unifiées »), sans alourdir le frame d'analyse principal."""
from __future__ import annotations
import pandas as pd

from . import ingest

NOTE = "(descriptif, sans règle d'alerte)"

# (subtype utm, colonnes de regroupement à relire, libellé)
_SPECS = [
    ("ips", ["attack", "severity"], "signatures/attaques"),
    ("webfilter", ["hostname", "catdesc", "action"], "domaines/catégories bloqués"),
    ("dns", ["qname", "catdesc", "action"], "domaines/catégories bloqués"),
    ("antivirus", ["virus"], "verdicts"),
]

COLS = ["type_utm", "libelle", "valeur", "occurrences", "note"]


def build_utm_descriptifs(full: pd.DataFrame, files, cfg: dict) -> pd.DataFrame:
    if full is None or full.empty or "subtype" not in full.columns:
        return pd.DataFrame(columns=COLS)
    n = int((cfg.get("utm_descriptif") or {}).get("top_n", 20))
    rows = []
    for subtype, group_cols, libelle in _SPECS:
        mask = full["type"].astype(str).eq("utm") & full["subtype"].astype(str).eq(subtype)
        if not mask.any():
            continue
        wanted = set(zip(full.loc[mask, "source_file"].astype(str), full.loc[mask, "_row"]))
        extra = ingest.load_columns_for_rows(files, wanted, group_cols)
        present = [c for c in group_cols
                  if c in extra.columns and extra[c].astype(str).str.strip().ne("").any()]
        if not present:
            continue
        g = (extra.groupby(present, observed=True).size().reset_index(name="occurrences")
             .sort_values("occurrences", ascending=False).head(n))
        for _, r in g.iterrows():
            valeur = " / ".join(str(r[c]) for c in present if str(r[c]).strip())
            if not valeur:
                continue
            rows.append({"type_utm": subtype, "libelle": libelle, "valeur": valeur,
                        "occurrences": int(r["occurrences"]), "note": NOTE})
    return pd.DataFrame(rows, columns=COLS)
